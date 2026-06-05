"""FastAPI 启停钩子"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI

import src.globals as g
from src.tmp_dir import init_tmp_dir
from src.config import load_config
from src.logg import setup_logging
from src.core.event_handlers import register_default_handlers
from src.core.task_control import reload_paused_from_db
from src.infrastructure.db import dispose_engine, init_engine
from src.infrastructure.db.init_db import init_db
from src.services.config_service import ensure_jwt_secret
from src.storage import close_clients, init_clients
from src.tools.bootstrap.startup import ensure_tool_dependencies_at_startup

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动时同时初始化 PostgreSQL 与 Neo4j（幂等），关停时释放连接。"""
    config = load_config()
    app.state.config = config
    setup_logging(level=config.log_level, log_file=config.log_file)

    logger.info("[lifespan] 应用启动中 …")

    # 任务临时目录：与 src/main.py 一致；未设置时由 init_tmp_dir 统一 resolve。
    if not str(getattr(g, "TMP_DIR", "") or "").strip():
        init_tmp_dir()
        logger.info("[lifespan] 临时目录已初始化: %s", getattr(g, "TMP_DIR", ""))

    # 1) PostgreSQL：engine + 建表 + 种子
    init_engine(config.postgres)
    try:
        init_db(config)
        logger.info(
            "[lifespan] PostgreSQL 就绪: %s:%s/%s",
            config.postgres.host,
            config.postgres.port,
            config.postgres.db,
        )
    except Exception as ex:  # pragma: no cover - 启动失败直接抛出
        logger.exception("[lifespan] init_db 失败: %s", ex)
        raise

    # 2) Neo4j：全局客户端 + repository
    try:
        init_clients(config)
        logger.info("[lifespan] Neo4j 就绪: %s", config.neo4j.uri)
    except Exception as ex:  # pragma: no cover - Neo4j 不可达不阻断 API 启动
        logger.warning("[lifespan] Neo4j 初始化失败（将在运行期按需重试）: %s", ex)

    ensure_jwt_secret()
    logger.info("[lifespan] JWT 密钥已校验")

    register_default_handlers()
    try:
        reload_paused_from_db()
        logger.info("[lifespan] 暂停任务状态已从数据库恢复")
    except Exception as ex:  # pragma: no cover
        logger.warning("[lifespan] 恢复暂停任务状态失败: %s", ex)

    # 启动时清理遗留的 running/paused 任务（进程重启后旧任务已失去执行线程）
    try:
        from src.infrastructure.db import session_scope
        from src.infrastructure.db.models import Task as TaskModel
        from src.core.task_control import get_task_control

        ctrl = get_task_control()
        with session_scope() as session:
            orphaned = session.query(TaskModel).filter(
                TaskModel.status.in_(["running", "paused"])
            ).all()
            if orphaned:
                orphaned_ids = [t.id for t in orphaned]
                for t in orphaned:
                    t.status = "failed"
                    t.error = "服务重启，任务被动终止"
                    t.finished_at = datetime.now(timezone.utc)
                    ctrl.clear_stopped(t.id)
                    ctrl.clear_paused(t.id)
                session.commit()
                logger.info(
                    "[lifespan] 已将 %d 个遗留 running/paused 任务标记为 failed，内存标记已清理",
                    len(orphaned),
                )
                # 同时清理这些任务下遗留的 running 事件
                from src.infrastructure.db.models import EventRecord
                from src.core.enums import ActionType
                from sqlalchemy import update as sa_update
                ev_result = session.execute(
                    sa_update(EventRecord)
                    .where(
                        EventRecord.task_id.in_(orphaned_ids),
                        EventRecord.status == "running",
                        EventRecord.action_type != ActionType.INFORMATION.value,
                    )
                    .values(status="failed", finished_at=datetime.now(timezone.utc))
                )
                ev_count = int(ev_result.rowcount or 0)
                if ev_count:
                    session.commit()
                    logger.info(
                        "[lifespan] 已将 %d 条遗留 running 事件标记为 failed",
                        ev_count,
                    )
    except Exception as ex:  # pragma: no cover
        logger.warning("[lifespan] 清理遗留 running 任务失败: %s", ex)
    try:
        ensure_tool_dependencies_at_startup()
        logger.info("[lifespan] 工具依赖检查完成")
    except Exception as ex:  # pragma: no cover - 工具依赖检查失败不阻断 API 启动
        logger.warning("[lifespan] 工具依赖检查失败: %s", ex)

    logger.info("[lifespan] ArgusMind API 启动完成，开始接受请求")

    # 非阻塞后台任务：延迟拉取 OpenCode provider 列表（不阻塞启动）
    try:
        import threading
        def _deferred_opencode_fetch():
            import time
            time.sleep(10)  # 等 API 完全就绪
            try:
                from src.infrastructure.db.init_db import fetch_opencode_provider_list
                from src.infrastructure.db import session_scope
                from src.infrastructure.db.models import ConfigEntry
                fetched = fetch_opencode_provider_list()
                with session_scope() as session:
                    row = session.query(ConfigEntry).filter(
                        ConfigEntry.name == "code_agent_provider_list"
                    ).one_or_none()
                    if row is not None and fetched.get("providers"):
                        row.value_json = fetched
                logger.info("[lifespan] 后台 OpenCode provider 列表已更新")
            except Exception as ex:
                logger.debug("[lifespan] 后台 OpenCode provider 拉取未完成: %s", ex)
        threading.Thread(target=_deferred_opencode_fetch, daemon=True).start()
    except Exception:
        pass

    try:
        yield
    finally:
        logger.info("[lifespan] 应用关闭中 …")
        try:
            close_clients()
            logger.info("[lifespan] Neo4j 连接已关闭")
        except Exception as ex:  # pragma: no cover
            logger.warning("[lifespan] Neo4j 关闭异常: %s", ex)
        dispose_engine()
        logger.info("[lifespan] PostgreSQL 连接池已释放")

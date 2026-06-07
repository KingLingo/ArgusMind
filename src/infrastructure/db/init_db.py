"""数据库初始化：建表 + 种子数据"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import psycopg2
from psycopg2 import sql
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.config import Config
from src.infrastructure.db import Base, init_engine, session_scope
from src.infrastructure.db.models import ConfigEntry, User  # noqa: F401  保证模型被注册
from src.infrastructure.db import models  # noqa: F401  批量注册所有模型
from src.infrastructure.security.password import hash_password

logger = logging.getLogger(__name__)

# ---------------- 默认种子 ----------------

DEFAULT_USERNAME = "ArgusMind"
DEFAULT_PASSWORD = "ArgusMind"

POPULAR_PROVIDERS = {
    "opencode",
    "opencode-go",
    "anthropic",
    "github-copilot",
    "openai",
    "google",
    "openrouter",
    "vercel",
    "deepseek",
}

DEFAULT_CONFIGS: List[Dict[str, Any]] = [
    {
        "name": "LLM_config",
        "value_json": {
            "LLM_provider": "",
            "LLM_key": "",
            "LLM_model": "",
            "LLM_baseurl": "",
        },
        "description": "默认 LLM 接入配置",
    },
    {
        "name": "code_agent_config",
        "value_json": {
            "code_agent_provider": "",
            "code_agent_key": "",
            "code_agent_model": "",
            "code_agent_baseurl": "",
            "code_agent_engine": "",
        },
        "description": "默认 Code Agent 配置",
    },
    {
        "name": "LLM_provider_list",
        "value_json": {},
        "description": "内置 LLM 厂商/模型清单（通过 litellm.model_cost 获取）",
    },
    {
        "name": "code_agent_provider_list",
        "value_json": {"providers": []},
        "description": "内置 Code Agent 厂商/模型清单（通过 opencode 获取；当前占位，后续补充）",
    },
]


def fetch_litellm_provider_list() -> Dict[str, Any]:
    """拉取 litellm 内置厂商/模型清单并标记热门厂商。

    返回结构：{provider: {"models": [...], "provider_type": "popular"(可选)}}
    """
    try:
        from litellm import model_cost  # type: ignore

        provider_models: Dict[str, set[str]] = {}
        for model, info in (model_cost or {}).items():
            if not isinstance(info, dict):
                continue
            provider = (info.get("litellm_provider") or "").strip()
            if not provider:
                continue
            provider_models.setdefault(provider, set()).add(model)

        provider_entries: Dict[str, Any] = {}
        for provider, models in sorted(provider_models.items()):
            provider_item: Dict[str, Any] = {"models": sorted(models)}
            if provider in POPULAR_PROVIDERS:
                provider_item["provider_type"] = "popular"
            provider_entries[provider] = provider_item
        logger.info(
            "[init_db] litellm provider 清单拉取完成: providers=%d",
            len(provider_entries),
        )
        return provider_entries
    except Exception as ex:  # pragma: no cover - 离线或 litellm 未装时降级为空
        logger.warning("[init_db] litellm provider 清单拉取失败: %s", ex)
        return {"error": str(ex)}


def fetch_opencode_provider_list() -> Dict[str, Any]:
    """拉取 OpenCode 的 provider/model 清单（通过本地 opencode 服务）。"""
    from src.tools.opencode import OpenCodeTool
    tool: OpenCodeTool | None = None
    service_url = ""
    try:
        project_root = str(Path(__file__).resolve().parents[3])
        directory = str(Path(project_root).anchor or Path(project_root))
        # 初始化服务时 model/provider 参数可为空；这里给出默认占位值。
        tool = OpenCodeTool(
            project_path=project_root,
            model_id="gpt-4o-mini",
            provider_id="openai",
        )
        service_url = tool.get_url().rstrip("/")

        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            resp = client.get(
                f"{service_url}/provider",
                params={"directory": directory},
            )
            if resp.status_code == 200:
                data = resp.json()
                providers: List[Dict[str, Any]] = []
                all_providers = data.get("all") if isinstance(data, dict) else None
                if isinstance(all_providers, list):
                    for p in all_providers:
                        if not isinstance(p, dict):
                            continue
                        provider_id = (p.get("id") or "").strip()
                        if not provider_id:
                            continue
                        models = p.get("models") or {}
                        model_items: List[Dict[str, Any]] = []
                        if isinstance(models, dict):
                            for model_id in sorted(models.keys()):
                                model_info = models.get(model_id) or {}
                                model_item: Dict[str, Any] = {"id": model_id}
                                if provider_id == "opencode":
                                    cost = (
                                        model_info.get("cost")
                                        if isinstance(model_info, dict)
                                        else None
                                    )
                                    input_cost = None
                                    if isinstance(cost, dict):
                                        try:
                                            input_cost = float(cost.get("input"))
                                        except (TypeError, ValueError):
                                            input_cost = None
                                    if not cost or (
                                        isinstance(cost, dict) and input_cost == 0
                                    ):
                                        model_item["type"] = "free"
                                model_items.append(model_item)

                        provider_item: Dict[str, Any] = {
                            "id": provider_id,
                            "name": p.get("name") or provider_id,
                            "models": model_items,
                        }
                        if provider_id in POPULAR_PROVIDERS:
                            provider_item["provider_type"] = "popular"
                        providers.append(provider_item)
                logger.info(
                    "[init_db] opencode provider 清单拉取完成: providers=%d source=%s/provider",
                    len(providers),
                    service_url,
                )
                return {"providers": providers, "source": f"{service_url}/provider"}

            body_preview = (resp.text or "")[:200]
            logger.warning(
                "[init_db] opencode provider 清单拉取失败: status=%s url=%s/provider directory=%s body=%s",
                resp.status_code,
                service_url,
                directory,
                body_preview,
            )
            return {
                "providers": [],
                "error": f"HTTP {resp.status_code}",
                "source": f"{service_url}/provider",
            }
    except Exception as ex:  # pragma: no cover
        logger.warning(
            "[init_db] opencode provider 清单拉取失败: url=%s err=%s",
            service_url or "(服务未启动)",
            ex,
        )
        return {"providers": [], "error": str(ex)}
    finally:
        if tool is not None:
            try:
                tool.close()
            except Exception:
                pass
    logger.warning(
        "[init_db] opencode provider 清单拉取失败: url=%s reason=未返回有效响应",
        service_url or "(未知)",
    )
    return {"providers": []}


def create_all_tables(config: Config) -> bool:
    """确保所有 ORM 模型对应的表都存在；返回数据库是否是本次新创建的。

    Base.metadata.create_all 是幂等操作：已存在的表会跳过，缺失的表会被补建。
    这样新增模型（例如 opencode_events）也能在已存在的数据库上自动生效。
    """
    created = ensure_database_exists(config)
    engine = init_engine(config.postgres)
    Base.metadata.create_all(engine)
    logger.info("[init_db] ORM 建表完成: db=%s created=%s", config.postgres.db, created)

    # 对已有表的列补建（create_all 不会修改已有表结构）
    _ensure_missing_columns(engine, config.postgres.db)
    # 对已有表的外键约束进行迁移（create_all 不会修改已有约束）
    _ensure_fk_constraints(engine)

    return created


def _ensure_missing_columns(engine, db_name: str) -> None:
    """对已有表补建缺失的列（幂等：已存在则跳过）。

    两条路径：
    1. 硬编码迁移清单（用于旧表新增列的注释性迁移）
    2. 自动检测：遍历所有 ORM 注册的表，与数据库实际 schema 对比，补建缺失列
    """
    import sqlalchemy as sa

    # --- 路径1：硬编码迁移 ---
    migrations = [
        # (table, column, type_def)
        ("tasks", "offline_mode", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("tasks", "enable_sink_finder", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("tasks", "vuln_count", "INTEGER NOT NULL DEFAULT 0"),
        # vulnerability_details 新增字段
        ("vulnerability_details", "remediation", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "safe_validation", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "impact", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "owasp", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "gbt_mapping", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "cwe", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "cve", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "code_snippet", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "language", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "cvss_score", "TEXT NOT NULL DEFAULT ''"),
        ("vulnerability_details", "sink", "JSONB"),
    ]
    with engine.connect() as conn:
        for table, column, type_def in migrations:
            result = conn.execute(
                sa.text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name = :tn AND column_name = :cn"
                ),
                {"tn": table, "cn": column},
            )
            if result.fetchone() is None:
                conn.execute(sa.text(f"ALTER TABLE {table} ADD COLUMN {column} {type_def}"))
                conn.commit()
                logger.info("[init_db] 列迁移: %s.%s 已添加", table, column)

    # --- 路径2：自动检测 ORM 模型与数据库差异 ---
    _auto_sync_orm_columns(engine)


def _auto_sync_orm_columns(engine) -> None:
    """自动将 ORM 模型中定义了但数据库表中缺失的列补建。

    利用 SQLAlchemy metadata 对比 information_schema，自动补列，
    避免每次新增字段都要手动维护 migrations 列表。
    """
    import sqlalchemy as sa
    from src.infrastructure.db import Base

    inspector = sa.inspect(engine)
    with engine.connect() as conn:
        for table_name, table in Base.metadata.tables.items():
            if table_name.startswith("_") or table_name == "alembic_version":
                continue
            try:
                db_cols = {c["name"] for c in inspector.get_columns(table_name)}
            except Exception:
                continue  # 表不存在时跳过
            for column in table.columns:
                if column.key not in db_cols:
                    # 构造列 DDL
                    col_type = column.type.compile(engine.dialect)
                    nullable = "NULL" if column.nullable else "NOT NULL"
                    default = ""
                    if column.default is not None and column.default.arg is not None:
                        default_val = column.default.arg
                        if callable(default_val):
                            default_val = default_val()
                        if isinstance(default_val, str):
                            default = f"DEFAULT '{default_val}'"
                        elif isinstance(default_val, (int, float, bool)):
                            default = f"DEFAULT {default_val}"
                        else:
                            default = f"DEFAULT '{default_val}'"
                    ddl = f"ALTER TABLE {table_name} ADD COLUMN {column.key} {col_type} {nullable} {default}"
                    try:
                        conn.execute(sa.text(ddl))
                        conn.commit()
                        logger.info("[init_db] 自动补列: %s.%s (%s)", table_name, column.key, col_type)
                    except Exception as ex:
                        conn.rollback()
                        logger.warning("[init_db] 自动补列失败 %s.%s: %s", table_name, column.key, ex)


def _ensure_fk_constraints(engine) -> None:
    """将已有外键约束从 SET NULL 迁移为 CASCADE（幂等）。"""
    import sqlalchemy as sa

    migrates = [
        # (constraint_name, table, column, ref_table, ref_column)
        ("vulnerability_task_id_fkey", "vulnerability", "task_id", "tasks", "id"),
    ]
    with engine.connect() as conn:
        for cname, table, column, ref_table, ref_column in migrates:
            row = conn.execute(
                sa.text(
                    "SELECT delete_rule FROM information_schema.referential_constraints "
                    "WHERE constraint_name = :cn AND constraint_schema = 'public'"
                ),
                {"cn": cname},
            ).fetchone()
            if row and row[0] == "SET NULL":
                conn.execute(sa.text(f"ALTER TABLE {table} DROP CONSTRAINT {cname}"))
                conn.execute(
                    sa.text(
                        f"ALTER TABLE {table} ADD CONSTRAINT {cname} "
                        f"FOREIGN KEY ({column}) REFERENCES {ref_table}({ref_column}) ON DELETE CASCADE"
                    )
                )
                conn.commit()
                logger.info("[init_db] FK 迁移: %s ON DELETE SET NULL -> CASCADE", cname)


def ensure_database_exists(config: Config) -> bool:
    """若目标数据库不存在则自动创建，返回是否新建了数据库。

    支持以下场景：
    - PostgreSQL 有 `postgres` 维护库（标准安装）
    - `template1` 维护库（部分托管服务缺少 postgres 库）
    - 数据库已存在：幂等返回 False
    """
    pg = config.postgres
    target_db = pg.db

    # 先尝试直接连接到目标库校验是否存在
    conn = None
    try:
        conn = psycopg2.connect(
            host=pg.host,
            port=pg.port,
            user=pg.user,
            password=pg.password,
            dbname=target_db,
            connect_timeout=3,
        )
        conn.close()
        logger.info("[init_db] 目标数据库已存在: db=%s", target_db)
        return False
    except (psycopg2.OperationalError, psycopg2.ProgrammingError):
        pass
    finally:
        if conn is not None:
            conn.close()

    # 通过维护库创建目标库
    for maintenance_db in ("postgres", "template1"):
        conn = None
        try:
            conn = psycopg2.connect(
                host=pg.host,
                port=pg.port,
                user=pg.user,
                password=pg.password,
                dbname=maintenance_db,
                connect_timeout=3,
            )
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
                exists = cur.fetchone() is not None
                if not exists:
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(target_db)))
                    logger.info(
                        "[init_db] 目标数据库不存在，已创建: db=%s via=%s",
                        target_db,
                        maintenance_db,
                    )
                    return True
                logger.info("[init_db] 目标数据库已存在: db=%s via=%s", target_db, maintenance_db)
                return False
        except Exception as ex:
            logger.warning(
                "[init_db] 使用维护库连接失败，尝试下一个: maintenance_db=%s err=%s",
                maintenance_db,
                ex,
            )
            if maintenance_db == "template1":
                logger.warning("[init_db] 所有维护库连接失败，数据库可能未启动: host=%s port=%s", pg.host, pg.port)
                raise
        finally:
            if conn is not None:
                conn.close()
    # 如果所有尝试都失败（理论上不会走到这里，但防御性保留）
    raise RuntimeError(
        f"无法创建数据库 '{target_db}'：无法连接到 PostgreSQL (host={pg.host}:{pg.port})"
    )


def set_llm_provider(session: Session) -> None:
    # 若 provider list 当前为空，尝试在线拉取一次填充（失败不阻塞）
    _hydrate_provider_list(
        session,
        name="LLM_provider_list",
        fetcher=fetch_litellm_provider_list,
    )
    # OpenCode provider list 在启动时单独异步拉取，不阻塞 init_db
    # 首次初始化时仅写入占位空数据
    placeholder = {"providers": [], "note": "将在后台任务中更新"}
    row = session.query(ConfigEntry).filter(ConfigEntry.name == "code_agent_provider_list").one_or_none()
    if row is None:
        row = ConfigEntry(name="code_agent_provider_list", value_json=placeholder,
                          description="内置 Code Agent 厂商/模型清单")
        session.add(row)
    elif not row.value_json or not isinstance(row.value_json, dict) or not row.value_json.get("providers"):
        row.value_json = placeholder


def seed_default_data(session: Session) -> None:
    """写入默认种子数据（幂等）"""
    # 默认用户
    user = session.query(User).filter(User.username == DEFAULT_USERNAME).one_or_none()
    if user is None:
        user = User(
            username=DEFAULT_USERNAME,
            password_hash=hash_password(DEFAULT_PASSWORD),
            display_name="Administrator",
        )
        session.add(user)
        logger.info("[init_db] 默认用户已创建: username=%s", DEFAULT_USERNAME)
    else:
        logger.info("[init_db] 默认用户已存在: username=%s", DEFAULT_USERNAME)

    # 默认配置项
    created_config_count = 0
    for cfg in DEFAULT_CONFIGS:
        row = session.query(ConfigEntry).filter(ConfigEntry.name == cfg["name"]).one_or_none()
        if row is None:
            row = ConfigEntry(
                name=cfg["name"],
                value_json=cfg.get("value_json"),
                value_str=cfg.get("value_str"),
                description=cfg.get("description", ""),
            )
            session.add(row)
            created_config_count += 1

    # 确保 token_ledger 自动清理事件监听器相关配置存在
    for name in ("token_ledger_cleanup_enabled",):
        row = session.query(ConfigEntry).filter(ConfigEntry.name == name).one_or_none()
        if row is None:
            row = ConfigEntry(name=name, value_json={"enabled": True},
                              description="Token ledger 自动清理启用标志")
            session.add(row)

    session.flush()
    logger.info(
        "[init_db] 默认配置写入完成: created=%d total=%d",
        created_config_count,
        len(DEFAULT_CONFIGS),
    )


def _validate_init(session: Session) -> List[str]:
    """初始化完成后校验关键条件，返回缺失/异常列表。"""
    issues: List[str] = []

    # 1. 校验表是否存在
    import sqlalchemy as sa
    engine = session.bind
    required_tables = {
        "users", "configs", "projects", "tasks", "events", "event_details",
        "token_ledger", "vulnerability", "vulnerability_details", "logs",
        "human_interactions", "opencode_events",
    }
    existing = set(sa.inspect(engine).get_table_names())
    missing_tables = required_tables - existing
    if missing_tables:
        issues.append(f"缺失表: {', '.join(sorted(missing_tables))}")

    # 2. 校验种子用户是否存在
    user = session.query(User).filter(User.username == DEFAULT_USERNAME).one_or_none()
    if user is None:
        issues.append(f"默认用户 '{DEFAULT_USERNAME}' 未创建")

    # 3. 校验关键配置项是否存在
    required_configs = {"LLM_config", "code_agent_config"}
    existing_configs = set(
        row[0] for row in session.query(ConfigEntry.name).filter(
            ConfigEntry.name.in_(required_configs)
        ).all()
    )
    missing_configs = required_configs - existing_configs
    if missing_configs:
        issues.append(f"缺失配置项: {', '.join(sorted(missing_configs))}")

    # 4. 校验每个表至少有一列（表结构完整性）
    for table in required_tables:
        if table in existing:
            cols = [c["name"] for c in sa.inspect(engine).get_columns(table)]
            if not cols:
                issues.append(f"表 '{table}' 无有效列")

    return issues




def _hydrate_provider_list(session: Session, *, name: str, fetcher) -> None:
    row = session.query(ConfigEntry).filter(ConfigEntry.name == name).one_or_none()
    if row is None:
        logger.info("[init_db] 跳过 provider list 填充：配置项不存在 name=%s", name)
        return
    try:
        fetched = fetcher() or {}
    except Exception as ex:  # pragma: no cover
        logger.warning("[init_db] 拉取 %s 失败: %s", name, ex)
        fetched = {}
    row.value_json = fetched
    logger.info(
        "[init_db] provider list 已更新: name=%s empty=%s",
        name,
        not bool(fetched),
    )


def init_neo4j_indexes(config: Config) -> None:
    """确保 Neo4j 属性索引存在（``CREATE INDEX IF NOT EXISTS``，每次 init_db 调用）。"""
    from src.storage.neo4j.client import Neo4jClient
    from src.storage.neo4j.schema import ensure_neo4j_indexes

    client = Neo4jClient(config.neo4j)
    try:
        ensure_neo4j_indexes(client)
        logger.info("[init_db] Neo4j 索引初始化完成")
    except Exception as ex:
        logger.warning("[init_db] Neo4j 索引初始化失败: %s", ex)
    finally:
        client.close()


def init_db(config: Config) -> None:
    """初始化数据库：建表 + 种子数据 + Neo4j 索引（幂等可重复运行）"""
    logger.info("[init_db] 开始初始化: postgres_db=%s", config.postgres.db)
    create_all_tables(config)
    with session_scope() as session:
        logger.info("[init_db] 开始写入种子数据")
        seed_default_data(session)
        logger.info("[init_db] 开始刷新 provider 清单")
        set_llm_provider(session)
        logger.info("[init_db] 执行初始化校验…")
        issues = _validate_init(session)
        if issues:
            logger.warning("[init_db] 初始化校验发现 %d 个问题: %s", len(issues), "; ".join(issues))
        else:
            logger.info("[init_db] 初始化校验通过")
    _ensure_perf_indexes(config)
    init_neo4j_indexes(config)
    logger.info("[init_db] 初始化完成")


def _ensure_perf_indexes(config: Config) -> None:
    """创建性能相关索引（幂等）。"""
    import sqlalchemy as sa
    engine = init_engine(config.postgres)
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_token_ledger_note ON token_ledger (note)",
        "CREATE INDEX IF NOT EXISTS idx_token_ledger_created_at ON token_ledger (created_at)",
        "CREATE INDEX IF NOT EXISTS idx_token_ledger_task_id ON token_ledger (task_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_task_id_status ON events (task_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_opencode_events_event_id ON opencode_events (event_id)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_task_id ON vulnerability (task_id)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_project_id ON vulnerability (project_id)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_category_name ON vulnerability (category_name)",
        "CREATE INDEX IF NOT EXISTS idx_logs_task_id ON logs (task_id)",
        "CREATE INDEX IF NOT EXISTS idx_human_interactions_task_id ON human_interactions (task_id)",
        "CREATE INDEX IF NOT EXISTS idx_human_interactions_event_id ON human_interactions (event_id)",
    ]
    with engine.connect() as conn:
        for ddl in indexes:
            try:
                conn.execute(sa.text(ddl))
                conn.commit()
            except Exception as ex:
                logger.warning("[init_db] 索引创建失败: %s — %s", ddl, ex)
    logger.info("[init_db] 性能索引检查完成")

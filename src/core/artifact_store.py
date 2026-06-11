# -*- coding: utf-8 -*-
"""Artifact 持久化存储 —— 参考 CodeScan 的 artifact 机制。

大工具结果存储为 artifact，按需加载，避免上下文窗口溢出。

用法：
    store = ArtifactStore(base_dir="/tmp/ArgusMind/task123")
    art_id = store.save(content="...", tool_name="read_file", path="src/main.py")
    content = store.load(art_id)
    index = store.build_index()
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

_ARTIFACT_DIR = "artifacts"
_EVIDENCE_DIR = "evidence"
_INDEX_FILE = "artifact_index.json"


@dataclass
class ArtifactRecord:
    """单条 artifact 记录。"""
    id: str
    type: str = ""           # tool_output, code_snippet, evidence
    tool_name: str = ""
    path: str = ""
    start_line: int = 0
    end_line: int = 0
    original_bytes: int = 0
    truncated: bool = False
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "tool_name": self.tool_name,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "original_bytes": self.original_bytes,
            "truncated": self.truncated,
            "captured_at": self.captured_at,
        }


class ArtifactStore:
    """Artifact 持久化存储。

    目录结构：
        {base_dir}/artifacts/{id}.json   - artifact 内容
        {base_dir}/evidence/{id}.json    - evidence 内容（read_file 片段）
        {base_dir}/artifact_index.json   - 索引文件
    """

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.artifact_dir = self.base_dir / _ARTIFACT_DIR
        self.evidence_dir = self.base_dir / _EVIDENCE_DIR
        self.index_path = self.base_dir / _INDEX_FILE
        self._records: Dict[str, ArtifactRecord] = {}
        self._load_index()

    def _ensure_dirs(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        if not self.index_path.exists():
            return
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            for item in data:
                rec = ArtifactRecord(**item)
                self._records[rec.id] = rec
        except Exception as e:
            logger.warning("加载 artifact 索引失败: %s", e)

    def _save_index(self) -> None:
        self._ensure_dirs()
        data = [rec.to_dict() for rec in self._records.values()]
        self.index_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def save(
        self,
        content: str,
        tool_name: str = "",
        path: str = "",
        start_line: int = 0,
        end_line: int = 0,
        artifact_type: str = "tool_output",
        truncated: bool = False,
    ) -> str:
        """保存 artifact，返回 artifact ID。"""
        self._ensure_dirs()
        artifact_id = f"art-{uuid4().hex[:8]}"
        original_bytes = len(content.encode("utf-8"))

        record = ArtifactRecord(
            id=artifact_id,
            type=artifact_type,
            tool_name=tool_name,
            path=path,
            start_line=start_line,
            end_line=end_line,
            original_bytes=original_bytes,
            truncated=truncated,
        )

        # 选择存储目录
        if artifact_type == "evidence":
            target_dir = self.evidence_dir
        else:
            target_dir = self.artifact_dir

        file_path = target_dir / f"{artifact_id}.json"
        payload = {
            "record": record.to_dict(),
            "content": content,
        }
        file_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        self._records[artifact_id] = record
        self._save_index()
        logger.debug("保存 artifact %s (%d bytes, tool=%s)", artifact_id, original_bytes, tool_name)
        return artifact_id

    def load(self, artifact_id: str) -> Optional[str]:
        """按 ID 加载 artifact 内容。"""
        record = self._records.get(artifact_id)
        if record is None:
            return None

        if record.type == "evidence":
            file_path = self.evidence_dir / f"{artifact_id}.json"
        else:
            file_path = self.artifact_dir / f"{artifact_id}.json"

        if not file_path.exists():
            return None

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            return data.get("content", "")
        except Exception as e:
            logger.warning("加载 artifact %s 失败: %s", artifact_id, e)
            return None

    def load_evidence(self, evidence_id: str) -> Optional[str]:
        """加载 evidence 类型的 artifact。"""
        return self.load(evidence_id)

    def build_index(self) -> List[Dict[str, Any]]:
        """构建 artifact 索引摘要（用于 prompt 注入）。"""
        return [rec.to_dict() for rec in self._records.values()]

    def build_index_text(self) -> str:
        """构建可读的 artifact 索引文本。"""
        if not self._records:
            return ""
        lines = ["PRESERVED ARTIFACT INDEX:"]
        for rec in self._records.values():
            label = rec.type or rec.tool_name or "artifact"
            range_part = "range unknown"
            if rec.start_line > 0 and rec.end_line > 0:
                range_part = f"lines {rec.start_line}-{rec.end_line}"
            elif rec.start_line > 0:
                range_part = f"line {rec.start_line}+"
            path_part = rec.path or label
            trunc = " | truncated" if rec.truncated else ""
            lines.append(f"- {rec.id} | {path_part} | {range_part} | {rec.original_bytes} bytes{trunc}")
        return "\n".join(lines)

    def get_record(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """获取 artifact 记录（不含内容）。"""
        return self._records.get(artifact_id)

    def list_records(self) -> List[ArtifactRecord]:
        """列出所有 artifact 记录。"""
        return list(self._records.values())

    def delete(self, artifact_id: str) -> bool:
        """删除指定 artifact。"""
        record = self._records.pop(artifact_id, None)
        if record is None:
            return False
        if record.type == "evidence":
            file_path = self.evidence_dir / f"{artifact_id}.json"
        else:
            file_path = self.artifact_dir / f"{artifact_id}.json"
        if file_path.exists():
            file_path.unlink()
        self._save_index()
        return True

    def clear(self) -> int:
        """清空所有 artifact。"""
        count = len(self._records)
        self._records.clear()
        # 清理文件
        for d in [self.artifact_dir, self.evidence_dir]:
            if d.exists():
                for f in d.glob("*.json"):
                    f.unlink()
        if self.index_path.exists():
            self.index_path.unlink()
        return count

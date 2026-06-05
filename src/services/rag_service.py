# -*- coding: utf-8 -*-
"""RAG 服务 —— 整合自 gbt-codeagent。

基于关键词检索的安全知识检索服务，支持按类别、严重度、CWE 等维度查询。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.knowledge.vulnerability_patterns import ALL_VULNERABILITY_DOCS

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeDocument:
    """知识文档。"""
    id: str
    title: str
    content: str
    category: str = ""
    severity: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class SimpleRetriever:
    """简单关键词检索器。"""

    def __init__(self, documents: Optional[List[KnowledgeDocument]] = None) -> None:
        self._documents: List[KnowledgeDocument] = documents or []
        self._tag_index: Dict[str, List[KnowledgeDocument]] = {}
        self._build_index()

    def _build_index(self) -> None:
        for doc in self._documents:
            for tag in doc.tags:
                tag_lower = tag.lower()
                self._tag_index.setdefault(tag_lower, []).append(doc)

    def search(self, query: str, top_k: int = 5) -> List[KnowledgeDocument]:
        lower_query = query.lower()
        scored: List[tuple[float, KnowledgeDocument]] = []
        seen: set = set()

        for doc in self._documents:
            if doc.id in seen:
                continue

            score = 0.0

            if lower_query in doc.title.lower():
                score += 10.0

            if any(lower_query in tag.lower() for tag in doc.tags):
                score += 5.0

            if doc.cwe_ids and any(lower_query in cwe.lower() for cwe in doc.cwe_ids):
                score += 8.0

            content_lower = doc.content.lower()
            for word in lower_query.split():
                if word in content_lower:
                    score += 1.0

            if score > 0:
                scored.append((score, doc))
                seen.add(doc.id)

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:top_k]]

    def get_by_category(self, category: str) -> List[KnowledgeDocument]:
        return [doc for doc in self._documents if doc.category == category]

    def get_by_severity(self, severity: str) -> List[KnowledgeDocument]:
        return [doc for doc in self._documents if doc.severity == severity]

    def get_by_id(self, doc_id: str) -> Optional[KnowledgeDocument]:
        for doc in self._documents:
            if doc.id == doc_id:
                return doc
        return None

    @property
    def documents(self) -> List[KnowledgeDocument]:
        return self._documents


class RAGService:
    """安全知识检索服务。"""

    def __init__(self) -> None:
        self._retriever: Optional[SimpleRetriever] = None
        self._initialized = False

    def initialize(self, documents: Optional[List[KnowledgeDocument]] = None) -> None:
        if self._initialized:
            return

        docs = documents or self._load_default_documents()
        self._retriever = SimpleRetriever(docs)
        self._initialized = True
        logger.info("[RAG服务] 已初始化，知识文档数量: %d", len(docs))

    def _load_default_documents(self) -> List[KnowledgeDocument]:
        docs = []
        for vuln_doc in ALL_VULNERABILITY_DOCS:
            docs.append(KnowledgeDocument(
                id=vuln_doc.get("id", ""),
                title=vuln_doc.get("title", ""),
                content=vuln_doc.get("content", vuln_doc.get("description", "")),
                category=vuln_doc.get("category", ""),
                severity=vuln_doc.get("severity", ""),
                cwe_ids=vuln_doc.get("cweIds", vuln_doc.get("cwe_ids", [])),
                tags=vuln_doc.get("tags", []),
            ))
        return docs

    def query(self, query: str, top_k: int = 5, **options: Any) -> List[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()

        results = self._retriever.search(query, top_k)
        return [
            {
                "id": doc.id,
                "title": doc.title,
                "content": doc.content,
                "category": doc.category,
                "severity": doc.severity,
                "cwe_ids": doc.cwe_ids,
                "tags": doc.tags,
            }
            for doc in results
        ]

    def query_by_category(self, category: str) -> List[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()
        results = self._retriever.get_by_category(category)
        return [{"id": d.id, "title": d.title, "content": d.content} for d in results]

    def query_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()
        results = self._retriever.get_by_severity(severity)
        return [{"id": d.id, "title": d.title, "content": d.content} for d in results]

    def query_security_knowledge(
        self,
        query: str,
        language: str = "",
        severity: str = "",
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        results = self.query(query, top_k * 2)

        if language:
            lang_lower = language.lower()
            results = [
                r for r in results
                if any(tag.lower().startswith(lang_lower) for tag in r.get("tags", []))
            ]

        if severity:
            results = [r for r in results if r.get("severity", "").lower() == severity.lower()]

        return results[:top_k]


_service: Optional[RAGService] = None


def get_rag_service() -> RAGService:
    global _service
    if _service is None:
        _service = RAGService()
    return _service

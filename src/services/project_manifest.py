# -*- coding: utf-8 -*-
"""项目热点清单预扫描 —— 参考 CodeScan 的 ProjectManifest 机制。

为每个审计阶段预定义 regex 规则，扫描项目生成热点文件清单，
注入到 SinkFinder/ChainAnalyzer prompt 中，帮助 LLM 聚焦关键文件。

用法：
    manifest = ProjectManifest.build("/path/to/project")
    hotspots = manifest.get_stage_hotspots("SQL_INJECTION")
    routes = manifest.route_candidates
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── 扫描限制 ──
_MANIFEST_MAX_FILE_BYTES = 2 * 1024 * 1024   # 跳过超过 2MB 的文件
_MANIFEST_MAX_LINES_PER_RULE = 20            # 每条规则最多记录 20 行
_MANIFEST_MAX_FILES_PER_SECTION = 150        # 每个分区最多 150 个文件

# ── 跳过的目录和扩展名 ──
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".idea", ".vscode",
    "target", "build", "dist", ".next", ".nuxt", "vendor",
    ".gradle", ".mvn", "venv", ".env", "env",
    ".mypy_cache", ".pytest_cache", ".tox",
})
_SKIP_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
    ".zip", ".tar", ".gz", ".lock", ".md5", ".sha256",
    ".log", ".tmp", ".bak", ".pyc", ".class", ".o", ".so",
})


@dataclass
class RuleHit:
    """单条规则命中。"""
    name: str
    lines: List[int]


@dataclass
class IndexedFile:
    """带规则命中的文件记录。"""
    path: str          # 相对路径
    rules: List[RuleHit] = field(default_factory=list)


@dataclass
class RouteCandidate:
    """路由候选文件。"""
    path: str
    rule_name: str
    lines: List[int]


@dataclass
class ProjectManifest:
    """项目热点清单。"""
    generated_at: float = 0.0
    languages: Set[str] = field(default_factory=set)
    framework_hints: Set[str] = field(default_factory=set)
    route_candidate_files: List[IndexedFile] = field(default_factory=list)
    stage_hotspots: Dict[str, List[IndexedFile]] = field(default_factory=dict)
    route_context: str = ""  # 路由上下文摘要（注入 prompt 用）

    def get_stage_hotspots(self, stage: str) -> List[IndexedFile]:
        """获取指定阶段的热点文件。"""
        return self.stage_hotspots.get(stage, [])

    def build_hotspot_text(self, stage: str, max_files: int = 30) -> str:
        """构建指定阶段热点文件的可读文本（用于 prompt 注入）。"""
        hotspots = self.get_stage_hotspots(stage)
        if not hotspots:
            return ""
        lines = [f"## {stage} 阶段热点文件（{len(hotspots)} 个）"]
        for f in hotspots[:max_files]:
            rule_names = ", ".join(r.name for r in f.rules)
            hit_lines = []
            for r in f.rules[:3]:
                hit_lines.extend(r.lines[:5])
            line_hint = ", ".join(str(l) for l in sorted(set(hit_lines))[:10])
            lines.append(f"- {f.path} (rules: {rule_names}, lines: {line_hint})")
        if len(hotspots) > max_files:
            lines.append(f"- ... 还有 {len(hotspots) - max_files} 个文件")
        return "\n".join(lines)

    def build_route_context_text(self, max_routes: int = 30) -> str:
        """构建路由上下文文本。"""
        if not self.route_candidate_files:
            return ""
        lines = [f"## 路由候选文件（{len(self.route_candidate_files)} 个）"]
        for f in self.route_candidate_files[:max_routes]:
            rule_names = ", ".join(r.name for r in f.rules)
            lines.append(f"- {f.path} (rules: {rule_names})")
        if len(self.route_candidate_files) > max_routes:
            lines.append(f"- ... 还有 {len(self.route_candidate_files) - max_routes} 个文件")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "languages": sorted(self.languages),
            "framework_hints": sorted(self.framework_hints),
            "route_candidate_count": len(self.route_candidate_files),
            "stage_hotspot_counts": {k: len(v) for k, v in self.stage_hotspots.items()},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def save(self, path: str | Path) -> None:
        """保存到 JSON 文件。"""
        data = {
            "generated_at": self.generated_at,
            "languages": sorted(self.languages),
            "framework_hints": sorted(self.framework_hints),
            "route_candidate_files": [
                {"path": f.path, "rules": [{"name": r.name, "lines": r.lines} for r in f.rules]}
                for f in self.route_candidate_files
            ],
            "stage_hotspots": {
                stage: [
                    {"path": f.path, "rules": [{"name": r.name, "lines": r.lines} for r in f.rules]}
                    for f in files
                ]
                for stage, files in self.stage_hotspots.items()
            },
            "route_context": self.route_context,
        }
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> Optional["ProjectManifest"]:
        """从 JSON 文件加载。"""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            manifest = cls(
                generated_at=data.get("generated_at", 0),
                languages=set(data.get("languages", [])),
                framework_hints=set(data.get("framework_hints", [])),
                route_context=data.get("route_context", ""),
            )
            for f in data.get("route_candidate_files", []):
                manifest.route_candidate_files.append(IndexedFile(
                    path=f["path"],
                    rules=[RuleHit(name=r["name"], lines=r.get("lines", [])) for r in f.get("rules", [])],
                ))
            for stage, files in data.get("stage_hotspots", {}).items():
                manifest.stage_hotspots[stage] = [
                    IndexedFile(
                        path=f["path"],
                        rules=[RuleHit(name=r["name"], lines=r.get("lines", [])) for r in f.get("rules", [])],
                    )
                    for f in files
                ]
            return manifest
        except Exception as e:
            logger.warning("加载 ProjectManifest 失败: %s", e)
            return None


# ══════════════════════════════════════════════════════════════════
# Regex 规则定义（参考 CodeScan 的 routeCandidateRules + stageHotspotRules）
# ══════════════════════════════════════════════════════════════════

@dataclass
class _ManifestRule:
    name: str
    pattern: re.Pattern


# ── 路由候选规则 ──
_ROUTE_CANDIDATE_RULES: List[_ManifestRule] = [
    _ManifestRule("spring_mapping", re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|PatchMapping)")),
    _ManifestRule("flask", re.compile(r"@app\.route\(")),
    _ManifestRule("fastapi", re.compile(r"@(app|router)\.(get|post|put|delete|patch)\(")),
    _ManifestRule("django", re.compile(r"\b(path|url|re_path)\(")),
    _ManifestRule("express_koa", re.compile(r"\.(get|post|put|delete|patch|use|route)\(")),
    _ManifestRule("nestjs", re.compile(r"@(Get|Post|Put|Delete|Patch|Controller)\(")),
    _ManifestRule("gin_echo_fiber", re.compile(r"\.(GET|POST|PUT|DELETE|PATCH|Any|Group|Static)\(")),
    _ManifestRule("chi", re.compile(r"\.(Get|Post|Put|Delete|Patch|Route|Mount)\(")),
    _ManifestRule("gorilla_mux", re.compile(r"\.(HandleFunc|Handle|PathPrefix)\(")),
    _ManifestRule("stdlib_http", re.compile(r"http\.(HandleFunc|Handle)\(")),
    _ManifestRule("php_router", re.compile(r"\$router->(get|post|put|delete|patch|any)\(")),
    _ManifestRule("rails", re.compile(r"(get|post|put|delete|patch)\s+['\"]\/")),
]

# ── 阶段热点规则（漏洞类型 → regex 列表）──
_STAGE_HOTSPOT_RULES: Dict[str, List[_ManifestRule]] = {
    "COMMAND_INJECTION": [
        _ManifestRule("command_exec", re.compile(r"\b(exec|system|popen|subprocess|Runtime\.getRuntime|ProcessBuilder|os\.system|os\.popen|commands\.getoutput)\b")),
        _ManifestRule("shell_invoke", re.compile(r"\b(shell_exec|passthru|proc_open|pcntl_exec)\b")),
        _ManifestRule("eval_exec", re.compile(r"\b(eval|exec\(|Function\(|assert\(|vm\.runInThisContext)\b")),
    ],
    "SQL_INJECTION": [
        _ManifestRule("raw_sql", re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|WHERE|SET)\b", re.IGNORECASE)),
        _ManifestRule("sql_format", re.compile(r"\b(fmt\.Sprintf|f\"|\+\s*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE))\b")),
        _ManifestRule("orm_raw_query", re.compile(r"\b(\.Raw\(|\.Exec\(|\.Query\(|createNativeQuery|createQuery|executeQuery)\b")),
        _ManifestRule("nosql_query", re.compile(r"\b(find\(|aggregate\(|where\(|\$ne|\$gt|\$regex|\$where)\b")),
    ],
    "AUTH_BYPASS": [
        _ManifestRule("auth_entry", re.compile(r"\b(login|signin|signup|register|resetPassword|changePassword|forgot)\b", re.IGNORECASE)),
        _ManifestRule("session_state", re.compile(r"\b(session|cookie|Set-Cookie|express-session)\b")),
        _ManifestRule("jwt_usage", re.compile(r"\b(jwt|jsonwebtoken|ParseWithClaims|SignedString|Jwts\.builder)\b")),
        _ManifestRule("auth_middleware", re.compile(r"\b(Auth|Authenticate|Authorization|RequireLogin|middleware|SecurityContext)\b")),
    ],
    "SSRF": [
        _ManifestRule("http_client", re.compile(r"\b(HttpURLConnection|RestTemplate|WebClient|HttpClient|requests\.(get|post)|fetch\(|axios\.)\b")),
        _ManifestRule("url_open", re.compile(r"\b(urllib\.request|URL\(|url_for|redirect)\b")),
    ],
    "DESERIALIZATION": [
        _ManifestRule("unsafe_deserialize", re.compile(r"\b(ObjectInputStream|pickle\.load|yaml\.load|XMLDecoder|XStream|enableDefaultTyping|Fastjson|readValue)\b")),
        _ManifestRule("json_parse", re.compile(r"\b(JSON\.parse|json\.loads|Gson|ObjectMapper)\b")),
    ],
    "XSS": [
        _ManifestRule("html_render", re.compile(r"\b(template\.HTML|innerHTML|dangerouslySetInnerHTML|v-html|\.html\(|response\.write)\b")),
        _ManifestRule("unescaped_output", re.compile(r"\b(ExecuteTemplate|Mustache|render_template|Markup)\b")),
    ],
    "PATH_TRAVERSAL": [
        _ManifestRule("file_read", re.compile(r"\b(ReadFile|OpenFile|ServeFile|SendFile|Download|readFileSync|createReadStream)\b")),
        _ManifestRule("path_join", re.compile(r"\b(filepath\.Join|path\.Join|os\.path\.join|path\.resolve|Clean\(|normalize)\b")),
        _ManifestRule("file_write", re.compile(r"\b(WriteFile|writeFile|FileOutputStream|FileWriter|SaveUploadedFile)\b")),
    ],
    "FILE_UPLOAD": [
        _ManifestRule("upload_entry", re.compile(r"\b(FormFile|SaveUploadedFile|MultipartFile|upload|multer|multipart)\b", re.IGNORECASE)),
        _ManifestRule("archive_extract", re.compile(r"\b(zip\.NewReader|tar\.NewReader|Extract|Unzip|ZipFile|shutil\.unpack_archive)\b")),
    ],
    "CODE_INJECTION": [
        _ManifestRule("code_eval", re.compile(r"\b(eval\(|Function\(|compile\(|exec\(|__import__)\b")),
        _ManifestRule("template_exec", re.compile(r"\b(template\.Must|ExecuteTemplate|render_template_string|Jinja2)\b")),
        _ManifestRule("spel_ognl", re.compile(r"\b(ExpressionParser|Ognl\.getValue|SpEL)\b")),
    ],
    "HARD_CODED_SECRET": [
        _ManifestRule("secret_material", re.compile(r"\b(password|secret|api_key|apikey|private_key|token)\s*[=:]\s*[\"'][^\"']+[\"']", re.IGNORECASE)),
        _ManifestRule("config_secret", re.compile(r"\b(AKIA[A-Z0-9]{16}|sk-[a-zA-Z0-9]{20,})\b")),
    ],
    "XXE": [
        _ManifestRule("xml_parser", re.compile(r"\b(SAXReader|SAXBuilder|DocumentBuilder|XMLReader|XMLInputFactory|parseXML)\b")),
        _ManifestRule("external_entity", re.compile(r"\b(DTDHandler|EntityResolver|FEATURE_EXTERNAL_GENERAL_ENTITIES)\b")),
    ],
    "JNDI_INJECTION": [
        _ManifestRule("jndi_lookup", re.compile(r"\b(InitialContext|lookup|DirContext|jndi)\b", re.IGNORECASE)),
    ],
    "SPEL_INJECTION": [
        _ManifestRule("spel_eval", re.compile(r"\b(ExpressionParser|StandardEvaluationContext|parseExpression)\b")),
    ],
    "SSTI": [
        _ManifestRule("template_engine", re.compile(r"\b(Jinja2|Tornado|Thymeleaf|FreeMarker|Velocity|Mustache|Handlebars)\b")),
    ],
    "INSECURE_RANDOM": [
        _ManifestRule("weak_random", re.compile(r"\b(Math\.random|Random\(\)|random\.random|rand\(\))\b")),
    ],
    "CORS": [
        _ManifestRule("cors_config", re.compile(r"\b(AllowOrigin|Access-Control|CORS|addCorsMappings)\b")),
    ],
}

# ── 框架识别规则 ──
_FRAMEWORK_HINT_RULES = [
    ("spring", re.compile(r"spring-boot|@RestController|@RequestMapping|@SpringBootApplication")),
    ("flask", re.compile(r"flask|@app\.route")),
    ("fastapi", re.compile(r"fastapi|@app\.(get|post|put|delete|patch)")),
    ("django", re.compile(r"django|urlpatterns")),
    ("express", re.compile(r"express\(|require\(['\"]express['\"]\)|from ['\"]express['\"]")),
    ("nestjs", re.compile(r"@nestjs/|@Controller\(")),
    ("gin", re.compile(r"gin-gonic/gin|\bgin\.")),
    ("spring_security", re.compile(r"spring-security|WebSecurityConfigurerAdapter|SecurityFilterChain")),
]

# ── 语言识别 ──
_EXT_TO_LANG = {
    ".go": "go", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".py": "python", ".php": "php", ".rb": "ruby",
    ".cs": "csharp", ".kt": "kotlin", ".swift": "swift",
    ".rs": "rust",
}


def _is_binary(data: bytes, check_bytes: int = 8192) -> bool:
    """快速判断文件是否为二进制。"""
    chunk = data[:check_bytes]
    if b"\x00" in chunk:
        return True
    # 非 ASCII 字符占比过高可能为二进制
    non_ascii = sum(1 for b in chunk if b > 127)
    return non_ascii > len(chunk) * 0.3


def _detect_language(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return _EXT_TO_LANG.get(ext, "")


def _module_dir(rel_path: str) -> str:
    parts = rel_path.replace("\\", "/").split("/")
    return "/".join(parts[:-1]) if len(parts) > 1 else "."


def build_project_manifest(project_path: str, file_list: Optional[List[str]] = None) -> ProjectManifest:
    """扫描项目，生成热点清单。

    Args:
        project_path: 项目根目录绝对路径
        file_list: 预收集的文件相对路径列表（可选，不传则自行遍历）
    """
    manifest = ProjectManifest(generated_at=time.time())
    language_set: Set[str] = set()
    framework_set: Set[str] = set()

    route_hits: Dict[str, IndexedFile] = {}
    stage_hits: Dict[str, Dict[str, IndexedFile]] = {stage: {} for stage in _STAGE_HOTSPOT_RULES}

    # 遍历文件
    if file_list is None:
        file_list = []
        for root, dirs, filenames in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, project_path).replace("\\", "/")
                file_list.append(rel_path)

    for rel_path in file_list:
        fname = os.path.basename(rel_path)
        _, ext = os.path.splitext(fname)

        # 语言识别
        lang = _detect_language(fname)
        if lang:
            language_set.add(lang)

        # 跳过不感兴趣的扩展名
        if ext.lower() in _SKIP_EXTS:
            continue

        abs_path = os.path.join(project_path, rel_path)
        try:
            file_size = os.path.getsize(abs_path)
            if file_size <= 0 or file_size > _MANIFEST_MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue

        if _is_binary(content.encode("utf-8", errors="replace")[:8192]):
            continue

        # 框架识别
        for hint_name, hint_pattern in _FRAMEWORK_HINT_RULES:
            if hint_pattern.search(content) or hint_pattern.search(rel_path):
                framework_set.add(hint_name)

        # 逐行扫描
        lines = content.split("\n")
        _collect_line_hits(route_hits, rel_path, _ROUTE_CANDIDATE_RULES, lines)
        for stage, rules in _STAGE_HOTSPOT_RULES.items():
            _collect_line_hits(stage_hits[stage], rel_path, rules, lines)

    # 组装结果
    manifest.languages = language_set
    manifest.framework_hints = framework_set
    manifest.route_candidate_files = _finalize_files(route_hits)
    manifest.stage_hotspots = {stage: _finalize_files(hits) for stage, hits in stage_hits.items()}

    # 生成路由上下文摘要
    manifest.route_context = _build_route_context_summary(manifest)

    return manifest


def _collect_line_hits(
    target: Dict[str, IndexedFile],
    rel_path: str,
    rules: List[_ManifestRule],
    lines: List[str],
) -> None:
    """逐行收集规则命中。"""
    for rule in rules:
        hit_lines: List[int] = []
        for i, line in enumerate(lines):
            if len(hit_lines) >= _MANIFEST_MAX_LINES_PER_RULE:
                break
            if rule.pattern.search(line):
                hit_lines.append(i + 1)

        if hit_lines:
            if rel_path not in target:
                target[rel_path] = IndexedFile(path=rel_path)
            target[rel_path].rules.append(RuleHit(name=rule.name, lines=hit_lines))

            # 限制文件数量
            if len(target) >= _MANIFEST_MAX_FILES_PER_SECTION:
                break


def _finalize_files(hits: Dict[str, IndexedFile]) -> List[IndexedFile]:
    """按规则命中数排序，返回结果。"""
    files = list(hits.values())
    files.sort(key=lambda f: (-sum(len(r.lines) for r in f.rules), f.path))
    return files[:_MANIFEST_MAX_FILES_PER_SECTION]


def _build_route_context_summary(manifest: ProjectManifest) -> str:
    """构建路由上下文摘要文本。"""
    lines = ["Route Inventory:"]
    lines.append(f"- route_candidate_files: {len(manifest.route_candidate_files)}")
    if manifest.route_candidate_files:
        for f in manifest.route_candidate_files[:10]:
            rule_names = [r.name for r in f.rules]
            lines.append(f"  - {f.path} ({', '.join(rule_names)})")
        if len(manifest.route_candidate_files) > 10:
            lines.append(f"  - ... 还有 {len(manifest.route_candidate_files) - 10} 个文件")
    return "\n".join(lines)


def get_manifest_path(task_id: str) -> str:
    """获取 manifest 缓存文件路径。"""
    import tempfile
    base = os.path.join(tempfile.gettempdir(), "ArgusMind", task_id)
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "project_manifest.json")


def ensure_project_manifest(
    project_path: str,
    task_id: str,
    file_list: Optional[List[str]] = None,
) -> ProjectManifest:
    """确保 ProjectManifest 存在（优先从缓存加载）。"""
    cache_path = get_manifest_path(task_id)
    cached = ProjectManifest.load(cache_path)
    if cached is not None:
        return cached
    manifest = build_project_manifest(project_path, file_list)
    try:
        manifest.save(cache_path)
    except Exception as e:
        logger.warning("保存 ProjectManifest 缓存失败: %s", e)
    return manifest

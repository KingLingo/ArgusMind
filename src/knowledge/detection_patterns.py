# -*- coding: utf-8 -*-
"""检测模式知识库 —— 整合自 gbt-codeagent/config/prompts。

包含：Source→Sink→Safety 三段式检测模式、安全检查清单、
语言专属检查清单、Sink 证据点模板。
"""

from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════
# 第一部分：Source → Sink → Safety 三段式检测模式
# ═══════════════════════════════════════════════════════════════

DETECTION_PATTERNS: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "java": {
        "命令注入": [
            {"source": "request.getParameter, @RequestParam, @PathVariable, @RequestBody",
             "sink": "Runtime.exec(), ProcessBuilder",
             "safety": ""},
        ],
        "SQL注入": [
            {"source": "request.getParameter, @RequestParam, @PathVariable, @RequestBody",
             "sink": "Statement/JdbcTemplate 拼接, MyBatis ${}, HQL 拼接",
             "safety": "PreparedStatement, MyBatis #{}, JPA :param"},
        ],
        "路径遍历": [
            {"source": "同上 + MultipartFile 文件名",
             "sink": "FileInputStream/FileOutputStream(用户可控路径)",
             "safety": "Paths.get(), toRealPath(), normalize()"},
        ],
        "SSRF": [
            {"source": "request.getParameter, @RequestParam 等",
             "sink": "HttpURLConnection, RestTemplate, WebClient(用户可控 URL)",
             "safety": "域名白名单, 内网地址过滤"},
        ],
        "反序列化": [
            {"source": "@RequestBody",
             "sink": "ObjectInputStream, XMLDecoder, XStream, Jackson enableDefaultTyping, Fastjson parseObject",
             "safety": "类型白名单, 安全配置"},
        ],
        "代码注入": [
            {"source": "request.getParameter, @RequestParam 等",
             "sink": "ScriptEngine.eval(), GroovyShell.evaluate(), SpEL ExpressionParser",
             "safety": "表达式沙箱, 输入白名单"},
        ],
        "JNDI注入": [
            {"source": "request.getParameter, @RequestParam 等",
             "sink": "InitialContext.lookup(用户输入)",
             "safety": "固定 JNDI 名称"},
        ],
        "SSTI": [
            {"source": "@RequestParam, @PathVariable",
             "sink": "Thymeleaf 视图名拼接, FreeMarker/Velocity 模板字符串",
             "safety": "模板路径来自文件"},
        ],
        "XXE": [
            {"source": "@RequestBody",
             "sink": "XMLReader, SAXReader, SAXBuilder, DocumentBuilder(未禁用外部实体)",
             "safety": "禁用 DTD/外部实体"},
        ],
        "XSS": [
            {"source": "@RequestParam",
             "sink": "用户输入直接写入响应体(return content)",
             "safety": "HTML 实体编码"},
        ],
        "认证绕过": [
            {"source": "",
             "sink": "缺少 @PreAuthorize 的敏感端点, 客户端可控的头(X-Forwarded-For)做 IP 校验",
             "safety": "Spring Security 全局拦截器"},
        ],
        "硬编码凭据": [
            {"source": "",
             "sink": "password/secret/api_key 字面量",
             "safety": "环境变量/KMS 获取"},
        ],
        "文件上传": [
            {"source": "MultipartFile, @RequestParam('file')",
             "sink": "getOriginalFilename()拼路径, transferTo(), FileOutputStream(用户可控文件名)",
             "safety": "UUID重命名, 白名单扩展名+MIME, 上传目录禁用脚本执行"},
        ],
        "CORS": [
            {"source": "",
             "sink": "Access-Control-Allow-Origin 反射 Origin 头 + allowCredentials:true",
             "safety": "固定白名单"},
        ],
    },
    "javascript": {
        "命令注入": [
            {"source": "req.query, req.body, req.params",
             "sink": "child_process.exec()/spawn()/execSync()",
             "safety": "execFile() + args 数组"},
        ],
        "SQL注入": [
            {"source": "req.query, req.body, req.params",
             "sink": "mysql.query(拼接), sequelize.query(拼接)",
             "safety": "mysql2.execute(), sequelize bind, Prisma ORM"},
        ],
        "路径遍历": [
            {"source": "req.query, req.body, req.params",
             "sink": "fs.readFile/writeFile/createReadStream(用户可控路径)",
             "safety": "path.resolve()+白名单"},
        ],
        "SSRF": [
            {"source": "req.query, req.body, req.params",
             "sink": "fetch/axios/http.get(用户可控 URL)",
             "safety": "URL 白名单"},
        ],
        "代码注入": [
            {"source": "req.query, req.body, req.params",
             "sink": "eval(), new Function(), vm.runInNewContext",
             "safety": ""},
        ],
        "XSS": [
            {"source": "req.query, req.body, req.params",
             "sink": "innerHTML, dangerouslySetInnerHTML, document.write",
             "safety": "DOMPurify, textContent, React 自动转义"},
        ],
        "NoSQL注入": [
            {"source": "req.query, req.body, req.params",
             "sink": "MongoDB find/$where, mongoose 查询对象拼接",
             "safety": "mongoose schema 校验"},
        ],
        "原型链污染": [
            {"source": "req.body",
             "sink": "Object.assign, _.merge, 展开运算符",
             "safety": "Object.create(null), __proto__ 过滤"},
        ],
    },
    "python": {
        "命令注入": [
            {"source": "request.args/form/json, input()",
             "sink": "os.system(), subprocess(shell=True)",
             "safety": "subprocess.run(args=[])"},
        ],
        "SQL注入": [
            {"source": "request.args/form/json",
             "sink": "字符串拼接 SQL",
             "safety": "参数化(sqlite3 ?, psycopg2 %s, SQLAlchemy bind)"},
        ],
        "代码注入": [
            {"source": "request.args/form/json, input()",
             "sink": "eval(), exec(), compile()",
             "safety": "ast.literal_eval"},
        ],
        "反序列化": [
            {"source": "request.args/form/json",
             "sink": "pickle.load/loads, yaml.load(非safe_load)",
             "safety": "yaml.safe_load, json.loads"},
        ],
        "路径遍历": [
            {"source": "request.args/form/json",
             "sink": "open/Path.open/read_text(用户可控)",
             "safety": "Path.resolve()"},
        ],
        "SSTI": [
            {"source": "request.args/form/json",
             "sink": "render_template_string(用户输入)",
             "safety": "模板来自文件"},
        ],
        "SSRF": [
            {"source": "request.args/form/json",
             "sink": "requests.get/httpx.get(用户可控 URL)",
             "safety": "URL 白名单"},
        ],
    },
    "go": {
        "命令注入": [
            {"source": "r.URL.Query(), c.Query/PostForm(), BindJSON",
             "sink": 'exec.Command("sh","-c",用户输入)',
             "safety": "exec.Command(args 数组)"},
        ],
        "SQL注入": [
            {"source": "r.URL.Query(), c.Query/PostForm(), BindJSON",
             "sink": "db.Query/db.Exec(拼接 SQL)",
             "safety": "占位符(?/$1)"},
        ],
        "路径遍历": [
            {"source": "r.URL.Query(), c.Query/PostForm(), BindJSON",
             "sink": "os.Open/Create(用户可控)",
             "safety": "filepath.Clean/Join"},
        ],
        "XSS": [
            {"source": "r.URL.Query(), c.Query/PostForm(), BindJSON",
             "sink": "template.HTML(用户输入)",
             "safety": "html/template(自动转义)"},
        ],
        "SSRF": [
            {"source": "r.URL.Query(), c.Query/PostForm(), BindJSON",
             "sink": "http.Get/Post(用户可控 URL)",
             "safety": "URL 白名单"},
        ],
    },
    "php": {
        "命令注入": [
            {"source": "$_GET, $_POST, $_REQUEST",
             "sink": "system/exec/shell_exec/passthru",
             "safety": "escapeshellcmd/arg"},
        ],
        "SQL注入": [
            {"source": "$_GET, $_POST, $_REQUEST",
             "sink": "mysqli_query(拼接), PDO::query(拼接)",
             "safety": "PDO::prepare + bindValue"},
        ],
        "文件包含": [
            {"source": "$_GET, $_POST, $_REQUEST",
             "sink": "include/require(动态路径)",
             "safety": "白名单, basename"},
        ],
        "反序列化": [
            {"source": "$_GET, $_POST, $_REQUEST",
             "sink": "unserialize(用户输入)",
             "safety": "json_decode"},
        ],
    },
    "c": {
        "命令注入": [
            {"source": "argv, getenv, socket 输入",
             "sink": "system/popen/execl",
             "safety": ""},
        ],
        "缓冲区溢出": [
            {"source": "argv, getenv, socket 输入",
             "sink": "sprintf/strcpy/strcat/gets(无边界)",
             "safety": "snprintf/strncpy(有边界)"},
        ],
        "路径遍历": [
            {"source": "argv, getenv, socket 输入",
             "sink": "fopen/open(用户可控路径)",
             "safety": "realpath"},
        ],
    },
    "cpp": {
        "命令注入": [
            {"source": "argv, getenv, socket 输入",
             "sink": "system/popen/execl",
             "safety": ""},
        ],
        "缓冲区溢出": [
            {"source": "argv, getenv, socket 输入",
             "sink": "sprintf/strcpy/strcat/gets(无边界)",
             "safety": "snprintf/strncpy(有边界)"},
        ],
        "路径遍历": [
            {"source": "argv, getenv, socket 输入",
             "sink": "fopen/open(用户可控路径)",
             "safety": "realpath"},
        ],
    },
    "csharp": {
        "命令注入": [
            {"source": "Request.Query/Form/Body",
             "sink": "Process.Start(用户输入)",
             "safety": "ProcessStartInfo + args"},
        ],
        "SQL注入": [
            {"source": "Request.Query/Form/Body",
             "sink": "SqlCommand 拼接",
             "safety": "SqlParameter"},
        ],
        "路径遍历": [
            {"source": "Request.Query/Form/Body + IFormFile",
             "sink": "File.ReadAllText/WriteAllText(用户可控)",
             "safety": "Path.GetFullPath/Combine"},
        ],
        "SSRF": [
            {"source": "Request.Query/Form/Body",
             "sink": "HttpClient.GetAsync(用户可控 URL)",
             "safety": "URL 白名单"},
        ],
        "反序列化": [
            {"source": "Request.Query/Form/Body",
             "sink": "BinaryFormatter, SoapFormatter",
             "safety": "类型白名单"},
        ],
    },
}

# 通用判定规则
DETECTION_JUDGMENT_RULES = """
## 通用判定规则
- Source 进入 Sink 且无 Safety → 优先确认风险
- 有 Safety 信号 → 降级为 Low/Medium（**必须仍报告**，在 killSwitchInfo 中说明原因）
- 仅 import 未调用 → 不报
- 测试代码/示例代码 → 不报
- 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记
- CORS判定：Origin 反射 AND allowCredentials=true 同时满足才报；仅反射 Origin 不报
"""


def get_detection_patterns(language: str, vuln_name: str) -> Optional[List[Dict[str, str]]]:
    """获取指定语言和漏洞类型的 Source→Sink→Safety 检测模式。"""
    lang_patterns = DETECTION_PATTERNS.get(language.lower())
    if not lang_patterns:
        return None
    # 精确匹配 + 关键词匹配
    if vuln_name in lang_patterns:
        return lang_patterns[vuln_name]
    for key, patterns in lang_patterns.items():
        if key in vuln_name or vuln_name in key:
            return patterns
    return None


def format_detection_patterns_for_prompt(language: str, vuln_name: str) -> str:
    """格式化检测模式为可注入 prompt 的文本。"""
    patterns = get_detection_patterns(language, vuln_name)
    if not patterns:
        return ""
    lines = [f"\n## {language} - {vuln_name} 检测模式（Source → Sink → Safety）\n"]
    for i, p in enumerate(patterns, 1):
        lines.append(f"| 维度 | 内容 |")
        lines.append(f"|------|------|")
        lines.append(f"| Source（输入源） | {p.get('source', '-')} |")
        lines.append(f"| Sink（危险API） | {p.get('sink', '-')} |")
        lines.append(f"| Safety（安全信号） | {p.get('safety', '-') or '无（高危）'} |")
        if i < len(patterns):
            lines.append("")
    lines.append("")
    lines.append(DETECTION_JUDGMENT_RULES)
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# 第二部分：跨语言安全检查清单
# ═══════════════════════════════════════════════════════════════

SECURITY_CHECKLIST = """
## 安全检查清单（跨语言通用）

### 注入
- [ ] 用户输入到达 SQL 查询 — 是否参数化？(PreparedStatement / ORM 安全方法)
- [ ] 用户输入到达 OS 命令 — 是否通过 args 数组，而非字符串插值？
- [ ] 用户输入在模板渲染中 — 是否沙箱化？
- [ ] NoSQL / LDAP / XPath 查询构造 — 用户输入是否净化？
- **跳过条件**: 参数化查询、ORM 安全 API、已验证白名单、或框架自动转义生效。

### 认证与授权
- [ ] 认证端点 — 认证是否可绕过（缺少密码校验、弱令牌）？
- [ ] 对象级访问 — 用户 ID 是否与 session 校验（而非仅来自请求参数）？
- [ ] 管理员/特权路由 — 每个端点是否存在角色检查？
- [ ] 会话固定 — 登录后会话是否失效并重新生成？(Java: session.invalidate(); JS: req.session.regenerate())
- **跳过条件**: 框架强制认证过滤器无例外，或端点故意公开。

### 敏感数据
- [ ] 硬编码密钥 — 源码中是否有 password、API key、token、私钥？
- [ ] 日志语句 — 是否打印密钥、令牌、PII 或完整请求体？
- [ ] 错误响应 — 是否泄露堆栈跟踪、DB 模式、内部路径？
- **跳过条件**: 值来自环境变量 / vault / 配置服务（非硬编码）。

### 文件操作
- [ ] 用户输入构建文件路径 — 是否防止了 ../ 遍历？
- [ ] 文件上传 — 是否服务端验证类型（MIME + magic bytes），文件名是否净化？
- [ ] 上传目录 — 是否在 web root 之外或防止直接 URL 访问？
- **跳过条件**: 路径使用 UUID 生成，或扩展名 + 内容的严格白名单验证。

### 反序列化与解析
- [ ] 不受信数据反序列化 — pickle、unserialize、ObjectInputStream、jsonpickle？
- [ ] XML 解析是否启用了外部实体（XXE）？
- [ ] YAML 解析是否启用了 !!python/object 或自定义标签？
- **跳过条件**: 使用安全解析器（JSON.parse、safe_load、显式类型白名单）。

### 并发（仅服务端）
- [ ] 共享可变状态 — 是否无锁 / synchronized / atomic 访问？
- [ ] 检查-然后-操作模式 — 检查和变更之间是否存在竞态窗口？
- **跳过条件**: 方法局部变量、只读访问、不可变对象、单线程上下文。
"""


# ═══════════════════════════════════════════════════════════════
# 第三部分：语言专属检查清单
# ═══════════════════════════════════════════════════════════════

LANGUAGE_CHECKLISTS: Dict[str, str] = {
    "java": """
## Java 专属检查清单
### Null Safety
- 可能 null 的返回值上调用方法，无 null 检查
- 可空包装类型的自动拆箱
- **跳过**: 使用 Optional、@Nullable 注解 + 已检查、存在 null 守卫

### Thread Safety
仅报告多线程上下文中的共享可变状态：
- Check-then-act 模式、无双重检查锁定的懒初始化
- **跳过**: 方法局部变量、不可变对象、final 字段、单线程组件

### 资源与性能
- Stream/Connection/Reader 不在 try-with-resources 中
- 循环内 DB 查询 (N+1)
- **跳过**: try-with-resources、框架管理资源、已知小数据量

### 框架
- **Spring**: @Transactional 在 private 方法上、缺少 @PreAuthorize
- **MyBatis**: ${} vs #{} — 标记 ${} 中用户可控参数
- **JPA**: JPQL 拼接而非参数绑定
""",
    "javascript": """
## JavaScript/TypeScript 专属检查清单
### 注入与执行
- eval() / Function() / setTimeout(string) / setInterval(string) — 始终标记
- innerHTML / insertAdjacentHTML 含用户内容 — XSS
- document.write() — 始终标记
- **跳过**: textContent、DOMPurify、硬编码内容

### 原型链污染
- Object.assign / _.merge / spread 到目标来自用户输入，无 __proto__ 过滤
- **跳过**: Object.create(null)、已对 __proto__/constructor 净化

### 异步与错误
- 未处理的 Promise rejection、空 catch 块
- **跳过**: 全局 unhandledRejection 处理器、框架错误边界

### Node.js (服务端)
- child_process.exec() 含用户输入 — 命令注入
- fs 含用户可控路径 — 路径遍历
- require() 含动态路径 — 代码注入
- **跳过**: execFile() + args 数组、path.resolve() + 白名单

### React
- 组件内定义组件（每次渲染重新创建）
- useEffect 缺少订阅/事件监听器清理
- 直接 DOM 操作 (ref.current.innerHTML = ...)
- **跳过**: useCallback、AbortController 清理
""",
    "python": """
## Python 专属检查清单
### 执行与注入
- eval()/exec()/compile() 含用户输入 — 严重
- os.system()/subprocess.call(shell=True) — 命令注入
- pickle.load()/yaml.load() 处理不受信数据 — 反序列化
- **跳过**: subprocess.run(args=[])、yaml.safe_load()、json.loads()、ast.literal_eval()

### 路径遍历
- open(user_input), os.path.join(user_input) 无净化
- **跳过**: pathlib.Path.resolve() 已检查、UUID 生成文件名

### 模板注入
- render_template_string(user_input) 在 Flask/Jinja2
- Template(user_input).substitute() 在 Django（用户控制模板时）
- **跳过**: 模板源仅来自文件

### 框架
- Django: DEBUG=True, SECRET_KEY 硬编码, ALLOWED_HOSTS=['*'], @csrf_exempt 无替代
- **跳过**: DEBUG 来自环境变量、SECRET_KEY 来自 secrets manager
""",
    "go": """
## Go 专属检查清单
### 错误处理
- 错误返回但未检查（赋值给 _）
- 库/handler 代码中的 panic()
- **跳过**: 有注释的故意忽略、defer 清理

### 并发
- Goroutine 泄漏（无取消/done channel）
- 数据竞争（共享变量，无 sync.Mutex/atomic）
- WaitGroup.Add() 在 goroutine 内部
- **跳过**: context.Context 取消、-race 测试、单 goroutine

### 资源
- 循环中 defer file.Close()（循环结束后才关闭，非每次迭代）
- HTTP 响应 body 未关闭
- **跳过**: 正确 defer 模式、框架管理

### 安全
- template.HTML(userInput) 在 html/template — XSS
- os/exec.Command("sh", "-c", userInput) — 命令注入
- math/rand 用于令牌/session ID — 使用 crypto/rand
- MD5/SHA1 用于密码哈希 — 使用 bcrypt/argon2
- **跳过**: html/template 自动转义、exec.Command + args 数组、crypto/rand
""",
}


def get_language_checklist(language: str) -> str:
    """获取指定语言的专属检查清单。"""
    return LANGUAGE_CHECKLISTS.get(language.lower(), "")


# ═══════════════════════════════════════════════════════════════
# 第四部分：Sink 证据点模板
# ═══════════════════════════════════════════════════════════════

SINK_EVIDENCE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "SQL注入": {
        "required_evidence": ["EVID_SQL_EXEC_POINT", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明用户输入到达 SQL 执行点",
        "kill_switch_signals": ["PreparedStatement", "参数化查询", "ORM 安全方法"],
    },
    "命令注入": {
        "required_evidence": ["EVID_CMD_EXEC_POINT", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明用户输入到达命令执行点",
        "kill_switch_signals": ["args 数组", "白名单校验", "escapeshellarg"],
    },
    "XSS": {
        "required_evidence": ["EVID_OUTPUT_POINT", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明用户输入未转义输出到响应",
        "kill_switch_signals": ["HTML 编码", "DOMPurify", "框架自动转义"],
    },
    "路径遍历": {
        "required_evidence": ["EVID_FILE_OPERATION", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明用户输入到达文件操作路径",
        "kill_switch_signals": ["路径规范化", "白名单目录", "UUID 文件名"],
    },
    "SSRF": {
        "required_evidence": ["EVID_NETWORK_REQUEST", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明用户输入控制网络请求目标",
        "kill_switch_signals": ["URL 白名单", "内网地址过滤"],
    },
    "反序列化": {
        "required_evidence": ["EVID_DESERIALIZE_POINT", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明不受信数据进入反序列化",
        "kill_switch_signals": ["类型白名单", "安全解析器", "json.loads"],
    },
    "XXE": {
        "required_evidence": ["EVID_XML_PARSE_POINT", "EVID_USER_INPUT_SOURCE"],
        "description": "需要证明 XML 解析未禁用外部实体",
        "kill_switch_signals": ["禁用 DTD", "禁用外部实体"],
    },
    "文件上传": {
        "required_evidence": ["EVID_UPLOAD_HANDLER", "EVID_FILENAME_CONTROL"],
        "description": "需要证明文件名/类型可被用户控制",
        "kill_switch_signals": ["UUID 重命名", "白名单扩展名", "MIME 校验"],
    },
    "认证绕过": {
        "required_evidence": ["EVID_AUTH_BYPASS_PATH", "EVID_SENSITIVE_ENDPOINT"],
        "description": "需要证明存在绕过认证访问敏感端点的路径",
        "kill_switch_signals": ["全局认证过滤器", "角色校验"],
    },
}


def get_evidence_template(vuln_name: str) -> Optional[Dict[str, Any]]:
    """获取漏洞类型的证据点模板。"""
    if vuln_name in SINK_EVIDENCE_TEMPLATES:
        return SINK_EVIDENCE_TEMPLATES[vuln_name]
    for key, template in SINK_EVIDENCE_TEMPLATES.items():
        if key in vuln_name or vuln_name in key:
            return template
    return None

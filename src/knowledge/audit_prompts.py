# -*- coding: utf-8 -*-
"""审计提示词组件 —— 整合自 gbt-codeagent。

包含：审查优先级分层、核心安全原则、严重度判定、证据契约、
去重规则、语言审计规则、双轨判定体系等。
"""

from typing import Dict

# 从 audit_skills 导入 Java 审计框架
try:
    from src.knowledge.audit_skills import (
        JAVA_SQL_AUDIT_FRAMEWORK,
        JAVA_AUTH_AUDIT_FRAMEWORK,
        JAVA_PARAM_CONTROLLABILITY,
        JAVA_FRAMEWORK_DETECTION,
    )
except ImportError:
    JAVA_SQL_AUDIT_FRAMEWORK = ""
    JAVA_AUTH_AUDIT_FRAMEWORK = ""
    JAVA_PARAM_CONTROLLABILITY = ""
    JAVA_FRAMEWORK_DETECTION = ""

# === 审查规则优先级分层 ===

REVIEW_PRIORITY_LAYERS = """
【审查规则优先级分层 - 必须严格遵守】

🔴 安全问题（优先级最高）- 必须检测：
- SQL注入：用户输入直接拼接SQL语句
- 命令注入：执行系统命令时使用用户可控数据
- XSS漏洞：用户输入未经过滤直接输出到页面
- 敏感信息硬编码：密码、密钥、API密钥明文存储
- 不安全的反序列化：使用不可信数据进行反序列化
- 认证绕过：身份验证逻辑缺陷
- 权限控制缺失：水平越权、垂直越权
- SSRF：服务器端请求伪造
- 路径遍历：文件路径包含用户可控输入
- 文件上传漏洞：文件类型验证不足
- CSRF：缺少CSRF令牌校验的写操作端点
- 日志注入：用户输入未过滤写入日志
- 开放重定向：重定向目标来自用户可控参数
- XXE：XML解析未禁用外部实体
- CORS配置缺陷：反射Origin且允许凭据
- 不安全组件：使用已知有漏洞的第三方组件(如Fastjson Log4j Shiro)

🟠 性能问题（优先级次之）- 重点检测：
- 循环中的数据库查询：N+1查询问题
- 大对象的频繁创建：内存占用过高
- 未关闭的资源：数据库连接、文件流泄漏
- 重复计算：相同计算多次执行
- 低效算法：时间复杂度较高的实现

🟡 代码规范（优先级较低）- 参考检测：
- 命名规范：变量、函数命名不规范
- 注释缺失：关键逻辑缺少注释说明
- 方法过长：单方法超过50行
- 复杂度过高：圈复杂度超过15
- 魔法数字：未定义常量的硬编码数值
"""

# === 核心安全分析原则 ===

CORE_SECURITY_PRINCIPLES = """
【核心安全分析原则】

1. 深度分析优于广度扫描
   - 深入分析少数真实漏洞比报告大量误报更有价值
   - 每个发现都需要上下文验证
   - 理解业务逻辑后才能判断安全影响

2. 数据流追踪
   - 从用户输入（Source）到危险函数（Sink）
   - 识别所有数据处理和验证节点
   - 评估过滤和编码的有效性

3. 上下文感知分析
   - 不要孤立看待代码片段
   - 理解函数调用链和模块依赖
   - 考虑运行时环境和配置

4. 质量优先
   - 高置信度发现优于低置信度猜测
   - 提供明确的证据和复现步骤
   - 给出实际可行的修复建议

5. 自检原则
   - 每报一个 critical 或 high，先问自己："我能描述这个漏洞会导致的精确用户事故吗？"
   - 如果答案模糊（"可能导致安全问题"），降级到 medium
   - 如果答案明确且可复现（"攻击者可通过 /api/user?id=xxx 读取任意用户数据"），保留级别
   - 如果你自己都不确定能不能被攻击，就不要报为 critical
"""

# === 运行时环境感知 ===

RUNTIME_CONTEXT_AWARENESS = """
【运行时环境感知 - 同问题不同环境不同级别】

同一类问题在不同运行时环境的影响完全不同，必须区分：

服务端（Node.js/Deno/Python/Go/Java）：
- 未处理异常 → 可能导致进程崩溃 → 🔴 critical
- 资源泄漏（连接/文件句柄）→ 累积耗尽 → 🔴 critical
- try-catch 空吞异常 → 静默故障，难以排查 → 🟠 high

浏览器端（React/Vue/Angular）：
- 未处理异常 → ErrorBoundary/全局 handler 兜底 → 最多 🟡 medium
- 渲染 undefined → 框架渲染空，不崩溃 → 不算漏洞
- 事件监听器未移除 → 内存增长 → 🟠 high

后端 API 端点：
- 缺少认证 → 数据泄露 → 🔴 critical
- 缺少授权检查 → 越权访问 → 🔴 critical

前端管理页面：
- 缺少前端路由守卫 → 但后端已有全局拦截 → 最多 🟡 medium
- loading/error 状态缺失 → 体验问题 → 🟢 low
"""

# === 严重级别判定标准 ===

SEVERITY_CLASSIFICATION_GUIDE = """
【严重级别判定标准 - 必须严格区分】

🔴 critical（严重）- 仅以下情况：
- 可直接通过网络远程利用，无需认证
- 可导致远程代码执行(RCE)、系统完全控制
- 可导致任意文件读取/写入
- 可绕过身份认证直接访问核心功能
- 明确的命令注入、SQL注入且用户输入未经任何过滤直接到达危险函数
- 硬编码的生产环境密钥/凭证
- ⚠️ critical 只能用于最严重的问题，不能滥用

🟠 high（高危）- 以下情况：
- 需要普通用户认证后可利用
- 可导致重要数据泄露（用户密码、个人信息）
- CSRF 可导致关键操作（修改密码、转账）
- 反序列化漏洞（有实际风险）
- SSRF 可访问内网
- 权限控制缺失导致越权
- 会话固定、敏感信息在日志中泄露

🟡 medium（中危）- 以下情况：
- 需要特定条件才能利用（如需要管理员权限）
- 信息泄露但影响范围有限（如版本号、路径泄露）
- 配置不当但不直接导致安全漏洞
- 弱加密算法但仍需要其他条件才能利用
- 输入验证不足但已有部分防护
- 仅测试/开发环境风险
- 竞争条件但利用难度大

🟢 low（低危）- 以下情况：
- 几乎无法实际利用
- 仅理论风险，缺乏实际攻击路径
- 代码风格问题不直接导致安全漏洞
- 已废弃但未删除的调试代码（不影响生产）
- 框架已默认防护的潜在风险
- low 用于信息性发现，置信度应设为 0.3-0.5

⚠️ 判定原则：
- 不确定时应降级而非升级：有疑问时选较低级别
- 需要认证或特定条件才能利用的，不应评为 critical
- 仅理论风险无实际攻击路径的，评为 low
- 如果所有发现都是同一级别，说明判定标准有问题，请重新审视

## 统计预期（校准用）
- 一个正常项目的审计结果中，critical 应为 0-2 个，high 应为 0-5 个
- 如果 critical 超过 5 个或 high 超过 15 个，说明严重度判定过于宽松，请重新审视并降级
- 如果所有发现都是 medium，说明你可能漏掉了真正的严重问题
- 如果所有发现都是 low，说明你过度保守，请提高对真实风险的认识

### 🚫 明确不算漏洞的情况（必须遵守）

以下情况绝对不能报为漏洞，即使看起来有问题：
- JS/TS 渲染中访问可能为 undefined 的属性（框架渲染空值，不会崩溃）
- "可以加可选链"但当前代码逻辑已经保证安全的场景
- 纯理论风险，缺少真实输入能触发的路径
- 仅代码风格 / 命名 / 重复代码问题（这些不是安全漏洞）
- 测试代码 / 演示代码 / 示例代码 / mock 文件中的"漏洞"
- 已被框架默认防护的潜在风险（如 Spring Security 已启用的 CSRF、框架自带的 XSS 过滤）
- CSS 工具类的数值（如 Tailwind text-[11px]、mt-3）、hex 颜色、CSS 单位
- 仅 import 语句但无实际调用的情况
- 非安全相关的代码规范建议（如"变量命名不够语义化"）
"""

# === 文件路径验证规则 ===

FILE_VALIDATION_RULES = """
【文件路径验证规则 - 防止幻觉】

⚠️ 严禁行为：
- 禁止报告不存在的文件路径
- 禁止凭记忆或推测编造代码片段
- 禁止假设特定文件存在（如 config/database.py、"Python项目通常有config.py"）
- 禁止报告注释行代码作为漏洞
- 禁止报告导入语句但无实际调用的代码
- 禁止基于"典型项目结构"猜测文件路径
- 禁止使用知识库示例代码作为项目实际代码

✅ 正确做法：
- 先 Glob 发现文件 → 再 Read 读取内容 → 再分析 → 再报告
- 只报告提供代码片段中确实存在的漏洞
- 引用实际代码时使用提供的 snippet（直接复制，保持格式和缩进）
- 行号必须在文件实际行数范围内，不确定时重新确认
- 漏洞类型必须与项目技术栈一致（不在 Rust 项目中报 Python 漏洞）

🔴 验证清单（每个发现前自检）：
□ 文件路径确认存在
□ 代码片段来自实际读取
□ 行号在文件行数范围内
□ 漏洞类型与技术栈一致
□ 不是从知识库示例推测的

⚠️ 知识库隔离原则：知识库示例用于理解漏洞概念和检测方法，≠ 项目代码。必须在实际代码中找到对应模式。

🔥 宁可漏报，不可误报。质量优于数量。
"""

# === 证据契约要求 ===

EVIDENCE_CONTRACT_GUIDE = """
【证据契约要求 - 每个漏洞必须提供标准证据】

🔴 核心原则：漏洞发现必须附带标准化证据点（EVID_*），用于后续验证和追溯。

【常见漏洞类型对应证据点】
| 漏洞类型 | 必须证据点 |
|---------|-----------|
| SQL注入 | EVID_SQL_EXEC_POINT, EVID_SQL_STRING_CONSTRUCTION, EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT |
| 命令注入 | EVID_CMD_EXEC_POINT, EVID_CMD_COMMAND_STRING_CONSTRUCTION, EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT |
| 文件操作 | EVID_FILE_WRAPPER_PREFIX, EVID_FILE_RESOLVED_TARGET, EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY |
| SSRF | EVID_SSRF_URL_NORMALIZATION, EVID_SSRF_FINAL_URL_HOST_PORT, EVID_SSRF_DNSIP_AND_INNER_BLOCK |
| XXE | EVID_XXE_PARSER_CALL, EVID_XXE_INPUT_SOURCE, EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO |
| 反序列化 | EVID_DESER_CALLSITE, EVID_DESER_INPUT_SOURCE, EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN |
| XSS | EVID_XSS_OUTPUT_POINT, EVID_XSS_USER_INPUT_INTO_OUTPUT, EVID_XSS_ESCAPE_OR_RAW_CONTROL |
| 认证绕过 | EVID_AUTH_PATH_PROTECTED_MATCH, EVID_AUTH_TOKEN_DECODE_JUDGMENT, EVID_AUTH_PERMISSION_CHECK_EXEC |

【证据点输出格式】
每个漏洞发现中必须包含 evidencePoints 数组，列出该漏洞涉及的所有证据点ID。

【证据完整性判定】
- ✅ COMPLETE: 所有关键证据点都存在
- ⚠️ PARTIAL: 部分证据点缺失，需人工复核
- ❌ UNRESOLVED: 关键证据点缺失，标记为待验证

⚠️ 注意：如果无法提供完整的证据链，必须将漏洞标记为"待验证"，不得直接标记为"已确认可利用"。
"""

# === 去重规则 ===

DE_DUPLICATION_RULES = """
【去重规则 - 必须遵守】

LLM 最常见的问题是同一个模式在多个文件中被重复报告为独立漏洞。以下规则强制避免：

✅ 应该合并的情况（同一根因）：
- 同一文件、同一函数、同一行号、同一漏洞类型 → 合并为一条
- 如果某个模式要报 10 个文件以上，说明这是系统性的代码风格，合为一条典型说明

❌ 不应该合并的情况（不同攻击面）：
- 不同 Controller/端点/参数的同类漏洞 → 分别报告
  - 例如 ProcessBuilder 命令注入 ≠ Runtime.exec 命令注入 ≠ ProcessImplVul 命令注入
  - 三个不同端点的 "命令注入" 是三个独立的攻击面，必须分别报告
- 不同文件、不同 sink 函数的同类漏洞 → 分别报告
- 不同利用前提（如一个需认证、一个无需认证）→ 分别报告

判定标准：如果合并后 attackVector 无法精确描述每个端点的攻击方式，则不应合并。

- 同一文件中相同类型且相同函数调用的问题合并为一条
"""

# === 双轨判定体系 ===

DUAL_VERDICT_SYSTEM = """
【漏洞判定双轨体系 - 确认风险 vs 可疑风险】

你必须对每个发现的漏洞使用以下判定体系，而不是仅报告严重度：

🔴 确认风险 — 同时满足以下条件：
  - 明确看到用户可控输入进入危险操作
  - 代码中缺少有效的校验/转义/鉴权防护
  - 能清晰描述完整的攻击链路和后果
  - 示例：request.args["id"] 直接进入 SQL 拼接且无 PreparedStatement

🟡 可疑风险 — 满足以下情况之一：
  - 看到明显的输入源和危险点，但缺少完整调用链证据
  - 看到危险点和明显缺失防护，但输入可控性不确定
  - 上下文不足以完全闭合利用链，但风险信号很强
  - 必须在攻击向量中明确写出"当前缺少哪些证据"
  - 等级上限为中危

⚪ 审计通过 — 以下情况：
  - 没有输入源 + 危险点的有效组合
  - 代码本身是安全封装/校验/日志/资源释放逻辑
  - 已有充分的参数化/白名单/鉴权/转义措施

【具体反误报负面示例 - 以下绝对不能报为漏洞】

错误示例 1：xstrdup(challenge) 可能导致缓冲区溢出
  → 原因：仅凭字符串复制函数名不能证明溢出

错误示例 2：sshbuf_free(b) 可能导致内存泄露
  → 原因：释放资源本身不是漏洞证据

错误示例 3：普通 malloc/free 配对
  → 原因：正常的内存管理操作不是漏洞

错误示例 4：import 某个库但未调用其危险函数
  → 原因：仅导入不构成攻击面

错误示例 5：CSS 工具类中的数字（如 Tailwind text-[11px]）
  → 原因：CSS 数值不是硬编码密码
"""

# === 语言级安全审计规则（LLM 审计增强） ===

LANGUAGE_AUDIT_RULES_LLM: Dict[str, str] = {
    ".py": """
[Python 审计规则]
1. 输入源识别：request.args, request.form, request.json, request.values, request.files, input(), sys.argv, os.environ, getenv, 上传文件对象, URL/path 参数
2. 危险点识别：eval(), exec(), pickle.load/loads, yaml.load (非 safe_load), subprocess.run/Popen/call (shell=True), os.system, SQL 字符串拼接, open/Path.open/read_text/write_text (用户可控路径), 模板直出 (Jinja2 未转义)
3. 安全信号：yaml.safe_load, html.escape/MarkupSafe.escape, pathlib.Path.resolve(), subprocess 列表参数 (非 shell 模式), 参数化查询 (sqlite3 ?, psycopg2 %s, sqlalchemy bind), pydantic/marshmallow 校验
4. 判定指引：看到 request 输入进入 SQL/命令/文件/URL/模板 → 优先确认风险；若有 safe_load/参数化/白名单 → 降低级别；仅 import 没有调用 → 不报""",

    ".js": """
[JavaScript 审计规则]
1. 输入源识别：req.query, req.body, req.params, req.headers, req.files, process.env, window.location, document.location, 上传文件对象, URL 参数
2. 危险点识别：child_process.exec/spawn/execSync, eval(), new Function(), vm.runInNewContext, 字符串拼接 SQL (mysql.query/sequelize.query 拼接), fs.readFile/writeFile/createReadStream/createWriteStream (用户可控路径), fetch/axios URL 拼接, dynamic require/import, innerHTML/dangerouslySetInnerHTML/document.write
3. 安全信号：path.normalize/join/resolve, prepared statement/参数化查询 (mysql2.execute, sequelize bind), DOMPurify, zod/joi/yup/express-validator, helmet
4. 判定指引：看到 req.query/body/params 进入 SQL/命令/文件/URL → 优先确认风险；若有 path.resolve+约束/参数化/DOMPurify → 降低级别；前端渲染 undefined → 不算漏洞""",

    ".ts": """
[TypeScript 审计规则]
1. 输入源识别：req.query, req.body, req.params, req.headers, process.env, 上传文件, URL/path 参数
2. 危险点识别：child_process.exec/spawn/execSync, eval(), new Function(), SQL 字符串拼接, fs.readFile/writeFile (用户可控), fetch/axios URL 拼接, dynamic import
3. 安全信号：path.normalize/join/resolve, prepared statement/参数化查询, zod/joi/class-validator/nestjs 校验, helmet, TypeScript 类型约束（不视为安全信号）
4. 判定指引：TypeScript 类型注解不是安全防护，仍需检查运行时输入；其余同 JS""",

    ".java": """
[Java 审计规则]
1. 输入源识别：request.getParameter(), @RequestParam, @PathVariable, @RequestBody, System.getenv, MultipartFile, 上传文件名, URL 参数, Cookie
2. 危险点识别：Runtime.exec(), ProcessBuilder, JDBC Statement.execute/executeQuery/executeUpdate (字符串拼接), Hibernate HQL 拼接, JdbcTemplate 拼接, FileInputStream/FileOutputStream (用户可控路径), HttpURLConnection/RestTemplate/WebClient URL 拼接, ObjectInputStream (反序列化), XMLDecoder, XStream, ScriptEngine.eval, GroovyShell
3. 安全信号：PreparedStatement (参数绑定), @PreAuthorize/@RolesAllowed/hasRole, Paths.get/toRealPath/normalize, @Valid + BindingResult, Spring Security 全局配置
4. 判定指引：看到 request.getParameter/@RequestParam 进入 SQL/命令/文件/URL → 优先确认风险；有 PreparedStatement/参数绑定 → 降低级别；Spring Security 全局 CSRF → 不报 CSRF""",

    ".go": """
[Go 审计规则]
1. 输入源识别：r.URL.Query(), r.FormValue(), r.PostFormValue(), c.Param()/c.Query()/c.PostForm() (gin), ShouldBindJSON/BindJSON, os.Getenv, 上传文件, URL/path 参数
2. 危险点识别：exec.Command (配合 sh -c 或用户可控参数), database/sql db.Query/db.Exec (拼接 SQL), os.Open/os.Create (用户可控路径), http.Get/http.Post (用户可控 URL), template.HTML (text/template 无转义)
3. 安全信号：html/template (自动转义), Query/Exec 占位符 (?/$1), PreparedStatement, filepath.Clean/Join, validator 绑定, ShouldBind 校验, r.Context()
4. 判定指引：看到 Query/FormValue/BindJSON 进入 SQL/命令/文件/URL → 优先确认风险；html/template 自动转义, 参数化 → 降低级别""",

    ".php": """
[PHP 审计规则]
1. 输入源识别：$_GET, $_POST, $_REQUEST, $_FILES, $_COOKIE, $_SERVER, $_ENV, file_get_contents('php://input'), URL 参数, 路径参数
2. 危险点识别：system/exec/shell_exec/passthru/proc_open, mysqli_query/mysql_query (拼接 SQL), PDO::query (拼接 SQL), include/require/include_once/require_once (动态路径), file_get_contents/fopen/fwrite (用户可控路径), unserialize, eval, preg_replace /e, create_function
3. 安全信号：PDO::prepare + bindValue/bindParam, filter_input/filter_var, htmlspecialchars, realpath/basename, password_hash/password_verify, CSRF token 校验
4. 判定指引：看到 $_GET/$_POST 进入 SQL/include/system/文件 → 优先确认风险；PDO prepare + bind → 降低级别""",

    ".c": """
[C 审计规则]
1. 输入源识别：argv, getenv, recv/read/fgets/scanf, socket 输入, 文件名/路径参数
2. 危险点识别：system/popen/execl/execv, sprintf/strcpy/strcat/gets (无边界), fopen/open (用户可控路径), 动态加载 dlopen, 认证逻辑绕过
3. 安全信号：snprintf/strncpy (有边界), realpath, strlen/sizeof 结合边界检查, strncmp/memcmp
4. 判定指引：仅凭 malloc/free/strdup/xstrdup 不报漏洞；需要可控输入+危险操作+缺失边界才报""",

    ".cpp": """
[C++ 审计规则]
1. 输入源识别：argv, getenv, recv/read/gets/scanf, std::cin, 文件名/路径参数
2. 危险点识别：system/popen, sprintf/strcpy/strcat, std::ifstream/ofstream/fstream (用户可控路径), 命令执行, 认证绕过
3. 安全信号：snprintf, std::filesystem::canonical, std::array, std::regex 校验, std::clamp, size()
4. 判定指引：仅凭内存分配/释放/字符串复制不报漏洞；需要可控输入+危险操作+缺失防护""",

    ".cs": """
[C# 审计规则]
1. 输入源识别：Request.Query, Request.Form, Request.Body, Request.Headers, IFormFile, Environment.GetEnvironmentVariable, URL/path 参数
2. 危险点识别：Process.Start, SqlCommand.ExecuteReader/ExecuteNonQuery (拼接 SQL), File.ReadAllText/WriteAllText/OpenRead/OpenWrite (用户可控路径), HttpClient.GetAsync/PostAsync (用户可控 URL), BinaryFormatter/SoapFormatter (反序列化), XPathNavigator/XPathExpression
3. 安全信号：SqlParameter/SqlCommand 参数化, Path.GetFullPath/Path.Combine, [Authorize]/[AllowAnonymous], ModelState.IsValid, DataAnnotations/FluentValidation, AntiForgeryToken (CSRF)
4. 判定指引：看到 Request 输入进入 SQL/Process/文件/URL → 优先确认风险；参数化查询/SqlParameter → 降低级别；[Authorize] 全局启用 → 不报认证绕过""",
}


def build_audit_system_prompt(
    language: str = "",
    include_priority_layers: bool = True,
    include_severity_guide: bool = True,
    include_evidence_contract: bool = True,
    include_dedup_rules: bool = True,
    include_dual_verdict: bool = True,
    include_language_rules: bool = True,
) -> str:
    """构建审计系统提示词。

    根据参数选择性组装各提示词组件，支持按需裁剪上下文长度。
    """
    parts = []

    if include_priority_layers:
        parts.append(REVIEW_PRIORITY_LAYERS)

    parts.append(CORE_SECURITY_PRINCIPLES)
    parts.append(RUNTIME_CONTEXT_AWARENESS)

    if include_severity_guide:
        parts.append(SEVERITY_CLASSIFICATION_GUIDE)

    parts.append(FILE_VALIDATION_RULES)

    if include_evidence_contract:
        parts.append(EVIDENCE_CONTRACT_GUIDE)

    if include_dedup_rules:
        parts.append(DE_DUPLICATION_RULES)

    if include_dual_verdict:
        parts.append(DUAL_VERDICT_SYSTEM)

    if include_language_rules and language:
        ext = f".{language}" if not language.startswith(".") else language
        lang_rules = LANGUAGE_AUDIT_RULES_LLM.get(ext, "")
        if lang_rules:
            parts.append(lang_rules)

        # Java 专属：注入审计框架知识（SQL注入 / Auth绕过 / 参数可控性 / 框架识别）
        if language.lower() in ("java", ".java"):
            if JAVA_SQL_AUDIT_FRAMEWORK:
                parts.append(JAVA_SQL_AUDIT_FRAMEWORK)
            if JAVA_AUTH_AUDIT_FRAMEWORK:
                parts.append(JAVA_AUTH_AUDIT_FRAMEWORK)
            if JAVA_PARAM_CONTROLLABILITY:
                parts.append(JAVA_PARAM_CONTROLLABILITY)
            if JAVA_FRAMEWORK_DETECTION:
                parts.append(JAVA_FRAMEWORK_DETECTION)

    return "\n\n".join(parts)

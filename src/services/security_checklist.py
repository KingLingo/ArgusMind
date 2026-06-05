# -*- coding: utf-8 -*-
"""安全检查清单 — 借鉴 gbt-codeagent 的 quality_standards.md 和 audit_workflow.md。

按漏洞类型提供按需注入的检查清单，帮助 ChainAnalyzer 在链路分析时
不遗漏关键检查点。
"""

from typing import Dict, Optional

# ═══════════════════════════════════════════════════════════════
# 漏洞类型 → 检查清单模板
# ═══════════════════════════════════════════════════════════════

SECURITY_CHECKLISTS: Dict[str, str] = {
    "SQL注入": """
## SQL 注入检查
- [ ] 检查是否为 PreparedStatement / 参数化查询
- [ ] 检查 MyBatis #{}/\\${} 使用是否正确
- [ ] 如果是 ORDER BY / GROUP BY 参数：是否经过白名单校验
- [ ] 如果是 HQL 拼接：是否使用 setParameter 绑定
- [ ] 检查异常处理是否泄露数据库结构
- [ ] 所需证据：SQL 执行点 + 字符串构造证据 + 用户参数到 SQL 片段的映射
""",

    "命令注入": """
## 命令注入检查
- [ ] ProcessBuilder / subprocess / Runtime.exec 参数是否用户可控
- [ ] shell=True 标志是否存在
- [ ] 参数是否使用数组传递（非 shell 字符串拼接）
- [ ] 是否配置了严格的命令白名单
- [ ] 所需证据：命令执行点 + 命令字符串构造 + 用户参数到命令片段的映射
""",

    "反序列化": """
## 反序列化检查
- [ ] 反序列化数据是否来自不可信源（@RequestBody、文件上传）
- [ ] ObjectInputStream 是否使用白名单 resolveClass
- [ ] XMLDecoder / XStream / Fastjson 是否启用安全配置
- [ ] pickle.loads / yaml.unsafe_load / marshal.load 是否可被用户输入触发
- [ ] 所需证据：反序列化调用点 + 输入来源 + 对象类型 / Magic 调用链
""",

    "代码注入": """
## 代码注入检查
- [ ] eval / exec / ScriptEngine / GroovyShell 是否用户可控
- [ ] SpEL 表达式是否含 #{...} 且用户输入可影响
- [ ] 模板引擎（Jinja2/FreeMarker/Thymeleaf）是否将用户输入作为模板渲染
- [ ] 所需证据：执行入口 + 表达式控制 + 执行链入口
""",

    "XSS": """
## XSS 检查
- [ ] 用户输入是否直接写入 HTTP 响应体
- [ ] innerHTML / dangerouslySetInnerHTML / document.write 是否使用用户输入
- [ ] 输出是否经过 HTML 实体编码（Spring HtmlUtils / Thymeleaf th:text / React JSX）
- [ ] 是否配置了 CSP 头
- [ ] 所需证据：输出点 + 用户输入进入输出 + 转义/原始输出控制
""",

    "SSRF": """
## SSRF 检查
- [ ] 用户输入是否控制 URL 的 host/port 部分
- [ ] 是否对目标域名/IP 做白名单限制
- [ ] 是否禁止访问内网地址（127.0.0.1 / 10.x / 172.16.x / 192.168.x）
- [ ] 是否限制协议（仅允许 http/https）
- [ ] 所需证据：URL 构造点 + 用户参数映射 + DNS/IP 内网拦截
""",

    "路径遍历": """
## 路径遍历检查
- [ ] 文件路径是否包含用户可控输入
- [ ] 是否使用 normalize() / realpath() 规范路径
- [ ] 是否使用 startsWith() 限制访问范围
- [ ] MultipartFile.getOriginalFilename() 是否直接拼路径
- [ ] 所需证据：文件读写 Sink + 路径构造证据 + 用户参数到路径的映射
""",

    "XXE": """
## XXE 检查
- [ ] XML 解析器是否禁用外部实体（disallow-doctype-decl / external-general-entities）
- [ ] 是否设置 FEATURE_SECURE_PROCESSING
- [ ] 解析的 XML 是否来自不可信源
- [ ] 所需证据：解析器调用点 + 输入源 + 实体 / DOCTYPE 安全配置
""",

    "认证绕过": """
## 认证绕过检查
- [ ] 鉴权检查是否使用 getRequestURI()（危险）还是 getServletPath()（安全）
- [ ] 是否分号路径参数可绕过：/admin;.js → startsWith 白名单
- [ ] Spring Security 是否使用 antMatchers（尾部斜杠可绕过）
- [ ] Shiro 版本是否 < 1.5.2 / < 1.6.0（已知 CVE）
- [ ] 所需证据：保护路径匹配 + Token 解码判定 + 权限检查执行
""",

    "硬编码凭据": """
## 硬编码凭据检查
- [ ] password / apiKey / secret / token 在源代码中是否有字符串字面量
- [ ] 是否来自环境变量（System.getenv / os.environ）或配置中心
- [ ] 日志输出是否打印了凭据
- [ ] 配置文件（.properties / .yml）是否明文存储密码
- [ ] 所需证据：硬编码位置 + 凭据类型 + 使用场景
""",

    "弱加密": """
## 弱加密检查
- [ ] 哈希算法是否为 MD5 / SHA-1（应使用 SHA-256 或以上）
- [ ] 对称加密是否为 DES / 3DES / RC4（应使用 AES-256-GCM）
- [ ] 密码存储是否使用 bcrypt / Argon2 / scrypt
- [ ] 随机数生成是否使用 java.util.Random / random.random()（应使用 SecureRandom / secrets）
- [ ] 密钥长度是否 ≥ 128 位（AES）
- [ ] 所需证据：算法调用点 + 使用场景 + 密钥长度
""",

    "文件上传": """
## 文件上传检查
- [ ] 文件类型验证是否仅客户端（可绕过）
- [ ] 是否进行服务端 MIME type + 魔数双重验证
- [ ] 文件名是否来自 getOriginalFilename() 且直接拼路径
- [ ] 上传目录是否可直接 URL 访问（需要禁止脚本执行）
- [ ] 是否限制文件大小（防止 DoS）
""",

    "CSRF": """
## CSRF 检查
- [ ] 写操作（POST/PUT/DELETE）端点是否有 CSRF Token 验证
- [ ] Spring Security 是否启用 csrf().disable()（如果禁用了，需要其他机制）
- [ ] Token 是否服务端生成且不可预测
- [ ] 是否验证 Referer / Origin 头
""",
}

# ═══════════════════════════════════════════════════════════════
# 漏洞类型关键词 → 检查清单的模糊匹配映射
# ═══════════════════════════════════════════════════════════════

_VULN_KEYWORD_TO_CHECKLIST: Dict[str, str] = {
    "SQL": "SQL注入",
    "sql": "SQL注入",
    "命令": "命令注入",
    "command": "命令注入",
    "反序列化": "反序列化",
    "deserial": "反序列化",
    "代码": "代码注入",
    "code_injection": "代码注入",
    "RCE": "代码注入",
    "XSS": "XSS",
    "xss": "XSS",
    "SSRF": "SSRF",
    "ssrf": "SSRF",
    "路径遍历": "路径遍历",
    "path_traversal": "路径遍历",
    "目录遍历": "路径遍历",
    "XXE": "XXE",
    "xxe": "XXE",
    "认证": "认证绕过",
    "auth_bypass": "认证绕过",
    "越权": "认证绕过",
    "IDOR": "认证绕过",
    "硬编码": "硬编码凭据",
    "secret": "硬编码凭据",
    "credential": "硬编码凭据",
    "弱加密": "弱加密",
    "weak_crypto": "弱加密",
    "弱哈希": "弱加密",
    "MD5": "弱加密",
    "SHA1": "弱加密",
    "DES": "弱加密",
    "文件上传": "文件上传",
    "upload": "文件上传",
    "CSRF": "CSRF",
    "csrf": "CSRF",
}


def get_security_checklist(category_name: str) -> Optional[str]:
    """按漏洞类型名返回对应的安全检查清单。"""
    if not category_name:
        return None

    # 精确匹配
    if category_name in SECURITY_CHECKLISTS:
        return SECURITY_CHECKLISTS[category_name]

    # 关键词模糊匹配
    for keyword, checklist_name in _VULN_KEYWORD_TO_CHECKLIST.items():
        if keyword in category_name:
            return SECURITY_CHECKLISTS.get(checklist_name)

    return None

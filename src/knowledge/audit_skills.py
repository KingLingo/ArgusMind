# -*- coding: utf-8 -*-
"""审计技能定义 —— 整合自 gbt-codeagent。

每个技能定义包含：id、name、description、reviewPrompt、evidencePoints 等。
同时整合了 gbt-audit/workflow 和 skill 中的审计流程知识：
- 三层审计分工（快速扫描 / LLM审计 / LLM审查）
- LLM审计详细检查清单（Controller/Service/配置/工具/实体）
- 质量检查标准（修复方案编写要求）
- 行号验证流程
- 组合漏洞分析模式
"""

from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════
# 审计流程知识（整合自 gbt-audit/workflow + skill）
# ═══════════════════════════════════════════════════════════════

AUDIT_WORKFLOW = """
## 三层审计分工

| 分工 | 负责方 | 发现的漏洞类型 | 检出率 |
|------|--------|---------------|--------|
| 快速扫描 | 代码（正则表达式） | 高风险函数调用 | ~64% |
| LLM审计 | LLM（语义分析） | 需要上下文分析的漏洞 | ~61% |
| LLM审查 | LLM（深入分析） | 复杂业务逻辑漏洞、漏洞验证 | 最高 |

## LLM审计详细检查清单

### Controller层检查
- 每个接口方法是否验证用户输入？
- 是否有权限检查（@PreAuthorize、SecurityContextHolder）？
- 是否有CSRF Token验证？
- 是否有速率限制？
- 重定向目标是否白名单验证？
- 文件操作是否路径遍历防护？
- SQL查询是否参数化？
- 日志记录是否脱敏？

### Service层检查
- 业务逻辑是否有状态绕过风险？
- 并发操作是否有竞态条件？
- 金额计算是否使用BigDecimal？
- 是否有整数溢出风险？
- 是否有事务管理？

### 配置类检查
- Security配置是否启用CSRF保护？
- CORS配置是否限制可信源？
- Session配置是否安全？
- 密码编码器是否使用单向哈希？
- 是否启用HSTS？

### 工具类检查
- 输入验证是否充分？
- 随机数生成是否使用SecureRandom？
- 加密算法是否安全？
- 文件操作是否路径验证？

### 实体类检查
- 敏感字段是否标记transient？
- 序列化是否安全？
- 是否有敏感数据暴露？
"""

QUALITY_STANDARDS = """
## 修复方案编写要求

### 禁止以下敷衍内容
- "根据国标要求修复"
- "消除安全隐患"
- "使用安全的方法"
- "加强验证"
- "进行过滤"
- 字数 < 30 字
- 不包含具体代码、命令、配置或 API 名称

### 必须包含
- 具体代码示例（如 PreparedStatement）
- 或具体命令（如 chmod 600）
- 或具体 API/类名（如 Cipher.getInstance("AES/GCM/NoPadding")）
- 字数 >= 30 字
- 必须包含技术动作词：使用、改用、替代、配置、启用等

### 修复方案示例
| 漏洞类型 | 合格修复方案 |
|---------|------------|
| SQL注入 | 使用 PreparedStatement：ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setString(1, userId); |
| 命令注入 | 改用 ProcessBuilder 参数数组：new ProcessBuilder("cat", filename).start() 并白名单验证 |
| 硬编码密码 | 密码移至环境变量：System.getenv("DB_PASSWORD") 或使用配置文件（权限 600） |
| 弱加密 | 使用 AES-256/GCM 替代 DES：Cipher.getInstance("AES/GCM/NoPadding") |
| 反序列化 | 禁止 pickle.loads() 反序列化不受信任数据，改用 JSON |
"""

COMBINED_VULN_PATTERNS = """
## 组合漏洞分析模式

| 组合模式 | 攻击链 | 最终影响 |
|---------|--------|---------|
| 信息泄露 + 身份伪造 | 泄露用户信息 → 伪造身份 → 账户接管 | 账户被盗 |
| SSRF + 内网访问 | SSRF漏洞 → 访问内网 → 权限提升 | 内网渗透 |
| 路径遍历 + 文件上传 | 路径遍历 → 上传恶意文件 → RCE | 服务器被控 |
| XSS + CSRF | 窃取Cookie → 伪造请求 → 执行操作 | 账户被盗 |
| 注入 + 权限绕过 | SQL注入 → 获取权限 → 越权操作 | 数据泄露 |
"""

LINE_VERIFICATION_FLOW = """
## 行号验证流程

1. 读取源文件（使用 Read 工具）
2. 定位问题代码（在源文件中精确搜索）
3. 使用 Grep 验证（精确验证行号）
4. 确认行号（验证行号对应代码行而非注释行）
5. 记录发现（行号验证通过后才创建发现对象）

### 强制要求
- 必须使用 Grep 工具验证行号（禁止凭记忆填写）
- 必须逐行核对源文件确认漏洞位置
- 行号必须精确对应问题代码所在行
- 禁止根据注释推断行号，必须定位实际代码
"""

# ═══════════════════════════════════════════════════════════════
# Java 审计框架（整合自 gbt-codeagent）—— 实战性极强
# ═══════════════════════════════════════════════════════════════

JAVA_SQL_AUDIT_FRAMEWORK = """
## Java SQL注入审计框架 — 行为驱动而非命名模式

### 1. 核心原则：看方法做了什么，不是看方法叫什么
- 错误做法：仅搜索 addOrderBy/Pagination 等"看起来可疑"的方法名
- 正确做法：搜索 "ORDER BY" + 变量拼接的**真实行为**

### 2. 框架感知检测
- JDBC: Statement.execute/executeQuery/executeUpdate + 字符串拼接
- MyBatis: `${}` 不安全拼接 vs `#{}` 安全参数绑定
- Hibernate: createQuery/createNativeQuery + 字符串拼接 vs setParameter 参数绑定
- JdbcTemplate: 字符串拼接 vs `?` 占位符
- JPA: JPQL 拼接 vs `:param` 命名参数

### 3. ORDER BY / GROUP BY 注入（最常被遗漏！）
- 搜索 `.getOrderBy()` `.getSortField()` `.getGroupBy()` 等调用
- 检查 "ORDER BY" + 变量拼接（StringBuilder.append / String.format / 字符串+连接）
- 白名单校验：`allowedColumns.contains(orderBy)` 才算安全
- 仅 String/Enum 类型参数可注入列名，Integer/Long 类型是安全的

### 4. 数据库分支分析（避免误报）
- 检查 isOracle()/isMySQL() 等条件分支
- 在特定数据库类型下才执行的路径 → 降低风险级别
- 标注为 "Oracle-only" / "MySQL-only" 而非通用

### 5. 参数可控性检查（排除误报的关键）
- 追踪参数从 HTTP 入口到 SQL 执行点的完整路径
- 检查参数是否被硬编码覆盖 → 排除误报
- 区分"参数传递到 DAO 层"和"参数实际拼接到 SQL"
- SQL中已硬编码 "ORDER BY id DESC" → page.orderBy 参数未使用 → 非漏洞
"""

JAVA_AUTH_AUDIT_FRAMEWORK = """
## Java认证鉴权审计框架 — URI 解析差异绕过

### 1. URI 解析差异检测（最常见绕过根因）
- **getRequestURI()** → 返回 `/admin;.js`（含路径参数） → 危险！
- **getServletPath()** → 返回 `/admin`（不含路径参数） → 安全
- 如果鉴权层和路由层使用不同的 URI API，存在绕过可能

### 2. 分号路径参数绕过
- Tomcat 中 getRequestURI() 返回 `/admin;.js`，getServletPath() 返回 `/admin`
- 静态资源后缀白名单（如 `.js` `.css` `.png`） + getRequestURI() → 可被 `/admin;.js` 绕过
- Payload: `/admin;.js`, `/admin;.css`, `/admin;jsessionid=xxx`, `/;/admin`

### 3. 路径穿越绕过
- `startsWith("/admin")` 可被 `/public/../admin` 绕过
- `contains("/api/")` 可被 `%61` URL 编码绕过
- 必须检查路径是否经过 normalize() 处理

### 4. 框架特定 CVE
- **Shiro < 1.5.2**: `/xxx/..;/admin` 绕过 (CVE-2020-1957)
- **Shiro < 1.6.0**: `/admin/;page` 绕过 (CVE-2020-13933)
- **Spring Security**: antMatchers `/admin/` 尾部斜杠绕过 → 改用 mvcMatchers
- **Spring < 5.3**: 后缀匹配 `/admin.json` 可绕过
- 检查 Filter/Interceptor 中是否使用 getRequestURI() 做鉴权判断

### 5. 数据流分析（避免误报）
- 发现 contains()/startsWith() 模式后，追踪变量在匹配后如何使用
- 检查是否有二次校验（Interceptor/Action 层）
- 区分"绕过登录检查"和"绕过权限检查"
"""

JAVA_PARAM_CONTROLLABILITY = """
## Java参数可控性分析框架 — 排除"参数传递但未使用"的误报

### 1. 覆盖类型判定
- 无覆盖：参数直接到达 Sink → ✅ 完全可控
- 无条件覆盖：`x = "hardcoded"` 不在 if 内 → ❌ 不可控（排除误报）
- 空值保护覆盖：`if (isEmpty(x)) x = default` → ⚠️ 非空时可控
- 白名单覆盖：`if (!allowed.contains(x)) x = default` → ⚠️ 白名单内可控
- 安全检查覆盖：`if (!isSafe(x)) x = safe` → ⚠️ 绕过检查时可控

### 2. 硬编码覆盖检测（排除误报的最强手段）
- SQL 中已硬编码 "ORDER BY id DESC" → page.orderBy 参数未使用 → ❌ 非漏洞
- 命令中已硬编码 "ls -la" → cmd 参数未使用 → ❌ 非漏洞
- 路径中已硬编码 "/tmp/fixed.txt" → path 参数未使用 → ❌ 非漏洞
- 方法参数被覆盖赋值为常量 → 该参数不再可控 → ❌ 非漏洞

### 3. 分支条件追踪
- 识别环境/平台分支（isOracle / isMySQL）
- 识别安全检查分支（isAllowed / isSafe）
- 识别空值/异常分支（提前 return）
- 标注危险操作在哪些分支中执行

### 4. 输出格式（可控性判定表）
| 参数 | Sink类型 | 覆盖类型 | 覆盖条件 | 可控性结论 | 可控场景 |
- 可控性结论：✅完全可控 / ⚠️条件可控 / ❌不可控
"""

JAVA_FRAMEWORK_DETECTION = """
## Java Web 框架自动识别

### 1. 框架识别特征
- Spring MVC: @Controller, @RequestMapping, @RestController
- Spring Boot: @SpringBootApplication, application.properties/yml
- Struts2: struts.xml, ActionSupport 继承, .action 后缀
- Servlet: web.xml, @WebServlet, extends HttpServlet
- JAX-RS: @Path, @GET, @POST, @PathParam
- CXF WebService: jaxws:endpoint, @WebService, cxf-servlet.xml
- JFinal: extends Controller, @ActionKey

### 2. 配置文件定位
- Spring: application.yml, application.properties, SecurityConfig.java
- Struts2: struts.xml, struts-*.xml, struts.properties
- Servlet: web.xml, context.xml
- MyBatis: mybatis-config.xml, *Mapper.xml
- Hibernate: hibernate.cfg.xml, persistence.xml

### 3. 通用配置提醒
- 独立应用(非Spring)：确认配置位置，检查是否硬编码端口、密钥，确认数据库连接无凭据硬编码
- 编译产物(不报)：@Generated注解、Lombok字节码、MapStruct、Parcelable序列化、反射生成的GRASP方法
- 资源文件(不报)：.properties配置类名(不直接执行)、日志配置、图标/MIME/静态映射

### 4. 通配符路由识别
- Struts2: name="*_*" 双通配 → 必须展开为实际 URL
- Spring: @RequestMapping 路径变量 /api/{id}/**
- Servlet: /api/* 通配 → 内部分发方法需识别
"""

# ═══════════════════════════════════════════════════════════════
# 审计技能列表
# ═══════════════════════════════════════════════════════════════

AUDIT_SKILLS: List[Dict[str, Any]] = [
    {
        "id": "access-control",
        "name": "访问控制",
        "description": "关注对象级授权、公共角色、插件路由和后台访问边界。",
        "version": "1.0.0",
        "tags": ["security", "authorization", "owasp-a01"],
        "triggers": ["越权", "权限", "访问控制", "authorization", "permission", "role", "admin"],
        "reviewPrompt": """## 访问控制审查清单
- [ ] 用户/资源 ID 是否来自请求参数（非 session 绑定）→ IDOR 风险
- [ ] 管理/特权端点是否有鉴权注解/中间件（@Roles, @PreAuthorize, middleware）
- [ ] 数据库查询是否按当前用户过滤（WHERE user_id = ?），而非仅靠 URL 参数
- [ ] 水平越权：同角色用户能否通过修改 ID 访问他人数据
- [ ] 垂直越权：低权限用户能否访问管理功能

## 不报告的情况
- 框架全局鉴权拦截器已覆盖（如 Spring Security filter chain 无例外）
- 端点明确设计为公开（如登录、注册、公开 API）
- 使用了成熟的鉴权框架且配置正确（如 Spring Security, Passport.js）""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "high",
    },
    {
        "id": "bootstrap-config",
        "name": "初始化与配置",
        "description": "关注初始化管理员、开发开关、默认凭据和危险默认值。",
        "version": "1.0.0",
        "tags": ["security", "configuration", "owasp-a05", "hardcoded"],
        "triggers": ["配置", "初始化", "setup", "init", "config", "secret", "cors"],
        "reviewPrompt": """## 初始化与配置审查清单
- [ ] DEBUG / DEV 模式是否在生产环境开启
- [ ] 是否存在硬编码默认密码或初始管理员凭据
- [ ] CORS 是否允许 '*' 且 allowCredentials: true
- [ ] 是否存在未清理的 setup/init/install 端点
- [ ] 错误处理是否 fail-open（异常时放行而非拒绝）
- [ ] 错误响应是否泄露堆栈/路径/DB 信息

## 不报告的情况
- DEBUG 从环境变量读取且生产环境未设置
- 默认凭据来自配置文件且有文档说明需要修改
- CORS 配置通过白名单管理且测试时临时放开""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "high",
    },
    {
        "id": "upload-storage",
        "name": "上传与存储",
        "description": "关注上传链路、路径约束、公开目录和文件托管边界。",
        "version": "1.0.0",
        "tags": ["security", "file-upload", "owasp-a03", "path-traversal"],
        "triggers": ["上传", "文件", "upload", "storage", "file", "path"],
        "reviewPrompt": """## 上传与存储审查清单
- [ ] 文件类型验证是否仅客户端（可绕过）→ 需服务端 MIME + 魔数验证
- [ ] 文件名是否直接使用用户输入（含 '../' 可路径穿越）
- [ ] 上传目录是否可通过 URL 直接访问（需在 Web 根外或禁用执行权限）
- [ ] 是否限制文件大小（防止 DoS）
- [ ] 上传 HTML/SVG 是否会导致存储型 XSS
- [ ] 是否重命名为 UUID/随机名（防止覆盖和猜测）

## 不报告的情况
- 使用白名单验证扩展名 + MIME type（双重验证）
- 上传目录配置了禁止脚本执行
- 文件重命名为服务端生成的随机名
- 上传到对象存储（S3/OSS）且不通过应用服务器""",
        "profiles": ["security", "default"],
        "priority": "medium",
    },
    {
        "id": "query-safety",
        "name": "查询与注入",
        "description": "关注原始查询、模板拼接、动态筛选和持久层输入约束。",
        "version": "1.0.0",
        "tags": ["security", "injection", "owasp-a03", "sql", "command"],
        "triggers": ["注入", "SQL", "命令执行", "query", "execute", "eval", "nosql"],
        "evidencePoints": {
            "SQL": ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION", "EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT"],
            "CMD": ["EVID_CMD_EXEC_POINT", "EVID_CMD_COMMAND_STRING_CONSTRUCTION", "EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT"],
            "NOSQL": ["EVID_NOSQL_QUERY_CONSTRUCTION", "EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE", "EVID_NOSQL_OPERATOR_INJECTION_FIELDS"],
            "LDAP": ["EVID_LDAP_EXEC_POINT", "EVID_LDAP_FILTER_STRING_CONSTRUCTION", "EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT"],
            "EXPR": ["EVID_EXPR_EVAL_ENTRY", "EVID_EXPR_EXPR_CONTROL", "EVID_EXPR_EXEC_CHAIN_ENTRY"],
        },
        "reviewPrompt": """## 注入漏洞审查清单
- [ ] SQL/NoSQL：用户输入是否直接拼接进查询字符串（非参数化）
- [ ] 命令注入：用户输入是否进入 exec() / os.system() / subprocess(shell=True) / Runtime.exec()
- [ ] 模板注入：用户输入是否进入模板引擎渲染上下文（非数据上下文）
- [ ] LDAP/XPATH：用户输入是否进入查询过滤器字符串
- [ ] 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记

## 不报告的情况
- 使用参数化查询（JDBC PreparedStatement / ORM 安全方法 / Mongoose schema validation）
- 使用 subprocess.run([...]) 参数数组（非 shell 字符串）
- 使用白名单 + 类型强校验过滤用户输入
- 框架自带的自动转义已生效""",
        "profiles": ["security", "default", "sensitive", "extreme"],
        "priority": "critical",
    },
    {
        "id": "secret-exposure",
        "name": "敏感信息",
        "description": "关注公开前端变量、配置文件中的密钥和占位凭据。",
        "version": "1.0.0",
        "tags": ["security", "secrets", "owasp-a02", "data-leak"],
        "triggers": ["密钥", "密码", "敏感", "secret", "password", "token", "api"],
        "reviewPrompt": """## 敏感信息审查清单
- [ ] 硬编码密钥：password / api_key / secret / token / private_key 在源文件中
- [ ] 日志输出：是否打印 token、密码、请求体全量 JSON
- [ ] 前端存储：localStorage/sessionStorage 是否存储 token 或敏感数据
- [ ] 错误响应：是否泄露堆栈路径、DB 结构、内部 IP
- [ ] 数据库连接串是否含明文密码

## 不报告的情况
- 值从环境变量/密钥管理服务读取（process.env.SECRET, os.getenv()）
- 明显的占位符/示例值（YOUR_API_KEY, changeme, test_）
- 代码中的公钥、client_id（这些天然公开）
- 仅变量名为 secret/token 但值来自外部配置""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "high",
    },
    {
        "id": "business-logic",
        "name": "业务逻辑",
        "description": "关注竞态条件、Mass Assignment、状态机验证、多租户隔离等业务逻辑漏洞。",
        "version": "1.0.0",
        "tags": ["security", "business-logic", "owasp-a07"],
        "triggers": ["业务逻辑", "竞态", "状态机", "mass assignment", "race condition", "并发"],
        "reviewPrompt": """## 业务逻辑审查清单
- [ ] 竞态条件：余额/库存/优惠券操作是否缺乏原子性（无锁、无 SELECT FOR UPDATE）
- [ ] Mass Assignment：请求体是否可批量绑定敏感字段（如 role, isAdmin, balance）
- [ ] 状态机：订单/支付/审批状态跳转是否校验了前置状态合法性
- [ ] 多租户：跨租户数据访问是否仅靠 URL 参数过滤（无 session 绑定校验）
- [ ] 幂等性：支付/扣款接口是否有防重复提交机制

## 不报告的情况
- 使用乐观锁（@Version / version 字段）或悲观锁（SELECT FOR UPDATE）
- DTO 显式声明允许字段（@JsonProperty(access=READ_ONLY) / 白名单绑定）
- 状态机使用枚举 + 合法转换表校验
- 租户 ID 从 JWT/session 中提取（非请求参数）""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "high",
    },
    {
        "id": "config-audit",
        "name": "配置审计",
        "description": "关注配置文件中的安全基线、认证配置、加密配置和安全开关。",
        "version": "1.0.0",
        "tags": ["security", "configuration", "owasp-a05", "secure-config"],
        "triggers": ["配置", "config", "application", "settings", "properties", "yml", "yaml"],
        "reviewPrompt": """## 配置文件审查清单
- [ ] 明文密码/密钥在配置文件中
- [ ] DEBUG=True / debug:true / NODE_ENV=development 在生产配置中
- [ ] CORS allowOrigins:* 且 allowCredentials:true
- [ ] CSRF 保护被显式禁用
- [ ] Session cookie 缺少 Secure / HttpOnly / SameSite 标志
- [ ] 日志级别设为 DEBUG/TRACE（泄露敏感信息）
- [ ] TLS 版本 < 1.2 / 弱密码套件

## 不报告的情况
- 值从 $ENV_VAR 或环境变量引用（非字面量）
- 开发/测试配置文件（application-dev.yml, .env.example）
- 已使用配置加密方案""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "high",
    },
    {
        "id": "supply-chain",
        "name": "供应链安全",
        "description": "关注第三方依赖库的已知漏洞、版本更新和安全配置。",
        "version": "1.0.0",
        "tags": ["security", "supply-chain", "dependencies", "cve", "owasp-a06"],
        "triggers": ["依赖", "package", "npm", "maven", "pip", "cve", "漏洞", "版本"],
        "reviewPrompt": """## 供应链安全审查清单
- [ ] 依赖是否有已知 CVE（检查版本号是否在受影响范围内）
- [ ] 是否依赖已废弃/不再维护的包
- [ ] 是否有版本锁定文件（package-lock.json / go.sum / Pipfile.lock）
- [ ] 是否有未审核的第三方脚本/SDK 直接引入

## 不报告的情况
- 版本号已包含安全补丁（需确认 CVE 的 fixed version）
- 依赖仅用于开发/测试（devDependencies / test scope）
- 使用内部私有包且有安全审计流程""",
        "profiles": ["security", "default", "sensitive"],
        "priority": "medium",
    },
    {
        "id": "crypto-audit",
        "name": "加密审计",
        "description": "关注密钥管理、密码算法强度、随机数生成和TLS配置。",
        "version": "1.0.0",
        "tags": ["security", "cryptography", "encryption", "owasp-a02", "secure-crypto"],
        "triggers": ["加密", "密钥", "crypto", "hash", "aes", "rsa", "ssl", "tls"],
        "reviewPrompt": """## 加密安全审查清单
- [ ] 弱哈希：MD5 / SHA1 用于密码存储或完整性校验
- [ ] 弱加密：DES / 3DES / RC4 / ECB 模式
- [ ] 密钥长度不足：AES < 256, RSA < 2048, EC < 256
- [ ] 非加密安全随机：Math.random() / Random() / rand() 用于 token/密钥生成
- [ ] 密钥硬编码在源代码或配置文件中
- [ ] TLS < 1.2 / 自签名证书 / 弱密码套件

## 不报告的情况
- MD5/SHA1 用于非安全场景（如文件去重 hash、缓存 key）
- 加密密钥从 KMS/Vault/HSM 获取
- 使用 crypto.randomBytes() / SecureRandom / secrets 模块
- 密码使用 bcrypt/scrypt/argon2 哈希""",
        "profiles": ["security", "sensitive", "extreme"],
        "priority": "high",
    },
    {
        "id": "gbt-code-audit",
        "name": "GB/T 国标代码安全审计",
        "description": "基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计。",
        "version": "1.0.0",
        "tags": ["security", "gbt", "national-standard", "multi-language", "compliance"],
        "triggers": ["国标", "GB/T", "合规", "安全审计", "代码审计", "漏洞检测", "security audit"],
        "evidencePoints": {
            "CMD": ["EVID_CMD_EXEC_POINT", "EVID_CMD_COMMAND_STRING_CONSTRUCTION", "EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT"],
            "SQL": ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION", "EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT"],
            "FILE": ["EVID_FILE_WRAPPER_PREFIX", "EVID_FILE_RESOLVED_TARGET", "EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY"],
            "WRITE": ["EVID_WRITE_WRITE_CALLSITE", "EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION", "EVID_WRITE_DESTPATH_RESOLVED_TARGET"],
            "UPLOAD": ["EVID_UPLOAD_DESTPATH", "EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE", "EVID_UPLOAD_ACCESSIBILITY_PROOF"],
            "SSRF": ["EVID_SSRF_URL_NORMALIZATION", "EVID_SSRF_FINAL_URL_HOST_PORT", "EVID_SSRF_DNSIP_AND_INNER_BLOCK"],
            "XSS": ["EVID_XSS_OUTPUT_POINT", "EVID_XSS_USER_INPUT_INTO_OUTPUT", "EVID_XSS_ESCAPE_OR_RAW_CONTROL"],
            "XXE": ["EVID_XXE_PARSER_CALL", "EVID_XXE_INPUT_SOURCE", "EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO"],
            "DESER": ["EVID_DESER_CALLSITE", "EVID_DESER_INPUT_SOURCE", "EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN"],
            "AUTH": ["EVID_AUTH_PATH_PROTECTED_MATCH", "EVID_AUTH_TOKEN_DECODE_JUDGMENT", "EVID_AUTH_PERMISSION_CHECK_EXEC"],
            "CSRF": ["EVID_CSRF_STATE_CHANGE_HANDLER_EXEC", "EVID_CSRF_TOKEN_SOURCE", "EVID_CSRF_TOKEN_VERIFY"],
        },
        "reviewPrompt": """## GB/T 国标代码安全审计清单
标准依据：GB/T 34943(C/C++) / GB/T 34944(Java) / GB/T 34946(C#) / GB/T 39412-2020

### 必须检测（按标准条款）
- [ ] 命令注入 (GB/T34944-6.1.1.6)：用户输入进入 exec/system/popen
- [ ] SQL注入 (GB/T34944-6.1.2.1)：字符串拼接构建查询
- [ ] 代码注入 (GB/T34944-6.1.1.7)：eval/exec/pickle/yaml.load 接收用户数据
- [ ] 路径遍历 (GB/T34944-6.2.1.3)：文件路径含用户可控输入
- [ ] 硬编码密钥 (GB/T34944-6.3.2.1)：password/secret/key 明文
- [ ] 弱加密 (GB/T34944-6.3.3.1)：MD5/SHA1/DES/3DES/RC4
- [ ] 反序列化 (GB/T34944-6.1.3.2)：不可信数据反序列化
- [ ] SSRF (GB/T39412-6.4)：用户输入进入 HTTP 请求 URL
- [ ] XXE (GB/T39412-6.5)：XML 解析未禁用外部实体
- [ ] 认证绕过 (GB/T34944-6.3.1.2)
- [ ] XSS (GB/T39412-6.1.1.3)
- [ ] CSRF (GB/T39412-6.1.2.3)

### 关键判定规则
- 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记
- 输出要求：每个发现必须包含 gbtMapping, cvssScore, confidence, evidenceLabel

### 不报告的情况
- 使用框架安全 API 且配置正确
- 安全测试用例 / 示例代码 / 文档中的代码片段""",
        "profiles": ["security", "default", "sensitive", "extreme", "portability"],
        "priority": "critical",
        "gbtStandards": {
            "GB/T34943-2017": "C/C++ 语言源代码漏洞测试规范",
            "GB/T34944-2017": "Java 语言源代码漏洞测试规范",
            "GB/T34946-2017": "C# 语言源代码漏洞测试规范",
            "GB/T39412-2020": "信息安全技术 代码安全审计规范",
        },
        "supportedLanguages": ["java", "python", "cpp", "csharp", "go", "javascript", "typescript", "php", "ruby", "rust"],
    },
]

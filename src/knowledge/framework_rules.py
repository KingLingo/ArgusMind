# -*- coding: utf-8 -*-
"""框架安全规则与语言适配器 —— 整合自 gbt-codeagent。

包含：框架特定漏洞规则（framework-rules/*.yaml）、
语言安全控制适配器（language_adapters/*.yaml）、
框架配置路径、路由注解、危险模式等。

数据来源：
- gbt-codeagent/config/framework-rules/express.yaml, django.yaml
- gbt-codeagent/config/language_adapters/python.yaml, java.yaml, javascript.yaml, go.yaml, php.yaml
"""

from typing import Any, Dict, List


# ═══════════════════════════════════════════════════════════════
# 第一部分：框架特定漏洞规则
# ═══════════════════════════════════════════════════════════════

FRAMEWORK_RULES: Dict[str, Dict[str, Any]] = {
    "django": {
        "name": "Django",
        "languages": ["python"],
        "indicators": ["from django", "import django", "@app.route"],
        "specificVulnerabilities": [
            {
                "id": "django-sql-injection",
                "description": "Django ORM 不安全使用",
                "patterns": [r"extra\s*\(", r"raw\s*\(", r"\.objects\.raw\s*\("],
                "remediation": "使用 Django ORM 的参数化查询",
            },
            {
                "id": "django-ssti",
                "description": "模板注入",
                "patterns": [r"Template\s*\(\s*request\.", r"render_to_string\s*\([^,]*request\."],
                "remediation": "避免用户输入直接进入模板",
            },
        ],
    },
    "express": {
        "name": "Express.js",
        "languages": ["javascript"],
        "indicators": [r"require\s*\(\s*['\"]express['\"]\)", r"from\s+['\"]express['\"]"],
        "specificVulnerabilities": [
            {
                "id": "express-nosql-injection",
                "description": "NoSQL 注入",
                "patterns": [r"findOne\s*\([^)]*\+\s*[^)]*\)", r"findById\s*\([^)]*req\."],
                "remediation": "验证和清理用户输入，使用参数化查询",
            },
            {
                "id": "express-route-traversal",
                "description": "路由遍历",
                "patterns": [r"res\.sendFile\s*\([^)]*\+\s*"],
                "remediation": "使用路径安全函数，避免用户控制的文件路径",
            },
        ],
    },
    "spring": {
        "name": "Spring Framework",
        "languages": ["java"],
        "indicators": ["@Controller", "@RestController", "@RequestMapping", "SpringBootApplication"],
        "specificVulnerabilities": [
            {
                "id": "spring-sqli",
                "description": "Spring JDBC SQL注入",
                "patterns": [r"JdbcTemplate.*\+\s*", r"createQuery\s*\(\s*.*\+"],
                "remediation": "使用 NamedParameterJdbcTemplate 或参数化查询",
            },
            {
                "id": "spring-ssti",
                "description": "SpEL 表达式注入",
                "patterns": [r"parseExpression\s*\(", r"StandardEvaluationContext"],
                "remediation": "使用 SimpleEvaluationContext 替代 StandardEvaluationContext",
            },
            {
                "id": "spring4shell",
                "description": "Spring4Shell RCE (CVE-2022-22965)",
                "patterns": [r"class\.module\.classLoader"],
                "remediation": "升级 Spring Framework 到 5.3.18+，禁止 class 属性绑定",
            },
        ],
    },
    "flask": {
        "name": "Flask",
        "languages": ["python"],
        "indicators": ["from flask", "import flask", "Flask(__name__)"],
        "specificVulnerabilities": [
            {
                "id": "flask-ssti",
                "description": "Jinja2 模板注入",
                "patterns": [r"render_template_string\s*\([^)]*request\.", r"Template\s*\([^)]*request\."],
                "remediation": "使用 render_template 而非 render_template_string",
            },
        ],
    },
    "fastapi": {
        "name": "FastAPI",
        "languages": ["python"],
        "indicators": ["from fastapi", "FastAPI()"],
        "specificVulnerabilities": [
            {
                "id": "fastapi-injection",
                "description": "依赖注入参数验证不足",
                "patterns": [r"Depends\s*\([^)]*\)", r"Query\s*\([^)]*\+\s*"],
                "remediation": "使用 Pydantic 模型验证所有输入参数",
            },
        ],
    },
    "laravel": {
        "name": "Laravel",
        "languages": ["php"],
        "indicators": ["use Illuminate", "artisan", "Route::"],
        "specificVulnerabilities": [
            {
                "id": "laravel-mass-assignment",
                "description": "Mass Assignment 批量赋值漏洞",
                "patterns": [r"create\s*\(\s*request\->all", r"update\s*\(\s*request\->all"],
                "remediation": "在 Model 中定义 $fillable 或 $guarded 属性",
            },
        ],
    },
    "mybatis": {
        "name": "MyBatis",
        "languages": ["java"],
        "indicators": ["mybatis", "Mapper.xml", "@Mapper"],
        "specificVulnerabilities": [
            {
                "id": "mybatis-sqli-dollar",
                "description": "MyBatis ${} 不安全拼接",
                "patterns": [r"\$\{[^}]+\}"],
                "remediation": "使用 #{} 参数化占位符替代 ${} 字符串拼接",
            },
            {
                "id": "mybatis-orderby-injection",
                "description": "OrderBy 注入",
                "patterns": [r"getOrderBy\s*\(", r"getSortField\s*\(", r"sql.*append.*order"],
                "remediation": "使用白名单验证排序字段",
            },
        ],
    },
    "gin": {
        "name": "Gin",
        "languages": ["go"],
        "indicators": ["gin.Default()", "gin.New()", "gin.Engine"],
        "specificVulnerabilities": [
            {
                "id": "gin-path-traversal",
                "description": "Gin 路径遍历",
                "patterns": [r"c\.File\s*\([^)]*\+", r"c\.DataFromReader"],
                "remediation": "使用 filepath.Clean 规范化路径",
            },
        ],
    },
    "koa": {
        "name": "Koa",
        "languages": ["javascript"],
        "indicators": ["require('koa')", "from 'koa'", "new Koa()"],
        "specificVulnerabilities": [
            {
                "id": "koa-body-injection",
                "description": "Koa Body 解析注入",
                "patterns": [r"ctx\.request\.body", r"ctx\.params"],
                "remediation": "对所有 body/params 输入做验证和清理",
            },
        ],
    },
    "nest_fastify": {
        "name": "NestJS / Fastify",
        "languages": ["typescript", "javascript"],
        "indicators": ["@nestjs/common", "@Controller()", "fastify"],
        "specificVulnerabilities": [
            {
                "id": "nest-guards-missing",
                "description": "缺少 Guard 保护的路由",
                "patterns": [r"@Controller\(\)[^@]*@(Get|Post|Put|Delete)"],
                "remediation": "在 Controller 或路由方法上添加 @UseGuards",
            },
        ],
    },
    "rails": {
        "name": "Ruby on Rails",
        "languages": ["ruby"],
        "indicators": ["ActiveRecord::Base", "ApplicationController", "rails"],
        "specificVulnerabilities": [
            {
                "id": "rails-sqli",
                "description": "Rails SQL 注入",
                "patterns": [r"\.where\(.*#\{", r"\.order\(.*params", r"\.find_by_sql"],
                "remediation": "使用参数化查询 .where(name: ?, value)",
            },
            {
                "id": "rails-mass-assignment",
                "description": "批量赋值",
                "patterns": [r"params\.require\(:\w+\)\.permit!"],
                "remediation": "明确列出 permit 允许的字段",
            },
        ],
    },
    "rust_web": {
        "name": "Rust Web (Actix/Axum/Rocket)",
        "languages": ["rust"],
        "indicators": ["actix_web", "axum", "rocket", "#[get(", "#[post("],
        "specificVulnerabilities": [
            {
                "id": "rust-unsafe-block",
                "description": "unsafe 块中的内存安全问题",
                "patterns": [r"unsafe\s*\{"],
                "remediation": "审查 unsafe 块，确保内存安全不变量",
            },
        ],
    },
    "dotnet": {
        "name": ".NET / ASP.NET",
        "languages": ["csharp"],
        "indicators": ["Microsoft.AspNetCore", "ControllerBase", "[HttpGet]"],
        "specificVulnerabilities": [
            {
                "id": "dotnet-sqli",
                "description": "ASP.NET SQL 注入",
                "patterns": [r"FromSqlRaw\(", r"ExecuteSqlRaw\(", r"string\.Format.*SELECT"],
                "remediation": "使用参数化查询 FromSqlInterpolated 或 EF Core LINQ",
            },
            {
                "id": "dotnet-deserialization",
                "description": ".NET 反序列化",
                "patterns": [r"BinaryFormatter", r"LosFormatter", r"NetDataContractSerializer"],
                "remediation": "使用 JsonSerializer 或 MessagePack 等安全序列化器",
            },
        ],
    },
    "java_web": {
        "name": "Java Web 通用",
        "languages": ["java"],
        "indicators": ["javax.servlet", "jakarta.servlet", "HttpServlet"],
        "specificVulnerabilities": [
            {
                "id": "java-servlet-injection",
                "description": "Servlet 直接使用请求参数",
                "patterns": [r"request\.getParameter\(.*\+.*Statement", r"doGet|doPost.*getParameter"],
                "remediation": "对所有请求参数做验证，使用 PreparedStatement",
            },
        ],
    },
}


# ═══════════════════════════════════════════════════════════════
# 第二部分：语言安全控制适配器
# ═══════════════════════════════════════════════════════════════

LANGUAGE_ADAPTERS: Dict[str, Dict[str, Any]] = {
    "python": {
        "file_extensions": [".py"],
        "control_patterns": {
            "authentication": {
                "jwt": ["JWT|PyJWT|jwt\\.encode|jwt\\.decode", "create_access_token|create_refresh_token"],
                "session": ["session[.user.]", "flask.session|request.session", "login_user|logout_user|login_required"],
                "oauth": ["OAuth2|OAuth2PasswordBearer", "client_id|client_secret"],
            },
            "authorization": {
                "decorators": ["@login_required|@auth_required", "@roles_required|@permissions_required"],
                "rbac": ["has_role(|has_permission(", "is_admin(|is_superuser"],
                "ownership": ["user_id.*=.*request.user", "filter.*user_id|exclude.*user_id"],
            },
            "csrf_protection": {
                "flask": ["CSRFProtect|csrf.exempt", "wtforms|FlaskForm"],
                "django": ["@csrf_protect|csrf_exempt", "ensure_csrf_cookie|get_csrf_token"],
            },
            "input_validation": {
                "pydantic": ["BaseModel|Field(|validator", "@validate|@root_validator"],
                "marshmallow": ["Schema|fields.", "@validates|validates_schema"],
                "django": ["forms.Form|ModelForm", "cleaned_data|is_valid"],
            },
            "sql_protection": {
                "orm": ["SQLAlchemy|Model|session.query", "filter(|filter_by(|get(|first("],
                "parameterized": ["execute(.*,%|execute(.*,\\s*\\["],
            },
            "xss_protection": {
                "escaping": ["escape|html.escape|cgi.escape", "markupsafe|MarkupSafe"],
                "sanitization": ["bleach.clean|bleach.sanitize"],
                "template": ["jinja2|Jinja2Templates", "render_template|render_template_string"],
            },
            "path_traversal": {
                "safe_join": ["os.path.join|pathlib.Path", "abspath|realpath|normpath"],
                "validation": ["validate_file_path|sanitize_path"],
            },
        },
    },
    "java": {
        "file_extensions": [".java"],
        "control_patterns": {
            "authentication": {
                "spring_security": [
                    "@PreAuthorize.*isAuthenticated", "@Secured",
                    "SecurityContextHolder.getContext().getAuthentication()",
                    "Principal principal", "@AuthenticationPrincipal",
                ],
                "shiro": ["SecurityUtils.getSubject()", "subject.isAuthenticated()", "@RequiresAuthentication"],
                "jwt": ["JwtAuthenticationFilter", "parseToken|validateToken", "Jwts.parser"],
            },
            "authorization": {
                "spring_security": ["@PreAuthorize", "@PostAuthorize", "@RolesAllowed", "hasRole(|hasAuthority("],
                "shiro": ["@RequiresRoles", "@RequiresPermissions", "subject.isPermitted("],
                "custom": ["checkPrivilege|hasPrivilege", "isAdmin(|isManager("],
            },
            "csrf_protection": {
                "spring": ["csrf().disable()", "CsrfToken", "_csrf", "X-CSRF-TOKEN"],
            },
            "input_validation": {
                "java_validation": ["@Valid", "@Validated", "@NotNull|@NotEmpty|@NotBlank", "@Size|@Min|@Max"],
            },
            "parameterized_query": {
                "patterns": ["PreparedStatement", "@Param(", "createQuery.*setParameter", "JdbcTemplate.*?"],
            },
        },
        "dangerous_patterns": {
            "command_exec": ["Runtime.getRuntime().exec", "ProcessBuilder"],
            "sql_injection_risk": ["Statement.executeQuery", "createStatement()", "${.*}", "createQuery.*(.*\\+"],
            "deserialization": ["ObjectInputStream", "readObject()", "XMLDecoder", "XStream.fromXML"],
            "xxe": ["DocumentBuilderFactory.newInstance", "SAXParserFactory.newInstance", "XMLInputFactory.newInstance"],
            "ssrf": ["HttpURLConnection", "RestTemplate", "WebClient", "URL.*=.*new URL"],
            "code_exec": ["ScriptEngine.eval", "GroovyShell", "parseExpression", "StandardEvaluationContext"],
        },
        "route_annotations": {
            "spring_mvc": ["@Controller", "@RestController", "@RequestMapping", "@GetMapping", "@PostMapping"],
            "jax_rs": ["@Path", "@GET", "@POST", "@PathParam", "@QueryParam"],
            "servlet": ["@WebServlet", "HttpServlet", "doGet", "doPost"],
            "struts2": ["ActionSupport", "@Action", "@Result"],
        },
        "framework_configs": {
            "spring_boot": {
                "config_files": ["application.yml", "application.properties", "SecurityConfig.java"],
                "security_location": "**/security/**",
                "controller_location": "**/controller/**",
            },
            "shiro": {
                "config_files": ["shiro.ini", "ShiroConfig.java", "shiro-spring.xml"],
            },
            "mybatis": {
                "config_files": ["mybatis-config.xml", "*Mapper.xml"],
                "mapper_location": "**/mapper/**",
            },
        },
    },
    "javascript": {
        "file_extensions": [".js", ".jsx", ".ts", ".tsx"],
        "control_patterns": {
            "authentication": {
                "jwt": ["jsonwebtoken|jwt-simple|jose", "sign(|verify(|decode(", "JwtService|JWTModule"],
                "session": ["express-session|cookie-session", "req.session|session.user", "passport|PassportStrategy"],
                "oauth": ["OAuth2Client|google-auth-library", "passport-oauth2|passport-jwt"],
            },
            "authorization": {
                "decorators": ["@UseGuards|@AuthGuard", "@Roles|@Role|@RolesAllowed"],
                "middleware": ["isAuthenticated|ensureAuthenticated", "checkRole|hasRole|requireRole"],
            },
            "csrf_protection": {
                "express": ["csurf|csrf-protection", "csrfToken|req.csrfToken"],
            },
            "input_validation": {
                "class_validator": ["@IsString|@IsNumber|@IsBoolean", "@IsEmail|@IsUrl|@IsUUID"],
                "joi": ["Joi.object|Joi.string|Joi.number"],
                "zod": ["z.object|z.string|z.number", "parse(|safeParse("],
            },
            "sql_protection": {
                "orm": ["Sequelize|Model.find|Model.findOne", "where(|include(|order("],
                "prisma": ["PrismaClient|prisma.", "findUnique|findMany|create"],
                "typeorm": ["Repository|EntityManager", "createQueryBuilder|getRepository"],
            },
            "xss_protection": {
                "escaping": ["DOMPurify|sanitize-html", "escapeHtml|htmlEscape"],
                "react": ["dangerouslySetInnerHTML"],
            },
        },
    },
    "go": {
        "file_extensions": [".go"],
        "control_patterns": {
            "authentication": {
                "jwt": ["jwt.NewWithClaims|jwt.Parse", "jwt-go|go-jwt-middleware"],
                "session": ["gorilla/sessions|scs/v2", "SessionStore|LoadAndSave"],
                "oauth": ["golang.org/x/oauth2", "oauth2.Config|oauth2.Token"],
            },
            "authorization": {
                "middleware": ["AuthMiddleware|RequireAuth", "RequireRole|HasRole"],
            },
            "input_validation": {
                "validator": ['validator.Validate|ValidateStruct', 'binding:"|validate:"'],
            },
            "sql_protection": {
                "orm_gorm": ["gorm.DB|db.Where", "Find(|First(|Take("],
                "sqlx": ["sqlx.DB|sqlx.Named", "Get(|Select(|Exec("],
            },
            "xss_protection": {
                "escaping": ["html.EscapeString|html.UnescapeString", "template.HTMLEscape"],
                "sanitization": ["bluemonday.Sanitize"],
            },
        },
    },
    "php": {
        "file_extensions": [".php"],
        "control_patterns": {
            "authentication": {
                "session": ["session_start", "session_regenerate_id", "$_SESSION"],
                "jwt": ["Firebase\\JWT\\JWT", "JWT::encode", "JWT::decode"],
                "form_login": ["password_verify", "password_hash", "Auth::attempt", "Auth::check"],
            },
            "authorization": {
                "rbac": ["Gate::allows", "Gate::denies", "@can", "@cannot"],
                "role_based": ["hasRole", "hasAnyRole", "isAdmin"],
            },
            "csrf": {
                "laravel": ["@csrf", "csrf_field", "csrf_token", "VerifyCsrfToken"],
            },
            "input_validation": {
                "laravel": ["Validator::make", "->validate"],
                "general": ["filter_var", "filter_input", "htmlspecialchars"],
            },
            "xss_protection": {
                "output": ["htmlspecialchars", "htmlentities", "strip_tags"],
                "template": ["Blade::escape", "e("],
            },
        },
        "dangerous_patterns": {
            "command_execution": ["exec(", "system(", "shell_exec(", "passthru(", "pcntl_exec(", "proc_open("],
            "sql_injection": ["mysql_query(", "mysqli_query(", "pdo->query("],
            "file_operations": ["fopen(", "file_get_contents(", "file_put_contents(", "unlink("],
            "unserialize": ["unserialize("],
            "info_disclosure": ["phpinfo(", "var_dump(", "print_r("],
        },
        "framework_configs": {
            "Laravel": {
                "config_files": ["config/app.php", "config/auth.php", "config/session.php"],
                "security_location": "app/Http/Middleware/",
                "controller_location": "app/Http/Controllers/",
                "action_location": "routes/",
            },
            "Symfony": {
                "config_files": ["config/packages/security.yaml", "config/packages/cors.yaml"],
                "security_location": "src/Security/",
                "controller_location": "src/Controller/",
            },
        },
        "route_annotations": {
            "Laravel": ["Route::get", "Route::post", "Route::put", "Route::delete"],
            "Symfony": ["@Route"],
            "Yii": ["public function action"],
        },
    },
}


# ═══════════════════════════════════════════════════════════════
# 第三部分：查询工具函数
# ═══════════════════════════════════════════════════════════════

def detect_framework(code: str, language: str = "") -> List[str]:
    """检测代码使用的框架。"""
    detected = []
    for fw_id, fw_data in FRAMEWORK_RULES.items():
        if language and language.lower() not in [l.lower() for l in fw_data.get("languages", [])]:
            continue
        for indicator in fw_data.get("indicators", []):
            import re
            try:
                if re.search(indicator, code, re.IGNORECASE):
                    detected.append(fw_id)
                    break
            except re.error:
                if indicator in code:
                    detected.append(fw_id)
                    break
    return detected


def get_framework_vulns(framework_id: str) -> List[Dict[str, Any]]:
    """获取框架的特定漏洞规则。"""
    fw = FRAMEWORK_RULES.get(framework_id, {})
    return fw.get("specificVulnerabilities", [])


def get_language_adapter(language: str) -> Dict[str, Any]:
    """获取语言安全控制适配器。"""
    return LANGUAGE_ADAPTERS.get(language.lower(), {})


def get_control_patterns(language: str, category: str = "") -> Dict[str, Any]:
    """获取语言的安全控制模式。"""
    adapter = LANGUAGE_ADAPTERS.get(language.lower(), {})
    patterns = adapter.get("control_patterns", {})
    if category:
        return patterns.get(category, {})
    return patterns


def get_dangerous_patterns(language: str) -> Dict[str, List[str]]:
    """获取语言的危险模式列表。"""
    adapter = LANGUAGE_ADAPTERS.get(language.lower(), {})
    return adapter.get("dangerous_patterns", {})


def get_framework_configs(language: str) -> Dict[str, Any]:
    """获取语言的框架配置路径信息。"""
    adapter = LANGUAGE_ADAPTERS.get(language.lower(), {})
    return adapter.get("framework_configs", {})


def get_route_annotations(language: str) -> Dict[str, List[str]]:
    """获取语言的路由注解/装饰器。"""
    adapter = LANGUAGE_ADAPTERS.get(language.lower(), {})
    return adapter.get("route_annotations", {})


# 用于 RAG 检索的文档列表
FRAMEWORK_DOCS = []
for _fw_id, _fw_data in FRAMEWORK_RULES.items():
    _vulns = "; ".join(v.get("description", "") for v in _fw_data.get("specificVulnerabilities", []))
    FRAMEWORK_DOCS.append({
        "id": f"framework_{_fw_id}",
        "title": f"{_fw_data['name']} 框架安全规则",
        "content": f"{_fw_data['name']} ({', '.join(_fw_data.get('languages', []))}): {_vulns}",
        "tags": [_fw_id, "framework"] + _fw_data.get("languages", []),
        "category": "framework_rule",
    })

for _lang, _adapter in LANGUAGE_ADAPTERS.items():
    _categories = list(_adapter.get("control_patterns", {}).keys())
    _dangerous = list(_adapter.get("dangerous_patterns", {}).keys())
    FRAMEWORK_DOCS.append({
        "id": f"adapter_{_lang}",
        "title": f"{_lang} 安全控制适配器",
        "content": f"控制类别: {', '.join(_categories)}; 危险模式: {', '.join(_dangerous)}",
        "tags": [_lang, "language_adapter"],
        "category": "language_adapter",
    })

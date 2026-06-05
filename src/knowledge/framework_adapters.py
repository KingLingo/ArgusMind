# -*- coding: utf-8 -*-
"""框架安全控制适配器 —— 整合自 config/language_adapters/*.yaml。

定义各语言生态系统中安全控制的检测模式：
- 认证（Spring Security、Shiro、JWT、Session）
- 授权（@PreAuthorize、@Secured、所有权校验）
- CSRF 保护
- 输入验证（@Valid、@NotNull、@Pattern 等）
- XSS 保护（CSP、HttpOnly、SRI）
"""

from __future__ import annotations

import re
from typing import Dict, List


# ═══════════════════════════════════════════════════════════════
# Java 安全控制适配器
# ═══════════════════════════════════════════════════════════════

JAVA_AUTH_PATTERNS = [
    # Spring Security 认证
    re.compile(r"@PreAuthorize.*isAuthenticated", re.I),
    re.compile(r"@Secured", re.I),
    re.compile(r"SecurityContextHolder\.getContext\(\)\.getAuthentication\(\)", re.I),
    re.compile(r"Principal\s+principal", re.I),
    re.compile(r"@AuthenticationPrincipal", re.I),
    re.compile(r"httpSecurity.*authenticated\(\)", re.I),
    re.compile(r"\.authenticated\(\)", re.I),
    re.compile(r"AuthenticationManager", re.I),
    re.compile(r"UserDetailsService", re.I),
    re.compile(r"PasswordEncoder", re.I),
    # Shiro 认证
    re.compile(r"SecurityUtils\.getSubject\(\)", re.I),
    re.compile(r"subject\.isAuthenticated\(\)", re.I),
    re.compile(r"@RequiresAuthentication", re.I),
    re.compile(r"UsernamePasswordToken", re.I),
    re.compile(r"AuthenticatingRealm", re.I),
    # JWT 认证
    re.compile(r"JwtAuthenticationFilter", re.I),
    re.compile(r"parseToken|validateToken", re.I),
    re.compile(r"JwtUtils|JwtProvider", re.I),
    re.compile(r"Jwts\.parser", re.I),
    # Session 认证
    re.compile(r'session\.getAttribute\("user"\)', re.I),
    re.compile(r'session\.getAttribute\("admin"\)', re.I),
    re.compile(r"request\.getSession\(\)", re.I),
    re.compile(r"SecurityContextHolder", re.I),
]

JAVA_AUTHZ_PATTERNS = [
    # Spring Security 授权
    re.compile(r"@PreAuthorize", re.I),
    re.compile(r"@PostAuthorize", re.I),
    re.compile(r"@Secured\(['\"]ROLE_", re.I),
    re.compile(r"@RolesAllowed", re.I),
    re.compile(r"hasRole\(|hasAuthority\(", re.I),
    re.compile(r"hasPermission\(", re.I),
    re.compile(r"@EnableGlobalMethodSecurity", re.I),
    re.compile(r"AccessDecisionManager", re.I),
    re.compile(r"FilterSecurityInterceptor", re.I),
    # Shiro 授权
    re.compile(r"@RequiresRoles", re.I),
    re.compile(r"@RequiresPermissions", re.I),
    re.compile(r"subject\.isPermitted\(", re.I),
    re.compile(r"subject\.hasRole\(", re.I),
    re.compile(r"AuthorizingRealm", re.I),
    # 自定义授权
    re.compile(r"checkPrivilege|hasPrivilege", re.I),
    re.compile(r"checkPermission|hasPermission", re.I),
    re.compile(r"isAdmin\(|isManager\(", re.I),
    re.compile(r"checkAuth\(|verifyAuth\(", re.I),
    re.compile(r"checkAccess\(|validateAccess\(", re.I),
]

JAVA_OWNERSHIP_PATTERNS = [
    re.compile(r"getUserId\(\)\.equals\(", re.I),
    re.compile(r"getOwnerId\(\)\.equals\(", re.I),
    re.compile(r"userId\s*==\s*", re.I),
    re.compile(r"\.getCreatedBy\(\)\.equals\(", re.I),
    re.compile(r"belongsToUser\(|isOwner\(", re.I),
    re.compile(r"repository\.findByIdAndUserId\(", re.I),
    re.compile(r"WHERE.*user_id\s*=\s*:", re.I),
    re.compile(r"@Query.*WHERE.*userId\s*=", re.I),
    re.compile(r"findByUsernameAndId|findByUserId", re.I),
]

JAVA_CSRF_PATTERNS = [
    re.compile(r"csrf\(\)", re.I),
    re.compile(r"CsrfToken", re.I),
    re.compile(r"_csrf", re.I),
    re.compile(r"X-CSRF-TOKEN", re.I),
    re.compile(r"CsrfTokenRepository", re.I),
]

JAVA_VALIDATION_PATTERNS = [
    re.compile(r"@Valid", re.I),
    re.compile(r"@Validated", re.I),
    re.compile(r"@NotNull|@NotEmpty|@NotBlank", re.I),
    re.compile(r"@Size|@Min|@Max", re.I),
    re.compile(r"@Pattern", re.I),
    re.compile(r"@Email", re.I),
    re.compile(r"BindingResult", re.I),
]

# ═══════════════════════════════════════════════════════════════
# Python 安全控制适配器
# ═══════════════════════════════════════════════════════════════

PYTHON_AUTH_PATTERNS = [
    # Django 认证
    re.compile(r"@login_required", re.I),
    re.compile(r"@permission_required", re.I),
    re.compile(r"request\.user\.is_authenticated", re.I),
    re.compile(r"authenticate\s*\(", re.I),
    re.compile(r"login\s*\(request", re.I),
    # Flask 认证
    re.compile(r"@login_required", re.I),
    re.compile(r"flask_login\.login_required", re.I),
    re.compile(r"current_user\.is_authenticated", re.I),
    # FastAPI 认证
    re.compile(r"Depends\s*\(\s*get_current_user", re.I),
    re.compile(r"OAuth2PasswordBearer", re.I),
    re.compile(r"Security\s*\(\s*", re.I),
    # JWT
    re.compile(r"jwt\.encode|jwt\.decode", re.I),
    re.compile(r"pyjwt\.encode|pyjwt\.decode", re.I),
]

PYTHON_CSRF_PATTERNS = [
    re.compile(r"csrf_protect", re.I),
    re.compile(r"{% csrf_token %}", re.I),
    re.compile(r"csrf_token", re.I),
]

PYTHON_VALIDATION_PATTERNS = [
    re.compile(r"@validator|@field_validator", re.I),
    re.compile(r"@root_validator", re.I),
    re.compile(r"Field\s*\(\s*.*regex", re.I),
    re.compile(r"Field\s*\(\s*.*gt=|Field\s*\(\s*.*lt=", re.I),
    re.compile(r"Field\s*\(\s*.*max_length", re.I),
]

# ═══════════════════════════════════════════════════════════════
# JavaScript/TypeScript 安全控制适配器
# ═══════════════════════════════════════════════════════════════

JS_AUTH_PATTERNS = [
    # Express/Passport
    re.compile(r"passport\.authenticate", re.I),
    re.compile(r"req\.isAuthenticated\s*\(\s*\)", re.I),
    re.compile(r"req\.user", re.I),
    re.compile(r"isAuthenticated.*middleware", re.I),
    # JWT
    re.compile(r"jsonwebtoken\.verify", re.I),
    re.compile(r"jwt\.verify", re.I),
    re.compile(r"verifyToken", re.I),
    # Auth middleware
    re.compile(r"authMiddleware|requireAuth|withAuth", re.I),
]

JS_CSRF_PATTERNS = [
    re.compile(r"csurf\s*\(", re.I),
    re.compile(r"csrfProtection\s*\(", re.I),
    re.compile(r"csrf\s*:\s*true", re.I),
]

JS_VALIDATION_PATTERNS = [
    re.compile(r"Joi\.(object|string|number|validate)", re.I),
    re.compile(r"express-validator", re.I),
    re.compile(r"zod\s*\(", re.I),
    re.compile(r"yup\s*\(", re.I),
    re.compile(r"class-validator.*@Is", re.I),
    re.compile(r"@IsString|@IsInt|@IsEmail", re.I),
]

# ═══════════════════════════════════════════════════════════════
# 通用安全头/XSS保护模式
# ═══════════════════════════════════════════════════════════════

SECURITY_HEADER_PATTERNS = [
    re.compile(r"Content-Security-Policy|contentSecurityPolicy", re.I),
    re.compile(r"X-Content-Type-Options", re.I),
    re.compile(r"X-Frame-Options", re.I),
    re.compile(r"X-XSS-Protection", re.I),
    re.compile(r"Strict-Transport-Security", re.I),
    re.compile(r"Referrer-Policy", re.I),
    re.compile(r"helmet\s*\(", re.I),
    re.compile(r"secure_headers", re.I),
]

HTTPONLY_SAMESITE_PATTERNS = [
    re.compile(r"HttpOnly.*true", re.I),
    re.compile(r"httpOnly.*true", re.I),
    re.compile(r"SameSite.*(Strict|Lax)", re.I),
    re.compile(r"sameSite.*(strict|lax)", re.I),
    re.compile(r"setSecure\s*\(\s*true", re.I),
    re.compile(r"Secure.*true", re.I),
]


# ═══════════════════════════════════════════════════════════════
# 按语言汇总
# ═══════════════════════════════════════════════════════════════

FRAMEWORK_ADAPTERS: Dict[str, Dict[str, List[re.Pattern]]] = {
    "java": {
        "auth": JAVA_AUTH_PATTERNS,
        "authz": JAVA_AUTHZ_PATTERNS,
        "ownership": JAVA_OWNERSHIP_PATTERNS,
        "csrf": JAVA_CSRF_PATTERNS,
        "validation": JAVA_VALIDATION_PATTERNS,
    },
    "python": {
        "auth": PYTHON_AUTH_PATTERNS,
        "csrf": PYTHON_CSRF_PATTERNS,
        "validation": PYTHON_VALIDATION_PATTERNS,
    },
    "javascript": {
        "auth": JS_AUTH_PATTERNS,
        "csrf": JS_CSRF_PATTERNS,
        "validation": JS_VALIDATION_PATTERNS,
    },
    "typescript": {
        "auth": JS_AUTH_PATTERNS,
        "csrf": JS_CSRF_PATTERNS,
        "validation": JS_VALIDATION_PATTERNS,
    },
    "php": {
        "auth": [
            re.compile(r"isset\s*\(\s*\$_SESSION", re.I),
            re.compile(r"session_start\s*\(", re.I),
            re.compile(r"Auth::", re.I),
            re.compile(r"auth\(\)->check", re.I),
        ],
        "csrf": [
            re.compile(r"csrf_field", re.I),
            re.compile(r"csrf_token", re.I),
        ],
        "validation": [
            re.compile(r"filter_var\s*\(", re.I),
            re.compile(r"preg_match\s*\(", re.I),
        ],
    },
}


def get_framework_patterns(language: str, category: str) -> List[re.Pattern]:
    """获取指定语言和类别的框架检测模式。"""
    return FRAMEWORK_ADAPTERS.get(language, {}).get(category, [])


def check_framework_safety(language: str, code_window: str) -> Dict[str, bool]:
    """检查代码窗口中是否存在框架级安全措施。

    Returns:
        {category: has_match}
    """
    result: Dict[str, bool] = {}
    adapters = FRAMEWORK_ADAPTERS.get(language, {})
    for category, patterns in adapters.items():
        result[category] = any(p.search(code_window) for p in patterns)
    return result

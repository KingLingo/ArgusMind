# -*- coding: utf-8 -*-
"""漏洞特征配置 —— 整合自 config/vuln-profiles/*.yaml。

每个漏洞类型 {语言: {risk: 危险模式, safe: 安全模式, severity, cwe, remediation}}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


# ═══════════════════════════════════════════════════════════════
# 漏洞特征表 {vuln_type: {meta, languages: {lang: {risk, safe, severity, remediation}}}}
# ═══════════════════════════════════════════════════════════════

VULN_PROFILES: Dict[str, Dict[str, Any]] = {
    # ── 命令注入 ──
    "COMMAND_INJECTION": {
        "cwe": "CWE-78",
        "gbt": "GB/T34943-2017, GB/T34944-2017",
        "default_severity": "CRITICAL",
        "desc": "命令注入漏洞",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"os\.system\s*\("),
                    re.compile(r"os\.popen\s*\("),
                    re.compile(r"subprocess\.(call|Popen|run)\s*\([^)]*shell\s*=\s*True"),
                ],
                "safe": [
                    re.compile(r"subprocess\.run\s*\([^,]+,\s*shell\s*=\s*False"),
                    re.compile(r"shlex\.quote\s*\("),
                ],
                "remediation": "避免使用 shell=True，使用 shlex.quote 转义用户输入",
            },
            "java": {
                "risk": [
                    re.compile(r"Runtime\.exec\s*\([^)]*\+[^)]*\)"),
                    re.compile(r"ProcessBuilder\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"new String\[\].*\)"),
                ],
                "remediation": "使用数组形式传递命令参数，避免字符串拼接",
            },
            "javascript": {
                "risk": [
                    re.compile(r"child_process\.exec\s*\([^)]*\+"),
                    re.compile(r"exec\s*\(`.*\$\{"),
                ],
                "safe": [
                    re.compile(r"execFile\s*\("),
                    re.compile(r"spawn\s*\([^,]+,\s*\["),
                ],
                "remediation": "避免使用 exec，采用 spawn/execFile 数组参数形式",
            },
            "php": {
                "risk": [
                    re.compile(r"system\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"exec\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"shell_exec\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"passthru\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"popen\s*\([^)]*\+\s*[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"escapeshellarg\s*\("),
                    re.compile(r"escapeshellcmd\s*\("),
                ],
                "remediation": "使用 escapeshellarg/escapeshellcmd 转义用户输入",
            },
            "go": {
                "risk": [
                    re.compile(r"exec\.Command\s*\([^)]*\+\s*[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"exec\.Command\s*\([^,]+,[^)]*\)"),
                ],
                "remediation": "使用数组形式传递命令参数，避免字符串拼接",
            },
            "csharp": {
                "risk": [
                    re.compile(r"Process\.Start\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"ProcessStartInfo\.Arguments\s*=\s*[^;]*\+"),
                ],
                "safe": [],
                "remediation": "显式设置 Arguments，避免字符串拼接",
            },
        },
    },

    # ── SQL 注入 ──
    "SQL_INJECTION": {
        "cwe": "CWE-89",
        "gbt": "GB/T34943-2017, GB/T34944-2017, GB/T34946-2017",
        "default_severity": "HIGH",
        "desc": "SQL 注入漏洞",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"execute\s*\([^)]*\+[^)]*\)"),
                    re.compile(r"cursor\.execute\s*\([^)]*format\s*\("),
                    re.compile(r"cursor\.execute\s*\([^)]*%[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"execute\s*\([^,]+,\s*\[.*\]\)"),
                    re.compile(r"cursor\.execute\s*\([^,]+,\s*\(.*\)\)"),
                ],
                "remediation": "使用参数化查询或 ORM",
            },
            "java": {
                "risk": [
                    re.compile(r"Statement\.executeQuery\s*\([^)]*\+[^)]*\)"),
                    re.compile(r"createStatement\(\)\.executeQuery\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"PreparedStatement"),
                    re.compile(r"\?\s*=\s*.*set\w+"),
                ],
                "remediation": "使用 PreparedStatement 参数化查询",
            },
            "javascript": {
                "risk": [
                    re.compile(r"query\s*\([^)]*\+[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"\$in\s*:\s*\["),
                ],
                "remediation": "使用参数化查询",
            },
            "php": {
                "risk": [
                    re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*?\].*?(?:SELECT|INSERT|UPDATE|DELETE)"),
                    re.compile(r"mysql_query\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"mysqli_query\s*\([^)]*\+\s*[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"\$stmt\s*=\s*\$\w+->prepare\s*\("),
                    re.compile(r"\$stmt->bind_param\s*\("),
                ],
                "remediation": "使用 PDO prepare/bind 参数化查询",
            },
        },
    },

    # ── 反序列化 ──
    "DESERIALIZATION": {
        "cwe": "CWE-502",
        "default_severity": "HIGH",
        "desc": "不安全反序列化",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"pickle\.loads?\s*\("),
                    re.compile(r"yaml\.load\s*\([^)]*\)"),
                    re.compile(r"marshal\.loads?\s*\("),
                    re.compile(r"cloudpickle\.loads\s*\("),
                    re.compile(r"shelve\.open\s*\("),
                ],
                "safe": [
                    re.compile(r"yaml\.safe_load\s*\("),
                    re.compile(r"json\.loads\s*\("),
                    re.compile(r"msgpack\.unpackb\s*\("),
                ],
                "remediation": "使用 yaml.safe_load 替代 yaml.load，使用 JSON 而非 pickle",
            },
            "java": {
                "risk": [
                    re.compile(r"ObjectInputStream"),
                    re.compile(r"readObject\s*\("),
                    re.compile(r"XMLDecoder\s*\("),
                    re.compile(r"YAML\.load\s*\("),
                    re.compile(r"XStream\.fromXML\s*\("),
                    re.compile(r"Jackson.*enableDefaultTyping"),
                ],
                "safe": [
                    re.compile(r"ObjectInputStream.*validateObject"),
                    re.compile(r"JSON\.parse"),
                    re.compile(r"ObjectMapper\.configure.*FAIL_ON_UNKNOWN_PROPERTIES"),
                ],
                "remediation": "避免原生反序列化，使用 JSON 或配置验证",
            },
            "php": {
                "risk": [
                    re.compile(r"unserialize\s*\("),
                ],
                "safe": [
                    re.compile(r"json_decode\s*\("),
                ],
                "remediation": "避免使用 unserialize，使用 json_decode",
            },
            "ruby": {
                "risk": [
                    re.compile(r"Marshal\.load\s*\("),
                    re.compile(r"YAML\.load\s*\([^)]*\)"),
                    re.compile(r"Psych\.load\s*\("),
                ],
                "safe": [
                    re.compile(r"YAML\.safe_load\s*\("),
                    re.compile(r"JSON\.parse"),
                ],
                "remediation": "使用 YAML.safe_load，避免 Marshal.load",
            },
        },
    },

    # ── XSS ──
    "XSS": {
        "cwe": "CWE-79",
        "gbt": "GB/T34946-2017",
        "default_severity": "HIGH",
        "desc": "跨站脚本攻击 (XSS)",
        "languages": {
            "javascript": {
                "risk": [
                    re.compile(r"innerHTML\s*="),
                    re.compile(r"outerHTML\s*="),
                    re.compile(r"document\.write\s*\("),
                    re.compile(r"insertAdjacentHTML"),
                    re.compile(r"dangerouslySetInnerHTML"),
                ],
                "safe": [
                    re.compile(r"textContent\s*="),
                    re.compile(r"innerText\s*="),
                    re.compile(r"createTextNode"),
                    re.compile(r"encodeURIComponent"),
                    re.compile(r"DOMPurify\.sanitize"),
                ],
                "remediation": "使用 textContent/innerText 替代 innerHTML，对用户输入进行编码",
            },
            "php": {
                "risk": [
                    re.compile(r"echo\s+\$_(GET|POST|REQUEST|COOKIE)"),
                    re.compile(r"print\s+\$_(GET|POST|REQUEST|COOKIE)"),
                ],
                "safe": [
                    re.compile(r"htmlspecialchars\s*\("),
                    re.compile(r"htmlentities\s*\("),
                ],
                "remediation": "使用 htmlspecialchars 或 htmlentities 对输出进行编码",
            },
            "csharp": {
                "risk": [
                    re.compile(r"Response\.Write\s*\([^)]*\+"),
                    re.compile(r"@Html\.Raw\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"@Model\."),
                ],
                "remediation": "使用 @Model 而非 @Html.Raw",
            },
        },
    },

    # ── 路径遍历 ──
    "PATH_TRAVERSAL": {
        "cwe": "CWE-22",
        "default_severity": "MEDIUM",
        "desc": "路径遍历漏洞",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"open\s*\("),
                    re.compile(r"os\.path\.join\s*\([^)]*request\."),
                    re.compile(r"shutil\.(copy|move)\s*\([^)]*input"),
                ],
                "safe": [
                    re.compile(r"os\.path\.realpath\s*\("),
                    re.compile(r"os\.path\.abspath\s*\("),
                    re.compile(r"pathlib\.Path\([^)]*\)\.resolve\("),
                    re.compile(r"ALLOWED_DIRS|allowed_paths|whitelist.*path"),
                ],
                "remediation": "使用 Path.resolve() 规范化路径，验证路径在允许范围内",
            },
            "java": {
                "risk": [
                    re.compile(r"new File\s*\([^)]*\+"),
                    re.compile(r"FileInputStream\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"toRealPath"),
                    re.compile(r"toPath\(\)\.\s*normalize\(\)"),
                    re.compile(r"getCanonicalPath"),
                ],
                "remediation": "使用 Path.normalize() 和 realPath() 规范化路径",
            },
            "php": {
                "risk": [
                    re.compile(r"(include|require)(_once)?\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"fopen\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"file_get_contents\s*\([^)]*\+\s*[^)]*\)"),
                    re.compile(r"readfile\s*\([^)]*\+\s*[^)]*\)"),
                ],
                "safe": [
                    re.compile(r"basename\s*\("),
                    re.compile(r"realpath\s*\("),
                    re.compile(r"in_array\s*\(\s*\$[\w]+\s*,\s*\$allowed"),
                ],
                "remediation": "使用 realpath() 规范化路径，验证文件存在且在允许范围内",
            },
        },
    },

    # ── SSRF ──
    "SSRF": {
        "cwe": "CWE-918",
        "default_severity": "HIGH",
        "desc": "服务器端请求伪造 (SSRF)",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"requests\.(get|post)\s*\([^)]*\+\s*"),
                    re.compile(r"urllib\.(request\.)?urlopen\s*\([^)]*\+"),
                    re.compile(r"http\.client\.(HTTPConnection|HTTPSConnection)"),
                ],
                "safe": [
                    re.compile(r"urlparse\s*\("),
                    re.compile(r"startswith\s*\(\s*['\"]https?://"),
                ],
                "remediation": "验证和限制 URL 协议、主机名，使用 urlparse 解析检查",
            },
            "javascript": {
                "risk": [
                    re.compile(r"fetch\s*\([^)]*\+"),
                    re.compile(r"axios\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"new URL\s*\("),
                    re.compile(r"URLSearchParams"),
                ],
                "remediation": "使用 URL 构造函数验证，确保 URL 符合预期",
            },
            "java": {
                "risk": [
                    re.compile(r"HttpURLConnection|URLConnection"),
                    re.compile(r"RestTemplate|WebClient"),
                    re.compile(r"HttpClient|CloseableHttpClient"),
                ],
                "safe": [
                    re.compile(r"URI\.create|new URI\s*\("),
                ],
                "remediation": "验证 URL 协议和主机名，使用 URI 类解析",
            },
        },
    },

    # ── 硬编码凭据 ──
    "HARD_CODE_PASSWORD": {
        "cwe": "CWE-798",
        "default_severity": "HIGH",
        "desc": "硬编码凭据/密钥",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"password\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"api_key\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"secret\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"token\s*=\s*['\"][^'\"]+['\"]"),
                ],
                "safe": [
                    re.compile(r"os\.getenv\s*\("),
                    re.compile(r"os\.environ\s*\["),
                ],
                "remediation": "使用环境变量或安全的密钥管理服务",
            },
            "java": {
                "risk": [
                    re.compile(r"password\s*=\s*\"[^\"]+\""),
                    re.compile(r"apiKey\s*=\s*\"[^\"]+\""),
                    re.compile(r"secretKey\s*=\s*\"[^\"]+\""),
                    re.compile(r"privateKey\s*=\s*\"[^\"]+\""),
                ],
                "safe": [
                    re.compile(r"System\.getenv\s*\("),
                    re.compile(r"@Value\s*\(\s*\"\$\{"),
                ],
                "remediation": "使用环境变量或密钥管理服务",
            },
            "javascript": {
                "risk": [
                    re.compile(r"const\s+(apiKey|api_key)\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"const\s+password\s*=\s*['\"][^'\"]+['\"]"),
                ],
                "safe": [
                    re.compile(r"process\.env\."),
                ],
                "remediation": "使用环境变量或配置服务",
            },
            "php": {
                "risk": [
                    re.compile(r"\$password\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"\$apiKey\s*=\s*['\"][^'\"]+['\"]"),
                    re.compile(r"define\s*\(['\"](API_KEY|SECRET|PASSWORD)\s*,\s*['\"][^'\"]+['\"]"),
                ],
                "safe": [
                    re.compile(r"getenv\s*\("),
                    re.compile(r"\$_ENV\["),
                ],
                "remediation": "使用环境变量或配置服务",
            },
            "go": {
                "risk": [
                    re.compile(r"apiKey\s*:=\s*\"[^\"]+\""),
                    re.compile(r"password\s*:=\s*\"[^\"]+\""),
                    re.compile(r"secret\s*:=\s*\"[^\"]+\""),
                    re.compile(r"token\s*:=\s*\"[^\"]+\""),
                ],
                "safe": [
                    re.compile(r"os\.Getenv\s*\("),
                ],
                "remediation": "使用环境变量或密钥管理服务",
            },
        },
    },

    # ── 弱加密 ──
    "WEAK_CRYPTO": {
        "cwe": "CWE-327",
        "default_severity": "MEDIUM",
        "desc": "使用弱加密算法",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"hashlib\.md5\s*\("),
                    re.compile(r"hashlib\.sha1\s*\("),
                    re.compile(r"Crypto\.Cipher\.DES"),
                    re.compile(r"random\.random\s*\("),
                ],
                "safe": [
                    re.compile(r"hashlib\.sha256\s*\("),
                    re.compile(r"hashlib\.sha3"),
                    re.compile(r"Crypto\.Cipher\.AES"),
                    re.compile(r"secrets\.token"),
                ],
                "remediation": "使用 SHA-256+/AES，密钥使用 secrets 模块生成",
            },
            "java": {
                "risk": [
                    re.compile(r"MD5|MessageDigest\.getInstance\(\"MD5"),
                    re.compile(r"SHA-1|MessageDigest\.getInstance\(\"SHA-1"),
                    re.compile(r"DES|Cipher\.getInstance\(\"DES"),
                    re.compile(r"ECB|Cipher\.getInstance\(.*ECB"),
                    re.compile(r"new Random\(\s*\)"),
                ],
                "safe": [
                    re.compile(r"SHA-256|SHA-512"),
                    re.compile(r"AES/GCM"),
                    re.compile(r"SecureRandom"),
                ],
                "remediation": "使用 AES-256/GCM、SHA-256+、SecureRandom",
            },
            "javascript": {
                "risk": [
                    re.compile(r"crypto\.createHash\(\s*['\"]md5"),
                    re.compile(r"crypto\.createHash\(\s*['\"]sha1"),
                    re.compile(r"Math\.random\s*\("),
                ],
                "safe": [
                    re.compile(r"crypto\.randomBytes\s*\("),
                    re.compile(r"crypto\.createHash\(\s*['\"]sha256"),
                ],
                "remediation": "使用 crypto.randomBytes、SHA-256+",
            },
        },
    },

    # ── 弱哈希 ──
    "WEAK_HASH": {
        "cwe": "CWE-328",
        "default_severity": "MEDIUM",
        "desc": "使用弱哈希算法",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"hashlib\.md5\s*\("),
                    re.compile(r"hashlib\.sha1\s*\("),
                ],
                "safe": [
                    re.compile(r"hashlib\.sha256\s*\("),
                    re.compile(r"hashlib\.sha3_512\s*\("),
                    re.compile(r"hashlib\.blake2"),
                ],
                "remediation": "使用 SHA-256 或 SHA-3 替代 MD5/SHA-1",
            },
            "java": {
                "risk": [
                    re.compile(r"MessageDigest\.getInstance\(\"MD5"),
                    re.compile(r"MessageDigest\.getInstance\(\"SHA-1"),
                ],
                "safe": [
                    re.compile(r"MessageDigest\.getInstance\(\"SHA-256"),
                    re.compile(r"MessageDigest\.getInstance\(\"SHA-512"),
                ],
                "remediation": "使用 SHA-256 或 SHA-512 替代 MD5/SHA-1",
            },
        },
    },

    # ── XXE ──
    "XXE": {
        "cwe": "CWE-611",
        "default_severity": "HIGH",
        "desc": "XML 外部实体注入 (XXE)",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"DocumentBuilderFactory\.newInstance\s*\("),
                    re.compile(r"SAXParserFactory\.newInstance\s*\("),
                    re.compile(r"XMLInputFactory\.newFactory\s*\("),
                    re.compile(r"SAXReader\s*\("),
                    re.compile(r"TransformerFactory\.newInstance\s*\("),
                ],
                "safe": [
                    re.compile(r"setFeature.*FEATURE_SECURE_PROCESSING"),
                    re.compile(r"setExpandEntityReferences\s*\(\s*false"),
                    re.compile(r"setFeature.*DISALLOW_DOCTYPE"),
                ],
                "remediation": "禁用 DTD 和外部实体解析，启用安全特性",
            },
            "python": {
                "risk": [
                    re.compile(r"etree\.parse\s*\("),
                    re.compile(r"xml\.etree\.ElementTree"),
                ],
                "safe": [
                    re.compile(r"defusedxml"),
                    re.compile(r"lxml\.etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*False"),
                ],
                "remediation": "使用 defusedxml 或设置 resolve_entities=False",
            },
        },
    },

    # ── 开放重定向 ──
    "OPEN_REDIRECT": {
        "cwe": "CWE-601",
        "default_severity": "MEDIUM",
        "desc": "开放重定向",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"redirect\s*\([^)]*request\."),
                    re.compile(r"HttpResponseRedirect\s*\([^)]*request\."),
                ],
                "safe": [
                    re.compile(r"url_has_allowed_host_and_scheme"),
                    re.compile(r"is_safe_url\s*\("),
                ],
                "remediation": "对重定向 URL 实施白名单校验",
            },
            "java": {
                "risk": [
                    re.compile(r"redirect\s*\("),
                    re.compile(r"sendRedirect\s*\("),
                ],
                "safe": [
                    re.compile(r"RedirectView\s*\(\s*[\"']/"),
                ],
                "remediation": "对重定向 URL 实施白名单校验",
            },
            "javascript": {
                "risk": [
                    re.compile(r"res\.redirect\s*\([^)]*req\."),
                    re.compile(r"window\.location\s*=\s*"),
                ],
                "safe": [
                    re.compile(r"res\.redirect\s*\(\s*[\"']/"),
                ],
                "remediation": "验证重定向 URL 是否为相对路径或白名单域名",
            },
        },
    },

    # ── CSRF ──
    "CSRF": {
        "cwe": "CWE-352",
        "default_severity": "HIGH",
        "desc": "跨站请求伪造 (CSRF)",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"csrf\(\)\.disable\(\)"),
                ],
                "safe": [
                    re.compile(r"csrf\(\)"),
                    re.compile(r"CsrfToken"),
                    re.compile(r"_csrf"),
                ],
                "remediation": "启用 CSRF 保护，使用 CSRF Token",
            },
            "python": {
                "risk": [
                    re.compile(r"csrf_exempt"),
                    re.compile(r"@csrf_exempt"),
                ],
                "safe": [
                    re.compile(r"csrf_protect"),
                    re.compile(r"{% csrf_token %}"),
                ],
                "remediation": "避免 csrf_exempt，使用 CSRF Token",
            },
        },
    },

    # ── 日志注入 ──
    "LOG_INJECTION": {
        "cwe": "CWE-117",
        "default_severity": "MEDIUM",
        "desc": "日志注入",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"log\.(info|error|warn|debug)\s*\(\s*['\"].*\+"),
                    re.compile(r"logger\.(info|error|warn|debug)\s*\(\s*['\"].*\+"),
                ],
                "safe": [
                    re.compile(r"ParameterizedLog"),
                    re.compile(r"logger\.(info|error|warn|debug)\s*\(\s*\"[^\"]*\{\}"),
                ],
                "remediation": "使用参数化日志记录，对用户输入进行换行符转义",
            },
        },
    },

    # ── 会话固定 ──
    "SESSION_FIXATION": {
        "cwe": "CWE-384",
        "default_severity": "MEDIUM",
        "desc": "会话固定",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"request\.getSession\s*\(\s*false\s*\)"),
                ],
                "safe": [
                    re.compile(r"session\.invalidate\s*\("),
                    re.compile(r"request\.changeSessionId\s*\("),
                ],
                "remediation": "登录后调用 session.invalidate() 并重新创建会话",
            },
        },
    },

    # ── JWT 漏洞 ──
    "JWT_VULNERABILITIES": {
        "cwe": "CWE-347",
        "default_severity": "HIGH",
        "desc": "JWT 签名验证不足",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"Jwts\.parser\(\)\.setSigningKey\("),
                    re.compile(r"JWT\.decode\s*\("),
                ],
                "safe": [
                    re.compile(r"Jwts\.parserBuilder\(\)\.setSigningKey\("),
                    re.compile(r"JWT\.require\s*\("),
                ],
                "remediation": "使用 parserBuilder 并指定算法，验证签名和过期时间",
            },
        },
    },

    # ── 竞态条件 ──
    "RACE_CONDITION": {
        "cwe": "CWE-362",
        "default_severity": "MEDIUM",
        "desc": "竞态条件",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"synchronized\s*\(.*\)\s*\{"),
                    re.compile(r"Thread\.sleep\s*\("),
                ],
                "safe": [
                    re.compile(r"ReentrantLock"),
                    re.compile(r"AtomicInteger|AtomicBoolean|AtomicReference"),
                    re.compile(r"@Transactional\s*\(.*isolation"),
                ],
                "remediation": "使用 ReentrantLock 或数据库事务隔离级别控制并发",
            },
        },
    },

    # ── 整数溢出 ──
    "INTEGER_OVERFLOW": {
        "cwe": "CWE-190",
        "default_severity": "MEDIUM",
        "desc": "整数溢出",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"Integer\.parseInt\s*\("),
                    re.compile(r"new\s+\w+\[.*Integer\.parseInt"),
                ],
                "safe": [
                    re.compile(r"Math\.addExact|Math\.multiplyExact"),
                ],
                "remediation": "使用 Math.addExact/Math.multiplyExact 检查溢出",
            },
        },
    },

    # ── 信息泄露 ──
    "INFORMATION_DISCLOSURE": {
        "cwe": "CWE-200",
        "default_severity": "MEDIUM",
        "desc": "敏感信息泄露",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"printStackTrace\s*\("),
                    re.compile(r"e\.getMessage\s*\(\s*\)"),
                ],
                "safe": [
                    re.compile(r"logger\.(info|error|warn)\s*\([^)]*e"),
                ],
                "remediation": "使用日志框架记录异常，避免直接向用户返回堆栈信息",
            },
        },
    },

    # ── 认证绕过 ──
    "AUTH_BYPASS": {
        "cwe": "CWE-287",
        "default_severity": "HIGH",
        "desc": "认证绕过",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"request\.getHeader\(\s*[\"']Referer[\"']"),
                    re.compile(r"request\.getHeader\(\s*[\"']referer[\"']"),
                ],
                "safe": [
                    re.compile(r"SecurityContextHolder\.getContext\(\)\.getAuthentication\(\)"),
                    re.compile(r"@PreAuthorize"),
                    re.compile(r"@Secured"),
                ],
                "remediation": "使用统一的认证中间件，避免依赖 Referer 等可伪造字段",
            },
        },
    },

    # ── CORS 配置不当 ──
    "CORS_MISCONFIGURATION": {
        "cwe": "CWE-942",
        "default_severity": "MEDIUM",
        "desc": "CORS 配置不当",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"setAllowedOrigins\s*\(\s*\*"),
                    re.compile(r"allowedOrigins\s*\(\s*\*"),
                ],
                "safe": [
                    re.compile(r"allowedOrigins\s*\(\s*[\"'][^\"']+[\"']"),
                ],
                "remediation": "明确指定允许的源，避免使用 * 通配符",
            },
            "javascript": {
                "risk": [
                    re.compile(r"Access-Control-Allow-Origin.*\*"),
                ],
                "safe": [
                    re.compile(r"Access-Control-Allow-Origin.*[\"'][^\"']+[\"']"),
                ],
                "remediation": "明确指定允许的源，避免使用 * 通配符",
            },
        },
    },

    # ── XML 注入 (XPath) ──
    "XPATH_INJECTION": {
        "cwe": "CWE-643",
        "default_severity": "HIGH",
        "desc": "XPath 注入",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"XPath\.compile\s*\([^)]*\+"),
                    re.compile(r"XPath\.evaluate\s*\([^)]*\+"),
                ],
                "safe": [
                    re.compile(r"XPath\.(setXPathVariableResolver|setXPathFunctionResolver)"),
                ],
                "remediation": "使用参数化 XPath，避免字符串拼接",
            },
        },
    },

    # ── NoSQL 注入 ──
    "NOSQL_INJECTION": {
        "cwe": "CWE-943",
        "default_severity": "HIGH",
        "desc": "NoSQL 注入",
        "languages": {
            "javascript": {
                "risk": [
                    re.compile(r"\$where\s*:"),
                    re.compile(r"\.find\s*\(\s*\{[^}]*\$"),
                    re.compile(r"\.findOne\s*\(\s*\{[^}]*\$"),
                ],
                "safe": [
                    re.compile(r"mongoose\.Types\.ObjectId"),
                    re.compile(r"santize\s*\("),
                ],
                "remediation": "对用户输入进行类型校验和清理，避免直接使用 $where",
            },
        },
    },

    # ── 代码注入 / 表达式注入 ──
    "CODE_INJECTION": {
        "cwe": "CWE-94",
        "gbt": "GB/T34944-6.1.1.6",
        "default_severity": "CRITICAL",
        "desc": "代码/表达式注入漏洞",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"eval\s*\(\s*[^)]*\+"),
                    re.compile(r"exec\s*\(\s*[^)]*\+"),
                    re.compile(r"compile\s*\(\s*[^)]*\+"),
                    re.compile(r"__import__\s*\(\s*[^)]*\+"),
                    re.compile(r"getattr\s*\([^,]*,\s*[^)]*\+"),
                ],
                "safe": [
                    re.compile(r"ast\.literal_eval\s*\("),
                    re.compile(r"json\.loads\s*\("),
                ],
                "remediation": "避免 eval/exec 执行用户输入，改用 ast.literal_eval 或 JSON 解析",
            },
            "javascript": {
                "risk": [
                    re.compile(r"eval\s*\(\s*[^)]*\+"),
                    re.compile(r"new\s+Function\s*\(\s*[^)]*\+"),
                    re.compile(r"setTimeout\s*\(\s*['\"`]"),
                    re.compile(r"setInterval\s*\(\s*['\"`]"),
                ],
                "safe": [
                    re.compile(r"Function\.prototype\.call"),
                    re.compile(r"vm2\."),
                ],
                "remediation": "避免使用 eval/Function 构造器，使用 JSON.parse 或沙箱执行",
            },
            "java": {
                "risk": [
                    re.compile(r"ScriptEngine\s*.*\.eval\s*\("),
                    re.compile(r"javax\.script\.ScriptEngine"),
                    re.compile(r"GroovyShell\s*.*\.evaluate\s*\("),
                ],
                "safe": [
                    re.compile(r"ScriptEngine.*getBindings\(ScriptContext\.ENGINE_SCOPE\)"),
                ],
                "remediation": "避免动态脚本执行，使用安全表达式引擎或限制 ScriptEngine 绑定",
            },
            "php": {
                "risk": [
                    re.compile(r"eval\s*\(\s*\$"),
                    re.compile(r"preg_replace\s*\(\s*['\"]/\w+/e"),
                    re.compile(r"assert\s*\(\s*\$"),
                    re.compile(r"create_function\s*\("),
                    re.compile(r"call_user_func\s*\(\s*\$"),
                ],
                "safe": [
                    re.compile(r"call_user_func\s*\(\s*['\"][\w:]+['\"]"),
                ],
                "remediation": "避免 eval/assert/create_function，使用 call_user_func 配合白名单",
            },
        },
    },

    # ── SPEL 表达式注入（Spring） ──
    "SPEL_INJECTION": {
        "cwe": "CWE-94",
        "gbt": "GB/T34944-6.1.1.6",
        "default_severity": "CRITICAL",
        "desc": "Spring SPEL 表达式注入",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"ExpressionParser\s*.*\."),
                    re.compile(r"SpelExpressionParser\s*\("),
                    re.compile(r"\.parseExpression\s*\("),
                    re.compile(r"@Value\s*\(\s*['\"]#\{[^}]*\+\s*"),
                ],
                "safe": [
                    re.compile(r"SimpleEvaluationContext"),
                    re.compile(r"StandardEvaluationContext.*setPropertyAccessors"),
                ],
                "remediation": "使用 SimpleEvaluationContext 而非 StandardEvaluationContext，限制表达式能力",
            },
        },
    },

    # ── JNDI 注入 ──
    "JNDI_INJECTION": {
        "cwe": "CWE-502",
        "gbt": "GB/T34944-6.1.1.6",
        "default_severity": "CRITICAL",
        "desc": "JNDI 注入（常与反序列化链组合利用）",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"InitialContext\s*\.\s*lookup\s*\("),
                    re.compile(r"Context\s*\.\s*lookup\s*\(\s*[^)]*\+"),
                    re.compile(r"ldap\s*:\s*/{2}"),
                    re.compile(r"rmi\s*:\s*/{2}"),
                    re.compile(r"jndi\s*:\s*"),
                ],
                "safe": [
                    re.compile(r"log4j2\.formatMsgNoLookups\s*=\s*true"),
                    re.compile(r"LOG4J_FORMAT_MSG_NO_LOOKUPS\s*=\s*true"),
                ],
                "remediation": "禁止来自不可信源的 JNDI lookup，设置 com.sun.jndi.ldap.object.trustURLCodebase=false",
            },
        },
    },

    # ── 模板注入（SSTI） ──
    "SSTI": {
        "cwe": "CWE-94",
        "gbt": "GB/T34944-6.1.1.6",
        "default_severity": "HIGH",
        "desc": "服务端模板注入",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"render_template_string\s*\("),
                    re.compile(r"Template\s*\([^)]*\)\.render\s*\("),
                    re.compile(r"jinja2\.Template\s*\("),
                    re.compile(r"\.from_string\s*\("),
                ],
                "safe": [
                    re.compile(r"render_template\s*\("),
                    re.compile(r"\.format\(|f['\"]"),
                ],
                "remediation": "避免使用 render_template_string 处理用户输入，使用 render_template + 静态模板",
            },
            "java": {
                "risk": [
                    re.compile(r"FreeMarker.*\.process\s*\("),
                    re.compile(r"Velocity\.(evaluate|mergeTemplate)\s*\("),
                    re.compile(r"Thymeleaf.*setProcessTemplate\s*\("),
                ],
                "safe": [
                    re.compile(r"Thymeleaf.*PREPROCESS"),
                    re.compile(r"FreeMarker.*setOutputEncoding"),
                ],
                "remediation": "使用安全模板引擎配置，禁用模板表达式执行",
            },
            "javascript": {
                "risk": [
                    re.compile(r"ejs\.render\s*\(.*\+"),
                    re.compile(r"pug\.compile\s*\(.*\+"),
                    re.compile(r"handlebars\.compile\s*\(.*\+"),
                ],
                "safe": [
                    re.compile(r"ejs\.renderFile\s*\("),
                    re.compile(r"\.locals\s*="),
                ],
                "remediation": "使用模板引擎的预编译功能，避免动态构造模板",
            },
        },
    },

    # ── 文件上传 ──
    "FILE_UPLOAD": {
        "cwe": "CWE-434",
        "gbt": "GB/T34944-6.2.7.2",
        "default_severity": "HIGH",
        "desc": "文件上传漏洞（类型校验缺失、路径穿越、Web目录写入）",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"MultipartFile\s+\w+\s*[,;)]"),
                    re.compile(r"getOriginalFilename\s*\(\s*\)"),
                    re.compile(r"\.transferTo\s*\(\s*new\s+File"),
                    re.compile(r"DiskFileItemFactory\s*\("),
                ],
                "safe": [
                    re.compile(r"Paths\.get\(.*\.normalize\(\)"),
                    re.compile(r"UUID\.randomUUID\(\)"),
                    re.compile(r"FilenameUtils\.getName\("),
                ],
                "remediation": "随机文件名 + 路径规范化 + 白名单校验类型 + 保存到 Web 根目录外",
            },
            "python": {
                "risk": [
                    re.compile(r"request\.files\["),
                    re.compile(r"\.save\s*\(\s*[^)]*\.filename"),
                    re.compile(r"os\.path\.join\s*\([^)]*\.filename"),
                ],
                "safe": [
                    re.compile(r"secure_filename\s*\("),
                    re.compile(r"uuid\.uuid4\(\)"),
                    re.compile(r"mimetypes\.guess_type\("),
                ],
                "remediation": "使用 secure_filename + 随机名称，白名单校验 MIME 类型",
            },
            "php": {
                "risk": [
                    re.compile(r"\$_FILES\["),
                    re.compile(r"move_uploaded_file\s*\([^)]*\$.*name"),
                    re.compile(r"copy\s*\(\s*\$.*tmp_name"),
                ],
                "safe": [
                    re.compile(r"pathinfo\(.*PATHINFO_EXTENSION\)"),
                    re.compile(r"uniqid\(\)"),
                    re.compile(r"finfo_file\s*\("),
                ],
                "remediation": "生成随机文件名，使用 finfo 校验 MIME，限制扩展名白名单",
            },
        },
    },

    # ── IDOR 越权 ──
    "IDOR": {
        "cwe": "CWE-639",
        "gbt": "GB/T34944-6.2.7.1",
        "default_severity": "HIGH",
        "desc": "不安全的直接对象引用 / 越权访问",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"@PathVariable\s+\w+\s+id"),
                    re.compile(r"@RequestParam\s+\w+\s+id"),
                    re.compile(r"findById\s*\(\s*request"),
                    re.compile(r"\.get\s*\(\s*request.*id"),
                ],
                "safe": [
                    re.compile(r"getPrincipal\(\)|getAuthentication\(\)"),
                    re.compile(r"validateOwnership|checkAccess|verifyPermission"),
                    re.compile(r"@PreAuthorize.*#id"),
                ],
                "remediation": "始终验证当前用户对目标资源的访问权限，使用 @PreAuthorize + 所有权校验",
            },
            "python": {
                "risk": [
                    re.compile(r"\.get\s*\(\s*request\.get\(['\"]id"),
                    re.compile(r"Model\.objects\.get\(.*request"),
                    re.compile(r"\.filter\s*\(\s*id\s*=\s*request"),
                ],
                "safe": [
                    re.compile(r"request\.user\.id"),
                    re.compile(r"\.objects\.filter\(.*owner.*=.*request"),
                    re.compile(r"get_object_or_404\(.*owner"),
                ],
                "remediation": "查询时始终过滤 owner/user 字段，验证资源归属",
            },
            "javascript": {
                "risk": [
                    re.compile(r"findById\s*\(\s*req\.params"),
                    re.compile(r"Model\.(findOne|findById)\s*\(.*req"),
                ],
                "safe": [
                    re.compile(r"where.*userId.*req\.user"),
                    re.compile(r"\.populate\(['\"]user"),
                    re.compile(r"req\.user\.id"),
                ],
                "remediation": "查询时添加 userId 过滤条件，验证所有权",
            },
        },
    },

    # ── 缺少认证 ──
    "AUTH_MISSING": {
        "cwe": "CWE-306",
        "gbt": "GB/T34944-6.2.7.1",
        "default_severity": "HIGH",
        "desc": "敏感端点缺少身份认证",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"@(Get|Post|Put|Delete|Patch)Mapping\s*\("),
                ],
                "safe": [
                    re.compile(r"@PreAuthorize\s*\("),
                    re.compile(r"@Secured\s*\("),
                    re.compile(r"@AuthenticationPrincipal"),
                ],
                "remediation": "为敏感端点添加 @PreAuthorize 或 @Secured 认证注解",
            },
            "python": {
                "risk": [
                    re.compile(r"@(app|router)\.(route|get|post)\s*\("),
                    re.compile(r"def\s+\w+\s*\(\s*request"),
                ],
                "safe": [
                    re.compile(r"@login_required"),
                    re.compile(r"@jwt_required"),
                    re.compile(r"request\.user\b"),
                ],
                "remediation": "为敏感路由添加 @login_required 或 @jwt_required 装饰器",
            },
            "javascript": {
                "risk": [
                    re.compile(r"(app|router)\.(get|post|put|delete)\s*\("),
                ],
                "safe": [
                    re.compile(r"ensureLoggedIn\s*\("),
                    re.compile(r"authenticate\s*\("),
                    re.compile(r"passport\.authenticate"),
                    re.compile(r"jwt.*middleware"),
                ],
                "remediation": "为敏感路由添加 passport/jwt 认证中间件",
            },
        },
    },

    # ── 不安全随机数 ──
    "INSECURE_RANDOM": {
        "cwe": "CWE-338",
        "gbt": "GB/T34944-6.2.7.3",
        "default_severity": "MEDIUM",
        "desc": "使用不安全的伪随机数生成器（用于密码学/令牌场合）",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"random\.(random|randint|choice)\s*\("),
                ],
                "safe": [
                    re.compile(r"secrets\.\w+\s*\("),
                    re.compile(r"os\.urandom\s*\("),
                ],
                "remediation": "安全场景使用 secrets 或 os.urandom 替代 random 模块",
            },
            "javascript": {
                "risk": [
                    re.compile(r"Math\.random\s*\("),
                ],
                "safe": [
                    re.compile(r"crypto\.randomBytes\s*\("),
                    re.compile(r"crypto\.randomUUID\s*\("),
                    re.compile(r"crypto\.getRandomValues\s*\("),
                ],
                "remediation": "安全场景使用 crypto.randomBytes 或 crypto.randomUUID",
            },
            "java": {
                "risk": [
                    re.compile(r"new\s+Random\s*\("),
                    re.compile(r"Math\.random\s*\("),
                ],
                "safe": [
                    re.compile(r"SecureRandom\s*\("),
                    re.compile(r"SecureRandom\.getInstanceStrong\s*\("),
                ],
                "remediation": "安全场景使用 java.security.SecureRandom",
            },
            "go": {
                "risk": [
                    re.compile(r"math/rand\.\w+\s*\("),
                ],
                "safe": [
                    re.compile(r"crypto/rand\.\w+\s*\("),
                ],
                "remediation": "安全场景使用 crypto/rand",
            },
        },
    },

    # ── Cookie 安全 ──
    "COOKIE_SECURITY": {
        "cwe": "CWE-1004",
        "gbt": "GB/T34944-6.2.7.3",
        "default_severity": "MEDIUM",
        "desc": "Cookie 缺少 Secure/HttpOnly/SameSite 安全属性",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"set_cookie\s*\(\s*[^)]*\bname\s*="),
                    re.compile(r"response\.set_cookie\s*\("),
                ],
                "safe": [
                    re.compile(r"secure\s*=\s*True"),
                    re.compile(r"httponly\s*=\s*True"),
                    re.compile(r"samesite\s*=\s*['\"]Strict['\"]"),
                ],
                "remediation": "设置 Secure=True, HttpOnly=True, SameSite='Strict'",
            },
            "java": {
                "risk": [
                    re.compile(r"new\s+Cookie\s*\("),
                    re.compile(r"addCookie\s*\("),
                ],
                "safe": [
                    re.compile(r"setSecure\s*\(\s*true\s*\)"),
                    re.compile(r"setHttpOnly\s*\(\s*true\s*\)"),
                    re.compile(r"setSameSite\s*\("),
                ],
                "remediation": "调用 setSecure(true), setHttpOnly(true), setSameSite(Strict)",
            },
            "javascript": {
                "risk": [
                    re.compile(r"document\.cookie\s*=\s*`?[^;]*`?\s*;?$"),
                    re.compile(r"res\.cookie\s*\("),
                ],
                "safe": [
                    re.compile(r";\s*Secure"),
                    re.compile(r";\s*HttpOnly"),
                    re.compile(r";\s*SameSite=(Strict|Lax)"),
                ],
                "remediation": "添加 Secure; HttpOnly; SameSite=Strict 属性",
            },
        },
    },

    # ── 业务逻辑漏洞 ──
    "BUSINESS_LOGIC": {
        "cwe": "CWE-840",
        "default_severity": "HIGH",
        "desc": "业务逻辑漏洞（价格操控、状态绕过、权限放大）",
        "languages": {
            "java": {
                "risk": [
                    re.compile(r"\.setPrice\s*\(.*request"),
                    re.compile(r"setAmount\s*\(.*request"),
                    re.compile(r"\.setStatus\s*\(.*request"),
                ],
                "safe": [
                    re.compile(r"@Transactional.*(checkBalance|validateOrder|verify)"),
                    re.compile(r"StateMachine|stateMachine"),
                ],
                "remediation": "价格/金额从数据库获取，状态转换使用状态机在服务端验证",
            },
            "python": {
                "risk": [
                    re.compile(r"price|amount|total|balance.*=\s*request\."),
                    re.compile(r"status\s*=\s*request\."),
                    re.compile(r"def\s+(cancel|refund|approve|reject).*request"),
                ],
                "safe": [
                    re.compile(r"server.*price|recalculate|verify_amount"),
                    re.compile(r"transition.*status|valid_status"),
                ],
                "remediation": "价格在服务端重新计算，状态转换在服务端验证",
            },
            "javascript": {
                "risk": [
                    re.compile(r"price\s*[:=]\s*req\.(body|query)"),
                    re.compile(r"status\s*[:=]\s*req\.(body|query)"),
                    re.compile(r"quantity\s*[:=]\s*req\.(body|query)"),
                ],
                "safe": [
                    re.compile(r"product\.price|dbPrice|serverPrice"),
                    re.compile(r"statusMachine|validTransitions"),
                ],
                "remediation": "价格从数据库获取，状态转换在服务端验证",
            },
        },
    },

    # ── 批量赋值 ──
    "MASS_ASSIGNMENT": {
        "cwe": "CWE-915",
        "default_severity": "HIGH",
        "desc": "批量赋值漏洞（请求体直接绑定含敏感字段的实体）",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"\*\*request\.(form|json|data)"),
                    re.compile(r"\.update\(request\.(form|json)\)"),
                    re.compile(r"Model\(\s*\*\*\s*request\.data"),
                ],
                "safe": [
                    re.compile(r"only\(|exclude\(|whitelist|allowed_fields"),
                    re.compile(r"serializer\.fields|fields\s*="),
                ],
                "remediation": "使用白名单限制可修改字段，避免直接解包请求数据",
            },
            "java": {
                "risk": [
                    re.compile(r"@RequestBody\s+.*DTO|@RequestBody\s+.*Entity"),
                    re.compile(r"BeanUtils\.copyProperties"),
                ],
                "safe": [
                    re.compile(r"@JsonProperty.*access.*READ_ONLY"),
                    re.compile(r"@JsonIgnore"),
                ],
                "remediation": "使用独立 DTO，限制可修改字段，排除敏感属性",
            },
            "javascript": {
                "risk": [
                    re.compile(r"\.\.\.req\.body|Object\.assign\(.*req\.body"),
                    re.compile(r"model\.set\(req\.body\)|model\.update\(req\.body\)"),
                ],
                "safe": [
                    re.compile(r"pick\(|omit\(|allowedFields|whitelist"),
                    re.compile(r"zod|joi|yup.*validate"),
                ],
                "remediation": "使用 pick/omit 限制可修改字段，加入 Schema 验证",
            },
        },
    },

    # ── 正则 ReDoS ──
    "REGEX_DOS": {
        "cwe": "CWE-1333",
        "default_severity": "MEDIUM",
        "desc": "正则表达式拒绝服务（灾难性回溯）",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"\(\.\*\+\)\s*\+\s*\("),
                    re.compile(r"\([^)]*[\*\+]\)\s*\([\*\+]"),
                ],
                "safe": [
                    re.compile(r"re\.compile\(.*timeout"),
                    re.compile(r"regex\.compile"),
                ],
                "remediation": "避免嵌套量词，使用 re.compile(timeout=...) 或 regex 库",
            },
            "javascript": {
                "risk": [
                    re.compile(r"/\([^)]*[\*\+]\)/"),
                    re.compile(r"/\.[\*\+]{2,}/"),
                ],
                "safe": [
                    re.compile(r"safe-regex|safeRegex"),
                    re.compile(r"re2"),
                ],
                "remediation": "使用 re2 引擎或 safe-regex 验证，避免灾难性回溯",
            },
            "java": {
                "risk": [
                    re.compile(r"Pattern\.compile\([^)]*[\*\+]{2,"),
                    re.compile(r"Pattern\.compile\([^)]*\)\.matcher\(.*[\*\+]"),
                ],
                "safe": [
                    re.compile(r"Pattern\.compile\(.*COMMENTS"),
                ],
                "remediation": "避免灾难性回溯，使用线程安全的 Pattern 编译",
            },
        },
    },

    # ── 幂等性缺失 ──
    "IDEMPOTENCY": {
        "cwe": "CWE-841",
        "default_severity": "MEDIUM",
        "desc": "缺少幂等性保护（支付/下单接口可重复提交）",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"@(app|router)\.\w+\(.*POST.*(pay|order|transfer|withdraw)"),
                ],
                "safe": [
                    re.compile(r"idempotency_key|idempotent|request_id|nonce"),
                    re.compile(r"redis.*(setnx|incr.*expire)|unique_together"),
                ],
                "remediation": "添加幂等键 (Idempotency-Key) + 数据库唯一约束防重复提交",
            },
            "java": {
                "risk": [
                    re.compile(r"@PostMapping.*(pay|order|transfer)"),
                ],
                "safe": [
                    re.compile(r"@Idempotent|IdempotencyKey|requestId"),
                    re.compile(r"redis.*setIfAbsent|unique.*constraint"),
                ],
                "remediation": "使用幂等键 + 数据库唯一约束",
            },
        },
    },

    # ── 速率限制缺失 ──
    "RATE_LIMIT": {
        "cwe": "CWE-770",
        "default_severity": "MEDIUM",
        "desc": "缺少速率限制（验证码/短信/登录接口可被暴力调用）",
        "languages": {
            "python": {
                "risk": [
                    re.compile(r"@(app|router)\.\w+\(.*POST.*(login|sms|verify|register)"),
                    re.compile(r"send_sms|send_email|send_verify"),
                ],
                "safe": [
                    re.compile(r"rate_limit|throttle|limiter"),
                    re.compile(r"redis.*(incr|expire)"),
                ],
                "remediation": "为敏感操作添加速率限制（Flask-Limiter / 自实现）",
            },
            "javascript": {
                "risk": [
                    re.compile(r"(app|router)\.post\(.*(login|sms|verify|register)"),
                    re.compile(r"sendVerification|sendOTP|sendSms"),
                ],
                "safe": [
                    re.compile(r"express-rate-limit|rateLimit"),
                    re.compile(r"throttle|limiter"),
                ],
                "remediation": "添加 express-rate-limit 等限流中间件",
            },
            "java": {
                "risk": [
                    re.compile(r"@(Post|Get)Mapping.*(login|sms|verify|register)"),
                ],
                "safe": [
                    re.compile(r"@RateLimit|Bucket4j"),
                    re.compile(r"RateLimiter"),
                ],
                "remediation": "使用 Bucket4j 或 Guava RateLimiter 限制频率",
            },
        },
    },

    # ── 邮件注入 ──
    "MAIL_INJECTION": {
        "cwe": "CWE-78",
        "default_severity": "MEDIUM",
        "desc": "邮件头注入 / 环境变量操控",
        "languages": {
            "php": {
                "risk": [
                    re.compile(r"\bmail\s*\("),
                    re.compile(r"\bmb_send_mail\s*\("),
                    re.compile(r"\bputenv\s*\("),
                    re.compile(r"\berror_log\s*\("),
                ],
                "safe": [
                    re.compile(r"filter_var\s*\(.*FILTER_VALIDATE_EMAIL"),
                    re.compile(r"htmlspecialchars\s*\(.*ENT_QUOTES"),
                ],
                "remediation": "对邮件地址使用 filter_var 验证，对邮件内容做输出编码",
            },
            "python": {
                "risk": [
                    re.compile(r"smtplib\.SMTP\s*\("),
                    re.compile(r"sendmail\s*\([^)]*\+"),
                    re.compile(r"MIMEText\s*\([^)]*\+"),
                    re.compile(r"os\.(putenv|environ\.__setitem__)\s*\("),
                ],
                "safe": [
                    re.compile(r"email\.utils\.parseaddr\s*\("),
                    re.compile(r"email_validator|validate_email"),
                    re.compile(r"smtplib\.SMTP.*starttls\s*\("),
                ],
                "remediation": "验证邮件地址格式，避免用户输入注入邮件头/体",
            },
        },
    },
}


# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def get_profile(vuln_type: str) -> Dict[str, Any]:
    """获取漏洞类型的完整特征。"""
    return VULN_PROFILES.get(vuln_type, {})


def get_risk_patterns(vuln_type: str, language: str) -> List[re.Pattern]:
    """获取指定漏洞类型和语言的危险模式。"""
    profile = VULN_PROFILES.get(vuln_type, {})
    lang = profile.get("languages", {}).get(language, {})
    return lang.get("risk", [])


def get_safe_patterns(vuln_type: str, language: str) -> List[re.Pattern]:
    """获取指定漏洞类型和语言的安全模式。"""
    profile = VULN_PROFILES.get(vuln_type, {})
    lang = profile.get("languages", {}).get(language, {})
    return lang.get("safe", [])


def get_all_safe_patterns(language: str) -> Dict[str, List[re.Pattern]]:
    """获取指定语言下所有漏洞类型的安全模式 {vuln_type: [patterns]}。"""
    result: Dict[str, List[re.Pattern]] = {}
    for vt, profile in VULN_PROFILES.items():
        lang = profile.get("languages", {}).get(language, {})
        safe = lang.get("safe", [])
        if safe:
            result[vt] = safe
    return result


def get_cwe(vuln_type: str) -> str:
    """获取漏洞类型对应的 CWE 编号。"""
    return VULN_PROFILES.get(vuln_type, {}).get("cwe", "")


def get_default_severity(vuln_type: str) -> str:
    """获取漏洞类型的默认严重等级。"""
    return VULN_PROFILES.get(vuln_type, {}).get("default_severity", "MEDIUM")

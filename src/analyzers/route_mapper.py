# -*- coding: utf-8 -*-
"""Java 路由映射分析器 —— 整合自 gbt-codeagent/analyzers/javaRouteMapper.js。

从 Java Web 项目中提取 HTTP 路由和参数结构，
支持 Spring MVC、Struts2、Servlet、JAX-RS、CXF Web Services。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class RouteInfo:
    """路由信息。"""
    http_method: str = ""
    path: str = ""
    handler_class: str = ""
    handler_method: str = ""
    params: List[Dict[str, str]] = field(default_factory=list)
    source_file: str = ""
    line_number: int = 0
    framework: str = ""


# ═══════════════════════════════════════════════════════════════
# Spring MVC 路由提取
# ═══════════════════════════════════════════════════════════════

# 类级别 @RequestMapping
_SPRING_CLASS_MAPPING = re.compile(
    r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']",
    re.I,
)
# 方法级别映射注解
_SPRING_METHOD_MAPPINGS = [
    (re.compile(r"@GetMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']", re.I), "GET"),
    (re.compile(r"@PostMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']", re.I), "POST"),
    (re.compile(r"@PutMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']", re.I), "PUT"),
    (re.compile(r"@DeleteMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']", re.I), "DELETE"),
    (re.compile(r"@PatchMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']", re.I), "PATCH"),
    (re.compile(r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'].*?method\s*=\s*(?:RequestMethod\.)?(\w+)", re.I | re.S), None),
]
# 方法级别 @RequestMapping（无 method）
_SPRING_REQUEST_MAPPING = re.compile(
    r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']\s*\)",
    re.I,
)
# 参数注解
_SPRING_PARAM_ANNOTATIONS = re.compile(
    r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)"
    r"(?:\s*\(\s*(?:value\s*=\s*)?[\"'](\w+)[\"'].*?)?\s+(\w+)\s*[,\)]",
    re.S,
)


# ═══════════════════════════════════════════════════════════════
# Struts2 路由提取
# ═══════════════════════════════════════════════════════════════

_STRUTS_ACTION = re.compile(
    r'@Action\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
    re.I,
)
_STRUTS_NAMESPACE = re.compile(
    r'@Namespace\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
    re.I,
)
_STRUTS_RESULT = re.compile(
    r'@Result\s*\(\s*.*?name\s*=\s*["\'](\w+)["\']',
    re.I,
)


# ═══════════════════════════════════════════════════════════════
# Servlet 路由提取
# ═══════════════════════════════════════════════════════════════

_SERVLET_ANNOTATION = re.compile(
    r'@WebServlet\s*\(\s*(?:value\s*=\s*|urlPatterns\s*=\s*)["\']([^"\']+)["\']',
    re.I,
)
_SERVLET_XML = re.compile(
    r'<url-pattern>\s*([^<]+)\s*</url-pattern>',
    re.I,
)


# ═══════════════════════════════════════════════════════════════
# JAX-RS 路由提取
# ═══════════════════════════════════════════════════════════════

_JAXRS_PATH = re.compile(
    r'@Path\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
    re.I,
)
_JAXRS_METHODS = [
    (re.compile(r'@GET\b', re.I), "GET"),
    (re.compile(r'@POST\b', re.I), "POST"),
    (re.compile(r'@PUT\b', re.I), "PUT"),
    (re.compile(r'@DELETE\b', re.I), "DELETE"),
]
_JAXRS_PARAM = re.compile(
    r'@(PathParam|QueryParam|FormParam|HeaderParam|CookieParam)'
    r'\s*\(\s*["\'](\w+)["\']\s*\)\s+\w+\s+(\w+)',
    re.S,
)


def extract_routes_from_file(file_path: str, content: str) -> List[RouteInfo]:
    """从单个 Java 文件提取路由信息。"""
    routes: List[RouteInfo] = []

    # 检测框架类型
    has_spring = bool(re.search(r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping', content))
    has_struts = bool(re.search(r'@(Action|Namespace|Result)\b', content))
    has_servlet = bool(re.search(r'@WebServlet\b', content))
    has_jaxrs = bool(re.search(r'@(Path|GET|POST|PUT|DELETE)\b', content))

    if has_spring:
        routes.extend(_extract_spring_routes(file_path, content))
    if has_struts:
        routes.extend(_extract_struts_routes(file_path, content))
    if has_servlet:
        routes.extend(_extract_servlet_routes(file_path, content))
    if has_jaxrs:
        routes.extend(_extract_jaxrs_routes(file_path, content))

    return routes


def _extract_spring_routes(file_path: str, content: str) -> List[RouteInfo]:
    """提取 Spring MVC 路由。"""
    routes: List[RouteInfo] = []

    # 类级别路径前缀
    class_path = ""
    class_match = _SPRING_CLASS_MAPPING.search(content)
    if class_match:
        class_path = class_match.group(1)

    # 类名
    class_name = ""
    class_decl = re.search(r'(?:public\s+)?class\s+(\w+)', content)
    if class_decl:
        class_name = class_decl.group(1)

    # 方法级别映射
    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern, method in _SPRING_METHOD_MAPPINGS:
            m = pattern.search(line)
            if m:
                path = m.group(1)
                http_method = method or m.group(2) if m.lastindex >= 2 else "GET"
                full_path = _join_paths(class_path, path)

                # 提取方法名
                method_name = ""
                for i in range(line_num, min(line_num + 5, len(lines) + 1)):
                    mm = re.search(r'public\s+\w+\s+(\w+)\s*\(', lines[i - 1])
                    if mm:
                        method_name = mm.group(1)
                        break

                # 提取参数
                params = _extract_spring_params(line)

                routes.append(RouteInfo(
                    http_method=http_method.upper() if http_method else "GET",
                    path=full_path,
                    handler_class=class_name,
                    handler_method=method_name,
                    params=params,
                    source_file=file_path,
                    line_number=line_num,
                    framework="spring",
                ))
                break

        # 简单 @RequestMapping（无 method 指定）
        m = _SPRING_REQUEST_MAPPING.search(line)
        if m:
            path = m.group(1)
            full_path = _join_paths(class_path, path)
            method_name = ""
            for i in range(line_num, min(line_num + 5, len(lines) + 1)):
                mm = re.search(r'public\s+\w+\s+(\w+)\s*\(', lines[i - 1])
                if mm:
                    method_name = mm.group(1)
                    break

            routes.append(RouteInfo(
                http_method="ALL",
                path=full_path,
                handler_class=class_name,
                handler_method=method_name,
                params=_extract_spring_params(line),
                source_file=file_path,
                line_number=line_num,
                framework="spring",
            ))

    return routes


def _extract_spring_params(line: str) -> List[Dict[str, str]]:
    """提取 Spring 参数注解。"""
    params = []
    for m in _SPRING_PARAM_ANNOTATIONS.finditer(line):
        annotation = m.group(1)
        name = m.group(2) if m.group(2) else m.group(3)
        var_name = m.group(3)
        params.append({
            "annotation": annotation,
            "name": name,
            "variable": var_name,
        })
    return params


def _extract_struts_routes(file_path: str, content: str) -> List[RouteInfo]:
    """提取 Struts2 路由。"""
    routes: List[RouteInfo] = []
    namespace = ""
    ns_match = _STRUTS_NAMESPACE.search(content)
    if ns_match:
        namespace = ns_match.group(1)

    class_name = ""
    class_decl = re.search(r'(?:public\s+)?class\s+(\w+)', content)
    if class_decl:
        class_name = class_decl.group(1)

    for m in _STRUTS_ACTION.finditer(content):
        action = m.group(1)
        full_path = _join_paths(namespace, action)
        routes.append(RouteInfo(
            http_method="POST",  # Struts2 默认 POST
            path=full_path,
            handler_class=class_name,
            handler_method="execute",
            source_file=file_path,
            framework="struts2",
        ))
    return routes


def _extract_servlet_routes(file_path: str, content: str) -> List[RouteInfo]:
    """提取 Servlet 路由。"""
    routes: List[RouteInfo] = []
    class_name = ""
    class_decl = re.search(r'(?:public\s+)?class\s+(\w+)', content)
    if class_decl:
        class_name = class_decl.group(1)

    for m in _SERVLET_ANNOTATION.finditer(content):
        path = m.group(1)
        routes.append(RouteInfo(
            http_method="ALL",
            path=path,
            handler_class=class_name,
            handler_method="doGet/doPost",
            source_file=file_path,
            framework="servlet",
        ))
    return routes


def _extract_jaxrs_routes(file_path: str, content: str) -> List[RouteInfo]:
    """提取 JAX-RS 路由。"""
    routes: List[RouteInfo] = []

    # 类级别 @Path
    class_path = ""
    path_match = _JAXRS_PATH.search(content)
    if path_match:
        class_path = path_match.group(1)

    class_name = ""
    class_decl = re.search(r'(?:public\s+)?class\s+(\w+)', content)
    if class_decl:
        class_name = class_decl.group(1)

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        # 方法级别 @Path
        method_path = ""
        mp = _JAXRS_PATH.search(line)
        if mp:
            method_path = mp.group(1)

        for pattern, method in _JAXRS_METHODS:
            if pattern.search(line):
                full_path = _join_paths(class_path, method_path)
                method_name = ""
                for i in range(line_num, min(line_num + 5, len(lines) + 1)):
                    mm = re.search(r'public\s+\w+\s+(\w+)\s*\(', lines[i - 1])
                    if mm:
                        method_name = mm.group(1)
                        break

                routes.append(RouteInfo(
                    http_method=method,
                    path=full_path,
                    handler_class=class_name,
                    handler_method=method_name,
                    source_file=file_path,
                    line_number=line_num,
                    framework="jaxrs",
                ))
                break

    return routes


def _join_paths(prefix: str, suffix: str) -> str:
    """拼接路径，处理重复斜杠。"""
    if not prefix:
        return suffix or "/"
    if not suffix:
        return prefix
    p = prefix.rstrip("/")
    s = suffix.lstrip("/")
    return f"{p}/{s}" if s else p


def extract_routes_from_project(
    project_path: str, java_files: List[str], file_reader=None
) -> List[RouteInfo]:
    """从项目中提取所有路由。

    Args:
        project_path: 项目根目录
        java_files: Java 文件相对路径列表
        file_reader: 可选的文件读取函数 (path) -> content

    Returns:
        所有提取到的路由列表
    """
    all_routes: List[RouteInfo] = []

    for rel_path in java_files:
        if not rel_path.lower().endswith(".java"):
            continue
        try:
            if file_reader:
                content = file_reader(rel_path)
            else:
                import os
                abs_path = os.path.join(project_path, rel_path)
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            routes = extract_routes_from_file(rel_path, content)
            all_routes.extend(routes)
        except Exception:
            continue

    return all_routes


def format_routes_for_prompt(routes: List[RouteInfo]) -> str:
    """格式化路由信息为可注入 prompt 的文本。"""
    if not routes:
        return ""

    lines = ["\n## Java Web 路由映射\n"]
    lines.append("| 方法 | 路径 | 处理类.方法 | 框架 |")
    lines.append("|------|------|------------|------|")
    for r in routes[:30]:  # 限制数量
        handler = f"{r.handler_class}.{r.handler_method}" if r.handler_class else r.handler_method
        params_str = ""
        if r.params:
            param_names = [p.get("name", p.get("variable", "?")) for p in r.params[:3]]
            params_str = f" (参数: {', '.join(param_names)})"
        lines.append(f"| {r.http_method} | {r.path} | {handler}{params_str} | {r.framework} |")

    if len(routes) > 30:
        lines.append(f"\n> 共 {len(routes)} 条路由，仅显示前 30 条")

    return "\n".join(lines)

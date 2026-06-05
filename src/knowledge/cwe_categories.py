# -*- coding: utf-8 -*-
"""CWE 漏洞分类 —— 整合自 gbt-codeagent 知识体系。"""

CWE_CATEGORIES = {
    "CWE-89": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input",
        "mitigations": ["Use parameterized queries", "Use ORM", "Input validation"],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input",
        "mitigations": ["Avoid shell commands", "Use APIs instead of exec", "Input validation"],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input",
        "mitigations": ["Output encoding", "Content Security Policy", "HTTPOnly cookies"],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "The software accepts input that contains path traversal characters",
        "mitigations": ["Use path.resolve()", "Validate paths against whitelist"],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "description": "The software fetches a remote resource without validating the URL",
        "mitigations": ["URL validation", "Allowlist domains", "Disable redirects"],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The software deserializes untrusted data without sufficient validation",
        "mitigations": ["Use secure serialization formats", "Implement strict type checking"],
    },
    "CWE-611": {
        "name": "XML External Entity",
        "description": "The software processes XML documents without properly disabling external entity resolution",
        "mitigations": ["Disable external entities", "Enable secure processing"],
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "description": "The software contains hardcoded credentials",
        "mitigations": ["Use environment variables", "Use secure key management"],
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "description": "The software uses a broken or risky cryptographic algorithm",
        "mitigations": ["Use modern cryptographic algorithms", "Avoid MD5/SHA1"],
    },
    "CWE-639": {
        "name": "Insecure Direct Object Reference",
        "description": "The software exposes a reference to an internal object without proper authorization",
        "mitigations": ["Implement proper authorization checks", "Use indirect references"],
    },
    "CWE-94": {
        "name": "Code Injection",
        "description": "The software constructs all or part of a code segment using externally-influenced input",
        "mitigations": ["Avoid eval/exec with user input", "Use sandboxed execution"],
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery",
        "description": "The web application does not verify the request was intentionally submitted by the user",
        "mitigations": ["Use anti-CSRF tokens", "SameSite cookie attribute"],
    },
    "CWE-259": {
        "name": "Use of Hard-coded Password",
        "description": "The software contains a hard-coded password",
        "mitigations": ["Use environment variables", "Use secure key management"],
    },
    "CWE-328": {
        "name": "Reversible One-Way Hash",
        "description": "The software uses a reversible one-way hash",
        "mitigations": ["Use bcrypt/scrypt/argon2", "Add salt"],
    },
    "CWE-338": {
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator",
        "description": "The software uses a PRNG that is not cryptographically strong",
        "mitigations": ["Use crypto/rand", "Use secrets module"],
    },
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input",
        "description": "The software copies input to a buffer without checking size",
        "mitigations": ["Use bounded copy functions", "Check input length"],
    },
    "CWE-134": {
        "name": "Use of Externally-Controlled Format String",
        "description": "The software uses a format string from an external source",
        "mitigations": ["Use constant format strings", "Validate format input"],
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "description": "The software performs a calculation that can produce an integer overflow",
        "mitigations": ["Use bounds checking", "Use safe math libraries"],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "The software does not prove the identity of an actor",
        "mitigations": ["Implement proper authentication", "Use multi-factor auth"],
    },
    "CWE-384": {
        "name": "Session Fixation",
        "description": "The software does not invalidate an existing session after successful authentication",
        "mitigations": ["Regenerate session ID after login", "Invalidate old sessions"],
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site",
        "description": "The software redirects to an untrusted URL",
        "mitigations": ["Whitelist redirect targets", "Validate redirect URLs"],
    },
    "CWE-643": {
        "name": "XPath Injection",
        "description": "The software uses external input to construct XPath queries",
        "mitigations": ["Use parameterized XPath", "Input validation"],
    },
    "CWE-942": {
        "name": "Permissive Cross-domain Policy",
        "description": "The software uses an overly permissive cross-domain policy",
        "mitigations": ["Restrict CORS to specific domains", "Avoid wildcard origins with credentials"],
    },
    "CWE-565": {
        "name": "Reliance on Cookies without Validation and Integrity Checking",
        "description": "The software relies on cookies without validation",
        "mitigations": ["Validate cookie values", "Use signed cookies"],
    },
    "CWE-293": {
        "name": "Referer Check for Authentication",
        "description": "The software uses the Referer header for authentication",
        "mitigations": ["Do not rely on Referer for security decisions"],
    },
    "CWE-204": {
        "name": "Observable Response Discrepancy",
        "description": "The software provides different responses to requests in a way that reveals state information",
        "mitigations": ["Standardize error responses", "Avoid information leakage"],
    },
    "CWE-703": {
        "name": "Improper Check or Handling of Exceptional Conditions",
        "description": "The software does not properly handle exceptional conditions",
        "mitigations": ["Handle all exceptions properly", "Avoid empty catch blocks"],
    },
    "CWE-521": {
        "name": "Weak Password Requirements",
        "description": "The software does not enforce strong passwords",
        "mitigations": ["Enforce password complexity", "Minimum length requirements"],
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Information",
        "description": "The software transmits sensitive information in cleartext",
        "mitigations": ["Use TLS", "Encrypt data in transit"],
    },
    "CWE-770": {
        "name": "Allocation of Resources Without Limits or Throttling",
        "description": "The software allocates resources without limits",
        "mitigations": ["Implement resource limits", "Use throttling"],
    },
    "CWE-362": {
        "name": "Concurrent Execution using Shared Resource with Improper Synchronization",
        "description": "The software uses shared resources without proper synchronization",
        "mitigations": ["Use locks", "Use atomic operations", "Use thread-safe data structures"],
    },
    "CWE-835": {
        "name": "Loop with Unreachable Exit Condition",
        "description": "The software has a loop with an unreachable exit condition",
        "mitigations": ["Ensure loop termination", "Add loop counters"],
    },
    "CWE-93": {
        "name": "Improper Neutralization of CRLF Sequences",
        "description": "The software does not neutralize CRLF sequences",
        "mitigations": ["Validate and sanitize input", "Filter CRLF characters"],
    },
    "CWE-114": {
        "name": "Process Control",
        "description": "The software allows external control of processes or operations",
        "mitigations": ["Restrict process control", "Validate inputs"],
    },
}

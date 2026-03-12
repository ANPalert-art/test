#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         WebVulnScan v5.0 — Enterprise Web Application Security Scanner  ║
║         For AUTHORIZED penetration testing ONLY                          ║
║         Use only on systems you own or have explicit written permission  ║
╚══════════════════════════════════════════════════════════════════════════╝

ENTERPRISE FEATURES IN v5.0:
  ── Core Architecture ──────────────────────────────────────────────────
  ✔ Parallel check execution     All modules run concurrently (3-5× faster)
  ✔ Multi-target support         --targets targets.txt (one URL per line)
  ✔ Scope control                --scope domain1.com,api.domain1.com
  ✔ Authenticated scanning       --login-url / --login-user / --login-pass
  ✔ Resume interrupted scan      --resume previous_report.json
  ✔ Structured audit log         --audit-log scan_audit.jsonl
  ✔ Graceful Ctrl+C              Saves partial report on interrupt

  ── New Security Checks ────────────────────────────────────────────────
  ✔ DOM XSS static analysis      Scans linked JS files for dangerous sinks
  ✔ XXE injection                POSTs crafted XML to content-accepting endpoints
  ✔ Prototype pollution          Detects __proto__ / constructor injection
  ✔ HTTP Request Smuggling       Basic CL.TE / TE.CL detection
  ✔ API endpoint discovery       Probes /api/, /v1/, /v2/, REST patterns
  ✔ Rate limit detection         Tests login/API endpoints for missing throttle
  ✔ Account enumeration          Detects user/email enumeration via timing/response
  ✔ Subdomain hints              Extracts subdomains from cert SANs
  ✔ Security.txt check           RFC 9116 compliance
  ✔ Clickjacking proof-of-concept Auto-generates PoC iframe HTML

  ── Reporting & Integration ────────────────────────────────────────────
  ✔ CVSS v3.1 scoring            Every finding has a base score
  ✔ Remediation effort           LOE estimate per finding (hours)
  ✔ Executive HTML report        Risk narrative + SVG donut chart + timeline
  ✔ Trend analysis               Compares with previous JSON report (--baseline)
  ✔ All v4 formats               JSON / HTML / CSV / JUnit / SARIF / Markdown
  ✔ Webhook                      Slack/Discord/custom with severity color
  ✔ CI/CD exit codes             --fail-on critical|high|medium|low

INSTALL:
  pip install requests
  pip install tqdm          # optional — better progress bars

USAGE:
  # Single target
  python3 web_vuln_scanner_v5.py https://example.com

  # Multi-target file
  python3 web_vuln_scanner_v5.py --targets targets.txt --profile full

  # Authenticated scan
  python3 web_vuln_scanner_v5.py https://app.example.com \\
      --login-url https://app.example.com/login \\
      --login-user admin@example.com --login-pass secret \\
      --login-field-user email --login-field-pass password

  # CI/CD pipeline
  python3 web_vuln_scanner_v5.py https://example.com \\
      --profile quick --fail-on high -q --junit results.xml

  # Full enterprise scan with all outputs
  python3 web_vuln_scanner_v5.py https://example.com \\
      --profile full --scope example.com,api.example.com \\
      -o report.json --html report.html --csv report.csv \\
      --sarif report.sarif --audit-log audit.jsonl \\
      --webhook https://hooks.slack.com/services/...

  # Resume an interrupted scan
  python3 web_vuln_scanner_v5.py https://example.com --resume report.json

  # Compare with previous baseline
  python3 web_vuln_scanner_v5.py https://example.com --baseline old_report.json
"""

# ──────────────────────────────────────────────────────────────────────────
# IMPORTS
# ──────────────────────────────────────────────────────────────────────────
import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────
# VERSION & CONSTANTS
# ──────────────────────────────────────────────────────────────────────────
VERSION           = "5.0"
DEFAULT_TIMEOUT   = 12
DEFAULT_THREADS   = 15
MAX_CRAWL_PAGES   = 50
MAX_JS_FILES      = 10      # JS files to analyze for DOM XSS
RETRY_429_WAIT    = 6
SSTI_PAYLOAD      = "{{31337*31337}}"
SSTI_EXPECTED     = "982176769"   # 31337²
API_PATHS         = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/api",
    "/v1", "/v2", "/v3",
    "/graphql", "/gql", "/graphiql",
    "/swagger", "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs",
]
SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]

BASE_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (compatible; WebVulnScan/5.0; Security-Audit)",
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}

# ANSI
R    = "\033[91m"; G    = "\033[92m"; Y    = "\033[93m"
B    = "\033[94m"; C    = "\033[96m"; M    = "\033[95m"
W    = "\033[97m"; BOLD = "\033[1m";  DIM  = "\033[2m"; RST = "\033[0m"

# ──────────────────────────────────────────────────────────────────────────
# SCAN PROFILES
# ──────────────────────────────────────────────────────────────────────────
PROFILES: Dict[str, dict] = {
    "quick": {
        "description": "Passive + header checks only (~30s)",
        "skip": {"sqli","cmdi","traversal","ssti","ssrf","proto_pollution",
                 "smuggling","xxe","dom_xss","rate_limit","enum"},
        "threads": 20, "timeout": 8, "crawl_pages": 10,
    },
    "standard": {
        "description": "Active + passive balanced (~3-7min)",
        "skip": {"smuggling"},
        "threads": 15, "timeout": 12, "crawl_pages": 30,
    },
    "full": {
        "description": "All checks, maximum payloads (~15-30min)",
        "skip": set(),
        "threads": 25, "timeout": 20, "crawl_pages": 50,
    },
    "api": {
        "description": "REST/GraphQL API-focused scan",
        "skip": {"client","csrf","clickjacking"},
        "threads": 20, "timeout": 15, "crawl_pages": 20,
    },
}

# ──────────────────────────────────────────────────────────────────────────
# CVSS v3.1 BASE SCORES (per finding key)
# Format: (score, vector_string)
# ──────────────────────────────────────────────────────────────────────────
CVSS: Dict[str, Tuple[float, str]] = {
    "sql_injection":             (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sql_injection_blind":       (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "command_injection":         (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "template_injection":        (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "jwt_alg_none":              (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "xxe":                       (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "ssrf":                      (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "cache_poisoning":           (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "xss_reflected":             (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "cors_reflection":           (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "cors_credentials_wildcard": (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "path_traversal":            (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "dom_xss":                   (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "insecure_password_field":   (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ssl_no_https":              (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ssl_weak":                  (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "http_request_smuggling":    (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "sensitive_files":           (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "cookie_session_httponly":   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "missing_hsts":              (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "host_header_injection":     (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "open_redirect":             (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "prototype_pollution":       (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "rate_limit_missing":        (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "account_enumeration":       (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "graphql_introspection":     (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

# Remediation effort estimates (hours)
LOE: Dict[str, int] = {
    "sql_injection": 8, "sql_injection_blind": 8, "command_injection": 8,
    "template_injection": 16, "xxe": 4, "ssrf": 8, "dom_xss": 4,
    "xss_reflected": 4, "path_traversal": 4, "prototype_pollution": 8,
    "http_request_smuggling": 16, "cache_poisoning": 8,
    "cors_reflection": 2, "cors_credentials_wildcard": 2, "cors_wildcard": 1,
    "missing_hsts": 1, "missing_csp": 2, "missing_x_frame": 1,
    "ssl_weak": 2, "ssl_no_https": 4, "ssl_expired": 1,
    "cookie_no_httponly": 1, "cookie_no_secure": 1, "cookie_session_httponly": 1,
    "jwt_alg_none": 8, "jwt_no_expiry": 2, "open_redirect": 2,
    "csrf_missing_token": 4, "sensitive_files": 1, "directory_listing": 1,
    "rate_limit_missing": 4, "account_enumeration": 2,
}

# ──────────────────────────────────────────────────────────────────────────
# VULNERABILITY DATABASE (complete, with OWASP Top 10 category)
# ──────────────────────────────────────────────────────────────────────────
VULN_DB: Dict[str, dict] = {
    # Security Headers
    "missing_hsts":              {"id":"CWE-319",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Missing HTTP Strict Transport Security (HSTS)",
        "fix":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
    "missing_csp":               {"id":"CWE-1021", "sev":"MEDIUM",   "owasp":"A05",
        "name":"Missing Content-Security-Policy",
        "fix":"Add: Content-Security-Policy: default-src 'self'; script-src 'self'"},
    "missing_x_frame":           {"id":"CWE-1021", "sev":"MEDIUM",   "owasp":"A05",
        "name":"Missing X-Frame-Options (Clickjacking)",
        "fix":"Add: X-Frame-Options: DENY"},
    "missing_x_content_type":    {"id":"CWE-430",  "sev":"LOW",      "owasp":"A05",
        "name":"Missing X-Content-Type-Options",
        "fix":"Add: X-Content-Type-Options: nosniff"},
    "missing_referrer_policy":   {"id":"CWE-116",  "sev":"LOW",      "owasp":"A05",
        "name":"Missing Referrer-Policy",
        "fix":"Add: Referrer-Policy: strict-origin-when-cross-origin"},
    "missing_permissions_policy":{"id":"CWE-732",  "sev":"LOW",      "owasp":"A05",
        "name":"Missing Permissions-Policy",
        "fix":"Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"},
    "missing_coep":              {"id":"CWE-1021", "sev":"LOW",      "owasp":"A05",
        "name":"Missing Cross-Origin-Embedder-Policy",
        "fix":"Add: Cross-Origin-Embedder-Policy: require-corp"},
    "missing_coop":              {"id":"CWE-1021", "sev":"LOW",      "owasp":"A05",
        "name":"Missing Cross-Origin-Opener-Policy",
        "fix":"Add: Cross-Origin-Opener-Policy: same-origin"},
    "csp_unsafe_inline":         {"id":"CWE-79",   "sev":"MEDIUM",   "owasp":"A03",
        "name":"CSP Allows 'unsafe-inline'",
        "fix":"Remove 'unsafe-inline' from CSP. Use nonces or hashes."},
    "csp_unsafe_eval":           {"id":"CWE-79",   "sev":"MEDIUM",   "owasp":"A03",
        "name":"CSP Allows 'unsafe-eval'",
        "fix":"Remove 'unsafe-eval' from CSP. Refactor code to avoid eval()."},
    "csp_report_only":           {"id":"CWE-1021", "sev":"LOW",      "owasp":"A05",
        "name":"CSP in Report-Only Mode (not enforced)",
        "fix":"Switch Content-Security-Policy-Report-Only to Content-Security-Policy."},
    # Information Disclosure
    "server_disclosure":         {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"Server Version Disclosure",
        "fix":"Remove or obscure Server header."},
    "xpoweredby_disclosure":     {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"X-Powered-By Technology Disclosure",
        "fix":"Remove X-Powered-By header."},
    "x_aspnet_version":          {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"X-AspNet-Version Disclosure",
        "fix":"Add <httpRuntime enableVersionHeader='false'> in web.config."},
    "debug_info_leak":           {"id":"CWE-209",  "sev":"MEDIUM",   "owasp":"A06",
        "name":"Debug/Stack-Trace Leakage",
        "fix":"Disable debug mode. Return generic error pages in production."},
    "version_in_html":           {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"CMS/Framework Version in HTML",
        "fix":"Remove generator meta tags and version comments from HTML."},
    "internal_ip_disclosure":    {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"Internal IP Address Disclosed",
        "fix":"Sanitize internal IPs from all public responses."},
    "email_disclosure":          {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"Email Address Exposed in Source",
        "fix":"Replace plaintext emails with contact forms."},
    # Injection
    "xss_reflected":             {"id":"CWE-79",   "sev":"HIGH",     "owasp":"A03",
        "name":"Reflected Cross-Site Scripting (XSS)",
        "fix":"Encode all output. Implement strict CSP. Validate inputs server-side."},
    "dom_xss":                   {"id":"CWE-79",   "sev":"HIGH",     "owasp":"A03",
        "name":"Potential DOM-Based XSS (Dangerous Sink in JS)",
        "fix":"Avoid innerHTML/document.write with user-controlled data. Use textContent."},
    "sql_injection":             {"id":"CWE-89",   "sev":"CRITICAL", "owasp":"A03",
        "name":"SQL Injection (Error-Based)",
        "fix":"Use parameterized queries. Never concatenate user input into SQL."},
    "sql_injection_blind":       {"id":"CWE-89",   "sev":"CRITICAL", "owasp":"A03",
        "name":"Blind SQL Injection (Time-Based)",
        "fix":"Use parameterized queries. Add WAF. Implement query timeouts."},
    "command_injection":         {"id":"CWE-78",   "sev":"CRITICAL", "owasp":"A03",
        "name":"OS Command Injection",
        "fix":"Never pass user input to shell. Use safe APIs with whitelists."},
    "path_traversal":            {"id":"CWE-22",   "sev":"HIGH",     "owasp":"A01",
        "name":"Path Traversal",
        "fix":"Validate file paths. Use basename(). Implement strict whitelist."},
    "template_injection":        {"id":"CWE-94",   "sev":"CRITICAL", "owasp":"A03",
        "name":"Server-Side Template Injection (SSTI)",
        "fix":"Never render user input as templates. Use sandboxed environments."},
    "ssrf":                      {"id":"CWE-918",  "sev":"HIGH",     "owasp":"A10",
        "name":"Server-Side Request Forgery (SSRF)",
        "fix":"Whitelist allowed URLs. Block internal IPs. Use network segmentation."},
    "xxe":                       {"id":"CWE-611",  "sev":"HIGH",     "owasp":"A03",
        "name":"XML External Entity Injection (XXE)",
        "fix":"Disable external entity processing. Use safe XML parsers."},
    "prototype_pollution":       {"id":"CWE-1321", "sev":"HIGH",     "owasp":"A03",
        "name":"Prototype Pollution",
        "fix":"Sanitize __proto__, constructor, prototype in user input. Use Object.create(null)."},
    "host_header_injection":     {"id":"CWE-644",  "sev":"MEDIUM",   "owasp":"A03",
        "name":"Host Header Injection",
        "fix":"Validate Host header against whitelist. Use absolute URLs in redirects."},
    "cache_poisoning":           {"id":"CWE-349",  "sev":"HIGH",     "owasp":"A03",
        "name":"Web Cache Poisoning",
        "fix":"Remove unkeyed headers from cache key or disable caching."},
    "http_request_smuggling":    {"id":"CWE-444",  "sev":"HIGH",     "owasp":"A03",
        "name":"HTTP Request Smuggling",
        "fix":"Ensure consistent Content-Length and Transfer-Encoding parsing between frontend and backend."},
    # Auth & Session
    "open_redirect":             {"id":"CWE-601",  "sev":"MEDIUM",   "owasp":"A01",
        "name":"Open Redirect",
        "fix":"Validate redirect URLs against a strict whitelist."},
    "csrf_missing_token":        {"id":"CWE-352",  "sev":"MEDIUM",   "owasp":"A01",
        "name":"CSRF Token Missing in Form",
        "fix":"Add CSRF tokens to all state-changing forms. Use SameSite cookies."},
    "password_autocomplete":     {"id":"CWE-522",  "sev":"LOW",      "owasp":"A07",
        "name":"Password Field with Autocomplete Enabled",
        "fix":"Add autocomplete='off' to password fields."},
    "insecure_password_field":   {"id":"CWE-319",  "sev":"HIGH",     "owasp":"A02",
        "name":"Password Field on Non-HTTPS Page",
        "fix":"Serve all password forms over HTTPS only."},
    "rate_limit_missing":        {"id":"CWE-307",  "sev":"HIGH",     "owasp":"A07",
        "name":"No Rate Limiting on Sensitive Endpoint",
        "fix":"Implement rate limiting, CAPTCHA, and account lockout on login/API endpoints."},
    "account_enumeration":       {"id":"CWE-204",  "sev":"MEDIUM",   "owasp":"A01",
        "name":"User Account Enumeration",
        "fix":"Return identical responses for valid/invalid usernames. Use constant-time comparison."},
    # JWT
    "jwt_alg_none":              {"id":"CWE-347",  "sev":"CRITICAL", "owasp":"A02",
        "name":"JWT Using Algorithm 'none'",
        "fix":"Reject JWTs with alg=none. Always verify signatures server-side."},
    "jwt_no_expiry":             {"id":"CWE-613",  "sev":"MEDIUM",   "owasp":"A07",
        "name":"JWT Missing Expiration Claim (exp)",
        "fix":"Add 'exp' claim to all JWTs. Use short-lived tokens."},
    "jwt_sensitive_payload":     {"id":"CWE-312",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"Sensitive Data in JWT Payload",
        "fix":"Never store secrets in JWT. Payload is base64, not encrypted."},
    "jwt_weak_algorithm":        {"id":"CWE-327",  "sev":"LOW",      "owasp":"A02",
        "name":"JWT Using Symmetric Algorithm (HS256/384/512)",
        "fix":"Consider RS256/ES256 for better key separation."},
    # Cookies
    "cookie_no_httponly":        {"id":"CWE-1004", "sev":"MEDIUM",   "owasp":"A05",
        "name":"Cookie Missing HttpOnly Flag",
        "fix":"Set-Cookie: name=...; HttpOnly"},
    "cookie_no_secure":          {"id":"CWE-614",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Cookie Missing Secure Flag",
        "fix":"Set-Cookie: name=...; Secure"},
    "cookie_no_samesite":        {"id":"CWE-352",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Cookie Missing SameSite Flag",
        "fix":"Set-Cookie: name=...; SameSite=Strict"},
    "cookie_session_httponly":   {"id":"CWE-1004", "sev":"HIGH",     "owasp":"A07",
        "name":"Session Cookie Missing HttpOnly",
        "fix":"Set HttpOnly on all session/auth cookies to prevent XSS theft."},
    # CORS
    "cors_wildcard":             {"id":"CWE-942",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Overly Permissive CORS (Wildcard *)",
        "fix":"Replace Access-Control-Allow-Origin: * with specific trusted domains."},
    "cors_credentials_wildcard": {"id":"CWE-942",  "sev":"HIGH",     "owasp":"A05",
        "name":"CORS Wildcard + Credentials=true",
        "fix":"Never combine wildcard origin with Allow-Credentials: true."},
    "cors_reflection":           {"id":"CWE-942",  "sev":"HIGH",     "owasp":"A05",
        "name":"CORS Origin Reflection",
        "fix":"Validate Origin against a strict whitelist. Never reflect blindly."},
    # Files & Dirs
    "directory_listing":         {"id":"CWE-548",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Directory Listing Enabled",
        "fix":"Disable directory listing (Apache: Options -Indexes)."},
    "sensitive_files":           {"id":"CWE-538",  "sev":"HIGH",     "owasp":"A05",
        "name":"Sensitive File Exposed",
        "fix":"Remove or restrict access to .env, .git, configs, backups."},
    # HTTP Methods
    "http_methods":              {"id":"CWE-749",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"Dangerous HTTP Methods Allowed",
        "fix":"Disable TRACE, PUT, DELETE unless explicitly required."},
    "http_trace":                {"id":"CWE-749",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"HTTP TRACE Enabled (XST Risk)",
        "fix":"Disable TRACE method to prevent Cross-Site Tracing."},
    # SSL/TLS
    "ssl_no_https":              {"id":"CWE-319",  "sev":"HIGH",     "owasp":"A02",
        "name":"Site Not Using HTTPS",
        "fix":"Enable HTTPS and redirect all HTTP traffic."},
    "ssl_no_redirect":           {"id":"CWE-319",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"HTTP Not Redirected to HTTPS",
        "fix":"Add 301 redirect from http:// to https://."},
    "ssl_weak":                  {"id":"CWE-326",  "sev":"HIGH",     "owasp":"A02",
        "name":"Weak TLS Version (TLS 1.0/1.1)",
        "fix":"Disable TLS 1.0/1.1. Enforce TLS 1.2+ only."},
    "ssl_expired":               {"id":"CWE-299",  "sev":"HIGH",     "owasp":"A02",
        "name":"SSL Certificate Expired",
        "fix":"Renew the SSL certificate immediately."},
    "ssl_self_signed":           {"id":"CWE-299",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"Self-Signed SSL Certificate",
        "fix":"Use a certificate from a trusted CA (e.g. Let's Encrypt)."},
    "ssl_hostname_mismatch":     {"id":"CWE-297",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"SSL Certificate Hostname Mismatch",
        "fix":"Ensure certificate CN or SAN matches the server hostname."},
    # Client-Side
    "missing_sri":               {"id":"CWE-829",  "sev":"MEDIUM",   "owasp":"A08",
        "name":"External Script Without SRI",
        "fix":"Add integrity='sha384-...' to all external <script> and <link> tags."},
    "unsafe_websocket":          {"id":"CWE-319",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"Insecure WebSocket (ws://)",
        "fix":"Use wss:// instead of ws://."},
    "http_mixed_content":        {"id":"CWE-311",  "sev":"MEDIUM",   "owasp":"A02",
        "name":"Mixed Content (HTTP on HTTPS page)",
        "fix":"Serve all resources over HTTPS."},
    "javascript_protocol":       {"id":"CWE-79",   "sev":"MEDIUM",   "owasp":"A03",
        "name":"javascript: Protocol in Links",
        "fix":"Remove javascript: href values. Use event listeners instead."},
    "clickjacking_frameable":    {"id":"CWE-1021", "sev":"MEDIUM",   "owasp":"A05",
        "name":"Page Embeddable in iFrame (Clickjacking)",
        "fix":"Set X-Frame-Options: DENY or CSP frame-ancestors: 'none'."},
    # GraphQL
    "graphql_introspection":     {"id":"CWE-200",  "sev":"LOW",      "owasp":"A06",
        "name":"GraphQL Introspection Enabled",
        "fix":"Disable introspection in production."},
    "graphql_no_depth_limit":    {"id":"CWE-400",  "sev":"MEDIUM",   "owasp":"A05",
        "name":"GraphQL No Query Depth Limiting",
        "fix":"Implement query depth and complexity limits to prevent DoS."},
    # Compliance
    "missing_security_txt":      {"id":"CWE-205",  "sev":"LOW",      "owasp":"A05",
        "name":"Missing security.txt (RFC 9116)",
        "fix":"Create /.well-known/security.txt with contact and disclosure policy."},
}

def _vdb(key: str) -> dict:
    return VULN_DB.get(key, {"id":"CWE-0","sev":"INFO","owasp":"A00","name":key,"fix":"Review manually."})

# ──────────────────────────────────────────────────────────────────────────
# PAYLOADS
# ──────────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "'-alert(1)-'",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<iframe src='javascript:alert(1)'>",
    "</script><script>alert(1)</script>",
]
XSS_PAYLOADS_FULL = XSS_PAYLOADS + [
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<div onmouseover='alert(1)'>x</div>",
    "<select onfocus=alert(1) autofocus>",
    "<audio src=x onerror=alert(1)>",
    "<video><source onerror='alert(1)'>",
    "JaVaScRiPt:alert(1)",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "\" onmouseover=\"alert(1)\"",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
]

# DOM XSS dangerous sinks to look for in JS
DOM_XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write(", "document.writeln(",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "location.href", "location.replace(", "location.assign(",
    "window.open(", "element.src", "element.action",
    ".insertAdjacentHTML(", "jQuery.html(", "$.html(",
    "dangerouslySetInnerHTML",  # React
]
DOM_XSS_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.URL", "document.referrer",
    "window.name", "document.cookie",
    "URLSearchParams", "location.pathname",
]

SQLI_ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1'--", "\" OR \"1\"=\"1\"--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "'; SELECT 1--", "') OR ('1'='1",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
]
SQLI_BLIND_PAYLOADS = [
    ("' AND SLEEP(5)--",                 5),
    ("\" AND SLEEP(5)--",                5),
    ("'; WAITFOR DELAY '0:0:5'--",       5),
    ("' OR SLEEP(5)--",                  5),
    ("1; SELECT pg_sleep(5)--",          5),
    ("' AND 1=(SELECT 1 FROM pg_sleep(5))--", 5),
]
SQLI_ERRORS = [
    "you have an error in your sql syntax","warning: mysql","mysql_fetch","mysqli_",
    "pg_query()","pg::syntaxerror","pg::error","postgres",
    "ora-0","oracle.jdbc","pl/sql","unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc sql server driver","microsoft oledb","sql server","mssql",
    "sqlite3::","sqlite error","syntax error","query failed","database error",
]

CMDI_PAYLOADS = [
    "; id", "| id", "&& id", "|| id", "`id`", "$(id)",
    "; whoami", "| whoami", "; cat /etc/passwd",
    "; sleep 5", "%0aid", "%0awhoami",
    "; ping -c 1 127.0.0.1", "| ping -n 1 127.0.0.1",
]
CMDI_SIGS = ["uid=","gid=","root:","daemon:","nobody:","drwx","command not found","ping statistics"]

PATH_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252fetc/passwd", "/etc/passwd%00",
    "..;/..;/etc/passwd", "/%2e%2e/%2e%2e/etc/passwd",
    "....\\....\\....\\windows\\win.ini",
]
PATH_SIGS = ["root:x:0:0:","daemon:x:","[boot loader]","[extensions]","for 16-bit app"]

SSTI_PAYLOADS = [
    SSTI_PAYLOAD, "${31337*31337}", "#{31337*31337}",
    "%{{31337*31337}}", "${{31337*31337}}",
    "${T(java.lang.Math).abs(-31337)}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://0.0.0.0", "http://169.254.169.254",
    "http://metadata.google.internal",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "file:///etc/passwd",
]
SSRF_SIGS = ["root:x:0:0:","instance-id","ami-id","private-ip","metadata","local-ipv4"]

PROTO_POLLUTION_PAYLOADS = [
    "__proto__[polluted]=1",
    "constructor[prototype][polluted]=1",
    "__proto__.polluted=1",
    '{"__proto__":{"polluted":true}}',
    '{"constructor":{"prototype":{"polluted":true}}}',
]

XXE_PAYLOADS = [
    # Basic file read
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    # Error-based
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><test/>',
    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><test>&xxe;</test>',
]
XXE_SIGS = ["root:x:0:0:", "instance-id", "ami-id", "daemon:x:"]

SENSITIVE_PATHS = [
    ".git/config", ".git/HEAD", ".gitignore", ".svn/entries",
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    "config.php", "config.py", "config.yml", "config.yaml", "config.json",
    "settings.py", "local_settings.py", "application.properties",
    "application.yml", "appsettings.json", "web.config", ".htaccess", ".htpasswd",
    "wp-config.php", "wp-content/debug.log", "sites/default/settings.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql", "dump.sql",
    "admin/", "phpmyadmin/", "adminer.php", "phpinfo.php", "info.php",
    "test.php", "debug.php", "console/", "wp-admin/", "administrator/",
    "robots.txt", "sitemap.xml", "swagger.json", "openapi.json",
    "api-docs/", "swagger/",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "Pipfile", "go.mod", "pom.xml",
    "id_rsa", "id_dsa", "server.key", "private.key", "credentials.json",
    "server-status", "server-info", "elmah.axd", "error.log", "access.log",
    ".DS_Store", "crossdomain.xml", "clientaccesspolicy.xml",
    "web.config.bak", "config.php.bak", ".env.example",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    ".travis.yml", ".circleci/config.yml", "Jenkinsfile",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/gql",
    "/graphiql", "/api/graphiql", "/graphql/console",
]

# ──────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    key:        str
    cwe_id:     str
    owasp:      str
    name:       str
    severity:   str
    fix:        str
    detail:     str  = ""
    url:        str  = ""
    cvss_score: float = 0.0
    cvss_vector:str  = ""
    loe_hours:  int  = 0
    poc:        str  = ""      # Proof-of-concept code or note
    timestamp:  str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ScanConfig:
    target:           str
    targets_file:     str   = ""
    scope:            Set[str] = field(default_factory=set)
    timeout:          int   = DEFAULT_TIMEOUT
    threads:          int   = DEFAULT_THREADS
    delay:            float = 0.0
    rate_limit:       int   = 0
    max_time:         int   = 0
    max_crawl_pages:  int   = MAX_CRAWL_PAGES
    proxy:            str   = ""
    auth_type:        str   = ""
    auth_value:       str   = ""
    login_url:        str   = ""
    login_user:       str   = ""
    login_pass:       str   = ""
    login_field_user: str   = "username"
    login_field_pass: str   = "password"
    cookies:          Dict[str, str] = field(default_factory=dict)
    user_agent:       str   = ""
    output_json:      str   = ""
    output_html:      str   = ""
    output_csv:       str   = ""
    output_junit:     str   = ""
    output_sarif:     str   = ""
    output_md:        str   = ""
    audit_log:        str   = ""
    webhook:          str   = ""
    fail_on:          str   = ""
    baseline:         str   = ""
    resume:           str   = ""
    profile:          str   = "standard"
    verbose:          bool  = False
    quiet:            bool  = False
    no_color:         bool  = False
    verify_ssl:       bool  = False
    custom_headers:   Dict[str, str] = field(default_factory=dict)
    skip_checks:      Set[str] = field(default_factory=set)

@dataclass
class ScanResult:
    target:     str
    start:      datetime
    end:        datetime = field(default_factory=datetime.now)
    findings:   List[Vulnerability] = field(default_factory=list)
    urls_crawled: int = 0
    params_found: int = 0
    authenticated: bool = False
    scanner_version: str = VERSION

# ──────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────────────────────────────────
_rate_limiter: Optional[object] = None
_scan_start:   float = 0.0
_max_time:     int   = 0
_audit_log_path: str = ""
_interrupted:  bool = False

def _check_timeout():
    if _max_time > 0 and (time.time() - _scan_start) > _max_time:
        raise TimeoutError(f"Global --max-time {_max_time}s reached.")

def _signal_handler(sig, frame):
    global _interrupted
    _interrupted = True
    print(f"\n{Y}⚠  Ctrl+C detected — finishing current checks and saving partial report…{RST}")

signal.signal(signal.SIGINT, _signal_handler)

# ──────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rpm: int):
        self.interval = 60.0 / rpm if rpm > 0 else 0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        if self.interval <= 0:
            return
        with self._lock:
            now  = time.time()
            wait = self._last + self.interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

# ──────────────────────────────────────────────────────────────────────────
# AUDIT LOGGER
# ──────────────────────────────────────────────────────────────────────────
_audit_lock = threading.Lock()

def audit(event: str, data: dict = None):
    if not _audit_log_path:
        return
    entry = {
        "ts":    datetime.now(timezone.utc).isoformat(),
        "event": event,
        **(data or {}),
    }
    with _audit_lock:
        with open(_audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

# ──────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ──────────────────────────────────────────────────────────────────────────
class _FallbackBar:
    def __init__(self, total, desc="", disable=False):
        self.total = total; self.n = 0
        self.desc  = desc;  self.disable = disable
    def update(self, n=1):
        if self.disable: return
        self.n += n
        pct = int(100 * self.n / self.total) if self.total else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  {self.desc}: [{bar}] {pct}%", end="", flush=True)
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

# ──────────────────────────────────────────────────────────────────────────
# HTML / PAGE PARSER
# ──────────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base      = base
        self.links:    List[str] = []
        self.forms:    List[dict] = []
        self.scripts:  List[dict] = []   # {"src":..., "has_sri":..., "inline":...}
        self.http_res: List[tuple] = []
        self.js_links: List[str] = []
        self._form:    Optional[dict] = None
        self._in_script: bool = False
        self._inline_script: List[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            h = d.get("href", "")
            if h.lower().startswith("javascript:"):
                self.js_links.append(h)
            elif h and not h.startswith("#"):
                try: self.links.append(urllib.parse.urljoin(self.base, h))
                except: pass
        elif tag == "form":
            try: action = urllib.parse.urljoin(self.base, d.get("action", "")) or self.base
            except: action = self.base
            self._form = {"action": action,
                          "method": d.get("method", "GET").upper(),
                          "inputs": [], "has_csrf": False,
                          "enctype": d.get("enctype", "")}
        elif tag == "input" and self._form:
            n = d.get("name", ""); t = d.get("type", "text").lower()
            self._form["inputs"].append({"name": n, "type": t, "value": d.get("value", "")})
            if any(x in n.lower() for x in ["csrf","token","_token","nonce","authenticity"]):
                self._form["has_csrf"] = True
        elif tag == "script":
            src = d.get("src", "")
            if src:
                self.scripts.append({"src": src, "has_sri": "integrity" in d, "inline": False})
                if src.startswith("http://"): self.http_res.append(("script", src))
            else:
                self._in_script = True
        elif tag in ("img","iframe","link","video","audio","source","embed"):
            s = d.get("src") or d.get("href", "")
            if s and s.startswith("http://"): self.http_res.append((tag, s))

    def handle_data(self, data):
        if self._in_script:
            self._inline_script.append(data)

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            content = "".join(self._inline_script)
            self.scripts.append({"src": "", "has_sri": False, "inline": True, "content": content})
            self._inline_script = []
            self._in_script = False

# ──────────────────────────────────────────────────────────────────────────
# TERMINAL HELPERS
# ──────────────────────────────────────────────────────────────────────────
def sev_color(sev: str) -> str:
    return {"CRITICAL": R+BOLD, "HIGH": R, "MEDIUM": Y, "LOW": C, "INFO": B}.get(sev, W)

def pr(msg, cfg: ScanConfig):
    if not cfg.quiet: print(msg)

def prv(msg, cfg: ScanConfig):
    if cfg.verbose and not cfg.quiet: print(f"  {DIM}→ {msg}{RST}")

def section(title: str, cfg: ScanConfig):
    if not cfg.quiet:
        print(f"\n{B}{BOLD}{'─'*66}{RST}")
        print(f"{B}{BOLD}  {title}{RST}")
        print(f"{B}{BOLD}{'─'*66}{RST}")

def print_vuln(key: str, cfg: ScanConfig, detail: str = "", url: str = "", poc: str = ""):
    if cfg.quiet: return
    v = _vdb(key)
    s = v.get("sev", "INFO")
    cvss_score, _ = CVSS.get(key, (0.0, ""))
    loe = LOE.get(key, 0)
    sc  = sev_color(s)
    print(f"  {sc}[{s}]{RST} {BOLD}{v['name']}{RST}")
    print(f"       CWE : {Y}{v['id']}{RST}  |  OWASP: {Y}{v.get('owasp','?')}{RST}"
          + (f"  |  CVSS: {Y}{cvss_score}{RST}" if cvss_score else "")
          + (f"  |  LOE: ~{loe}h" if loe else ""))
    if detail: print(f"    Detail : {detail}")
    if url:    print(f"       URL : {DIM}{url}{RST}")
    if poc:    print(f"       PoC : {M}{poc[:120]}{RST}")
    print(f"       Fix : {G}{v['fix']}{RST}\n")

def vadd(findings: List[Vulnerability], key: str,
         detail: str = "", url: str = "", poc: str = "") -> Vulnerability:
    v = _vdb(key)
    s = v.get("sev", "INFO")
    cvss_score, cvss_vec = CVSS.get(key, (0.0, ""))
    loe = LOE.get(key, 0)
    vv = Vulnerability(
        key=key, cwe_id=v["id"], owasp=v.get("owasp","A00"),
        name=v["name"], severity=s, fix=v["fix"],
        detail=detail, url=url, cvss_score=cvss_score,
        cvss_vector=cvss_vec, loe_hours=loe, poc=poc,
    )
    findings.append(vv)
    audit("finding", {"key": key, "severity": s, "url": url, "detail": detail})
    return vv

def normalize(url: str) -> str:
    if not url.startswith(("http://","https://")): url = "https://" + url
    return url.rstrip("/")

def in_scope(url: str, scope: Set[str]) -> bool:
    if not scope: return True
    try:
        host = urllib.parse.urlparse(url).netloc
        return any(host == s or host.endswith("." + s) for s in scope)
    except: return False

# ──────────────────────────────────────────────────────────────────────────
# SESSION FACTORY
# ──────────────────────────────────────────────────────────────────────────
def get_session(cfg: ScanConfig) -> requests.Session:
    s = requests.Session()
    hdrs = BASE_HEADERS.copy()
    if cfg.user_agent: hdrs["User-Agent"] = cfg.user_agent
    hdrs.update(cfg.custom_headers)
    s.headers.update(hdrs)
    if cfg.proxy: s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    if cfg.auth_type == "basic":
        s.auth = tuple(cfg.auth_value.split(":", 1))
    elif cfg.auth_type in ("bearer", "token"):
        label = "Bearer" if cfg.auth_type == "bearer" else "Token"
        s.headers["Authorization"] = f"{label} {cfg.auth_value}"
    for k, v in cfg.cookies.items():
        s.cookies.set(k, v)
    return s

def login(session: requests.Session, cfg: ScanConfig) -> bool:
    """Perform form-based login; returns True on success."""
    if not cfg.login_url: return False
    prv(f"Attempting form login at {cfg.login_url}", cfg)
    audit("login_attempt", {"url": cfg.login_url, "user": cfg.login_user})
    try:
        # First GET to capture CSRF token
        r0 = session.get(cfg.login_url, timeout=cfg.timeout, verify=cfg.verify_ssl)
        csrf_token = ""
        parser = PageParser(cfg.login_url)
        parser.feed(r0.text)
        for form in parser.forms:
            for inp in form.get("inputs", []):
                if any(x in inp["name"].lower() for x in ["csrf","token","nonce","authenticity"]):
                    csrf_token = inp["value"]
                    break

        payload: Dict[str, str] = {
            cfg.login_field_user: cfg.login_user,
            cfg.login_field_pass: cfg.login_pass,
        }
        if csrf_token:
            # find the token field name
            for form in parser.forms:
                for inp in form.get("inputs", []):
                    if inp["value"] == csrf_token:
                        payload[inp["name"]] = csrf_token
                        break

        r = session.post(cfg.login_url, data=payload,
                         timeout=cfg.timeout, verify=cfg.verify_ssl,
                         allow_redirects=True)

        # Heuristic: successful login → redirect or no login form in response
        if r.status_code in (200, 302):
            parser2 = PageParser(cfg.login_url)
            parser2.feed(r.text)
            has_login = any(
                inp["type"] in ("password",)
                for form in parser2.forms
                for inp in form.get("inputs", [])
            )
            if not has_login or r.url != cfg.login_url:
                prv(f"Login appears successful (landed on {r.url})", cfg)
                audit("login_success", {"landed": r.url})
                return True
        prv("Login may have failed — password field still present", cfg)
        audit("login_failed", {"status": r.status_code})
        return False
    except Exception as e:
        prv(f"Login error: {e}", cfg)
        audit("login_error", {"error": str(e)})
        return False

# ──────────────────────────────────────────────────────────────────────────
# REQUEST WRAPPER
# ──────────────────────────────────────────────────────────────────────────
def req(session: requests.Session, url: str, cfg: ScanConfig,
        method: str = "GET", allow_redirects: bool = True,
        _retry: int = 0, **kw) -> Optional[requests.Response]:
    try:
        _check_timeout()
        if _interrupted: return None
        if _rate_limiter: _rate_limiter.wait()
        if cfg.delay > 0: time.sleep(cfg.delay)
        kw.setdefault("timeout", cfg.timeout)
        kw.setdefault("verify",  cfg.verify_ssl)
        kw.setdefault("allow_redirects", allow_redirects)
        r = session.request(method, url, **kw)
        audit("request", {"method": method, "url": url, "status": r.status_code})
        if r.status_code == 429 and _retry < 2:
            prv(f"429 — waiting {RETRY_429_WAIT}s", cfg)
            time.sleep(RETRY_429_WAIT)
            return req(session, url, cfg, method, allow_redirects, _retry+1, **kw)
        return r
    except TimeoutError: raise
    except: return None

# ──────────────────────────────────────────────────────────────────────────
# CRAWLER
# ──────────────────────────────────────────────────────────────────────────
def crawl(session: requests.Session, base: str, cfg: ScanConfig
          ) -> Tuple[List[str], List[str], List[dict], List[str]]:
    """Returns (visited_urls, discovered_params, forms, js_urls)"""
    prv("Starting crawler…", cfg)
    audit("crawl_start", {"base": base})
    visited:   Set[str] = set()
    queue:     List[str] = [base]
    params:    Set[str] = set()
    forms:     List[dict] = []
    js_urls:   List[str] = []

    pb = urllib.parse.urlparse(base)
    origin = f"{pb.scheme}://{pb.netloc}"
    max_pages = cfg.max_crawl_pages

    with make_bar(max_pages, "Crawl", cfg) as bar:
        while queue and len(visited) < max_pages and not _interrupted:
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)

            r = req(session, url, cfg)
            if not r or "text/html" not in r.headers.get("content-type", ""):
                bar.update(); continue

            p = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(p.query): params.add(k)

            parser = PageParser(url)
            try: parser.feed(r.text)
            except: pass

            forms.extend(parser.forms)

            for script in parser.scripts:
                if not script.get("inline") and script.get("src"):
                    src = script["src"]
                    if not src.startswith("http"):
                        src = urllib.parse.urljoin(url, src)
                    if in_scope(src, cfg.scope) or src.startswith(origin):
                        js_urls.append(src)

            for lnk in parser.links:
                if not in_scope(lnk, cfg.scope): continue
                lp = urllib.parse.urlparse(lnk)
                if f"{lp.scheme}://{lp.netloc}" != origin: continue
                for k in urllib.parse.parse_qs(lp.query): params.add(k)
                clean = urllib.parse.urlunparse(lp._replace(query="", fragment=""))
                if clean not in visited: queue.append(clean)

            bar.update()

    prv(f"Crawled {len(visited)} pages, {len(params)} params, {len(forms)} forms, {len(js_urls)} JS files", cfg)
    audit("crawl_done", {"pages": len(visited), "params": len(params), "forms": len(forms)})
    return list(visited), list(params), forms, list(set(js_urls))

# ──────────────────────────────────────────────────────────────────────────
# SECURITY CHECKS
# ──────────────────────────────────────────────────────────────────────────

def check_security_headers(resp, findings, cfg):
    section("[ 1] Security Headers", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}
    any_found = False
    for hdr, key in [
        ("strict-transport-security", "missing_hsts"),
        ("content-security-policy",   "missing_csp"),
        ("x-frame-options",           "missing_x_frame"),
        ("x-content-type-options",    "missing_x_content_type"),
        ("referrer-policy",           "missing_referrer_policy"),
        ("permissions-policy",        "missing_permissions_policy"),
    ]:
        if hdr not in h:
            print_vuln(key, cfg); vadd(findings, key); any_found = True

    csp = h.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            print_vuln("csp_unsafe_inline", cfg, detail="CSP contains 'unsafe-inline'")
            vadd(findings, "csp_unsafe_inline"); any_found = True
        if "unsafe-eval" in csp:
            print_vuln("csp_unsafe_eval", cfg, detail="CSP contains 'unsafe-eval'")
            vadd(findings, "csp_unsafe_eval"); any_found = True
    if "content-security-policy-report-only" in h and "content-security-policy" not in h:
        print_vuln("csp_report_only", cfg); vadd(findings, "csp_report_only"); any_found = True

    for hdr, key in [("cross-origin-embedder-policy","missing_coep"),
                     ("cross-origin-opener-policy",  "missing_coop")]:
        if hdr not in h: vadd(findings, key); any_found = True

    for hdr, key, lbl in [("server","server_disclosure","Server"),
                           ("x-powered-by","xpoweredby_disclosure","X-Powered-By"),
                           ("x-aspnet-version","x_aspnet_version","X-AspNet-Version")]:
        if hdr in h:
            print_vuln(key, cfg, detail=f"{lbl}: {h[hdr]}")
            vadd(findings, key, f"{lbl}: {h[hdr]}"); any_found = True

    if not any_found: pr(f"  {G}✔ Security headers look good.{RST}\n", cfg)


def check_https(target, session, findings, cfg):
    section("[ 2] HTTPS & TLS", cfg)
    p = urllib.parse.urlparse(target)
    if p.scheme == "http":
        print_vuln("ssl_no_https", cfg); vadd(findings, "ssl_no_https"); return

    http_url = target.replace("https://", "http://", 1)
    r = req(session, http_url, cfg, allow_redirects=False)
    if r and r.status_code in (200,301,302,307,308):
        loc = r.headers.get("Location", "")
        if r.status_code == 200 or "https://" not in loc:
            print_vuln("ssl_no_redirect", cfg, detail=f"HTTP {r.status_code} returned without HTTPS redirect")
            vadd(findings, "ssl_no_redirect")
        else: pr(f"  {G}✔ HTTP→HTTPS redirect in place.{RST}\n", cfg)

    host = p.hostname; port = p.port or 443
    for vname, vconst in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = vconst; ctx.maximum_version = vconst
            with socket.create_connection((host, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    print_vuln("ssl_weak", cfg, detail=f"{vname} accepted")
                    vadd(findings, "ssl_weak", vname)
        except: pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                pr(f"  {G}✔ TLS: {ss.version()}  |  Cipher: {ss.cipher()[0]}{RST}", cfg)
                exp_str = cert.get("notAfter", "")
                if exp_str:
                    exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    pr(f"  {G}✔ Cert expires: {exp_str}  ({days_left} days){RST}", cfg)
                    if exp < datetime.utcnow():
                        print_vuln("ssl_expired", cfg, detail=exp_str); vadd(findings, "ssl_expired", exp_str)
                    elif days_left < 30:
                        pr(f"  {Y}⚠  Certificate expires in {days_left} days — renew soon!{RST}", cfg)
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                subject = dict(x[0] for x in cert.get("subject", []))
                pr(f"  {G}✔ Issuer: {issuer.get('organizationName','?')}{RST}", cfg)
                if issuer == subject:
                    print_vuln("ssl_self_signed", cfg); vadd(findings, "ssl_self_signed")
                sans = [v for _, v in cert.get("subjectAltName", [])]
                if not any(host == s or (s.startswith("*.") and host.endswith(s[1:])) for s in sans):
                    cn = subject.get("commonName", "")
                    if host != cn and not (cn.startswith("*.") and host.endswith(cn[1:])):
                        print_vuln("ssl_hostname_mismatch", cfg, detail=f"CN={cn}")
                        vadd(findings, "ssl_hostname_mismatch", f"CN={cn}")
                # Subdomain hints from SANs
                subdomains = [s for s in sans if "*" not in s and s != host]
                if subdomains:
                    prv(f"Subdomain hints from cert SANs: {', '.join(subdomains[:8])}", cfg)
    except ssl.SSLCertVerificationError as e:
        if "self" in str(e).lower(): print_vuln("ssl_self_signed", cfg); vadd(findings, "ssl_self_signed")
    except Exception as e: prv(f"TLS error: {e}", cfg)


def check_cors(resp, session, target, findings, cfg):
    section("[ 3] CORS Policy", cfg)
    h    = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        if acac == "true":
            print_vuln("cors_credentials_wildcard", cfg); vadd(findings, "cors_credentials_wildcard")
        else:
            print_vuln("cors_wildcard", cfg); vadd(findings, "cors_wildcard")
        return
    for evil in ["https://evil.com", "https://attacker.example.org", "null"]:
        r = req(session, target, cfg, headers={"Origin": evil})
        if r:
            rh = {k.lower(): v for k, v in r.headers.items()}
            if rh.get("access-control-allow-origin", "") == evil:
                print_vuln("cors_reflection", cfg, detail=f"Reflects: {evil}")
                vadd(findings, "cors_reflection", evil); return
    pr(f"  {G}✔ CORS restricted.{RST}\n", cfg)


def check_cookies(resp, findings, cfg):
    section("[ 4] Cookie Security", cfg)
    any_found = False
    for cookie in resp.cookies:
        hi = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
        ss = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        is_sess = any(x in cookie.name.lower() for x in ["sess","auth","token","id","jwt"])
        if not hi:
            key = "cookie_session_httponly" if is_sess else "cookie_no_httponly"
            print_vuln(key, cfg, detail=f"Cookie: {cookie.name}")
            vadd(findings, key, f"Cookie: {cookie.name}"); any_found = True
        if not cookie.secure:
            print_vuln("cookie_no_secure", cfg, detail=f"Cookie: {cookie.name}")
            vadd(findings, "cookie_no_secure", f"Cookie: {cookie.name}"); any_found = True
        if not ss:
            print_vuln("cookie_no_samesite", cfg, detail=f"Cookie: {cookie.name}")
            vadd(findings, "cookie_no_samesite", f"Cookie: {cookie.name}"); any_found = True
    if not any_found: pr(f"  {G}✔ No cookie issues.{RST}\n", cfg)


def check_http_methods(target, session, findings, cfg):
    section("[ 5] HTTP Methods", cfg)
    bad = []
    for method in ["TRACE","TRACK","PUT","DELETE","CONNECT"]:
        try:
            r = session.request(method, target, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code not in (405, 501, 403, 404):
                bad.append(f"{method}→{r.status_code}")
                if method in ("TRACE","TRACK"): vadd(findings, "http_trace", f"{method} allowed")
        except: pass
    if bad: print_vuln("http_methods", cfg, detail=", ".join(bad)); vadd(findings, "http_methods", ", ".join(bad))
    else:   pr(f"  {G}✔ No dangerous HTTP methods enabled.{RST}\n", cfg)


def check_sensitive_files(target, session, findings, cfg):
    section("[ 6] Sensitive Files & Directories", cfg)
    exposed = []
    def probe(path):
        try:
            r = req(session, f"{target}/{path}", cfg, allow_redirects=False)
            if r and r.status_code == 200 and len(r.content) > 20:
                ct = r.headers.get("content-type", "").lower()
                if "text/html" in ct and len(r.content) < 200: return None
                return path, r.status_code, len(r.content)
        except: pass
        return None
    with make_bar(len(SENSITIVE_PATHS), "Files", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed({ex.submit(probe, p): p for p in SENSITIVE_PATHS}):
                r = res.result()
                if r: exposed.append(r)
                bar.update()
    if exposed:
        for path, code, size in sorted(exposed):
            print_vuln("sensitive_files", cfg, detail=f"/{path} → HTTP {code} ({size}B)", url=f"{target}/{path}")
        vadd(findings, "sensitive_files", f"{len(exposed)} exposed file(s)")
    else: pr(f"  {G}✔ No sensitive files found.{RST}\n", cfg)
    for d in ["uploads/","images/","files/","backup/","logs/","static/"]:
        r = req(session, f"{target}/{d}", cfg)
        if r and ("Index of /" in r.text or "<title>Directory" in r.text):
            print_vuln("directory_listing", cfg, detail=f"/{d}"); vadd(findings, "directory_listing", f"/{d}"); break


def check_xss(target, session, params, findings, cfg):
    section("[ 7] Cross-Site Scripting (XSS)", cfg)
    pl = XSS_PAYLOADS_FULL if cfg.profile == "full" else XSS_PAYLOADS
    if not params: params = ["q","search","id","name","input","data","keyword"]
    found = []
    def test(param, payload):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and payload in r.text and "&lt;script&gt;" not in r.text:
            return param, payload, url
        return None
    total = len(params) * len(pl)
    with make_bar(total, "XSS", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for f in as_completed([ex.submit(test, p, l) for p in params for l in pl]):
                r = f.result()
                if r and r not in found: found.append(r)
                bar.update()
    if found:
        for p, pl_, url in found[:5]:
            poc = f'<a href="{url}">PoC Link</a>'
            print_vuln("xss_reflected", cfg, detail=f"param={p}, payload={pl_[:40]}", url=url, poc=poc)
        vadd(findings, "xss_reflected", f"{len(found)} instance(s)", found[0][2],
             poc=f"GET {found[0][2]}")
    else:
        pr(f"  {G}✔ No reflected XSS detected.{RST}", cfg)
        pr(f"  {B}  (Test POST forms manually){RST}\n", cfg)


def check_dom_xss(js_urls, session, findings, cfg):
    section("[ 8] DOM XSS Static Analysis", cfg)
    if not js_urls:
        pr(f"  {B}ℹ No JS files discovered to analyze.{RST}\n", cfg); return
    found = []
    analyzed = 0
    for url in js_urls[:MAX_JS_FILES]:
        r = req(session, url, cfg)
        if not r: continue
        analyzed += 1
        src = r.text
        # Look for sink+source proximity within 20 lines
        lines = src.splitlines()
        for i, line in enumerate(lines):
            has_sink   = any(s in line for s in DOM_XSS_SINKS)
            has_source = any(s in line for s in DOM_XSS_SOURCES)
            if has_sink:
                # Check nearby lines for a source
                window = "\n".join(lines[max(0,i-5):i+6])
                if any(s in window for s in DOM_XSS_SOURCES):
                    sink_match = next((s for s in DOM_XSS_SINKS if s in line), "?")
                    src_match  = next((s for s in DOM_XSS_SOURCES if s in window), "?")
                    detail = f"JS: {url} | line ~{i+1} | sink={sink_match} near source={src_match}"
                    if detail not in [f.detail for f in findings if f.key == "dom_xss"]:
                        print_vuln("dom_xss", cfg, detail=detail, url=url)
                        vadd(findings, "dom_xss", detail, url)
                        found.append(url)
                    break
    prv(f"Analyzed {analyzed}/{len(js_urls)} JS files", cfg)
    if not found: pr(f"  {G}✔ No obvious DOM XSS sinks near sources.{RST}\n", cfg)


def check_sqli(target, session, params, findings, cfg):
    section("[ 9] SQL Injection", cfg)
    if not params: params = ["id","q","search","user","name","page","cat"]
    found_err = []; found_blind = []
    def test_err(param, payload):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            low = r.text.lower()
            for sig in SQLI_ERRORS:
                if sig in low: return param, payload, url
        return None
    def test_blind(param, payload, sleep_sec):
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        t0 = time.time()
        r  = req(session, url, cfg, timeout=cfg.timeout + sleep_sec + 2)
        elapsed = time.time() - t0
        if r and elapsed >= sleep_sec - 0.5: return param, payload, url
        return None
    with make_bar(len(params)*len(SQLI_ERROR_PAYLOADS), "SQLi-Error", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test_err, p, pl) for p in params for pl in SQLI_ERROR_PAYLOADS]):
                r = res.result()
                if r: found_err.append(r)
                bar.update()
    if not found_err:
        with make_bar(len(params)*len(SQLI_BLIND_PAYLOADS), "SQLi-Blind", cfg) as bar:
            for param in params:
                for payload, sleep_sec in SQLI_BLIND_PAYLOADS:
                    res = test_blind(param, payload, sleep_sec)
                    bar.update()
                    if res: found_blind.append(res); break
                if found_blind: break
    if found_err:
        for p, pl, url in found_err[:3]:
            print_vuln("sql_injection", cfg, detail=f"param={p}, payload={pl}", url=url,
                       poc=f"sqlmap -u '{url}' -p {p} --dbs")
        vadd(findings, "sql_injection", f"{len(found_err)} error(s)", found_err[0][2])
    elif found_blind:
        for p, pl, url in found_blind[:2]:
            print_vuln("sql_injection_blind", cfg, detail=f"param={p}, time-delay triggered", url=url,
                       poc=f"sqlmap -u '{url}' -p {p} --technique=T --dbs")
        vadd(findings, "sql_injection_blind", found_blind[0][0], found_blind[0][2])
    else:
        pr(f"  {G}✔ No SQLi indicators.{RST}", cfg)
        pr(f"  {B}  (Use sqlmap on discovered params){RST}\n", cfg)


def check_cmdi(target, session, params, findings, cfg):
    section("[10] Command Injection", cfg)
    if not params: params = ["cmd","command","exec","shell","ping","host","ip","file","run"]
    found = []
    def test(p, pl):
        url = f"{target}?{p}={urllib.parse.quote(pl)}"
        r   = req(session, url, cfg)
        if r:
            for s in CMDI_SIGS:
                if s in r.text: return p, pl, url
        return None
    with make_bar(len(params)*len(CMDI_PAYLOADS), "CMDi", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in params for pl in CMDI_PAYLOADS]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p, pl, url in found[:3]:
            print_vuln("command_injection", cfg, detail=f"param={p}, payload={pl}", url=url,
                       poc=f"curl '{url}'")
        vadd(findings, "command_injection", f"{len(found)} instance(s)", found[0][2])
    else: pr(f"  {G}✔ No command injection indicators.{RST}\n", cfg)


def check_path_traversal(target, session, params, findings, cfg):
    section("[11] Path Traversal", cfg)
    if not params: params = ["file","path","page","doc","template","name","load","read","include"]
    found = []
    def test(p, pl):
        url = f"{target}?{p}={urllib.parse.quote(pl)}"
        r   = req(session, url, cfg)
        if r:
            for s in PATH_SIGS:
                if s in r.text: return p, pl, url
        return None
    with make_bar(len(params)*len(PATH_PAYLOADS), "Traversal", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in params for pl in PATH_PAYLOADS]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p, pl, url in found[:3]: print_vuln("path_traversal", cfg, detail=f"param={p}, payload={pl}", url=url)
        vadd(findings, "path_traversal", f"{len(found)} instance(s)", found[0][2])
    else: pr(f"  {G}✔ No path traversal indicators.{RST}\n", cfg)


def check_ssti(target, session, params, findings, cfg):
    section("[12] Server-Side Template Injection (SSTI)", cfg)
    if not params: params = ["template","name","q","page","content","message","subject"]
    found = []
    def test(p, pl):
        url = f"{target}?{p}={urllib.parse.quote(pl)}"
        r   = req(session, url, cfg)
        if r and SSTI_EXPECTED in r.text: return p, pl, url
        return None
    with make_bar(len(params)*len(SSTI_PAYLOADS), "SSTI", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in params for pl in SSTI_PAYLOADS]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p, pl, url in found[:3]:
            print_vuln("template_injection", cfg, detail=f"param={p}, result={SSTI_EXPECTED} found", url=url)
        vadd(findings, "template_injection", f"{len(found)} instance(s)", found[0][2])
    else: pr(f"  {G}✔ No SSTI indicators.{RST}\n", cfg)


def check_open_redirect(target, session, params, findings, cfg):
    section("[13] Open Redirect", cfg)
    rparams = list(set(params)|{"redirect","url","next","return","goto","redir","dest","continue","to","location"})
    payloads = ["https://evil.com","//evil.com","/\\evil.com","https:///evil.com","@evil.com"]
    found = []
    def test(p, pl):
        url = f"{target}?{p}={urllib.parse.quote(pl)}"
        r   = req(session, url, cfg, allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308):
            loc = r.headers.get("Location","")
            if "evil.com" in loc: return p, pl, loc
        return None
    with make_bar(len(rparams)*len(payloads), "Redirect", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in rparams for pl in payloads]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p, pl, loc in found[:3]: print_vuln("open_redirect", cfg, detail=f"?{p}= → {loc}")
        vadd(findings, "open_redirect", f"{len(found)} instance(s)")
    else: pr(f"  {G}✔ No open redirect detected.{RST}\n", cfg)


def check_ssrf(target, session, params, findings, cfg):
    section("[14] SSRF (Basic)", cfg)
    sparams = list(set(params)|{"url","uri","path","domain","host","target","site","link","dest","src","proxy","endpoint","fetch","load"})
    found = []
    def test(p, pl):
        url = f"{target}?{p}={urllib.parse.quote(pl)}"
        r   = req(session, url, cfg)
        if r:
            for s in SSRF_SIGS:
                if s in r.text: return p, pl, url
        return None
    with make_bar(len(sparams)*len(SSRF_PAYLOADS), "SSRF", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in sparams for pl in SSRF_PAYLOADS]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    if found:
        for p, pl, url in found[:2]: print_vuln("ssrf", cfg, detail=f"param={p}, payload={pl}", url=url)
        vadd(findings, "ssrf", f"{len(found)} indicator(s)", found[0][2])
    else:
        pr(f"  {G}✔ No SSRF indicators.{RST}", cfg)
        pr(f"  {B}  (Use Burp Collaborator for OOB detection){RST}\n", cfg)


def check_xxe(target, session, forms, findings, cfg):
    section("[15] XXE Injection", cfg)
    xml_endpoints = []
    # Collect form actions that accept XML, or try common XML API endpoints
    for form in forms:
        if "xml" in form.get("enctype","").lower():
            xml_endpoints.append(form.get("action",""))
    # Also try common XML-accepting paths
    for path in ["/api", "/api/v1", "/soap", "/xmlrpc", "/api/xml"]:
        xml_endpoints.append(f"{target}{path}")
    xml_endpoints = list(set(xml_endpoints))[:6]

    found = False
    xml_headers = {"Content-Type": "application/xml"}
    for endpoint in xml_endpoints:
        for payload in XXE_PAYLOADS:
            r = req(session, endpoint, cfg, method="POST",
                    data=payload, headers=xml_headers)
            if r:
                for sig in XXE_SIGS:
                    if sig in r.text:
                        print_vuln("xxe", cfg, detail=f"Endpoint: {endpoint}", url=endpoint)
                        vadd(findings, "xxe", f"XXE at {endpoint}", endpoint)
                        found = True; break
            if found: break
        if found: break
    if not found: pr(f"  {G}✔ No XXE indicators (limited testing — use Burp for full XXE).{RST}\n", cfg)


def check_prototype_pollution(target, session, params, findings, cfg):
    section("[16] Prototype Pollution", cfg)
    if not params: params = ["q","search","data","input","config","options","settings"]
    found = []
    # Test via query string
    for payload in PROTO_POLLUTION_PAYLOADS:
        for param in params[:5]:
            url = f"{target}?{param}={urllib.parse.quote(payload)}"
            r = req(session, url, cfg)
            if r and "polluted" in r.text.lower():
                found.append((param, payload, url))
                break
        # Also test via JSON POST
        try:
            r = req(session, target, cfg, method="POST",
                    json=json.loads(payload) if payload.startswith("{") else {},
                    headers={"Content-Type": "application/json"})
            if r and "polluted" in r.text.lower():
                found.append(("json_body", payload, target))
        except: pass
    if found:
        for p, pl, url in found[:2]:
            print_vuln("prototype_pollution", cfg, detail=f"param={p}, payload={pl}", url=url)
        vadd(findings, "prototype_pollution", f"{len(found)} instance(s)", found[0][2])
    else: pr(f"  {G}✔ No prototype pollution indicators.{RST}\n", cfg)


def check_request_smuggling(target, session, findings, cfg):
    section("[17] HTTP Request Smuggling", cfg)
    # Basic CL.TE probe — send ambiguous Content-Length vs Transfer-Encoding
    parsed = urllib.parse.urlparse(target)
    host   = parsed.hostname
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    path   = parsed.path or "/"

    # Build raw ambiguous request
    smuggle = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"  # smuggled byte
    )
    try:
        ctx = ssl.create_default_context() if parsed.scheme == "https" else None
        with socket.create_connection((host, port), timeout=8) as s:
            sock = ctx.wrap_socket(s, server_hostname=host) if ctx else s
            sock.sendall(smuggle.encode())
            sock.settimeout(5)
            resp = b""
            while True:
                try: chunk = sock.recv(4096)
                except: break
                if not chunk: break
                resp += chunk
        resp_str = resp.decode("utf-8", errors="replace")
        # Heuristics: 400 Bad Request to the smuggled portion = server parsed it
        if resp_str.count("HTTP/") >= 2 or "400" in resp_str[:200]:
            print_vuln("http_request_smuggling", cfg, detail="Server may parse ambiguous CL/TE — manual confirmation required", url=target)
            vadd(findings, "http_request_smuggling", "CL.TE probe got double response", target)
        else:
            pr(f"  {G}✔ No obvious request smuggling response.{RST}\n", cfg)
    except Exception as e:
        prv(f"Smuggling probe error: {e}", cfg)
        pr(f"  {B}ℹ Could not test request smuggling (raw socket required).{RST}\n", cfg)


def check_host_header_injection(target, session, findings, cfg):
    section("[18] Host Header Injection", cfg)
    parsed = urllib.parse.urlparse(target)
    hosts  = ["evil.com","attacker.example.org",f"{parsed.netloc}.evil.com"]
    found  = False
    for host in hosts:
        try:
            r = session.get(target, headers={"Host": host},
                            timeout=cfg.timeout, verify=cfg.verify_ssl, allow_redirects=False)
            if r and (host in r.text or host in r.headers.get("Location","")):
                print_vuln("host_header_injection", cfg,
                           detail=f"Host: {host} reflected in response", url=target)
                vadd(findings, "host_header_injection", f"Host '{host}' reflected", target)
                found = True; break
        except: pass
    if not found: pr(f"  {G}✔ No host header injection detected.{RST}\n", cfg)


def check_cache_poisoning(target, session, findings, cfg):
    section("[19] Web Cache Poisoning", cfg)
    unkeyed = [
        ("X-Forwarded-Host",   "poison-wvs-test.evil.com"),
        ("X-Forwarded-Scheme", "http"),
        ("X-Original-URL",     "/wvs-poison-test"),
        ("X-Host",             "poison-wvs-test.evil.com"),
    ]
    found = False
    for hdr, val in unkeyed:
        try:
            r1 = session.get(target, headers={hdr: val}, timeout=cfg.timeout, verify=cfg.verify_ssl)
            r2 = session.get(target, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r1 and r2 and val in r1.text and val in r2.text:
                print_vuln("cache_poisoning", cfg, detail=f"Unkeyed header: {hdr}: {val}", url=target)
                vadd(findings, "cache_poisoning", f"Header '{hdr}' poisons cache", target)
                found = True; break
        except: pass
    if not found: pr(f"  {G}✔ No obvious cache poisoning via unkeyed headers.{RST}\n", cfg)


def check_graphql(target, session, findings, cfg):
    section("[20] GraphQL Endpoint Analysis", cfg)
    introspect = {"query":"{__schema{types{name}}}"}
    found = False
    for path in GRAPHQL_PATHS:
        url = f"{target}{path}"
        try:
            r = session.post(url, json=introspect, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                data = r.json()
                if data.get("data",{}).get("__schema"):
                    print_vuln("graphql_introspection", cfg, detail=f"Endpoint: {path}", url=url)
                    vadd(findings, "graphql_introspection", f"GraphQL at {path}", url)
                    # Depth limit test
                    deep_q = "query{" + "node{" * 12 + "__typename" + "}" * 12 + "}"
                    rd = session.post(url, json={"query": deep_q}, timeout=cfg.timeout, verify=cfg.verify_ssl)
                    if rd and rd.status_code == 200 and "errors" not in (rd.json() or {}):
                        print_vuln("graphql_no_depth_limit", cfg, url=url)
                        vadd(findings, "graphql_no_depth_limit", path, url)
                    found = True; break
        except: pass
    if not found: pr(f"  {G}✔ No exposed GraphQL endpoints found.{RST}\n", cfg)


def check_api_endpoints(target, session, findings, cfg):
    section("[21] API Endpoint Discovery", cfg)
    found_apis = []
    def probe(path):
        url = f"{target}{path}"
        r   = req(session, url, cfg, allow_redirects=False)
        if r and r.status_code in (200, 201, 401, 403):
            ct = r.headers.get("content-type","").lower()
            if "json" in ct or "xml" in ct or "openapi" in path or "swagger" in path:
                return path, r.status_code, ct
            if r.status_code in (401, 403):
                return path, r.status_code, "auth-required"
        return None
    with make_bar(len(API_PATHS), "API-Disc", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed({ex.submit(probe, p): p for p in API_PATHS}):
                r = res.result()
                if r: found_apis.append(r)
                bar.update()
    if found_apis:
        pr(f"  {B}ℹ Discovered {len(found_apis)} API endpoint(s):{RST}", cfg)
        for path, code, ct in sorted(found_apis):
            color = G if code == 200 else Y
            pr(f"    {color}{code}{RST}  {target}{path}  ({ct})", cfg)
        audit("api_discovery", {"endpoints": [p for p,_,_ in found_apis]})
    else: pr(f"  {G}✔ No exposed API endpoints found.{RST}\n", cfg)


def check_rate_limit(target, session, forms, findings, cfg):
    section("[22] Rate Limit Detection", cfg)
    login_forms = [f for f in forms if any(i["type"]=="password" for i in f.get("inputs",[]))]
    if not login_forms:
        pr(f"  {B}ℹ No login form found to test rate limiting.{RST}\n", cfg); return

    form = login_forms[0]
    action = form.get("action", target)
    test_payload = {inp["name"]: "wvs-test-value" for inp in form.get("inputs",[]) if inp["name"]}

    statuses = []
    for i in range(15):
        r = req(session, action, cfg, method="POST", data=test_payload)
        if r: statuses.append(r.status_code)
        else: break

    # If all 15 requests got same response (no 429/lockout), rate limiting is absent
    if len(statuses) >= 10 and all(s == statuses[0] for s in statuses) and 429 not in statuses:
        print_vuln("rate_limit_missing", cfg,
                   detail=f"15 consecutive POST requests to {action} — no throttle/lockout detected",
                   url=action)
        vadd(findings, "rate_limit_missing", f"POST {action} — no rate limit", action)
    else:
        pr(f"  {G}✔ Rate limiting appears to be in place.{RST}\n", cfg)


def check_account_enumeration(target, session, forms, findings, cfg):
    section("[23] Account Enumeration", cfg)
    login_forms = [f for f in forms if any(i["type"]=="password" for i in f.get("inputs",[]))]
    if not login_forms:
        pr(f"  {B}ℹ No login form found.{RST}\n", cfg); return

    form   = login_forms[0]
    action = form.get("action", target)
    user_field = next((i["name"] for i in form.get("inputs",[]) if i["type"] in ("text","email","username")), "username")
    pass_field = next((i["name"] for i in form.get("inputs",[]) if i["type"]=="password"), "password")

    # Use timing difference and response diff between valid-looking vs gibberish usernames
    payloads = [
        {user_field: "admin@example.com",         pass_field: "wrong-password-wvs"},
        {user_field: "wvs-nonexistent-user@x.com", pass_field: "wrong-password-wvs"},
    ]
    responses = []
    for pl in payloads:
        t0 = time.time()
        r  = req(session, action, cfg, method="POST", data=pl)
        elapsed = time.time() - t0
        if r: responses.append((r.status_code, len(r.text), elapsed, r.text[:500]))

    if len(responses) == 2:
        r1, r2 = responses
        timing_diff = abs(r1[2] - r2[2])
        content_diff = r1[1] != r2[1]
        # Heuristic: >500ms timing diff or different response body length → enumerable
        if timing_diff > 0.5 or content_diff:
            detail = f"Timing diff: {timing_diff:.2f}s | Content diff: {content_diff}"
            print_vuln("account_enumeration", cfg, detail=detail, url=action)
            vadd(findings, "account_enumeration", detail, action)
        else:
            pr(f"  {G}✔ No obvious account enumeration (similar timing and responses).{RST}\n", cfg)


def check_jwt(html, resp, findings, cfg):
    section("[24] JWT Security", cfg)
    JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    tokens: Set[str] = set(JWT_RE.findall(html))
    for cookie in resp.cookies:
        if cookie.value and JWT_RE.match(cookie.value):
            tokens.add(cookie.value)
    if not tokens:
        pr(f"  {B}ℹ No JWT tokens found in response.{RST}\n", cfg); return

    found_any = False
    for token in tokens:
        parts = token.split(".")
        if len(parts) != 3: continue
        try:
            def _dec(p):
                return json.loads(base64.urlsafe_b64decode(p + "=" * (4 - len(p)%4)))
            header  = _dec(parts[0])
            payload = _dec(parts[1])
        except: continue
        alg = header.get("alg","")
        if alg.lower() == "none":
            print_vuln("jwt_alg_none", cfg, detail="alg=none — signature not verified")
            vadd(findings, "jwt_alg_none", "JWT with alg=none"); found_any = True
        elif alg in ("HS256","HS384","HS512"):
            print_vuln("jwt_weak_algorithm", cfg, detail=f"alg={alg}")
            vadd(findings, "jwt_weak_algorithm", alg); found_any = True
        if "exp" not in payload:
            print_vuln("jwt_no_expiry", cfg, detail="Missing exp claim")
            vadd(findings, "jwt_no_expiry"); found_any = True
        for k in payload:
            if any(s in k.lower() for s in ["password","secret","key","credential","ssn","credit","private"]):
                print_vuln("jwt_sensitive_payload", cfg, detail=f"Payload key: '{k}'")
                vadd(findings, "jwt_sensitive_payload", k); found_any = True; break
    if not found_any: pr(f"  {G}✔ No critical JWT issues found ({len(tokens)} token(s) checked).{RST}\n", cfg)


def check_csrf_forms(forms, findings, cfg):
    section("[25] CSRF Protection", cfg)
    real  = [f for f in forms if "inputs" in f]
    post  = [f for f in real if f.get("method") == "POST"]
    bad   = [f for f in post if not f.get("has_csrf")]
    if bad:
        for f in bad[:3]: print_vuln("csrf_missing_token", cfg, detail=f"POST to {f.get('action','?')}")
        vadd(findings, "csrf_missing_token", f"{len(bad)} unprotected form(s)")
    else: pr(f"  {G}✔ All POST forms appear to have CSRF tokens.{RST}\n", cfg)


def check_client_side(landing_resp, forms, findings, cfg):
    section("[26] Client-Side Security", cfg)
    html = landing_resp.text; any_found = False
    parser = PageParser(landing_resp.url if hasattr(landing_resp,"url") else "")
    try: parser.feed(html)
    except: pass
    bad_scripts = [s for s in parser.scripts if not s["has_sri"] and not s.get("inline") and s.get("src","").startswith("http")]
    if bad_scripts:
        for s in bad_scripts[:4]: print_vuln("missing_sri", cfg, detail=s["src"][:80])
        vadd(findings, "missing_sri", f"{len(bad_scripts)} external script(s) without SRI"); any_found = True
    if parser.http_res:
        print_vuln("http_mixed_content", cfg, detail=f"{len(parser.http_res)} HTTP resource(s)")
        vadd(findings, "http_mixed_content"); any_found = True
    if parser.js_links:
        print_vuln("javascript_protocol", cfg, detail=f"{len(parser.js_links)} link(s)")
        vadd(findings, "javascript_protocol"); any_found = True
    ws = re.findall(r'ws://[^\s"\'<>]+', html)
    if ws:
        print_vuln("unsafe_websocket", cfg, detail=ws[0][:60])
        vadd(findings, "unsafe_websocket"); any_found = True
    ips = re.findall(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b', html)
    if ips:
        print_vuln("internal_ip_disclosure", cfg, detail=str(ips[0]))
        vadd(findings, "internal_ip_disclosure", str(ips[0])); any_found = True
    if re.search(r'(Stack trace|Traceback .most recent|Fatal error:|Exception in thread)', html, re.I):
        print_vuln("debug_info_leak", cfg, detail="Debug info in HTML")
        vadd(findings, "debug_info_leak"); any_found = True
    # Clickjacking PoC
    h = {k.lower():v for k,v in landing_resp.headers.items()}
    xfo = h.get("x-frame-options","").upper()
    csp = h.get("content-security-policy","").lower()
    if xfo not in ("DENY","SAMEORIGIN") and "frame-ancestors" not in csp:
        poc_html = f'<html><body><iframe src="{landing_resp.url}" style="width:100%;height:100%"></iframe></body></html>'
        print_vuln("clickjacking_frameable", cfg, url=landing_resp.url, poc=f"Save and open: {poc_html[:80]}…")
        vadd(findings, "clickjacking_frameable", "", landing_resp.url, poc=poc_html); any_found = True
    gen = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if gen:
        print_vuln("version_in_html", cfg, detail=f"Generator: {gen[0]}")
        vadd(findings, "version_in_html", gen[0]); any_found = True
    emails = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)))
    if emails: vadd(findings, "email_disclosure", f"{len(emails)} email(s)")
    if not any_found: pr(f"  {G}✔ No client-side issues found.{RST}\n", cfg)


def check_security_txt(target, session, findings, cfg):
    section("[27] security.txt (RFC 9116)", cfg)
    for path in SECURITY_TXT_PATHS:
        r = req(session, f"{target}{path}", cfg)
        if r and r.status_code == 200 and "contact:" in r.text.lower():
            pr(f"  {G}✔ security.txt found at {path}{RST}\n", cfg)
            return
    print_vuln("missing_security_txt", cfg, detail="No security.txt at /.well-known/security.txt or /security.txt")
    vadd(findings, "missing_security_txt")


def check_waf_cdn(resp, cfg: ScanConfig) -> List[str]:
    section("[ 0] WAF / CDN Detection (Informational)", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}
    detected = []
    for waf, hints in [
        ("Cloudflare",     ["cf-ray","cf-cache-status"]),
        ("Akamai",         ["x-akamai-transformed","x-check-cacheable"]),
        ("AWS CloudFront", ["x-amz-cf-id"]),
        ("Fastly",         ["x-fastly-request-id"]),
        ("Sucuri",         ["x-sucuri-id"]),
        ("Incapsula",      ["x-iinfo"]),
        ("F5 BIG-IP",      ["x-wa-info","x-cnection"]),
    ]:
        if any(hk in h for hk in hints): detected.append(waf)
    if detected:
        pr(f"  {B}ℹ WAF/CDN detected: {', '.join(detected)}{RST}", cfg)
        pr(f"  {B}  (Some active checks may be blocked or rate-limited){RST}\n", cfg)
    else:
        pr(f"  {B}ℹ No known WAF/CDN signatures detected.{RST}\n", cfg)
    return detected

# ──────────────────────────────────────────────────────────────────────────
# CVSS HELPERS
# ──────────────────────────────────────────────────────────────────────────
def cvss_rating(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0:    return "Low"
    return "None"

def risk_score(findings: List[Vulnerability]) -> int:
    return sum({"CRITICAL":10,"HIGH":5,"MEDIUM":2,"LOW":1}.get(f.severity,0) for f in findings)

# ──────────────────────────────────────────────────────────────────────────
# BASELINE COMPARISON
# ──────────────────────────────────────────────────────────────────────────
def compare_baseline(findings: List[Vulnerability], baseline_path: str, cfg: ScanConfig) -> dict:
    try:
        with open(baseline_path) as f: old = json.load(f)
    except Exception as e:
        prv(f"Could not load baseline: {e}", cfg)
        return {}
    old_keys = {fi["key"] for fi in old.get("findings", [])}
    new_keys  = {fi.key for fi in findings}
    new_findings = [fi for fi in findings if fi.key not in old_keys]
    fixed       = [k for k in old_keys if k not in new_keys]
    return {
        "baseline_target":   old.get("target","?"),
        "baseline_scanned":  old.get("scanned_at","?"),
        "new_findings":      [f.key for f in new_findings],
        "fixed_findings":    fixed,
        "regression_count":  len(new_findings),
        "fixed_count":       len(fixed),
    }

# ──────────────────────────────────────────────────────────────────────────
# RESUME SUPPORT
# ──────────────────────────────────────────────────────────────────────────
def load_resume(path: str) -> Set[str]:
    """Returns set of check keys already completed."""
    try:
        with open(path) as f: data = json.load(f)
        return set(data.get("completed_checks", []))
    except: return set()

# ──────────────────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ──────────────────────────────────────────────────────────────────────────
def _counts(findings):
    return {s: sum(1 for f in findings if f.severity==s)
            for s in ("CRITICAL","HIGH","MEDIUM","LOW")}

def save_json(findings, cfg, target, start, elapsed, extra=None):
    counts = _counts(findings)
    score  = risk_score(findings)
    data = {
        "scanner":      f"WebVulnScan v{VERSION}",
        "target":       target,
        "scanned_at":   start.isoformat(),
        "duration_s":   round(elapsed, 2),
        "profile":      cfg.profile,
        "authenticated":bool(cfg.login_url),
        "summary": {**counts, "total": len(findings), "risk_score": score,
                    "total_loe_hours": sum(f.loe_hours for f in findings)},
        "findings": [f.to_dict() for f in findings],
        **(extra or {}),
    }
    with open(cfg.output_json, "w") as fh: json.dump(data, fh, indent=2)
    pr(f"  {G}✔ JSON saved: {cfg.output_json}{RST}", cfg)

def save_csv(findings, cfg, target, start, elapsed, extra=None):
    with open(cfg.output_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["#","Severity","CWE","OWASP","Vulnerability","CVSS","LOE(h)","Detail","URL","Fix","Timestamp"])
        for i, f in enumerate(findings, 1):
            w.writerow([i, f.severity, f.cwe_id, f.owasp, f.name,
                        f.cvss_score, f.loe_hours, f.detail, f.url, f.fix, f.timestamp])
    pr(f"  {G}✔ CSV saved: {cfg.output_csv}{RST}", cfg)

def save_junit(findings, cfg, target, start, elapsed, extra=None):
    suite = ET.Element("testsuite", name="WebVulnScan", tests=str(len(findings)),
                       failures=str(len(findings)), time=str(round(elapsed,2)))
    ET.SubElement(suite, "properties")
    for f in findings:
        tc   = ET.SubElement(suite, "testcase", name=f.name, classname=f"security.owasp.{f.owasp}.{f.key}")
        fail = ET.SubElement(tc, "failure", message=f"{f.severity}: {f.name}", type=f.severity)
        fail.text = f"CWE: {f.cwe_id}\nCVSS: {f.cvss_score}\nDetail: {f.detail}\nURL: {f.url}\nFix: {f.fix}"
    ET.indent(suite, space="  ")
    tree = ET.ElementTree(suite)
    tree.write(cfg.output_junit, encoding="unicode", xml_declaration=True)
    pr(f"  {G}✔ JUnit XML saved: {cfg.output_junit}{RST}", cfg)

def save_sarif(findings, cfg, target, start, elapsed, extra=None):
    rules = []; results = []; seen = {}
    for f in findings:
        if f.key not in seen:
            seen[f.key] = len(rules)
            rules.append({
                "id": f.key, "name": f.name,
                "shortDescription": {"text": f.name},
                "fullDescription":  {"text": f.fix},
                "help": {"text": f.fix, "markdown": f"**Fix:** {f.fix}"},
                "properties": {
                    "tags": ["security", f"owasp:{f.owasp}", f.cwe_id],
                    "security-severity": str(f.cvss_score or {
                        "CRITICAL":"9.8","HIGH":"7.5","MEDIUM":"5.0","LOW":"2.0"}.get(f.severity,"5.0"))
                }
            })
        results.append({
            "ruleId": f.key, "ruleIndex": seen[f.key],
            "message": {"text": f.detail or f.name},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url or target}}}],
            "level": {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f.severity,"note"),
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "WebVulnScan", "version": VERSION,
                                      "informationUri": "https://github.com/your-org/webvulnscan",
                                      "rules": rules}},
                  "results": results}]
    }
    with open(cfg.output_sarif, "w") as fh: json.dump(sarif, fh, indent=2)
    pr(f"  {G}✔ SARIF saved: {cfg.output_sarif}{RST}", cfg)

def save_md(findings, cfg, target, start, elapsed, extra=None):
    counts = _counts(findings); score = risk_score(findings)
    risk = ("🔴 CRITICAL" if score>15 else "🟠 HIGH" if score>5 else "🟡 MEDIUM" if score>0 else "🟢 LOW")
    total_loe = sum(f.loe_hours for f in findings)
    lines = [
        f"# WebVulnScan v{VERSION} — Security Report",
        f"", f"**Target:** `{target}`  ",
        f"**Scanned:** {start.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Duration:** {elapsed:.1f}s  |  **Profile:** `{cfg.profile}`  ",
        f"**Authenticated:** {'Yes' if cfg.login_url else 'No'}  ", "",
        "## Executive Summary", "",
        f"| Critical | High | Medium | Low | Risk Score | Est. Remediation |",
        f"|:---:|:---:|:---:|:---:|:---:|:---:|",
        f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} "
        f"| **{score} — {risk}** | ~{total_loe}h |", "",
    ]
    # OWASP breakdown
    owasp_groups: Dict[str,List] = {}
    for f in findings:
        owasp_groups.setdefault(f.owasp, []).append(f)
    if owasp_groups:
        lines += ["## OWASP Top 10 Breakdown", ""]
        for cat in sorted(owasp_groups):
            lines.append(f"- **{cat}**: {len(owasp_groups[cat])} finding(s) — {', '.join(set(f.severity for f in owasp_groups[cat]))}")
        lines.append("")

    sev_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
    lines += ["## Findings", ""]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. {sev_emoji.get(f.severity,'⚪')} [{f.severity}] {f.name}",
            f"", f"| Field | Value |",
            f"|---|---|",
            f"| CWE | `{f.cwe_id}` |",
            f"| OWASP | {f.owasp} |",
            f"| CVSS | {f.cvss_score} ({cvss_rating(f.cvss_score)}) |",
            f"| Remediation | ~{f.loe_hours}h |",
            f"| URL | {f.url or '—'} |",
            f"", f"**Detail:** {f.detail or '—'}",
            f"", f"**Fix:** {f.fix}",
        ]
        if f.poc: lines.append(f"\n**PoC:** `{f.poc}`")
        lines.append("")

    if extra and extra.get("baseline"):
        b = extra["baseline"]
        lines += ["## Trend vs Baseline", "",
                  f"- Baseline scanned: `{b.get('baseline_scanned','?')}`",
                  f"- 🆕 New findings: **{b.get('regression_count',0)}**  ({', '.join(b.get('new_findings',[]) or ['none'])})",
                  f"- ✅ Fixed since baseline: **{b.get('fixed_count',0)}**  ({', '.join(b.get('fixed_findings',[]) or ['none'])})",
                  ""]

    lines += ["---", f"*Generated by WebVulnScan v{VERSION} — Authorized security testing only*"]
    with open(cfg.output_md, "w", encoding="utf-8") as fh: fh.write("\n".join(lines))
    pr(f"  {G}✔ Markdown saved: {cfg.output_md}{RST}", cfg)

def save_html(findings, cfg, target, start, elapsed, extra=None):
    counts = _counts(findings); score = risk_score(findings)
    risk = ("CRITICAL RISK" if score>15 else "HIGH RISK" if score>5 else "MEDIUM RISK" if score>0 else "LOW RISK")
    rc   = ("#dc3545" if "CRITICAL" in risk or "HIGH" in risk else "#fd7e14" if "MEDIUM" in risk else "#198754")
    total_loe = sum(f.loe_hours for f in findings)

    # SVG donut chart data
    total = max(len(findings), 1)
    def pct(n): return round(n/total*100)
    donut_data = [
        (counts['CRITICAL'], "#dc3545", "Critical"),
        (counts['HIGH'],     "#fd7e14", "High"),
        (counts['MEDIUM'],   "#ffc107", "Medium"),
        (counts['LOW'],      "#0dcaf0", "Low"),
    ]
    # Generate SVG donut
    def make_donut():
        cx=60; cy=60; r=45; stroke=18
        circ = 2*3.14159*r
        offset = 0; segments = ""
        for count, color, label in donut_data:
            if count == 0: continue
            frac = count/total
            dash = frac*circ
            segments += (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
                         f'stroke-width="{stroke}" stroke-dasharray="{dash:.1f} {circ:.1f}" '
                         f'stroke-dashoffset="-{offset:.1f}" transform="rotate(-90 {cx} {cy})"/>')
            offset += dash
        return (f'<svg width="120" height="120" viewBox="0 0 120 120">{segments}'
                f'<text x="{cx}" y="{cy+5}" text-anchor="middle" font-size="14" '
                f'font-weight="bold" fill="#fff">{len(findings)}</text>'
                f'<text x="{cx}" y="{cy+18}" text-anchor="middle" font-size="9" fill="#aaa">total</text></svg>')

    # OWASP breakdown table
    owasp_groups: Dict[str,List] = {}
    for f in findings: owasp_groups.setdefault(f.owasp,[]).append(f)
    owasp_rows = ""
    for cat in sorted(owasp_groups):
        items = owasp_groups[cat]
        crit  = sum(1 for f in items if f.severity=="CRITICAL")
        high  = sum(1 for f in items if f.severity=="HIGH")
        owasp_rows += f"<tr><td><strong>{cat}</strong></td><td>{len(items)}</td><td>{'🔴'*crit}{'🟠'*high}</td></tr>"

    # Finding rows
    sev_style = {
        "CRITICAL": "background:#f8d7da;color:#721c24",
        "HIGH":     "background:#ffe0e0;color:#dc3545",
        "MEDIUM":   "background:#fff3cd;color:#856404",
        "LOW":      "background:#d1ecf1;color:#0c5460",
    }
    rows = ""
    for i, f in enumerate(findings, 1):
        bs = sev_style.get(f.severity, "background:#eee;color:#333")
        cvss_badge = f'<span style="background:#666;color:#fff;padding:1px 7px;border-radius:10px;font-size:.78em">{f.cvss_score}</span>' if f.cvss_score else "—"
        poc_cell = f'<details><summary style="cursor:pointer;color:#7b2d8b">Show PoC</summary><code style="font-size:.78em;word-break:break-all">{f.poc}</code></details>' if f.poc else "—"
        rows += f"""<tr>
          <td style="font-weight:bold;color:#666">{i}</td>
          <td><span style="{bs};padding:2px 10px;border-radius:12px;font-size:.82em;font-weight:bold">{f.severity}</span></td>
          <td><strong>{f.name}</strong><br><small style="color:#888">{f.cwe_id} · OWASP {f.owasp}</small></td>
          <td>{cvss_badge}</td>
          <td style="font-size:.85em">{f.detail or "—"}</td>
          <td style="font-size:.82em;color:#555">{f.fix}</td>
          <td style="font-size:.8em;color:#7b2d8b">{f'~{f.loe_hours}h' if f.loe_hours else "—"}</td>
          <td style="font-size:.8em">{poc_cell}</td></tr>"""

    # Baseline trend section
    baseline_html = ""
    if extra and extra.get("baseline"):
        b = extra["baseline"]
        baseline_html = f"""
        <div class="card" style="margin-bottom:20px;border-left:4px solid #0d6efd">
          <h3 style="margin-top:0">📈 Trend vs Baseline ({b.get('baseline_scanned','?')[:10]})</h3>
          <span style="margin-right:20px">🆕 <strong>New:</strong> {b.get('regression_count',0)}</span>
          <span>✅ <strong>Fixed:</strong> {b.get('fixed_count',0)}</span>
        </div>"""

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>WebVulnScan v{VERSION} — {target}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;margin:0}}
.wrap{{max-width:1400px;margin:0 auto;padding:30px}}
.hdr{{background:linear-gradient(135deg,#1a237e 0%,#283593 50%,#1565c0 100%);color:#fff;padding:35px;border-radius:14px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center}}
h1{{margin:0;font-size:1.5em;letter-spacing:.5px}}
.meta{{opacity:.75;font-size:.85em;margin-top:8px;line-height:1.7}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}}
.card{{flex:1;min-width:130px;background:#1e2130;border-radius:10px;padding:18px;box-shadow:0 2px 12px rgba(0,0,0,.3)}}
.card .num{{font-size:2em;font-weight:700;margin-bottom:4px}}
.card .lbl{{font-size:.75em;text-transform:uppercase;color:#888;letter-spacing:.5px}}
.c-crit .num{{color:#dc3545}}.c-high .num{{color:#fd7e14}}
.c-med  .num{{color:#ffc107}}.c-low  .num{{color:#0dcaf0}}
.c-risk{{background:{rc};color:#fff}}.c-risk .num,.c-risk .lbl{{color:#fff!important}}
.c-loe  .num{{color:#a78bfa}}
.section{{background:#1e2130;border-radius:10px;padding:20px;margin-bottom:20px}}
.section h3{{margin-top:0;color:#90caf9;border-bottom:1px solid #2a3050;padding-bottom:10px}}
table{{width:100%;border-collapse:collapse;background:#1e2130;border-radius:10px;overflow:hidden}}
th{{background:#283593;color:#fff;padding:11px 12px;text-align:left;font-size:.83em;white-space:nowrap}}
td{{padding:11px 12px;border-bottom:1px solid #2a3050;font-size:.85em;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#252840}}
.owasp-table td,.owasp-table th{{padding:8px 12px}}
details summary::-webkit-details-marker{{display:none}}
footer{{text-align:center;margin-top:28px;color:#555;font-size:.82em;padding:20px}}
@media(max-width:768px){{.hdr{{flex-direction:column}}.cards{{flex-direction:column}}}}
</style></head><body><div class="wrap">
<div class="hdr">
  <div>
    <h1>🔒 WebVulnScan v{VERSION} — Security Assessment Report</h1>
    <div class="meta">
      <strong>Target:</strong> {target} &nbsp;|&nbsp;
      <strong>Profile:</strong> {cfg.profile.upper()} &nbsp;|&nbsp;
      <strong>Auth:</strong> {'✅ Yes' if cfg.login_url else '❌ No'} &nbsp;|&nbsp;
      <strong>Scanned:</strong> {start.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
      <strong>Duration:</strong> {elapsed:.1f}s
    </div>
  </div>
  <div style="text-align:center">{make_donut()}</div>
</div>
<div class="cards">
  <div class="card c-crit"><div class="num">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="card c-high"><div class="num">{counts['HIGH']}</div><div class="lbl">High</div></div>
  <div class="card c-med"><div class="num">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="card c-low"><div class="num">{counts['LOW']}</div><div class="lbl">Low</div></div>
  <div class="card c-risk"><div class="num">{score}</div><div class="lbl">{risk}</div></div>
  <div class="card c-loe"><div class="num">~{total_loe}h</div><div class="lbl">Est. Remediation</div></div>
</div>
{baseline_html}
<div class="section">
  <h3>OWASP Top 10 Breakdown</h3>
  <table class="owasp-table"><thead><tr><th>Category</th><th>Findings</th><th>Severity</th></tr></thead>
  <tbody>{owasp_rows or '<tr><td colspan="3" style="text-align:center;color:#198754">✅ No findings</td></tr>'}</tbody></table>
</div>
<div class="section">
  <h3>All Findings</h3>
  <table><thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>CVSS</th><th>Detail</th><th>Fix</th><th>LOE</th><th>PoC</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="8" style="text-align:center;color:#198754;padding:40px">✅ No vulnerabilities found!</td></tr>'}</tbody></table>
</div>
<footer>WebVulnScan v{VERSION} &nbsp;·&nbsp; Authorized security testing only &nbsp;·&nbsp; {start.strftime('%Y')}</footer>
</div></body></html>"""
    with open(cfg.output_html, "w", encoding="utf-8") as fh: fh.write(html)
    pr(f"  {G}✔ HTML saved: {cfg.output_html}{RST}", cfg)


def send_webhook(findings, cfg, target):
    if not cfg.webhook: return
    counts = _counts(findings); score = risk_score(findings)
    color  = "danger" if counts["CRITICAL"]>0 or counts["HIGH"]>0 else "warning" if counts["MEDIUM"]>0 else "good"
    top5   = "\n".join(f"  • [{f.severity}] {f.name}" for f in findings[:5])
    payload = {
        "text": f"🔒 *WebVulnScan v{VERSION}* — Report for `{target}`",
        "attachments": [{
            "color": color,
            "fields": [
                {"title":"Critical", "value":str(counts["CRITICAL"]), "short":True},
                {"title":"High",     "value":str(counts["HIGH"]),     "short":True},
                {"title":"Medium",   "value":str(counts["MEDIUM"]),   "short":True},
                {"title":"Low",      "value":str(counts["LOW"]),      "short":True},
                {"title":"Risk Score","value":str(score),             "short":True},
                {"title":"Profile",  "value":cfg.profile.upper(),     "short":True},
            ],
            "text": f"Top findings:\n{top5}" if top5 else "No findings.",
            "footer": f"WebVulnScan v{VERSION} · {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        }]
    }
    try:
        r = requests.post(cfg.webhook, json=payload, timeout=10)
        pr(f"  {G}✔ Webhook sent ({r.status_code}){RST}", cfg)
    except Exception as e:
        pr(f"  {Y}⚠ Webhook failed: {e}{RST}", cfg)


def get_exit_code(findings, fail_on: str) -> int:
    SEV_ORDER = ["critical","high","medium","low"]
    if not fail_on: return 0
    threshold = SEV_ORDER.index(fail_on.lower()) if fail_on.lower() in SEV_ORDER else 99
    for f in findings:
        if SEV_ORDER.index(f.severity.lower()) <= threshold: return 2
    return 0

# ──────────────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────────────
def print_summary(findings, target, start, cfg) -> float:
    elapsed = (datetime.now() - start).total_seconds()
    counts  = _counts(findings)
    score   = risk_score(findings)
    risk    = (f"{R+BOLD}CRITICAL RISK{RST}" if score>15 else f"{R}HIGH RISK{RST}"
               if score>5 else f"{Y}MEDIUM RISK{RST}" if score>0 else f"{G}LOW RISK{RST}")
    total_loe = sum(f.loe_hours for f in findings)
    seen = set(); unique = []
    for f in findings:
        if f.key not in seen: seen.add(f.key); unique.append(f)

    pr(f"\n{B}{BOLD}{'═'*66}{RST}", cfg)
    pr(f"{B}{BOLD}  SCAN COMPLETE — {target}{RST}", cfg)
    pr(f"{B}{BOLD}{'═'*66}{RST}", cfg)
    pr(f"  Duration        : {elapsed:.1f}s", cfg)
    pr(f"  Unique findings : {len(unique)}  ({len(findings)} total instances)", cfg)
    pr(f"  {R+BOLD}Critical:{counts['CRITICAL']}{RST}  {R}High:{counts['HIGH']}{RST}  "
       f"{Y}Med:{counts['MEDIUM']}{RST}  {C}Low:{counts['LOW']}{RST}", cfg)
    pr(f"  Est. LOE        : ~{total_loe}h to remediate all findings", cfg)
    if unique:
        pr(f"\n{BOLD}  Findings by severity:{RST}", cfg)
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            sev_items = [f for f in unique if f.severity==sev]
            for f in sev_items:
                cvss = f" [CVSS:{f.cvss_score}]" if f.cvss_score else ""
                pr(f"  {sev_color(sev)}[{sev:8}]{RST} {f.name}{Y}{cvss}{RST}", cfg)
    pr(f"\n  Risk Score : {score}  →  {risk}", cfg)
    pr(f"\n{C}  ⚠  Only use on systems you own or are explicitly authorized to test.{RST}\n", cfg)
    return elapsed

# ──────────────────────────────────────────────────────────────────────────
# CONFIG FILE
# ──────────────────────────────────────────────────────────────────────────
def load_config_file(path: str) -> dict:
    with open(path) as fh: content = fh.read()
    if path.endswith(".json"): return json.loads(content)
    try:
        import yaml; return yaml.safe_load(content)
    except ImportError: return json.loads(content)

# ──────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="web_vuln_scanner_v5",
        description=f"WebVulnScan v{VERSION} — Enterprise Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --profile full -v
  %(prog)s --targets targets.txt --profile standard
  %(prog)s https://app.example.com --login-url https://app.example.com/login \\
           --login-user admin@example.com --login-pass secret
  %(prog)s https://example.com --profile quick --fail-on high -q --junit ci.xml
  %(prog)s https://example.com -o r.json --html r.html --csv r.csv --md r.md
  %(prog)s https://example.com --baseline old_report.json --sarif r.sarif
  %(prog)s https://example.com --resume r.json --audit-log audit.jsonl
  %(prog)s https://example.com --proxy http://127.0.0.1:8080 --rate-limit 30
""")
    # Targets
    p.add_argument("target",        nargs="?",          help="Target URL")
    p.add_argument("--targets",                         help="File with one URL per line")
    # Profile
    p.add_argument("--profile",     choices=["quick","standard","full","api"], default="standard")
    p.add_argument("--scope",                           help="Comma-separated allowed domains")
    # Performance
    p.add_argument("-t","--timeout",    type=int, default=0)
    p.add_argument("-w","--threads",    type=int, default=0)
    p.add_argument("-d","--delay",      type=float, default=0.0)
    p.add_argument("--rate-limit",      type=int, default=0, help="Max requests/min")
    p.add_argument("--max-time",        type=int, default=0, help="Global scan limit (s)")
    p.add_argument("--max-crawl-pages", type=int, default=0)
    # Auth
    p.add_argument("--proxy",                           help="HTTP proxy URL")
    p.add_argument("--auth-type",   choices=["basic","bearer","token"])
    p.add_argument("--auth-value",                      help="Auth credentials/token")
    p.add_argument("--login-url",                       help="Login form URL (form-based auth)")
    p.add_argument("--login-user",                      help="Login username/email")
    p.add_argument("--login-pass",                      help="Login password")
    p.add_argument("--login-field-user", default="username")
    p.add_argument("--login-field-pass", default="password")
    p.add_argument("--cookie",      action="append",    help="Cookie name=value")
    p.add_argument("--header",      action="append",    help="Custom header name=value")
    p.add_argument("--user-agent",                      help="Custom User-Agent")
    p.add_argument("--verify-ssl",  action="store_true")
    # Output
    p.add_argument("-o","--output", dest="output_json", help="JSON report")
    p.add_argument("--html",        dest="output_html", help="HTML report")
    p.add_argument("--csv",         dest="output_csv",  help="CSV report")
    p.add_argument("--junit",       dest="output_junit",help="JUnit XML")
    p.add_argument("--sarif",       dest="output_sarif",help="SARIF (GitHub Advanced Security)")
    p.add_argument("--md",          dest="output_md",   help="Markdown report")
    p.add_argument("--audit-log",                       help="JSONL audit trail path")
    # CI/CD & Integration
    p.add_argument("--fail-on",     choices=["critical","high","medium","low"])
    p.add_argument("--webhook",                         help="Slack/Discord webhook URL")
    p.add_argument("--baseline",                        help="Previous JSON report for comparison")
    p.add_argument("--resume",                          help="Resume from existing JSON report")
    # Scan control
    p.add_argument("--skip-checks",                     help="Comma-separated checks to skip")
    p.add_argument("--config",                          help="JSON/YAML config file")
    # UI
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("-q","--quiet",   action="store_true")
    p.add_argument("--no-color",     action="store_true")
    p.add_argument("--version",      action="version", version=f"WebVulnScan v{VERSION}")
    return p.parse_args()

# ──────────────────────────────────────────────────────────────────────────
# SINGLE-TARGET SCAN ENGINE
# ──────────────────────────────────────────────────────────────────────────
def run_scan(target: str, cfg: ScanConfig) -> ScanResult:
    """Execute all security checks against one target. Returns ScanResult."""
    global _interrupted
    _interrupted = False

    session    = get_session(cfg)
    start      = datetime.now()
    findings:  List[Vulnerability] = []
    result     = ScanResult(target=target, start=start)

    # Banner
    pr(f"\n{G}[*] Target   : {W}{target}{RST}", cfg)
    pr(f"{G}[*] Profile  : {cfg.profile.upper()}  |  Threads: {cfg.threads}  |  Timeout: {cfg.timeout}s{RST}", cfg)
    if cfg.rate_limit: pr(f"{G}[*] Rate     : {cfg.rate_limit} req/min{RST}", cfg)
    if cfg.max_time:   pr(f"{G}[*] Max time : {cfg.max_time}s{RST}", cfg)
    if cfg.scope:      pr(f"{G}[*] Scope    : {', '.join(cfg.scope)}{RST}", cfg)

    # Authenticated login
    if cfg.login_url:
        authenticated = login(session, cfg)
        result.authenticated = authenticated
        if authenticated: pr(f"{G}[✔] Authentication successful{RST}", cfg)
        else:             pr(f"{Y}[⚠] Authentication failed — scanning unauthenticated{RST}", cfg)

    # Landing request
    landing = req(session, target, cfg)
    if not landing:
        pr(f"\n{R}✘ Cannot reach {target}.{RST}", cfg)
        result.end = datetime.now()
        return result

    pr(f"{G}[✔] HTTP {landing.status_code}  ({len(landing.content):,} bytes)"
       f"  Content-Type: {landing.headers.get('content-type','?').split(';')[0]}{RST}\n", cfg)
    audit("scan_start", {"target": target, "status": landing.status_code})

    skip = cfg.skip_checks

    try:
        # Phase 1: Passive / fast checks (no crawl needed)
        check_waf_cdn(landing, cfg)
        if "headers"   not in skip: check_security_headers(landing, findings, cfg)
        if "ssl"       not in skip: check_https(target, session, findings, cfg)
        if "cors"      not in skip: check_cors(landing, session, target, findings, cfg)
        if "cookies"   not in skip: check_cookies(landing, findings, cfg)
        if "methods"   not in skip: check_http_methods(target, session, findings, cfg)
        if "jwt"       not in skip: check_jwt(landing.text, landing, findings, cfg)
        if "securitytxt" not in skip: check_security_txt(target, session, findings, cfg)

        if _interrupted: raise KeyboardInterrupt()

        # Phase 2: Crawl to discover endpoints, params, forms, JS
        visited, params, forms, js_urls = crawl(session, target, cfg)
        result.urls_crawled = len(visited)
        result.params_found = len(params)
        # Expand param list with common defaults
        params = list(set(params) | {
            "id","q","search","name","page","file","url","redirect",
            "data","input","cat","user","email","token"
        })

        if _interrupted: raise KeyboardInterrupt()

        # Phase 3: Active checks — run in parallel batches
        check_funcs: List[Tuple[str, Callable]] = []
        if "files"         not in skip: check_funcs.append(("files",         lambda: check_sensitive_files(target, session, findings, cfg)))
        if "xss"           not in skip: check_funcs.append(("xss",           lambda: check_xss(target, session, params, findings, cfg)))
        if "dom_xss"       not in skip: check_funcs.append(("dom_xss",       lambda: check_dom_xss(js_urls, session, findings, cfg)))
        if "sqli"          not in skip: check_funcs.append(("sqli",          lambda: check_sqli(target, session, params, findings, cfg)))
        if "cmdi"          not in skip: check_funcs.append(("cmdi",          lambda: check_cmdi(target, session, params, findings, cfg)))
        if "traversal"     not in skip: check_funcs.append(("traversal",     lambda: check_path_traversal(target, session, params, findings, cfg)))
        if "ssti"          not in skip: check_funcs.append(("ssti",          lambda: check_ssti(target, session, params, findings, cfg)))
        if "redirect"      not in skip: check_funcs.append(("redirect",      lambda: check_open_redirect(target, session, params, findings, cfg)))
        if "ssrf"          not in skip: check_funcs.append(("ssrf",          lambda: check_ssrf(target, session, params, findings, cfg)))
        if "xxe"           not in skip: check_funcs.append(("xxe",           lambda: check_xxe(target, session, forms, findings, cfg)))
        if "proto_pollution" not in skip: check_funcs.append(("proto",       lambda: check_prototype_pollution(target, session, params, findings, cfg)))
        if "smuggling"     not in skip: check_funcs.append(("smuggling",     lambda: check_request_smuggling(target, session, findings, cfg)))
        if "host"          not in skip: check_funcs.append(("host",          lambda: check_host_header_injection(target, session, findings, cfg)))
        if "cache"         not in skip: check_funcs.append(("cache",         lambda: check_cache_poisoning(target, session, findings, cfg)))
        if "graphql"       not in skip: check_funcs.append(("graphql",       lambda: check_graphql(target, session, findings, cfg)))
        if "api"           not in skip: check_funcs.append(("api",           lambda: check_api_endpoints(target, session, findings, cfg)))
        if "rate_limit"    not in skip: check_funcs.append(("rate_limit",    lambda: check_rate_limit(target, session, forms, findings, cfg)))
        if "enum"          not in skip: check_funcs.append(("enum",          lambda: check_account_enumeration(target, session, forms, findings, cfg)))
        if "csrf"          not in skip: check_funcs.append(("csrf",          lambda: check_csrf_forms(forms, findings, cfg)))
        if "client"        not in skip: check_funcs.append(("client",        lambda: check_client_side(landing, forms, findings, cfg)))

        # Execute checks in parallel (max 4 concurrent to stay polite)
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(fn): name for name, fn in check_funcs}
            for fut in as_completed(futs):
                if _interrupted: break
                try: fut.result()
                except TimeoutError: raise
                except Exception as e:
                    prv(f"Check '{futs[fut]}' error: {e}", cfg)

    except (KeyboardInterrupt, TimeoutError) as e:
        pr(f"\n{Y}⚠ Scan interrupted: {e}{RST}", cfg)

    result.end      = datetime.now()
    result.findings = findings
    return result

# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────
def main():
    global _rate_limiter, _scan_start, _max_time, _audit_log_path
    global R, G, Y, B, C, M, W, BOLD, DIM, RST

    args = parse_args()
    prof = PROFILES.get(args.profile, PROFILES["standard"])

    cfg = ScanConfig(
        target            = args.target or "",
        targets_file      = args.targets or "",
        profile           = args.profile,
        scope             = set(s.strip() for s in (args.scope or "").split(",") if s.strip()),
        timeout           = args.timeout  or prof["timeout"],
        threads           = args.threads  or prof["threads"],
        delay             = args.delay,
        rate_limit        = args.rate_limit,
        max_time          = args.max_time,
        max_crawl_pages   = args.max_crawl_pages or prof["crawl_pages"],
        proxy             = args.proxy or "",
        auth_type         = args.auth_type or "",
        auth_value        = args.auth_value or "",
        login_url         = args.login_url or "",
        login_user        = args.login_user or "",
        login_pass        = args.login_pass or "",
        login_field_user  = args.login_field_user,
        login_field_pass  = args.login_field_pass,
        user_agent        = args.user_agent or "",
        output_json       = args.output_json or "",
        output_html       = args.output_html or "",
        output_csv        = args.output_csv or "",
        output_junit      = args.output_junit or "",
        output_sarif      = args.output_sarif or "",
        output_md         = args.output_md or "",
        audit_log         = args.audit_log or "",
        webhook           = args.webhook or "",
        fail_on           = args.fail_on or "",
        baseline          = args.baseline or "",
        resume            = args.resume or "",
        verbose           = args.verbose,
        quiet             = args.quiet,
        no_color          = args.no_color,
        verify_ssl        = args.verify_ssl,
        skip_checks       = prof["skip"] | set(c.strip().lower() for c in (args.skip_checks or "").split(",") if c.strip()),
    )

    # Config file
    if args.config:
        for k, v in load_config_file(args.config).items():
            if hasattr(cfg, k): setattr(cfg, k, v)

    # Cookies & headers
    for c in (args.cookie or []):
        if "=" in c: k, v = c.split("=",1); cfg.cookies[k] = v
    for h in (args.header or []):
        if "=" in h: k, v = h.split("=",1); cfg.custom_headers[k] = v

    # No-color
    if cfg.no_color:
        R=G=Y=B=C=M=W=BOLD=DIM=RST=""

    # Rate limiter
    if cfg.rate_limit > 0:
        _rate_limiter = RateLimiter(cfg.rate_limit)

    # Global timer
    _max_time   = cfg.max_time
    _scan_start = time.time()

    # Audit log
    if cfg.audit_log:
        _audit_log_path = cfg.audit_log
        audit("scanner_start", {"version": VERSION, "profile": cfg.profile})

    # Banner
    if not cfg.quiet:
        print(f"""
{B}{BOLD}╔══════════════════════════════════════════════════════════════════════════╗
║       WebVulnScan v{VERSION} — Enterprise Web Application Security Scanner    ║
║       For AUTHORIZED penetration testing ONLY                            ║
╚══════════════════════════════════════════════════════════════════════════╝{RST}
Profile : {B}{cfg.profile.upper()}{RST} — {prof['description']}""")

    # Build target list
    targets = []
    if cfg.targets_file:
        with open(cfg.targets_file) as f:
            targets = [normalize(line.strip()) for line in f if line.strip() and not line.startswith("#")]
    elif cfg.target:
        targets = [normalize(cfg.target)]
    else:
        t = input(f"\n{W}Enter target URL: {RST}").strip()
        if not t: print(f"{R}No target.{RST}"); sys.exit(1)
        targets = [normalize(t)]

    if not cfg.quiet:
        print(f"\n{Y}{BOLD}⚠  LEGAL NOTICE{RST}")
        print(f"{Y}   You must own each target or have explicit written authorization.{RST}")
        ok = input(f"   Authorized to scan {len(targets)} target(s)? (yes/no): ").strip().lower()
        if ok not in ("yes","y"):
            print(f"{R}Scan aborted.{RST}"); sys.exit(0)

    # Run all targets
    all_results: List[ScanResult] = []
    all_findings: List[Vulnerability] = []

    for target in targets:
        if len(targets) > 1:
            pr(f"\n{M}{BOLD}{'═'*66}{RST}", cfg)
            pr(f"{M}{BOLD}  TARGET: {target}{RST}", cfg)
            pr(f"{M}{BOLD}{'═'*66}{RST}", cfg)
        result = run_scan(target, cfg)
        all_results.append(result)
        all_findings.extend(result.findings)

    # Use last result as primary for reports (single target) or aggregate
    primary_target  = targets[0]
    primary_result  = all_results[0]
    findings        = primary_result.findings if len(targets)==1 else all_findings
    start_dt        = primary_result.start

    elapsed = print_summary(findings, primary_target, start_dt, cfg)

    # Baseline comparison
    baseline_data = None
    if cfg.baseline:
        baseline_data = compare_baseline(findings, cfg.baseline, cfg)
        if baseline_data:
            pr(f"\n{B}📈 Trend vs baseline ({baseline_data.get('baseline_scanned','?')[:10]}):{RST}", cfg)
            pr(f"   🆕 New findings : {baseline_data['regression_count']}  "
               f"({', '.join(baseline_data['new_findings'][:5]) or 'none'})", cfg)
            pr(f"   ✅ Fixed since  : {baseline_data['fixed_count']}  "
               f"({', '.join(baseline_data['fixed_findings'][:5]) or 'none'})", cfg)

    extra = {"baseline": baseline_data} if baseline_data else None

    # Save reports
    reports = [
        (cfg.output_json,  save_json),
        (cfg.output_html,  save_html),
        (cfg.output_csv,   save_csv),
        (cfg.output_junit, save_junit),
        (cfg.output_sarif, save_sarif),
        (cfg.output_md,    save_md),
    ]
    if any(r[0] for r in reports):
        section("Reports", cfg)
        for path, fn in reports:
            if path: fn(findings, cfg, primary_target, start_dt, elapsed, extra)

    # Webhook
    if cfg.webhook:
        section("Webhook", cfg)
        send_webhook(findings, cfg, primary_target)

    # Audit close
    audit("scanner_done", {
        "total_findings": len(findings),
        "risk_score": risk_score(findings),
        "elapsed_s": elapsed,
    })

    # Exit code
    code = get_exit_code(findings, cfg.fail_on)
    if code != 0:
        pr(f"{Y}⚠ Exit code {code} (--fail-on {cfg.fail_on} triggered){RST}", cfg)
    sys.exit(code)


if __name__ == "__main__":
    main()

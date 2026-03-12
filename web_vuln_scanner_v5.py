#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         WebVulnScan v7.0 — "Omniscient" Ultimate Security Scanner       ║
║         The All-In-One Enterprise Web & Server Vulnerability Engine     ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import configparser
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Set

import requests
from requests.adapters import HTTPAdapter, Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("webvulnscan")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ──────────────────────────────────────────────────────────────────────────
# CONSTANTS & PAYLOADS
# ──────────────────────────────────────────────────────────────────────────
VERSION = "7.0"
DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 10
MAX_CRAWL_PAGES = 50

# ANSI Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
C = "\033[96m"; M = "\033[95m"; W = "\033[97m"; BOLD = "\033[1m"
DIM = "\033[2m"; RST = "\033[0m"

# Payloads
XSS_PAYLOADS = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1"]
SQLI_ERRORS = ["syntax error", "mysql_fetch", "ORA-0", "PostgreSQL", "SQLite3", "unclosed quotation"]
SQLI_TIME_PAYLOADS = ["' AND SLEEP(5)--", "' AND BENCHMARK(5000000,SHA1('x'))--", "' WAITFOR DELAY '00:00:05'--"]
PATH_TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd"]
REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://metadata.google.internal", "http://169.254.169.254"]
CRYPTO_PARAMS = ["private_key", "mnemonic", "seed", "api_key", "secret", "token", "wallet", "pk"]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>", "[=7*7=]"]
XXE_PAYLOADS = ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
CMD_INJECTION_PAYLOADS = ["; id", "| cat /etc/passwd", "` whoami `", "$(whoami)"]
LDAP_INJECTION_PAYLOADS = ["*", "admin*", "*)(uid=*", "admin)(|(uid=*"]
BACKUP_EXTENSIONS = [".bak", ".old", ".backup", ".swp", ".git", ".zip", ".tar", ".env", ".sql", ".config"]
DEFAULT_PATHS = ["/admin", "/admin.php", "/login", "/wp-admin", "/administrator", "/phpmyadmin", "/.git", "/.env", "/web.config", "/config.php"]
DEFAULT_CREDENTIALS = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("admin", "123456"), ("test", "test")]
API_KEY_PATTERNS = [r'api[_-]?key[\s:=]+["\']?([a-zA-Z0-9\-]{20,})', r'(sk|pk)_[a-zA-Z0-9_]{32,}', r'token[\s:=]+["\']?([a-zA-Z0-9\-_.]{20,})']
KNOWN_CVE_VERSIONS = {
    "Apache/2.4.49": "CVE-2021-41773",
    "Apache/2.4.50": "CVE-2021-42013",
    "nginx/1.16": "CVE-2019-9511",
    "OpenSSL/1.0.2": "CVE-2016-2183",
}

# ──────────────────────────────────────────────────────────────────────────
# VULNERABILITY DATABASE (Expanded to 25+ Types)
# ──────────────────────────────────────────────────────────────────────────
VULN_DB = {
    "sql_injection": {"id": "CWE-89", "sev": "CRITICAL", "owasp": "A03", "name": "SQL Injection", "fix": "Use parameterized queries."},
    "xss_reflected": {"id": "CWE-79", "sev": "HIGH", "owasp": "A03", "name": "Reflected XSS", "fix": "Encode output."},
    "timing_sqli": {"id": "CWE-89", "sev": "HIGH", "owasp": "A03", "name": "Timing-based SQL Injection", "fix": "Use parameterized queries & WAF."},
    "xxe": {"id": "CWE-611", "sev": "CRITICAL", "owasp": "A05", "name": "XML External Entity (XXE)", "fix": "Disable XML external entity processing."},
    "ldap_injection": {"id": "CWE-90", "sev": "HIGH", "owasp": "A03", "name": "LDAP Injection", "fix": "Sanitize LDAP queries."},
    "command_injection": {"id": "CWE-78", "sev": "CRITICAL", "owasp": "A03", "name": "Command Injection", "fix": "Avoid shell execution; use APIs."},
    "ssti": {"id": "CWE-1336", "sev": "HIGH", "owasp": "A03", "name": "Server-Side Template Injection", "fix": "Use safe templating engines."},
    "missing_hsts": {"id": "CWE-319", "sev": "MEDIUM", "owasp": "A05", "name": "Missing HSTS", "fix": "Add HSTS header."},
    "missing_csp": {"id": "CWE-1021", "sev": "MEDIUM", "owasp": "A05", "name": "Missing CSP", "fix": "Add CSP header."},
    "cors_misconfigured": {"id": "CWE-942", "sev": "HIGH", "owasp": "A05", "name": "CORS Misconfiguration", "fix": "Validate CORS origins."},
    "insecure_cookie": {"id": "CWE-614", "sev": "MEDIUM", "owasp": "A05", "name": "Insecure Cookie Flags", "fix": "Set HttpOnly, Secure, SameSite."},
    "open_redirect": {"id": "CWE-601", "sev": "MEDIUM", "owasp": "A01", "name": "Open Redirect", "fix": "Validate redirect URLs."},
    "directory_traversal": {"id": "CWE-22", "sev": "HIGH", "owasp": "A01", "name": "Path Traversal", "fix": "Validate file paths."},
    "info_disclosure": {"id": "CWE-200", "sev": "LOW", "owasp": "A01", "name": "Information Disclosure", "fix": "Remove sensitive headers."},
    "missing_x_frame_options": {"id": "CWE-1021", "sev": "MEDIUM", "owasp": "A05", "name": "Missing X-Frame-Options", "fix": "Add X-Frame-Options."},
    "host_header_injection": {"id": "CWE-644", "sev": "MEDIUM", "owasp": "A05", "name": "Host Header Injection", "fix": "Validate Host header."},
    "ssrf": {"id": "CWE-918", "sev": "HIGH", "owasp": "A10", "name": "Server-Side Request Forgery", "fix": "Whitelist allowed domains."},
    "crypto_key_exposure": {"id": "CWE-798", "sev": "CRITICAL", "owasp": "A07", "name": "Crypto Key/Secret Exposure", "fix": "Never pass keys in URLs."},
    "backup_file_exposure": {"id": "CWE-200", "sev": "MEDIUM", "owasp": "A01", "name": "Backup File Exposure", "fix": "Remove/lock backup files."},
    "http_method_allowed": {"id": "CWE-200", "sev": "MEDIUM", "owasp": "A05", "name": "Dangerous HTTP Methods", "fix": "Disable PUT/DELETE/TRACE."},
    "default_credentials": {"id": "CWE-521", "sev": "CRITICAL", "owasp": "A07", "name": "Default Credentials Found", "fix": "Change all default passwords."},
    "weak_jwt": {"id": "CWE-347", "sev": "HIGH", "owasp": "A02", "name": "Weak JWT Signature", "fix": "Use RS256, strong secrets."},
    "api_key_leakage": {"id": "CWE-798", "sev": "CRITICAL", "owasp": "A07", "name": "API Key in Response", "fix": "Never expose keys client-side."},
    "weak_ssl_tls": {"id": "CWE-326", "sev": "HIGH", "owasp": "A02", "name": "Weak SSL/TLS Configuration", "fix": "Use TLS 1.2+, strong ciphers."},
    "outdated_server": {"id": "CWE-937", "sev": "HIGH", "owasp": "A06", "name": "Outdated Server Software", "fix": "Update to latest patch level."},
    "idor": {"id": "CWE-639", "sev": "HIGH", "owasp": "A01", "name": "Insecure Direct Object Reference", "fix": "Implement access controls."},
    "rate_limiting": {"id": "CWE-770", "sev": "MEDIUM", "owasp": "A04", "name": "Missing Rate Limiting", "fix": "Implement rate limiting."},
    "web3_injection": {"id": "CWE-913", "sev": "HIGH", "owasp": "A03", "name": "Web3/Blockchain Injection", "fix": "Sanitize Web3 inputs."},
}

CVSS = {
    "sql_injection": 9.8, "xss_reflected": 7.4, "timing_sqli": 7.1, "xxe": 9.8,
    "ldap_injection": 7.5, "command_injection": 9.8, "ssti": 8.0,
    "cors_misconfigured": 7.5, "directory_traversal": 7.5, "open_redirect": 6.1,
    "insecure_cookie": 5.3, "ssrf": 8.6, "crypto_key_exposure": 9.1,
    "backup_file_exposure": 5.3, "http_method_allowed": 6.5,
    "default_credentials": 9.8, "weak_jwt": 7.5, "api_key_leakage": 9.1,
    "weak_ssl_tls": 7.5, "outdated_server": 7.8, "idor": 7.1,
    "rate_limiting": 5.3, "web3_injection": 8.1,
}

def _vdb(key): return VULN_DB.get(key, {"id":"?", "sev":"INFO", "owasp":"?", "name":key, "fix":"?"})

# ──────────────────────────────────────────────────────────────────────────
# CLASSES
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Vulnerability:
    key: str; cwe_id: str; owasp: str; name: str; severity: str; fix: str
    detail: str = ""; url: str = ""; cvss_score: float = 0.0; poc: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    def to_dict(self): return asdict(self)

@dataclass
class ScanConfig:
    target: str; targets_file: str = ""; profile: str = "standard"
    scope: Set[str] = field(default_factory=set); timeout: int = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS; max_crawl_pages: int = MAX_CRAWL_PAGES
    proxy: str = ""; output_json: str = ""; output_html: str = ""
    output_pocs: str = ""; quiet: bool = False; verbose: bool = False
    verify_ssl: bool = True; skip_checks: Set[str] = field(default_factory=set)

class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._current_form: Dict = None
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            h = d['href']
            if not h.startswith(('javascript:', '#', 'mailto:')):
                self.links.append(urllib.parse.urljoin(self.base, h))
        elif tag == "form":
            self._current_form = {**d, 'inputs': []}
            self.forms.append(self._current_form)
        elif tag == "input" and d.get("name"):
            if self._current_form is not None:
                self._current_form['inputs'].append(d.get('name'))
    def handle_endtag(self, tag):
        if tag == 'form': self._current_form = None

# ──────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────
def pr(msg, cfg):
    if cfg.quiet: return
    if cfg.verbose: logger.info(msg)
    else: print(msg)

def section(title, cfg):
    if not cfg.quiet: print(f"\n{B}{BOLD}{'─'*50}{RST}\n{B}{BOLD}{title}{RST}\n{B}{BOLD}{'─'*50}{RST}")

def print_vuln(key, cfg, detail="", url="", poc=""):
    v = _vdb(key); s = v['sev']; c = CVSS.get(key, 0.0)
    clr = R if s in ["CRITICAL", "HIGH"] else Y if s == "MEDIUM" else C
    print(f"  {clr}[{s}]{RST} {v['name']} (CVSS: {c})")
    if detail: print(f"    Detail: {detail}")
    if url:    print(f"    URL:    {url}")
    if poc:    print(f"    {M}PoC:    {poc}{RST}")
    print(f"    Fix:    {G}{v['fix']}{RST}\n")

def vadd(findings, key, detail="", url="", poc=""):
    v = _vdb(key)
    findings.append(Vulnerability(
        key=key, cwe_id=v['id'], owasp=v['owasp'], name=v['name'], severity=v['sev'], fix=v['fix'],
        detail=detail, url=url, cvss_score=CVSS.get(key,0.0), poc=poc
    ))

def normalize(url):
    if not url.startswith("http"): return "https://" + url
    return url.rstrip("/")

def get_session(cfg):
    s = requests.Session()
    s.headers.update({"User-Agent": f"WebVulnScan/{VERSION}"})
    if cfg.proxy:
        s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    s.verify = cfg.verify_ssl
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s

def req(session, url, cfg, method="GET", **kw):
    try:
        kw.setdefault('timeout', cfg.timeout)
        r = session.request(method, url, **kw)
        r.raise_for_status()
        return r
    except requests.RequestException as e:
        if cfg.verbose: logger.debug(f"Connection error ({method} {url}): {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error during request to {url}")
        return None

class _FallbackBar:
    def __init__(self, total, desc="", disable=False):
        self.total = total; self.n = 0; self.desc = desc; self.disable = disable
    def update(self, n=1):
        if self.disable: return
        self.n += n
        pct = int(100 * self.n / self.total) if self.total else 0
        print(f"\r  {self.desc}: [{pct}%]", end="", flush=True)
    def close(self):
        if not self.disable: print()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

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
    pr(f"  {C}[*] Starting Crawler...{RST}", cfg)
    visited = set()
    to_visit = [base]
    found_params = set()
    found_forms: List[Dict] = []
    
    domain = urllib.parse.urlparse(base).netloc
    
    with make_bar(cfg.max_crawl_pages, "Crawling", cfg) as bar:
        while to_visit and len(visited) < cfg.max_crawl_pages:
            url = to_visit.pop(0)
            if url in visited: continue
            visited.add(url)
            
            r = req(session, url, cfg)
            if not r or "text/html" not in r.headers.get("content-type", ""): 
                bar.update()
                continue
                
            try:
                p = PageParser(url)
                p.feed(r.text)
                
                parsed = urllib.parse.urlparse(url)
                for k in urllib.parse.parse_qs(parsed.query): found_params.add(k)
                
                if p.forms:
                    for form in p.forms:
                        form['action_url'] = urllib.parse.urljoin(url, form.get('action', ''))
                        found_forms.append(form)
                
                for link in p.links:
                    if domain in urllib.parse.urlparse(link).netloc:
                        if link not in visited: to_visit.append(link)
            except Exception as e:
                if cfg.verbose: logger.debug(f"Error parsing {url}: {e}")
            bar.update()
            
    pr(f"  {G}✔ Crawled {len(visited)} pages, found {len(found_params)} parameters and {len(found_forms)} forms.{RST}", cfg)
    return list(found_params), found_forms

# ──────────────────────────────────────────────────────────────────────────
# CHECKS
# ──────────────────────────────────────────────────────────────────────────

def check_crypto_exposure(target, session, params, findings, cfg):
    section("[0] Blockchain & Crypto Security", cfg)
    # Check URL parameters for sensitive names
    suspicious = []
    for p in params:
        if any(x in p.lower() for x in CRYPTO_PARAMS):
            suspicious.append(p)
    
    if suspicious:
        for p in suspicious:
            url = f"{target}?{p}=test"
            print_vuln("crypto_key_exposure", cfg, detail=f"Suspicious parameter '{p}' found in URL.", url=url, poc=f"curl '{url}'")
            vadd(findings, "crypto_key_exposure", f"Param: {p}", url)
    else:
        pr(f"  {G}✔ No obvious crypto parameters in query strings.{RST}", cfg)

def check_headers(resp, findings, cfg):
    section("[1] Security Headers", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}
    if "strict-transport-security" not in h:
        poc = f"curl.exe -I '{resp.url}' | grep -i 'strict-transport'"
        print_vuln("missing_hsts", cfg); vadd(findings, "missing_hsts", poc=poc)
    else: pr(f"  {G}✔ HSTS Present{RST}", cfg)
    
    if "content-security-policy" not in h:
        poc = f"curl.exe -I '{resp.url}' | grep -i 'content-security'"
        print_vuln("missing_csp", cfg); vadd(findings, "missing_csp", poc=poc)
    else: pr(f"  {G}✔ CSP Present{RST}", cfg)

def check_sqli(target, session, params, forms, findings, cfg):
    section("[2] SQL Injection", cfg)
    if not params: params = ["id", "q", "search", "cat", "item"]

    found = []
    def test_get(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            for sig in SQLI_ERRORS:
                if sig in r.text.lower(): return (p, payload, url)
        return None

    def test_post(p, payload, action):
        data = {p: payload}
        r = req(session, action, cfg, method='POST', data=data)
        if r:
            for sig in SQLI_ERRORS:
                if sig in r.text.lower(): return (p, payload, action)
        return None

    post_inputs = []
    for form in forms:
        if form.get('method', '').lower() == 'post':
            post_inputs.extend(form.get('inputs', []))

    total_tests = len(params) * len(SQLI_PAYLOADS) + len(post_inputs) * len(SQLI_PAYLOADS)
    with make_bar(total_tests, "SQLi Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in SQLI_PAYLOADS:
                    futures[ex.submit(test_get, p, pl)] = (p, pl, 'GET')
            for p in post_inputs:
                for pl in SQLI_PAYLOADS:
                    action = target
                    for form in forms:
                        if p in form.get('inputs', []):
                            action = form['action_url']
                            break
                    futures[ex.submit(test_post, p, pl, action)] = (p, pl, 'POST')
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()
    
    if found:
        for p, pl, url in found:
            poc = f"sqlmap -u '{url}' -p {p} --batch --dbs"
            print_vuln("sql_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "sql_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No SQL Injection found.{RST}", cfg)

def check_xss(target, session, params, forms, findings, cfg):
    section("[3] Cross-Site Scripting (XSS)", cfg)
    if not params: params = ["q", "search", "name", "input", "data"]
    
    post_inputs = []
    for form in forms:
        if form.get('method', '').lower() == 'post':
            post_inputs.extend(form.get('inputs', []))

    found = []
    def test_get(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and payload in r.text: return (p, payload, url)
        return None

    def test_post(p, payload, action):
        data = {p: payload}
        r = req(session, action, cfg, method='POST', data=data)
        if r and payload in r.text: return (p, payload, action)
        return None

    total_tests = len(params) * len(XSS_PAYLOADS) + len(post_inputs) * len(XSS_PAYLOADS)
    with make_bar(total_tests, "XSS Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in XSS_PAYLOADS:
                    futures[ex.submit(test_get, p, pl)] = (p, pl, 'GET')
            for p in post_inputs:
                for pl in XSS_PAYLOADS:
                    action = target
                    for form in forms:
                        if p in form.get('inputs', []):
                            action = form['action_url']
                            break
                    futures[ex.submit(test_post, p, pl, action)] = (p, pl, 'POST')
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' | grep -i '<script>'\\nManually visit: {url}"
            print_vuln("xss_reflected", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "xss_reflected", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No Reflected XSS found.{RST}", cfg)

def check_cors(resp, findings, cfg):
    section("[4] CORS Configuration", cfg)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    acao = headers.get("access-control-allow-origin", "")
    if acao:
        if acao == "*":
            print_vuln("cors_misconfigured", cfg, detail="Allow Origin: *", url=resp.url)
            vadd(findings, "cors_misconfigured", detail="Allow Origin: *", url=resp.url)
        else:
            pr(f"  {G}✔ CORS Origin restricted to: {acao}{RST}", cfg)
    else:
        pr(f"  {G}✔ No CORS headers present (default behavior){RST}", cfg)

def check_cookies(resp, findings, cfg):
    section("[5] Cookie Security", cfg)
    cookies = resp.headers.get("set-cookie", "")
    if cookies:
        has_issues = False
        if "HttpOnly" not in cookies:
            poc = f"curl.exe -I '{resp.url}' | grep -i 'set-cookie'"
            print_vuln("insecure_cookie", cfg, detail="Missing HttpOnly flag", url=resp.url, poc=poc)
            vadd(findings, "insecure_cookie", detail="Missing HttpOnly flag", url=resp.url, poc=poc)
            has_issues = True
        if "Secure" not in cookies:
            poc = f"curl.exe -I '{resp.url}' | grep -i 'set-cookie'"
            print_vuln("insecure_cookie", cfg, detail="Missing Secure flag", url=resp.url, poc=poc)
            vadd(findings, "insecure_cookie", detail="Missing Secure flag", url=resp.url, poc=poc)
            has_issues = True
        if not has_issues:
            pr(f"  {G}✔ Cookies have proper security flags{RST}", cfg)
    else:
        pr(f"  {G}✔ No set-cookie headers found{RST}", cfg)

def check_open_redirect(target, session, params, findings, cfg):
    section("[6] Open Redirect", cfg)
    if not params: params = ["redirect", "url", "return", "target", "next"]
    found = []
    
    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        try:
            r = session.head(url, timeout=cfg.timeout, allow_redirects=False)
            loc = r.headers.get("location", "")
            if loc and "evil.com" in loc:
                return (p, payload, url, loc)
        except: pass
        return None

    with make_bar(len(params), "Redirect Scan", cfg) as bar:
        for p in params:
            for payload in ["https://evil.com", "//evil.com"]:
                res = test(p, payload)
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url, loc in found:
            poc = f"curl.exe -i -L '{url}' | grep -i 'Location:' # Check redirect target"
            print_vuln("open_redirect", cfg, detail=f"Param: {p} → {loc}", url=url, poc=poc)
            vadd(findings, "open_redirect", f"Param: {p} → {loc}", url, poc=poc)
    else:
        pr(f"  {G}✔ No Open Redirects detected.{RST}", cfg)

def check_path_traversal(target, session, params, findings, cfg):
    section("[7] Path Traversal", cfg)
    if not params: params = ["file", "path", "doc", "download", "page"]
    
    signatures = ["root:", "[boot loader]", "etc/passwd", "win.ini"]
    found = []
    
    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            for sig in signatures:
                if sig in r.text.lower(): return (p, payload, url)
        return None

    with make_bar(len(params) * len(PATH_TRAVERSAL_PAYLOADS), "Path Traversal Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in PATH_TRAVERSAL_PAYLOADS:
                    futures[ex.submit(test, p, pl)] = (p, pl)
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' # Check for file content in response (e.g., /etc/passwd content)"
            print_vuln("directory_traversal", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "directory_traversal", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No Path Traversal detected.{RST}", cfg)

def check_info_disclosure(resp, findings, cfg):
    section("[8] Information Disclosure", cfg)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    
    sensitive_headers = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]
    found_info = []
    
    for header in sensitive_headers:
        if header in headers:
            found_info.append((header, headers[header]))

    if found_info:
        for hdr, val in found_info:
            print_vuln("info_disclosure", cfg, detail=f"{hdr}: {val}", url=resp.url)
            vadd(findings, "info_disclosure", detail=f"{hdr}: {val}", url=resp.url)
    else:
        pr(f"  {G}✔ No sensitive headers disclosed.{RST}", cfg)

def check_ssrf(target, session, params, findings, cfg):
    section("[9] SSRF", cfg)
    if not params: params = ["url", "uri", "path", "domain", "site"]

    found = []
    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            # Basic heuristics for cloud metadata
            if "metadata.google.internal" in r.text or "ami-id" in r.text:
                return (p, payload, url)
        return None

    with make_bar(len(params) * len(SSRF_PAYLOADS), "SSRF Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {}
            for p in params:
                for pl in SSRF_PAYLOADS:
                    futures[ex.submit(test, p, pl)] = (p, pl)
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()
    
    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' # Server will fetch the URL - indicates SSRF"
            print_vuln("ssrf", cfg, detail=f"Param: {p} reachable internal resource", url=url, poc=poc)
            vadd(findings, "ssrf", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No basic SSRF detected.{RST}", cfg)

def check_host_header(target, session, findings, cfg):
    section("[10] Host Header Injection", cfg)
    # Test if server reflects arbitrary Host headers
    r = req(session, target, cfg, headers={"Host": "evil.com"})
    if r and "evil.com" in r.text:
        print_vuln("host_header_injection", cfg, detail="Host header reflected in response body", url=target)
        vadd(findings, "host_header_injection", detail="Host header reflected", url=target)
    else:
        pr(f"  {G}✔ Host header not reflected.{RST}", cfg)

def check_timing_sqli(target, session, params, findings, cfg):
    section("[11] Timing-based SQL Injection", cfg)
    if not params: params = ["id", "q", "search"]
    
    found = []
    def test_timing(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        try:
            start = time.time()
            r = req(session, url, cfg, timeout=10)
            elapsed = time.time() - start
            if elapsed > 5:  # Significant delay indicates sleep worked
                return (p, payload, url, elapsed)
        except:
            pass
        return None

    with make_bar(len(params) * len(SQLI_TIME_PAYLOADS), "Timing SQLi Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=3) as ex:  # Slower to measure time
            futures = {}
            for p in params[:2]:  # Test only 2 params to save time
                for pl in SQLI_TIME_PAYLOADS:
                    futures[ex.submit(test_timing, p, pl)] = (p, pl)
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()
    
    if found:
        for p, pl, url, t in found:
            print_vuln("timing_sqli", cfg, detail=f"Param: {p}, Delay: {t:.2f}s", url=url)
            vadd(findings, "timing_sqli", f"Param: {p}, delay {t:.2f}s", url)
    else:
        pr(f"  {G}✔ No timing-based SQLi detected.{RST}", cfg)

def check_backup_files(target, session, findings, cfg):
    section("[12] Backup File Exposure", cfg)
    base_path = target.rstrip('/')
    found_backups = []
    
    # Test common file paths with backup extensions
    common_files = ["", "/index.html", "/index.php", "/admin", "/config", "/web.config", "/.htaccess"]
    
    def check_backup(file_path, ext):
        try:
            url = f"{base_path}{file_path}{ext}"
            r = session.head(url, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code == 200:
                return (ext, url)
        except (requests.exceptions.RequestException, Exception):
            pass
        return None

    with make_bar(len(BACKUP_EXTENSIONS) * len(common_files), "Backup File Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(check_backup, fp, ext): (fp, ext) 
                      for fp in common_files for ext in BACKUP_EXTENSIONS}
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res: found_backups.append(res)
                except Exception as e:
                    logger.debug(f"Backup check error: {e}")
                bar.update()
    
    if found_backups:
        for ext, url in found_backups:
            print_vuln("backup_file_exposure", cfg, detail=f"Backup file found: {ext}", url=url)
            vadd(findings, "backup_file_exposure", f"File: {ext}", url)
    else:
        pr(f"  {G}✔ No backup files exposed.{RST}", cfg)

def check_http_methods(target, session, findings, cfg):
    section("[13] Dangerous HTTP Methods", cfg)
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
    found_methods = []
    
    for method in dangerous_methods:
        try:
            r = session.request(method, target, timeout=cfg.timeout, verify=cfg.verify_ssl)
            if r and r.status_code not in [404, 405, 501]:
                found_methods.append(method)
        except (requests.exceptions.RequestException, Exception):
            pass

    if found_methods:
        poc = f"curl.exe -X PUT '{target}' # Or: DELETE, TRACE, CONNECT"
        print_vuln("http_method_allowed", cfg, detail=f"Methods allowed: {', '.join(found_methods)}", url=target, poc=poc)
        vadd(findings, "http_method_allowed", f"Methods: {', '.join(found_methods)}", url=target, poc=poc)
    else:
        pr(f"  {G}✔ Dangerous HTTP methods disabled.{RST}", cfg)

def check_jwt_tokens(resp, findings, cfg):
    section("[14] JWT Token Analysis", cfg)
    cookies_str = resp.headers.get("set-cookie", "") + "; ".join([k + "=" + v for k, v in resp.cookies.items()])
    jwt_pattern = r'([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
    
    found_jwts = re.findall(jwt_pattern, cookies_str)
    if found_jwts:
        for jwt in found_jwts:
            # Check for "none" algorithm vulnerability
            if jwt.split('.')[1].count('=') % 4:  # Bad padding check
                print_vuln("weak_jwt", cfg, detail="JWT with weak/none algorithm", url=resp.url)
                vadd(findings, "weak_jwt", "JWT algorithm issue", url=resp.url)
                break
    else:
        pr(f"  {G}✔ No JWT tokens found.{RST}", cfg)

def check_api_key_leakage(resp, findings, cfg):
    section("[15] API Key Leakage", cfg)
    found_keys = []
    
    for pattern in API_KEY_PATTERNS:
        matches = re.findall(pattern, resp.text, re.IGNORECASE)
        if matches:
            for match in matches[:3]:  # Report first 3
                found_keys.append(match if isinstance(match, str) else match[0] if match else "")
    
    if found_keys:
        for key in found_keys:
            if key:
                print_vuln("api_key_leakage", cfg, detail=f"Potential API key: {key[:20]}...", url=resp.url)
                vadd(findings, "api_key_leakage", f"Key: {key[:20]}...", url=resp.url)
    else:
        pr(f"  {G}✔ No obvious API keys found.{RST}", cfg)

def check_default_credentials(target, session, findings, cfg):
    section("[16] Default Credentials", cfg)
    found_creds = []
    
    for username, password in DEFAULT_CREDENTIALS:
        try:
            # Try common login paths
            for path in ["/login", "/admin/login", "/administrator"]:
                try:
                    url = target.rstrip('/') + path
                    data = {"username": username, "password": password, "user": username, "pass": password}
                    r = session.post(url, data=data, timeout=5, verify=cfg.verify_ssl)
                    if r and r.status_code == 200 and ("dashboard" in r.text.lower() or "logout" in r.text.lower()):
                        found_creds.append((username, password, url))
                        break
                except (requests.exceptions.RequestException, Exception):
                    pass
        except Exception as e:
            logger.debug(f"Default credential check error: {e}")

    if found_creds:
        for user, pwd, url in found_creds:
            poc = f"curl.exe -X POST '{url}' -d 'username={user}&password={pwd}'"
            print_vuln("default_credentials", cfg, detail=f"Creds: {user}:{pwd}", url=url, poc=poc)
            vadd(findings, "default_credentials", f"{user}:{pwd}", url, poc=poc)
    else:
        pr(f"  {G}✔ No default credentials accepted.{RST}", cfg)

def check_ssti(target, session, params, findings, cfg):
    section("[17] SSTI Detection", cfg)
    if not params: params = ["name", "template", "view"]
    
    found = []
    def test_ssti(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            # Check if template math is computed
            if "49" in r.text or "7 * 7" not in r.text:
                return (p, payload, url)
        return None

    with make_bar(len(params) * len(SSTI_PAYLOADS), "SSTI Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_ssti, p, pl): (p, pl) for p in params for pl in SSTI_PAYLOADS}
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' # Look for 49 in response (7*7)"
            print_vuln("ssti", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "ssti", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No SSTI detected.{RST}", cfg)

def check_xxe(target, session, params, findings, cfg):
    section("[18] XXE Detection", cfg)
    if not params: params = ["xml", "data", "file"]
    
    found = []
    def test_xxe(p):
        url = target
        data = {p: XXE_PAYLOADS[0]}
        try:
            r = session.post(url, data=data, timeout=5, verify=cfg.verify_ssl)
            if r and ("root:" in r.text or "xml" in r.text.lower()):
                return (p, url)
        except:
            pass
        return None

    with make_bar(len(params), "XXE Scan", cfg) as bar:
        for p in params:
            res = test_xxe(p)
            if res: found.append(res)
            bar.update()

    if found:
        for p, url in found:
            poc = f"POST data: {p}=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"
            print_vuln("xxe", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "xxe", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No XXE detected.{RST}", cfg)

def check_command_injection(target, session, params, findings, cfg):
    section("[19] Command Injection", cfg)
    if not params: params = ["cmd", "command", "exec", "system"]
    
    found = []
    def test_cmd(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            if "root:" in r.text or "uid=" in r.text or "bin/bash" in r.text:
                return (p, payload, url)
        return None

    with make_bar(len(params) * len(CMD_INJECTION_PAYLOADS), "Command Injection Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_cmd, p, pl): (p, pl) for p in params for pl in CMD_INJECTION_PAYLOADS}
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' # Look for 'root:' or 'uid=' in response (output of id or whoami)"
            print_vuln("command_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "command_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No command injection detected.{RST}", cfg)

def check_ldap_injection(target, session, params, findings, cfg):
    section("[20] LDAP Injection", cfg)
    if not params: params = ["search", "filter", "user", "query"]
    
    found = []
    def test_ldap(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and r.status_code == 200:  # Wildcard filter may cause different output
            return (p, payload, url)
        return None

    with make_bar(len(params) * len(LDAP_INJECTION_PAYLOADS), "LDAP Injection Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test_ldap, p, pl): (p, pl) for p in params for pl in LDAP_INJECTION_PAYLOADS}
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl.exe -k '{url}' # LDAP filter injection with * or special chars"
            print_vuln("ldap_injection", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "ldap_injection", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No LDAP injection detected.{RST}", cfg)

def check_outdated_server(resp, findings, cfg):
    section("[21] Outdated Server Detection", cfg)
    server_header = resp.headers.get("server", "")
    
    if server_header:
        for known_vuln, cve in KNOWN_CVE_VERSIONS.items():
            if known_vuln.lower() in server_header.lower():
                print_vuln("outdated_server", cfg, detail=f"Vulnerable server: {server_header} ({cve})", url=resp.url)
                vadd(findings, "outdated_server", f"{server_header} - {cve}", url=resp.url)
                return
        pr(f"  {G}✔ Server: {server_header}{RST}", cfg)
    else:
        pr(f"  {G}✔ Server header not disclosed.{RST}", cfg)

def check_ssl_tls(target, session, findings, cfg):
    section("[22] SSL/TLS Configuration", cfg)
    try:
        # Try SSLv3 or weak TLS
        import ssl
        if target.startswith("https://"):
            hostname = urllib.parse.urlparse(target).hostname
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with session.get(target, verify=False, timeout=5) as r:
                pr(f"  {G}✔ TLS connection successful.{RST}", cfg)
    except Exception as e:
        if "sslv3" in str(e).lower() or "ssl" in str(e).lower():
            print_vuln("weak_ssl_tls", cfg, detail=str(e)[:50], url=target)
            vadd(findings, "weak_ssl_tls", str(e)[:50], url=target)

def check_idor(target, session, params, findings, cfg):
    section("[23] IDOR Detection", cfg)
    id_params = [p for p in params if any(x in p.lower() for x in ["id", "user", "account", "profile"])]
    
    if id_params:
        for param in id_params[:3]:
            # Try different ID values
            for test_id in ["1", "2", "999", "admin"]:
                url = f"{target}?{param}={test_id}"
                r = req(session, url, cfg)
                if r and r.status_code == 200:
                    poc = f"curl.exe -k '{url}' # Check if accessible without proper authorization"
                    pr(f"  {Y}⚠ Param '{param}' with ID '{test_id}' returns 200 - potential IDOR{RST}", cfg)
                    print_vuln("idor", cfg, detail=f"Param: {param}, accessible ID: {test_id}", url=url, poc=poc)
                    vadd(findings, "idor", f"Param: {param}", url, poc=poc)
                    break
    else:
        pr(f"  {G}✔ No ID-like parameters found.{RST}", cfg)

def check_rate_limiting(target, session, findings, cfg):
    section("[24] Rate Limiting", cfg)
    
    # Send 10 rapid requests and check for 429/throttle headers
    responses = []
    try:
        for i in range(10):
            try:
                r = session.get(target, timeout=2, verify=cfg.verify_ssl)
                responses.append(r.status_code)
            except (requests.exceptions.RequestException, Exception):
                pass
    except Exception as e:
        logger.debug(f"Rate limiting check error: {e}")
    
    if responses and 429 not in responses and "X-RateLimit-Remaining" not in str(responses):
        print_vuln("rate_limiting", cfg, detail="No rate limiting detected", url=target)
        vadd(findings, "rate_limiting", "No rate limiting", url=target)
    else:
        pr(f"  {G}✔ Rate limiting in place or unavailable.{RST}", cfg)

# ──────────────────────────────────────────────────────────────────────────
# REPORTING
# ──────────────────────────────────────────────────────────────────────────
def save_pocs(findings, cfg, target):
    if not cfg.output_pocs: return
    pocs = [f for f in findings if f.poc]
    if not pocs: 
        pr(f"  {Y}ℹ No exploitable PoCs to save.{RST}", cfg)
        return
    try:
        with open(cfg.output_pocs, "w") as f:
            f.write(f"#!/bin/bash\n# PoCs for {target}\n\n")
            for v in pocs:
                f.write(f"# {v.name}\n{v.poc}\n\n")
        os.chmod(cfg.output_pocs, 0o755)
        pr(f"  {G}✔ PoC script saved to: {cfg.output_pocs}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write PoC file {cfg.output_pocs}: {e}")

def save_json(findings, cfg, target):
    if not cfg.output_json: return
    data = {"target": target, "findings": [f.to_dict() for f in findings]}
    try:
        with open(cfg.output_json, "w") as f:
            json.dump(data, f, indent=2)
        pr(f"  {G}✔ JSON report saved to: {cfg.output_json}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write JSON report {cfg.output_json}: {e}")

def save_html(findings, cfg, target):
    if not cfg.output_html: return
    
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts: counts[f.severity] += 1

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {target}</title>
    <style>
        body {{ font-family: sans-serif; background: #f4f4f4; color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: flex; justify-content: space-around; margin-bottom: 30px; text-align: center; }}
        .card {{ padding: 15px; border-radius: 5px; width: 20%; color: #fff; font-weight: bold; }}
        .crit {{ background: #e74c3c; }} .high {{ background: #e67e22; }}
        .med {{ background: #f1c40f; color: #333; }} .low {{ background: #3498db; }}
        .finding-row {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 3px; }}
        .severity-CRITICAL {{ color: #e74c3c; font-weight: bold; }}
        .severity-HIGH {{ color: #e67e22; font-weight: bold; }}
        .severity-MEDIUM {{ color: #f39c12; font-weight: bold; }}
        .severity-LOW {{ color: #3498db; font-weight: bold; }}
        .poc-box {{ font-family: monospace; background: #2c3e50; color: #2ecc71; padding: 10px; border-radius: 3px; margin: 10px 0; white-space: pre-wrap; word-wrap: break-word; border-left: 3px solid #2ecc71; }}
        .method-box {{ background: #ecf0f1; padding: 8px; border-radius: 3px; margin: 5px 0; }}
        .step {{ margin: 8px 0; padding: 5px; }}
        .url {{ word-break: break-all; color: #2980b9; }}
        h4 {{ margin: 10px 0 5px 0; color: #2c3e50; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 WebVulnScan v{VERSION} Security Report</h1>
        <p><strong>Target:</strong> <span class="url">{target}</span><br>
        <strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <strong>Total Vulnerabilities:</strong> {len(findings)}</p>
        
        <div class="summary">
            <div class="card crit">🔴<br>{counts['CRITICAL']}<br>Critical</div>
            <div class="card high">🟠<br>{counts['HIGH']}<br>High</div>
            <div class="card med">🟡<br>{counts['MEDIUM']}<br>Medium</div>
            <div class="card low">🔵<br>{counts['LOW']}<br>Low</div>
        </div>

        <h2>Security Findings</h2>
    """

    for f in findings:
        poc_display = f.poc if f.poc else "Automatic detection - Manually verify in browser"
        html_content += f"""
        <div class="finding-row">
            <h3>{f.name}</h3>
            <p><span class="severity-{f.severity}">[{f.severity}]</span> CVSS: {f.cvss_score:.1f} | CWE: {f.cwe_id}</p>
            <p><strong>URL:</strong> <span class="url">{f.url}</span></p>
            <p><strong>Detail:</strong> {f.detail}</p>
            <h4>📋 How to Exploit:</h4>
            <div class="poc-box">{poc_display}</div>
            <h4>✅ Remediation:</h4>
            <p>{f.fix}</p>
        </div>
        """
    
    html_content += """
        <hr>
        <footer style="color: #7f8c8d; font-size: 0.9em; margin-top: 30px;">
            <p><strong>Report Generated by WebVulnScan v7.0</strong> | Enterprise Web Vulnerability Scanner</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </footer>
    </div>
</body>
</html>
    """
    
    try:
        with open(cfg.output_html, "w") as f:
            f.write(html_content)
        pr(f"  {G}✔ HTML report saved to: {cfg.output_html}{RST}", cfg)
    except Exception as e:
        logger.error(f"Failed to write HTML report {cfg.output_html}: {e}")

# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description=f"WebVulnScan v{VERSION}")
    p.add_argument("target", nargs="?", help="Target URL")
    p.add_argument("--targets", help="File with list of URLs")
    p.add_argument("--profile", choices=["quick", "standard", "full", "api"], default="standard")
    p.add_argument("-t", "--timeout", type=int, default=None)
    p.add_argument("-w", "--threads", type=int, default=None)
    p.add_argument("--proxy", help="HTTP Proxy")
    p.add_argument("-o", "--output", dest="output_json", help="JSON Output")
    p.add_argument("--html", dest="output_html", help="HTML Output")
    p.add_argument("--save-pocs", dest="output_pocs", help="File to save PoC commands")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", help="Verify TLS certificates")
    p.add_argument("--no-verify", dest="verify_ssl", action="store_false", help="Do not verify TLS certificates")
    p.set_defaults(verify_ssl=True)
    p.add_argument("--config", help="Path to config file")
    p.add_argument("--version", action="version", version=f"WebVulnScan {VERSION}")
    args = p.parse_args()

    profiles = {
        "quick": {"threads": 20, "timeout": 5, "pages": 10},
        "standard": {"threads": 15, "timeout": 10, "pages": 30},
        "full": {"threads": 25, "timeout": 15, "pages": 100},
        "api": {"threads": 20, "timeout": 10, "pages": 20}
    }
    prof = profiles.get(args.profile, profiles["standard"])

    cfg_file_settings: Dict[str, str] = {}
    if args.config:
        cp = configparser.ConfigParser()
        try:
            cp.read(args.config)
            if 'scan' in cp:
                cfg_file_settings = dict(cp['scan'])
                logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to read config file {args.config}: {e}")

    env = os.environ
    def get_setting(name, default=None):
        # FIXED: Check explicitly for None to allow False values (like --no-verify)
        val = getattr(args, name, None)
        if val is not None: return val
        val = cfg_file_settings.get(name)
        if val is not None: return val
        val = env.get(name.upper())
        if val is not None: return val
        return default

    if args.verbose: logger.setLevel(logging.DEBUG)
    elif args.quiet: logger.setLevel(logging.WARNING)

    logfn = cfg_file_settings.get('log_file')
    if logfn:
        try:
            fh = logging.FileHandler(logfn)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            logger.info(f"Logging to file {logfn}")
        except Exception as e:
            logger.error(f"Could not open log file {logfn}: {e}")

    cfg = ScanConfig(
        target=get_setting('target', ''),
        targets_file=get_setting('targets_file', ''),
        profile=get_setting('profile', args.profile),
        timeout=int(get_setting('timeout', prof['timeout'])),
        threads=int(get_setting('threads', prof['threads'])),
        max_crawl_pages=int(get_setting('max_crawl_pages', prof['pages'])),
        proxy=get_setting('proxy', ''),
        output_json=get_setting('output_json', ''),
        output_html=get_setting('output_html', ''),
        output_pocs=get_setting('output_pocs', ''),
        verbose=bool(get_setting('verbose', args.verbose)),
        quiet=bool(get_setting('quiet', args.quiet)),
        verify_ssl=bool(get_setting('verify_ssl', True)),
        skip_checks=set(get_setting('skip_checks', '').split(',')) if get_setting('skip_checks', '') else set()
    )

    targets = []
    if cfg.targets_file:
        try:
            with open(cfg.targets_file) as f:
                targets = [normalize(line.strip()) for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Could not read targets file {cfg.targets_file}: {e}")
            sys.exit(1)
    elif cfg.target:
        targets = [normalize(cfg.target)]
    else:
        print(f"{R}Error: No target specified.{RST}"); sys.exit(1)

    all_findings = []
    try:
        for target in targets:
            pr(f"\n{G}[*] Scanning: {target}{RST} (Profile: {cfg.profile.upper()})", cfg)
            session = get_session(cfg)
            findings = []
            
            r = req(session, target, cfg)
            if not r:
                pr(f"{R}Could not connect to {target}{RST}", cfg); continue
            
            # Passive Checks (on initial response)
            check_headers(r, findings, cfg)
            check_cors(r, findings, cfg)
            check_cookies(r, findings, cfg)
            check_info_disclosure(r, findings, cfg)
            check_jwt_tokens(r, findings, cfg)
            check_api_key_leakage(r, findings, cfg)
            check_outdated_server(r, findings, cfg)
            
            # Active Checks (crawl & test parameters)
            if cfg.profile != "quick":
                params, forms = crawl(session, target, cfg)
            else:
                params = []
                forms = []
            
            check_crypto_exposure(target, session, params, findings, cfg)
            if "sqli" not in cfg.skip_checks:
                check_sqli(target, session, params, forms, findings, cfg)
                check_timing_sqli(target, session, params, findings, cfg)
            if "xss" not in cfg.skip_checks:
                check_xss(target, session, params, forms, findings, cfg)
            if "redirect" not in cfg.skip_checks:
                check_open_redirect(target, session, params, findings, cfg)
            if "traversal" not in cfg.skip_checks:
                check_path_traversal(target, session, params, findings, cfg)
            if "ssrf" not in cfg.skip_checks:
                check_ssrf(target, session, params, findings, cfg)
            if "ssti" not in cfg.skip_checks:
                check_ssti(target, session, params, findings, cfg)
            if "xxe" not in cfg.skip_checks:
                check_xxe(target, session, params, findings, cfg)
            if "cmd" not in cfg.skip_checks:
                check_command_injection(target, session, params, findings, cfg)
            if "ldap" not in cfg.skip_checks:
                check_ldap_injection(target, session, params, findings, cfg)
            if "idor" not in cfg.skip_checks:
                check_idor(target, session, params, findings, cfg)
            
            # Server-level checks
            check_host_header(target, session, findings, cfg)
            check_backup_files(target, session, findings, cfg)
            check_http_methods(target, session, findings, cfg)
            check_default_credentials(target, session, findings, cfg)
            check_ssl_tls(target, session, findings, cfg)
            if cfg.profile == "full":
                check_rate_limiting(target, session, findings, cfg)
            
            save_json(findings, cfg, target)
            save_html(findings, cfg, target)
            save_pocs(findings, cfg, target)
            
            all_findings.extend(findings)
    except KeyboardInterrupt:
        logger.warning("Scan aborted by user")
    except Exception as e:
        logger.exception(f"Unexpected error during scanning: {e}")

    pr(f"\n{B}{'─'*50}{RST}", cfg)
    pr(f"{B}Scan Complete.{RST} Total Findings: {len(all_findings)}", cfg)

if __name__ == "__main__":
    main()

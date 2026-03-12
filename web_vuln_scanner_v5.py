#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         WebVulnScan v5.0 — Enterprise Web Application Security Scanner  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import base64
import json
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
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────
VERSION = "5.0"
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
CMDI_PAYLOADS = [";id", "|id", "`id`"]
CMDI_SIGS = ["uid=", "gid=", "root:"]

# Database
VULN_DB = {
    "sql_injection": {"id": "CWE-89", "sev": "CRITICAL", "owasp": "A03", "name": "SQL Injection", "fix": "Use parameterized queries."},
    "xss_reflected": {"id": "CWE-79", "sev": "HIGH", "owasp": "A03", "name": "Reflected XSS", "fix": "Encode output."},
    "command_injection": {"id": "CWE-78", "sev": "CRITICAL", "owasp": "A03", "name": "Command Injection", "fix": "Sanitize input."},
    "missing_hsts": {"id": "CWE-319", "sev": "MEDIUM", "owasp": "A05", "name": "Missing HSTS", "fix": "Add HSTS header."},
    "missing_csp": {"id": "CWE-1021", "sev": "MEDIUM", "owasp": "A05", "name": "Missing CSP", "fix": "Add CSP header."},
    "sensitive_files": {"id": "CWE-538", "sev": "HIGH", "owasp": "A05", "name": "Sensitive File", "fix": "Restrict access."},
}
CVSS = {"sql_injection": 9.8, "xss_reflected": 7.4, "command_injection": 9.8}

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
    verify_ssl: bool = False; skip_checks: Set[str] = field(default_factory=set)

class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__(); self.base = base; self.links = []; self.forms = []; self.inputs = []
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            h = d['href']
            if not h.startswith(('javascript:', '#', 'mailto:')):
                self.links.append(urllib.parse.urljoin(self.base, h))
        elif tag == "form": self.forms.append(d)
        elif tag == "input" and d.get("name"): self.inputs.append(d.get('name'))

# ──────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────
def pr(msg, cfg): 
    if not cfg.quiet: print(msg)

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
    if cfg.proxy: s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    s.verify = cfg.verify_ssl
    return s

def req(session, url, cfg, method="GET", **kw):
    try:
        kw.setdefault('timeout', cfg.timeout)
        return session.request(method, url, **kw)
    except Exception as e:
        if cfg.verbose: print(f"  {DIM}Connection error: {e}{RST}")
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
    
    # Limit crawl to same domain
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
                
            # Parse HTML
            try:
                p = PageParser(url)
                p.feed(r.text)
                
                # Extract params from URL
                parsed = urllib.parse.urlparse(url)
                for k in urllib.parse.parse_qs(parsed.query): found_params.add(k)
                
                # Add new links
                for link in p.links:
                    if domain in urllib.parse.urlparse(link).netloc:
                        if link not in visited: to_visit.append(link)
            except:
                pass
            bar.update()
            
    pr(f"  {G}✔ Crawled {len(visited)} pages, found {len(found_params)} parameters.{RST}", cfg)
    return list(found_params)

# ──────────────────────────────────────────────────────────────────────────
# CHECKS
# ──────────────────────────────────────────────────────────────────────────
def check_headers(resp, findings, cfg):
    section("[1] Security Headers", cfg)
    h = {k.lower(): v for k, v in resp.headers.items()}
    if "strict-transport-security" not in h:
        print_vuln("missing_hsts", cfg); vadd(findings, "missing_hsts")
    else: pr(f"  {G}✔ HSTS Present{RST}", cfg)
    
    if "content-security-policy" not in h:
        print_vuln("missing_csp", cfg); vadd(findings, "missing_csp")
    else: pr(f"  {G}✔ CSP Present{RST}", cfg)

def check_sqli(target, session, params, findings, cfg):
    section("[2] SQL Injection", cfg)
    if not params: params = ["id", "q", "search", "cat", "item"]
    
    found = []
    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r:
            for sig in SQLI_ERRORS:
                if sig in r.text.lower(): return (p, payload, url)
        return None

    with make_bar(len(params)*len(SQLI_PAYLOADS), "SQLi Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test, p, pl): (p,pl) for p in params for pl in SQLI_PAYLOADS}
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

def check_xss(target, session, params, findings, cfg):
    section("[3] Cross-Site Scripting (XSS)", cfg)
    if not params: params = ["q", "search", "name", "input", "data"]
    
    found = []
    def test(p, payload):
        url = f"{target}?{p}={urllib.parse.quote(payload)}"
        r = req(session, url, cfg)
        if r and payload in r.text: return (p, payload, url)
        return None

    with make_bar(len(params)*len(XSS_PAYLOADS), "XSS Scan", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            futures = {ex.submit(test, p, pl): (p,pl) for p in params for pl in XSS_PAYLOADS}
            for f in as_completed(futures):
                res = f.result()
                if res: found.append(res)
                bar.update()

    if found:
        for p, pl, url in found:
            poc = f"curl -k '{url}'"
            print_vuln("xss_reflected", cfg, detail=f"Param: {p}", url=url, poc=poc)
            vadd(findings, "xss_reflected", f"Param: {p}", url, poc=poc)
    else:
        pr(f"  {G}✔ No Reflected XSS found.{RST}", cfg)

# ──────────────────────────────────────────────────────────────────────────
# REPORTING
# ──────────────────────────────────────────────────────────────────────────
def save_pocs(findings, cfg, target):
    if not cfg.output_pocs: return
    pocs = [f for f in findings if f.poc]
    if not pocs: 
        pr(f"  {Y}ℹ No exploitable PoCs to save.{RST}", cfg)
        return
    
    with open(cfg.output_pocs, "w") as f:
        f.write(f"#!/bin/bash\n# PoCs for {target}\n\n")
        for v in pocs:
            f.write(f"# {v.name}\n{v.poc}\n\n")
    try: os.chmod(cfg.output_pocs, 0o755)
    except: pass
    pr(f"  {G}✔ PoC script saved to: {cfg.output_pocs}{RST}", cfg)

def save_json(findings, cfg, target):
    if not cfg.output_json: return
    data = {"target": target, "findings": [f.to_dict() for f in findings]}
    with open(cfg.output_json, "w") as f:
        json.dump(data, f, indent=2)
    pr(f"  {G}✔ JSON report saved to: {cfg.output_json}{RST}", cfg)

# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description=f"WebVulnScan v{VERSION}")
    p.add_argument("target", nargs="?", help="Target URL")
    p.add_argument("--targets", help="File with list of URLs")
    p.add_argument("--profile", choices=["quick", "standard", "full", "api"], default="standard")
    p.add_argument("-t", "--timeout", type=int, default=0)
    p.add_argument("-w", "--threads", type=int, default=0)
    p.add_argument("--proxy", help="HTTP Proxy")
    p.add_argument("-o", "--output", dest="output_json", help="JSON Output")
    p.add_argument("--html", dest="output_html", help="HTML Output")
    p.add_argument("--save-pocs", dest="output_pocs", help="File to save PoC commands")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--verify-ssl", action="store_true")
    args = p.parse_args()

    # Config
    profiles = {
        "quick": {"threads": 20, "timeout": 5, "pages": 10},
        "standard": {"threads": 15, "timeout": 10, "pages": 30},
        "full": {"threads": 25, "timeout": 15, "pages": 100},
        "api": {"threads": 20, "timeout": 10, "pages": 20}
    }
    prof = profiles.get(args.profile, profiles["standard"])

    cfg = ScanConfig(
        target=args.target or "",
        targets_file=args.targets or "",
        profile=args.profile,
        timeout=args.timeout or prof['timeout'],
        threads=args.threads or prof['threads'],
        max_crawl_pages=prof['pages'],
        proxy=args.proxy or "",
        output_json=args.output_json or "",
        output_html=args.output_html or "",
        output_pocs=args.output_pocs or "",
        verbose=args.verbose,
        quiet=args.quiet,
        verify_ssl=args.verify_ssl
    )

    # Targets
    targets = []
    if cfg.targets_file:
        with open(cfg.targets_file) as f:
            targets = [normalize(line.strip()) for line in f if line.strip()]
    elif cfg.target:
        targets = [normalize(cfg.target)]
    else:
        print(f"{R}Error: No target specified.{RST}"); sys.exit(1)

    all_findings = []
    for target in targets:
        pr(f"\n{G}[*] Scanning: {target}{RST} (Profile: {cfg.profile.upper()})", cfg)
        session = get_session(cfg)
        findings = []
        
        # 1. Landing & Headers
        r = req(session, target, cfg)
        if not r:
            pr(f"{R}Could not connect to {target}{RST}", cfg); continue
        
        check_headers(r, findings, cfg)
        
        # 2. Crawl
        if cfg.profile != "quick":
            params = crawl(session, target, cfg)
        else:
            params = []
            
        # 3. Active Checks
        # Only run if we have params or if it's a specific check
        if "sqli" not in cfg.skip_checks: check_sqli(target, session, params, findings, cfg)
        if "xss" not in cfg.skip_checks: check_xss(target, session, params, findings, cfg)
        
        # Reports
        save_json(findings, cfg, target)
        save_pocs(findings, cfg, target)
        
        all_findings.extend(findings)

    pr(f"\n{B}{'─'*50}{RST}", cfg)
    pr(f"{B}Scan Complete.{RST} Total Findings: {len(all_findings)}", cfg)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         WebVulnScan v5.0 — Enterprise Web Application Security Scanner  ║
║         For AUTHORIZED penetration testing ONLY                          ║
║         Use only on systems you own or have explicit written permission  ║
╚══════════════════════════════════════════════════════════════════════════╝
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
MAX_JS_FILES      = 10
RETRY_429_WAIT    = 6
SSTI_PAYLOAD      = "{{31337*31337}}"
SSTI_EXPECTED     = "982176769"

# ... [Truncated Constants for brevity: API_PATHS, SECURITY_TXT_PATHS, BASE_HEADERS, ANSI, PROFILES, CVSS, LOE, VULN_DB] ...
# ... [Assume all constants from the original script are present here] ...

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
    poc:        str  = ""      # Proof-of-concept command
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
    output_pocs:      str   = ""  # NEW: File to save PoC commands
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

# ... [Helper functions: _vdb, normalize, in_scope, get_session, req, crawl, etc.] ...
# [All helper functions from the original script remain unchanged]

# ──────────────────────────────────────────────────────────────────────────
# MODIFIED SECURITY CHECKS (PoC Generation Focus)
# ──────────────────────────────────────────────────────────────────────────

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

    # [Error-based checking logic...]
    with make_bar(len(params)*len(SQLI_ERROR_PAYLOADS), "SQLi-Error", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test_err, p, pl) for p in params for pl in SQLI_ERROR_PAYLOADS]):
                r = res.result()
                if r: found_err.append(r)
                bar.update()
    
    # [Blind checking logic...]
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
            # GENERATE EXPLOIT COMMAND (sqlmap)
            poc_cmd = f"sqlmap -u '{url}' -p {p} --batch --dbs --level=1 --risk=1"
            print_vuln("sql_injection", cfg, detail=f"param={p}, payload={pl}", url=url, poc=poc_cmd)
            vadd(findings, "sql_injection", f"{len(found_err)} error(s)", url, poc=poc_cmd)
            
    elif found_blind:
        for p, pl, url in found_blind[:2]:
            poc_cmd = f"sqlmap -u '{url}' -p {p} --technique=T --batch --dbs"
            print_vuln("sql_injection_blind", cfg, detail=f"param={p}, time-delay triggered", url=url, poc=poc_cmd)
            vadd(findings, "sql_injection_blind", found_blind[0][0], url, poc=poc_cmd)
    else:
        pr(f"  {G}✔ No SQLi indicators.{RST}\n", cfg)

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
    
    # [Checking logic...]
    total = len(params) * len(pl)
    with make_bar(total, "XSS", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for f in as_completed([ex.submit(test, p, l) for p in params for l in pl]):
                r = f.result()
                if r and r not in found: found.append(r)
                bar.update()
    
    if found:
        for p, pl_, url in found[:5]:
            # GENERATE EXPLOIT COMMAND (curl with payload)
            poc_cmd = f"curl -k -s \"{url}\" | grep -o \"{pl_}\""
            print_vuln("xss_reflected", cfg, detail=f"param={p}, payload={pl_[:40]}", url=url, poc=poc_cmd)
            vadd(findings, "xss_reflected", f"{len(found)} instance(s)", url, poc=poc_cmd)
    else:
        pr(f"  {G}✔ No reflected XSS detected.{RST}\n", cfg)

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

    # [Checking logic...]
    with make_bar(len(params)*len(CMDI_PAYLOADS), "CMDi", cfg) as bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for res in as_completed([ex.submit(test, p, pl) for p in params for pl in CMDI_PAYLOADS]):
                r = res.result()
                if r: found.append(r)
                bar.update()
    
    if found:
        for p, pl, url in found[:3]:
            # GENERATE EXPLOIT COMMAND (curl)
            poc_cmd = f"# Verify manually: curl -k '{url}'"
            print_vuln("command_injection", cfg, detail=f"param={p}, payload={pl}", url=url, poc=poc_cmd)
            vadd(findings, "command_injection", f"{len(found)} instance(s)", url, poc=poc_cmd)
    else: 
        pr(f"  {G}✔ No command injection indicators.{RST}\n", cfg)

# ... [Other checks: check_path_traversal, check_ssrf, etc.] ...
# [Include remaining checks from original script]

# ──────────────────────────────────────────────────────────────────────────
# NEW FEATURE: SAVE PoC COMMANDS
# ──────────────────────────────────────────────────────────────────────────
def save_pocs(findings, cfg, target):
    if not cfg.output_pocs: return
    
    pocs = [f for f in findings if f.poc]
    if not pocs:
        pr(f"  {Y}ℹ No exploitable PoCs generated to save.{RST}", cfg)
        return

    try:
        with open(cfg.output_pocs, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/bash\n")
            f.write(f"# WebVulnScan PoC Script for {target}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# WARNING: Run these commands only on systems you own.\n\n")
            
            for vuln in pocs:
                f.write(f"# [{vuln.severity}] {vuln.name} ({vuln.key})\n")
                f.write(f"# URL: {vuln.url}\n")
                f.write(f"# Detail: {vuln.detail}\n")
                f.write(f"{vuln.poc}\n\n")
        
        try:
            os.chmod(cfg.output_pocs, 0o755)
        except: pass
            
        pr(f"  {G}✔ PoC Script saved: {cfg.output_pocs}{RST}", cfg)
    except Exception as e:
        pr(f"  {R}✘ Failed to save PoCs: {e}{RST}", cfg)

# ──────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER (Updated)
# ──────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="web_vuln_scanner_v5",
        description=f"WebVulnScan v{VERSION} — Enterprise Web Application Security Scanner",
        epilog="""
Examples:
  # Run scan and generate PoC script
  %(prog)s https://example.com --save-pocs pocs.sh
""")
    # ... [Standard args] ...
    p.add_argument("target",        nargs="?",          help="Target URL")
    p.add_argument("--targets",                         help="File with one URL per line")
    p.add_argument("--profile",     choices=["quick","standard","full","api"], default="standard")
    p.add_argument("--scope",                           help="Comma-separated allowed domains")
    p.add_argument("-t","--timeout",    type=int, default=0)
    p.add_argument("-w","--threads",    type=int, default=0)
    p.add_argument("-d","--delay",      type=float, default=0.0)
    p.add_argument("--rate-limit",      type=int, default=0)
    p.add_argument("--max-time",        type=int, default=0)
    p.add_argument("--max-crawl-pages", type=int, default=0)
    p.add_argument("--proxy",                           help="HTTP proxy URL")
    p.add_argument("--auth-type",   choices=["basic","bearer","token"])
    p.add_argument("--auth-value",                      help="Auth credentials/token")
    p.add_argument("--login-url",                       help="Login form URL")
    p.add_argument("--login-user",                      help="Login username")
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
    p.add_argument("--sarif",       dest="output_sarif",help="SARIF")
    p.add_argument("--md",          dest="output_md",   help="Markdown report")
    
    # NEW ARGUMENT
    p.add_argument("--save-pocs",   dest="output_pocs", help="Save Proof-of-Concept commands to a shell script")
    
    p.add_argument("--audit-log",                       help="JSONL audit trail")
    p.add_argument("--fail-on",     choices=["critical","high","medium","low"])
    p.add_argument("--webhook",                         help="Slack/Discord webhook")
    p.add_argument("--baseline",                        help="Previous JSON report")
    p.add_argument("--resume",                          help="Resume from JSON report")
    p.add_argument("--skip-checks",                     help="Comma-separated checks to skip")
    p.add_argument("--config",                          help="JSON/YAML config file")
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("-q","--quiet",   action="store_true")
    p.add_argument("--no-color",     action="store_true")
    p.add_argument("--version",      action="version", version=f"WebVulnScan v{VERSION}")
    return p.parse_args()

# ──────────────────────────────────────────────────────────────────────────
# MAIN (Updated)
# ──────────────────────────────────────────────────────────────────────────
def main():
    # [Initialization logic...]
    args = parse_args()
    prof = PROFILES.get(args.profile, PROFILES["standard"])

    cfg = ScanConfig(
        # [Assignments...]
        output_pocs       = args.output_pocs or "", # NEW
        # [Other config...]
    )

    # ... [Scan Execution Logic] ...

    # [Inside the reporting section]
    # if cfg.output_json: save_json(...)
    # if cfg.output_html: save_html(...)
    
    # SAVE POCS
    if cfg.output_pocs:
        save_pocs(findings, cfg, primary_target)

    # ... [Exit logic] ...

if __name__ == "__main__":
    main()

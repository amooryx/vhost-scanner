#!/usr/bin/env python3
"""
VHost Scanner — Virtual Host Discovery via Host Header Brute-Force
Detects hidden vhosts on a target IP by fuzzing the Host header.
Author: Omar Khalid (amooryx) | github.com/amooryx/vhost-scanner
AUTHORIZED USE ONLY — for authorized red team engagements and bug bounty.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

COMMON_SUBDOMAINS = [
    "www", "dev", "staging", "api", "admin", "portal", "app", "mail",
    "vpn", "remote", "test", "beta", "qa", "internal", "intranet",
    "git", "gitlab", "jenkins", "jira", "confluence", "monitor",
    "grafana", "kibana", "phpmyadmin", "db", "database", "mysql",
    "redis", "memcache", "rabbitmq", "kafka", "elastic", "solr",
    "old", "legacy", "v2", "new", "preview", "demo",
]

def fingerprint_response(status: int, body: bytes, headers: dict) -> str:
    body_hash = hashlib.md5(body[:4096]).hexdigest()
    return f"{status}:{body_hash}:{len(body)}"

def check_vhost(target_ip: str, port: int, host: str, ssl: bool, baseline_fp: str,
                timeout: float, ua: str) -> dict | None:
    scheme = "https" if ssl else "http"
    url    = f"{scheme}://{target_ip}:{port}/"
    req    = urllib.request.Request(url)
    req.add_header("Host",       host)
    req.add_header("User-Agent", ua)
    try:
        ctx = None
        if ssl:
            import ssl as ssl_mod
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl_mod.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            body   = resp.read(8192)
            fp     = fingerprint_response(status, body, dict(resp.headers))
            if fp != baseline_fp:
                return {
                    "host":   host,
                    "status": status,
                    "length": len(body),
                    "title":  extract_title(body),
                    "server": resp.headers.get("Server", ""),
                }
    except urllib.error.HTTPError as e:
        fp = fingerprint_response(e.code, b"", {})
        if fp != baseline_fp:
            return {"host": host, "status": e.code, "length": 0, "title": "", "server": ""}
    except Exception:
        pass
    return None

def extract_title(body: bytes) -> str:
    text = body.decode(errors="ignore").lower()
    s = text.find("<title>")
    e = text.find("</title>", s)
    if s != -1 and e != -1:
        return body.decode(errors="ignore")[s+7:e].strip()[:100]
    return ""

def get_baseline(target_ip: str, port: int, ssl: bool, timeout: float, ua: str) -> str:
    scheme = "https" if ssl else "http"
    url    = f"{scheme}://{target_ip}:{port}/"
    req    = urllib.request.Request(url)
    req.add_header("Host",       f"nonexistent-{time.time()}.invalid")
    req.add_header("User-Agent", ua)
    try:
        ctx = None
        if ssl:
            import ssl as ssl_mod
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl_mod.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192)
            return fingerprint_response(resp.status, body, {})
    except urllib.error.HTTPError as e:
        return fingerprint_response(e.code, b"", {})
    except Exception:
        return "unreachable"

def main():
    parser = argparse.ArgumentParser(
        description="VHost Scanner — Virtual Host Discovery (Authorized use only)",
    )
    parser.add_argument("target",     help="Target IP address or hostname")
    parser.add_argument("domain",     help="Base domain for vhost testing (e.g., example.com)")
    parser.add_argument("--port",     type=int, default=80,  help="Port (default: 80)")
    parser.add_argument("--ssl",      action="store_true",   help="Use HTTPS")
    parser.add_argument("--wordlist", help="Custom subdomain wordlist")
    parser.add_argument("--threads",  type=int, default=20,  help="Concurrent threads")
    parser.add_argument("--timeout",  type=float, default=8)
    parser.add_argument("--ua",       default="Mozilla/5.0 VHostScanner/1.0")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    if args.ssl and args.port == 80:
        args.port = 443

    subs = COMMON_SUBDOMAINS
    if args.wordlist:
        with open(args.wordlist) as f:
            subs = [l.strip() for l in f if l.strip()]

    hosts = [f"{s}.{args.domain}" for s in subs]
    hosts.append(args.domain)

    print(f"[*] Baseline fingerprinting {args.target}:{args.port} ...")
    baseline = get_baseline(args.target, args.port, args.ssl, args.timeout, args.ua)
    print(f"  [+] Baseline: {baseline}")
    print(f"[*] Testing {len(hosts)} vhost candidates ...")

    hits = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(check_vhost, args.target, args.port, h,
                              args.ssl, baseline, args.timeout, args.ua): h for h in hosts}
        for fut in futures:
            result = fut.result()
            if result:
                print(f"  [+] {result['host']:40s}  [{result['status']}] {result['length']} bytes  \"{result['title']}\"")
                hits.append(result)

    print(f"\n[*] {len(hits)} distinct vhosts found")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(hits, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()

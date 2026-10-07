#!/usr/bin/env python3
"""Discover HTTP virtual hosts on an explicitly authorized target."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from threading import Lock

COMMON_SUBDOMAINS = [
    "www", "dev", "staging", "api", "admin", "portal", "app", "mail",
    "vpn", "remote", "test", "beta", "qa", "internal", "intranet",
    "git", "gitlab", "jenkins", "jira", "confluence", "monitor",
    "grafana", "kibana", "phpmyadmin", "db", "database", "mysql",
    "redis", "memcache", "rabbitmq", "kafka", "elastic", "solr",
    "old", "legacy", "v2", "new", "preview", "demo",
]
MAX_WORDLIST_ENTRIES = 10_000
MAX_RESPONSE_BYTES = 65_536
BASELINE_SAMPLES = 3
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Message
    truncated: bool

    @property
    def length(self):
        try:
            return int(self.headers.get("Content-Length"))
        except (TypeError, ValueError):
            return len(self.body)


class ScanError(Exception):
    """A network or input error that should be reported to the user."""


class RequestLimiter:
    def __init__(self, requests_per_second):
        self.interval = 1.0 / requests_per_second
        self.lock = Lock()
        self.next_request = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = self.next_request - now
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self.next_request = now + self.interval


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_hostname(value, label):
    value = value.strip().rstrip(".")
    if not value or any(char in value for char in "/\\:@?#[]") or any(
        ord(char) < 33 for char in value
    ):
        raise ValueError(f"{label} must be a hostname, not a URL or path")
    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{label} is not a valid hostname: {exc}") from exc
    if len(hostname) > 253 or any(
        not HOST_LABEL_RE.fullmatch(part) for part in hostname.split(".")
    ):
        raise ValueError(f"{label} is not a valid hostname")
    return hostname


def normalize_target(value):
    try:
        address = ipaddress.ip_address(value)
        return address.compressed
    except ValueError:
        return normalize_hostname(value, "target")


def normalize_wordlist_entry(value, line_number):
    try:
        return normalize_hostname(value, f"wordlist line {line_number}")
    except ValueError as exc:
        raise ValueError(f"{exc}; expected a subdomain label") from exc


def url_authority(target):
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return target
    if address.version == 6:
        return f"[{target}]"
    return target


def fingerprint_response(response):
    server = response.headers.get("Server", "").strip().lower()
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    body_hash = hashlib.sha256(response.body).hexdigest()
    return (
        response.status,
        body_hash,
        response.length,
        response.truncated,
        server,
        content_type,
    )


def extract_title(body):
    text = body.decode("utf-8", errors="replace")
    match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", text, re.IGNORECASE | re.DOTALL)
    if match:
        return re.sub(r"\s+", " ", match.group(1)).strip()[:100]
    return ""


def read_response(response):
    data = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(data) > MAX_RESPONSE_BYTES
    return Response(
        status=response.status,
        body=data[:MAX_RESPONSE_BYTES],
        headers=response.headers,
        truncated=truncated,
    )


def fetch(target, port, host, use_ssl, timeout, user_agent, limiter):
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{url_authority(target)}:{port}/"
    request = urllib.request.Request(url)
    request.add_header("Host", host)
    request.add_header("User-Agent", user_agent)
    context = None
    if use_ssl:
        import ssl

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if context is None:
        opener = urllib.request.build_opener(NoRedirectHandler)
    else:
        opener = urllib.request.build_opener(
            NoRedirectHandler, urllib.request.HTTPSHandler(context=context)
        )
    limiter.wait()
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, TimeoutError, http.client.HTTPException, urllib.error.URLError) as exc:
        raise ScanError(f"request for {host} failed: {exc}") from exc
    try:
        with response:
            return read_response(response)
    except (OSError, TimeoutError, http.client.HTTPException, urllib.error.URLError) as exc:
        raise ScanError(f"request for {host} failed: {exc}") from exc


def get_baseline(target, port, use_ssl, timeout, user_agent, limiter):
    fingerprints = []
    for index in range(BASELINE_SAMPLES):
        canary = f"vhost-scanner-{time.time_ns()}-{index}.invalid"
        try:
            response = fetch(target, port, canary, use_ssl, timeout, user_agent, limiter)
        except ScanError as exc:
            raise ScanError(f"baseline request failed: {exc}") from exc
        fingerprints.append(fingerprint_response(response))
    counts = Counter(fingerprints)
    fingerprint, count = counts.most_common(1)[0]
    if count < 2:
        raise ScanError(
            "the target returned inconsistent responses for nonexistent hosts; "
            "baseline is unstable, so results would be unreliable"
        )
    return set(fingerprints), fingerprint


def check_vhost(target, port, host, use_ssl, baseline_fingerprints,
                baseline_fingerprint, timeout, user_agent, limiter):
    first_response = fetch(target, port, host, use_ssl, timeout, user_agent, limiter)
    first_fingerprint = fingerprint_response(first_response)
    if first_fingerprint == baseline_fingerprint or first_fingerprint in baseline_fingerprints:
        return None

    confirm_response = fetch(target, port, host, use_ssl, timeout, user_agent, limiter)
    confirm_fingerprint = fingerprint_response(confirm_response)
    if confirm_fingerprint != first_fingerprint:
        return None

    return {
        "host": host,
        "status": first_response.status,
        "length": first_response.length,
        "truncated": first_response.truncated,
        "title": extract_title(first_response.body),
        "server": first_response.headers.get("Server", ""),
    }


def positive_int(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def bounded_int(maximum):
    def parse(value):
        parsed = positive_int(value)
        if parsed > maximum:
            raise argparse.ArgumentTypeError(f"must not exceed {maximum}")
        return parsed
    return parse


def positive_float(value):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed < 0.1 or parsed > 300:
        raise argparse.ArgumentTypeError("must be between 0.1 and 300 seconds")
    return parsed


def positive_rate(value):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed < 0.001 or parsed > 100:
        raise argparse.ArgumentTypeError("must be between 0.001 and 100 requests/second")
    return parsed


def load_wordlist(path, parser):
    entries = []
    seen = set()
    try:
        with Path(path).open(encoding="utf-8") as wordlist:
            for line_number, line in enumerate(wordlist, start=1):
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                try:
                    entry = normalize_wordlist_entry(entry, line_number)
                except ValueError as exc:
                    parser.error(str(exc))
                if entry not in seen:
                    seen.add(entry)
                    entries.append(entry)
                    if len(entries) > MAX_WORDLIST_ENTRIES:
                        parser.error(f"wordlist exceeds the {MAX_WORDLIST_ENTRIES} entry limit")
    except OSError as exc:
        parser.error(f"cannot read wordlist {path!r}: {exc}")
    return entries


def build_parser():
    parser = argparse.ArgumentParser(
        description="Discover HTTP virtual hosts on an explicitly authorized target.",
        epilog="Only scan systems you own or are authorized to test.",
    )
    parser.add_argument("target", help="Target IP address or hostname to connect to")
    parser.add_argument("domain", help="Base domain for vhost candidates (e.g. example.com)")
    parser.add_argument("--port", type=bounded_int(65535), help="Target port (default: 80; HTTPS: 443)")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS (certificate validation is disabled)")
    parser.add_argument("--wordlist", help="UTF-8 file with one subdomain label per line")
    parser.add_argument("--threads", type=bounded_int(100), default=10, help="Concurrent workers (1-100; default: 10)")
    parser.add_argument("--timeout", type=positive_float, default=8.0, help="Per-request timeout in seconds (max: 300)")
    parser.add_argument("--rate-limit", type=positive_rate, default=10.0,
                        help="Maximum request start rate, including baseline checks (default: 10/second)")
    parser.add_argument("--ua", default="Mozilla/5.0 VHostScanner/2.0", help="HTTP User-Agent")
    parser.add_argument("--out", help="Write findings as a JSON array")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        domain = normalize_hostname(args.domain, "domain")
    except ValueError as exc:
        parser.error(str(exc))

    if not args.ua or any(
        (ord(char) < 32 and char != "\t") or ord(char) > 255 for char in args.ua
    ):
        parser.error("--ua must be non-empty and contain only valid HTTP header characters")
    args.port = args.port if args.port is not None else (443 if args.ssl else 80)
    subs = load_wordlist(args.wordlist, parser) if args.wordlist else COMMON_SUBDOMAINS
    if any(len(f"{sub}.{domain}") > 253 for sub in subs):
        parser.error("a wordlist candidate combined with the domain exceeds 253 characters")
    hosts = list(dict.fromkeys([f"{sub}.{domain}" for sub in subs] + [domain]))
    limiter = RequestLimiter(args.rate_limit)

    print(f"[*] Baseline fingerprinting {target}:{args.port} ...")
    try:
        baseline_fingerprints, baseline_fingerprint = get_baseline(
            target, args.port, args.ssl, args.timeout, args.ua, limiter
        )
    except ScanError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    print(f"  [+] Stable baseline confirmed ({BASELINE_SAMPLES} checks)")
    print(f"[*] Testing {len(hosts)} vhost candidates with {args.threads} workers ...")

    hits = []
    failures = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                check_vhost, target, args.port, host, args.ssl,
                baseline_fingerprints, baseline_fingerprint,
                args.timeout, args.ua, limiter,
            ): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
            except ScanError as exc:
                failures.append(str(exc))
                print(f"  [!] {exc}", file=sys.stderr)
                continue
            if result:
                print(
                    f"  [+] {result['host']:40s} [{result['status']}] "
                    f"{result['length']} bytes  {result['title']!r}"
                )
                hits.append(result)

    hits.sort(key=lambda result: result["host"])
    print(f"\n[*] {len(hits)} confirmed vhost(s) found")
    if args.out:
        try:
            Path(args.out).write_text(json.dumps(hits, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"[!] cannot write results to {args.out!r}: {exc}", file=sys.stderr)
            return 2
        print(f"[*] Results written to {args.out}")
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

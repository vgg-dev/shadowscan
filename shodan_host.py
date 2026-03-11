#!/usr/bin/env python3
"""\
Simple CLI to query Shodan's Host API for a single host.

Default output is Nmap-style (summary only). Use --format json for raw output.

Examples (authorized assets only):
  $env:SHODAN_API_KEY = "..."
  python shodan_host.py 8.8.8.8
  python shodan_host.py example.com --resolve
  python shodan_host.py 8.8.8.8 --format json
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


SHODAN_HOST_ENDPOINT = "https://api.shodan.io/shodan/host/{ip}"


def _eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def _resolve_to_ip(host: str) -> str:
    return socket.gethostbyname(host)


def _http_get_json(url: str, timeout_s: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "shodan-host-cli/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        try:
            payload = e.read()
            data = json.loads(payload.decode("utf-8", errors="replace"))
            message = data.get("error") or data.get("message") or str(data)
        except Exception:
            message = e.reason
        raise RuntimeError(f"HTTP {e.code}: {message}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from None

    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON response: {e}") from None


def shodan_host_lookup(ip: str, api_key: str, *, timeout_s: float = 15.0) -> Dict[str, Any]:
    url = SHODAN_HOST_ENDPOINT.format(ip=urllib.parse.quote(ip, safe=""))
    query = urllib.parse.urlencode({"key": api_key})
    return _http_get_json(f"{url}?{query}", timeout_s=timeout_s)


def _get_first(dct: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in dct and dct[k] not in (None, "", [], {}):
            return dct[k]
    return None


@dataclass(frozen=True)
class ServiceRow:
    port: int
    proto: str
    service: str
    version: str
    timestamp: str


def _infer_service_name(svc: Dict[str, Any]) -> str:
    port = svc.get("port")
    has_ssl = bool(svc.get("ssl"))

    if svc.get("http") is not None:
        if has_ssl or port in (443, 8443, 9443):
            return "https"
        return "http"

    module = (svc.get("_shodan") or {}).get("module")
    if isinstance(module, str) and module.strip():
        return module.strip()

    product = svc.get("product")
    if isinstance(product, str) and product.strip():
        return product.strip().split()[0].lower()

    return "unknown"


def _infer_version_string(svc: Dict[str, Any], service_name: str) -> str:
    product = svc.get("product")
    version = svc.get("version")
    if product and version:
        return f"{product} {version}"
    if product:
        return str(product)

    http = svc.get("http")
    if service_name in ("http", "https") and isinstance(http, dict):
        server = http.get("server")
        if isinstance(server, str) and server.strip():
            return server.strip()

    banner = svc.get("data")
    if isinstance(banner, str) and banner.strip():
        first_line = banner.strip().splitlines()[0].strip()
        # Keep it short-ish; this is the "VERSION" column, not full banners.
        return first_line[:120]

    return ""


def _extract_services(raw: Dict[str, Any]) -> List[ServiceRow]:
    rows: List[ServiceRow] = []
    for svc in raw.get("data") or []:
        port = svc.get("port")
        if not isinstance(port, int):
            continue
        proto = str(svc.get("transport") or "tcp").lower()
        service_name = _infer_service_name(svc)
        version = _infer_version_string(svc, service_name)
        timestamp = str(svc.get("timestamp") or "")
        rows.append(ServiceRow(port=port, proto=proto, service=service_name, version=version, timestamp=timestamp))

    rows.sort(key=lambda r: (r.port, r.proto, r.service, r.version))
    return rows


def _collect_cpes(raw: Dict[str, Any]) -> List[str]:
    cpes: Set[str] = set()

    host_cpe = raw.get("cpe")
    if isinstance(host_cpe, list):
        for c in host_cpe:
            if isinstance(c, str) and c.strip():
                cpes.add(c.strip())

    for svc in raw.get("data") or []:
        svc_cpe = svc.get("cpe")
        if isinstance(svc_cpe, list):
            for c in svc_cpe:
                if isinstance(c, str) and c.strip():
                    cpes.add(c.strip())

    return sorted(cpes)


def _extract_vuln_ids(raw: Dict[str, Any]) -> List[str]:
    vulns = raw.get("vulns")
    if isinstance(vulns, dict):
        return sorted(str(k) for k in vulns.keys())
    if isinstance(vulns, list):
        return sorted(str(v) for v in vulns)
    return []


def _print_nmap_style(
    *,
    target: str,
    ip: str,
    raw: Dict[str, Any],
    max_services: int,
    include_vulns: bool,
) -> None:
    services = _extract_services(raw)

    if target != ip:
        print(f"Nmap scan report for {target} ({ip})")
    else:
        print(f"Nmap scan report for {ip}")

    last_update = _get_first(raw, "last_update")
    if last_update:
        print(f"Host is up (Shodan last update: {last_update}).")
    else:
        print("Host is up (Shodan data available).")

    print("PORT     STATE SERVICE      VERSION")
    for row in services[: max_services if max_services > 0 else len(services)]:
        portproto = f"{row.port}/{row.proto}"
        print(f"{portproto:<8} open  {row.service:<12} {row.version}")
    if max_services > 0 and len(services) > max_services:
        print(f"... ({len(services) - max_services} more services not shown)")

    os_name = _get_first(raw, "os")
    cpes = _collect_cpes(raw)
    if os_name or cpes:
        parts = []
        if os_name:
            parts.append(f"OS: {os_name}")
        if cpes:
            # Keep it readable like Nmap's "Service Info" line.
            joined = ", ".join(cpes[:10])
            if len(cpes) > 10:
                joined += f", ... (+{len(cpes) - 10})"
            parts.append(f"CPE: {joined}")
        print("Service Info: " + "; ".join(parts))

    org = _get_first(raw, "org")
    isp = _get_first(raw, "isp")
    asn = _get_first(raw, "asn")
    loc_bits = [
        _get_first(raw, "city"),
        _get_first(raw, "region_code", "region_name"),
        _get_first(raw, "country_name", "country_code"),
    ]
    location = ", ".join(str(x) for x in loc_bits if x)

    meta = []
    if org:
        meta.append(f"Org: {org}")
    if isp:
        meta.append(f"ISP: {isp}")
    if asn:
        meta.append(f"ASN: {asn}")
    if location:
        meta.append(f"Location: {location}")
    if meta:
        print("Host Info: " + "; ".join(meta))

    if include_vulns:
        vuln_ids = _extract_vuln_ids(raw)
        if vuln_ids:
            print("\nHost script results:")
            print("|_shodan-vulns: " + ", ".join(vuln_ids))


def _print_simple_summary(*, raw: Dict[str, Any], max_services: int, include_vulns: bool) -> None:
    summary = {
        "ip": _get_first(raw, "ip_str", "ip"),
        "org": _get_first(raw, "org"),
        "isp": _get_first(raw, "isp"),
        "asn": _get_first(raw, "asn"),
        "country": _get_first(raw, "country_name", "country_code"),
        "city": _get_first(raw, "city"),
        "region": _get_first(raw, "region_code", "region_name"),
        "hostnames": raw.get("hostnames") or [],
        "domains": raw.get("domains") or [],
        "os": _get_first(raw, "os"),
        "tags": raw.get("tags") or [],
        "last_update": _get_first(raw, "last_update"),
    }

    ports = raw.get("ports")
    if isinstance(ports, list):
        summary["ports"] = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})
    else:
        summary["ports"] = []

    services = _extract_services(raw)
    summary["services"] = [
        {"port": r.port, "transport": r.proto, "service": r.service, "version": r.version, "timestamp": r.timestamp}
        for r in services[: max_services if max_services > 0 else len(services)]
    ]
    summary["service_count"] = len(services)

    if include_vulns:
        summary["vulns"] = _extract_vuln_ids(raw)

    print(json.dumps(summary, indent=2, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Query Shodan Host API for a single host.")
    parser.add_argument("host", help="IP address (or hostname with --resolve).")
    parser.add_argument(
        "--api-key",
        help="Shodan API key (defaults to env var SHODAN_API_KEY).",
        default=os.environ.get("SHODAN_API_KEY"),
    )
    parser.add_argument("--resolve", action="store_true", help="Resolve hostname to IPv4 before querying.")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds (default: 15).")
    parser.add_argument(
        "--format",
        choices=["nmap", "summary", "json"],
        default="nmap",
        help="Output format (default: nmap).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Alias for --format json.",
    )
    parser.add_argument(
        "--include-vulns",
        action="store_true",
        help="Include vulnerability IDs when available.",
    )
    parser.add_argument(
        "--max-services",
        type=int,
        default=100,
        help="Max services to print (default: 100, 0 = no limit).",
    )
    args = parser.parse_args(argv)

    if not args.api_key:
        _eprint("Missing API key. Set SHODAN_API_KEY or pass --api-key.")
        return 2

    target = args.host.strip()
    ip = target
    if args.resolve:
        try:
            ip = _resolve_to_ip(target)
        except OSError as e:
            _eprint(f"Failed to resolve {target!r}: {e}")
            return 2

    try:
        raw = shodan_host_lookup(ip, args.api_key, timeout_s=args.timeout)
    except RuntimeError as e:
        _eprint(str(e))
        return 1

    fmt = args.format
    if args.json:
        fmt = "json"

    if fmt == "json":
        print(json.dumps(raw, indent=2, sort_keys=True))
        return 0

    if fmt == "summary":
        _print_simple_summary(raw=raw, max_services=args.max_services, include_vulns=args.include_vulns)
        return 0

    _print_nmap_style(
        target=target,
        ip=ip,
        raw=raw,
        max_services=args.max_services,
        include_vulns=args.include_vulns,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

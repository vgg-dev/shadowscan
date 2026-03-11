#!/usr/bin/env python3
"""\
ShadowScan: query Shodan's Host API for one or more hosts.

ShadowScan is a *passive* lookup tool (it does not scan targets). It fetches Shodan's view of a host and renders it in
Nmap-style output by default.

Examples (authorized assets only):
  $env:SHODAN_API_KEY = "..."
  python shadowscan.py 8.8.8.8
  python shadowscan.py example.com --resolve
  python shadowscan.py --input targets.txt
  python shadowscan.py --cidr 10.0.0.0/24 --authorized-scope scope.txt
  python shadowscan.py 8.8.8.8 --show-banners --grep "nginx"
  python shadowscan.py 8.8.8.8 --format json
  python shadowscan.py --input targets.txt --format ndjson

Output files (Nmap-ish):
  python shadowscan.py 8.8.8.8 -oN out.txt -oG out.grep -oX out.xml
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


SHODAN_HOST_ENDPOINT = "https://api.shodan.io/shodan/host/{ip}"
USER_AGENT = "ShadowScan/1.1"


def _eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def _now_utc_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_text_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def _resolve_to_ip(host: str) -> str:
    return socket.gethostbyname(host)


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except OSError:
        return None


@dataclass(frozen=True)
class HttpResult:
    json: Dict[str, Any]
    headers: Dict[str, str]


def _http_get_json(
    url: str,
    *,
    timeout_s: float,
    retries: int,
    backoff_s: float,
) -> HttpResult:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    attempt = 0
    while True:
        attempt += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                body = resp.read()
                headers = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            status = getattr(e, "code", None)
            retry_after = None
            try:
                retry_after = e.headers.get("Retry-After") if e.headers else None
            except Exception:
                retry_after = None

            message = None
            try:
                payload = e.read()
                data = json.loads(payload.decode("utf-8", errors="replace"))
                message = data.get("error") or data.get("message") or str(data)
            except Exception:
                message = getattr(e, "reason", None) or "HTTP error"

            if status == 429 and attempt <= max(1, retries):
                sleep_s = backoff_s * (2 ** (attempt - 1))
                if retry_after:
                    try:
                        sleep_s = max(sleep_s, float(retry_after))
                    except ValueError:
                        pass
                sleep_s = min(120.0, max(0.25, sleep_s))
                _eprint(f"HTTP 429 rate-limited. Retrying in {sleep_s:.1f}s (attempt {attempt}/{retries + 1})...")
                time.sleep(sleep_s)
                continue

            raise RuntimeError(f"HTTP {status}: {message}") from None
        except urllib.error.URLError as e:
            if attempt <= max(1, retries):
                sleep_s = min(30.0, max(0.25, backoff_s * (2 ** (attempt - 1))))
                _eprint(f"Network error: {getattr(e, 'reason', e)}. Retrying in {sleep_s:.1f}s...")
                time.sleep(sleep_s)
                continue
            raise RuntimeError(f"Network error: {getattr(e, 'reason', e)}") from None

        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as je:
            raise RuntimeError(f"Invalid JSON response: {je}") from None

        return HttpResult(json=data, headers=headers)


def shodan_host_lookup(
    ip: str,
    api_key: str,
    *,
    timeout_s: float,
    retries: int,
    backoff_s: float,
) -> HttpResult:
    url = SHODAN_HOST_ENDPOINT.format(ip=urllib.parse.quote(ip, safe=""))
    query = urllib.parse.urlencode({"key": api_key})
    return _http_get_json(f"{url}?{query}", timeout_s=timeout_s, retries=retries, backoff_s=backoff_s)


def _get_first(dct: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in dct and dct[k] not in (None, "", [], {}):
            return dct[k]
    return None


def _parse_ports(spec: Optional[str]) -> Optional[Set[int]]:
    if not spec:
        return None

    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a.strip())
            end = int(b.strip())
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)

    return ports


def _parse_csv_lower(spec: Optional[str]) -> Optional[Set[str]]:
    if not spec:
        return None
    vals = {p.strip().lower() for p in spec.split(",") if p.strip()}
    return vals or None

def _load_authorized_scope(path: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for line in _read_text_lines(path):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            if "/" in s:
                nets.append(ipaddress.ip_network(s, strict=False))
            else:
                ip = ipaddress.ip_address(s)
                nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
        except ValueError as e:
            raise RuntimeError(f"Invalid scope entry {s!r} in {path}: {e}") from None
    return nets


def _ip_in_scope(ip: str, nets: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _expand_cidrs(cidrs: Sequence[str], *, max_targets: int, allow_large: bool) -> List[str]:
    out: List[str] = []
    total = 0
    for c in cidrs:
        n = ipaddress.ip_network(c, strict=False)
        count = n.num_addresses
        total += int(count)
        if not allow_large and total > max_targets:
            raise RuntimeError(
                f"CIDR expansion would produce {total} targets (> {max_targets}). "
                f"Use --allow-large or --max-targets to override."
            )

        for ip in n.hosts() if n.num_addresses > 2 else n:
            out.append(str(ip))
            if not allow_large and len(out) > max_targets:
                raise RuntimeError(
                    f"CIDR expansion produced > {max_targets} targets. Use --allow-large or --max-targets to override."
                )

    return out


def _parse_targets(
    positional: Sequence[str],
    *,
    input_file: Optional[str],
    cidrs: Optional[Sequence[str]],
    resolve: bool,
    max_targets: int,
    allow_large: bool,
) -> List[Tuple[str, str]]:
    """Return list of (display_target, ip)."""

    raw_targets: List[str] = []
    raw_targets.extend([t.strip() for t in positional if t.strip()])

    if input_file:
        for line in _read_text_lines(input_file):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            raw_targets.append(s)

    if cidrs:
        raw_targets.extend(_expand_cidrs(cidrs, max_targets=max_targets, allow_large=allow_large))

    seen: Set[str] = set()
    deduped: List[str] = []
    for t in raw_targets:
        if t in seen:
            continue
        seen.add(t)
        deduped.append(t)

    if not allow_large and len(deduped) > max_targets:
        raise RuntimeError(f"Too many targets ({len(deduped)} > {max_targets}). Use --allow-large or --max-targets.")

    out: List[Tuple[str, str]] = []
    for t in deduped:
        ip = t
        if resolve:
            try:
                ip = _resolve_to_ip(t)
            except OSError as e:
                _eprint(f"Failed to resolve {t!r}: {e}")
                continue

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            _eprint(f"Skipping invalid IP/host: {t!r} (resolved: {ip!r})")
            continue

        out.append((t, ip))

    if not out:
        raise RuntimeError("No valid targets.")

    return out


def _cache_path(cache_dir: str, ip: str) -> str:
    safe = ip.replace(":", "_")
    return os.path.join(cache_dir, f"{safe}.json")


def _load_cache(path: str, *, ttl_s: int) -> Optional[Dict[str, Any]]:
    try:
        st = os.stat(path)
    except OSError:
        return None

    age_s = time.time() - st.st_mtime
    if ttl_s > 0 and age_s > ttl_s:
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            wrapper = json.load(f)
        if isinstance(wrapper, dict) and "data" in wrapper and isinstance(wrapper["data"], dict):
            return wrapper["data"]
        if isinstance(wrapper, dict):
            return wrapper
    except Exception:
        return None

    return None


def _save_cache(path: str, raw: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrapper = {"fetched_at": _now_utc_iso(), "data": raw}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2, sort_keys=True)


@dataclass(frozen=True)
class ServiceRow:
    port: int
    proto: str
    service: str
    version: str
    timestamp: str
    banner: str
    cpes: Tuple[str, ...]
    vulns: Tuple[str, ...]


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
        return first_line[:120]

    return ""


def _extract_vuln_ids_any(obj: Any) -> List[str]:
    if isinstance(obj, dict):
        return sorted(str(k) for k in obj.keys())
    if isinstance(obj, list):
        return sorted(str(v) for v in obj)
    return []


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
        banner = str(svc.get("data") or "")

        cpes: List[str] = []
        svc_cpe = svc.get("cpe")
        if isinstance(svc_cpe, list):
            for c in svc_cpe:
                if isinstance(c, str) and c.strip():
                    cpes.append(c.strip())

        vulns = _extract_vuln_ids_any(svc.get("vulns"))

        rows.append(
            ServiceRow(
                port=port,
                proto=proto,
                service=service_name,
                version=version,
                timestamp=timestamp,
                banner=banner,
                cpes=tuple(sorted(set(cpes))),
                vulns=tuple(vulns),
            )
        )

    rows.sort(key=lambda r: (r.port, r.proto, r.service, r.version))
    return rows


def _collect_host_cpes(raw: Dict[str, Any]) -> List[str]:
    cpes: Set[str] = set()

    host_cpe = raw.get("cpe")
    if isinstance(host_cpe, list):
        for c in host_cpe:
            if isinstance(c, str) and c.strip():
                cpes.add(c.strip())

    for row in _extract_services(raw):
        for c in row.cpes:
            cpes.add(c)

    return sorted(cpes)


def _filter_services(
    services: Sequence[ServiceRow],
    *,
    ports: Optional[Set[int]],
    protos: Optional[Set[str]],
    services_allow: Optional[Set[str]],
    grep_re: Optional[re.Pattern[str]],
) -> List[ServiceRow]:
    out: List[ServiceRow] = []
    for row in services:
        if ports is not None and row.port not in ports:
            continue
        if protos is not None and row.proto not in protos:
            continue
        if services_allow is not None and row.service.lower() not in services_allow:
            continue
        if grep_re is not None:
            hay = "\n".join([row.service, row.version, row.banner])
            if not grep_re.search(hay):
                continue
        out.append(row)
    return out


def _format_quota(headers: Dict[str, str]) -> Optional[str]:
    limit = headers.get("X-RateLimit-Limit")
    remaining = headers.get("X-RateLimit-Remaining")
    reset = headers.get("X-RateLimit-Reset")
    if not (limit or remaining or reset):
        return None

    parts = []
    if remaining is not None:
        parts.append(f"remaining={remaining}")
    if limit is not None:
        parts.append(f"limit={limit}")
    if reset is not None:
        try:
            reset_dt = _dt.datetime.fromtimestamp(int(reset), tz=_dt.timezone.utc)
            parts.append("reset=" + reset_dt.isoformat().replace("+00:00", "Z"))
        except Exception:
            parts.append(f"reset={reset}")

    return "Shodan quota: " + ", ".join(parts)


def _whois_lookup(ip: str) -> Optional[str]:
    whois_path = shutil.which("whois")
    if not whois_path:
        return None
    try:
        proc = subprocess.run(
            [whois_path, ip],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        text = text.strip()
        return text or None
    except Exception:
        return None


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


class _ListWriter:
    def __init__(self, buf: List[str]) -> None:
        self._buf = buf

    def write(self, s: str) -> None:
        self._buf.append(s)

def _emit_nmap(
    *,
    out: Any,
    display_target: str,
    ip: str,
    raw: Dict[str, Any],
    headers: Dict[str, str],
    services: Sequence[ServiceRow],
    max_services: int,
    show_banners: bool,
    banner_max_len: int,
    include_vulns: bool,
    show_quota: bool,
    dns: bool,
    whois: bool,
) -> None:
    rdns = _reverse_dns(ip) if dns else None

    header_target = display_target
    if display_target == ip and rdns:
        header_target = rdns

    if header_target != ip:
        out.write(f"Nmap scan report for {header_target} ({ip})\n")
    else:
        out.write(f"Nmap scan report for {ip}\n")

    last_update = _get_first(raw, "last_update")
    if last_update:
        out.write(f"Host is up (Shodan last update: {last_update}).\n")
    else:
        out.write("Host is up (Shodan data available).\n")

    if show_quota:
        quota = _format_quota(headers)
        if quota:
            out.write(quota + "\n")

    out.write("PORT     STATE SERVICE      VERSION\n")

    shown = services[: max_services if max_services > 0 else len(services)]
    for row in shown:
        portproto = f"{row.port}/{row.proto}"
        out.write(f"{portproto:<8} open  {row.service:<12} {row.version}\n")

    if max_services > 0 and len(services) > max_services:
        out.write(f"... ({len(services) - max_services} more services not shown)\n")

    os_name = _get_first(raw, "os")
    cpes = _collect_host_cpes(raw)
    parts = []
    if os_name:
        parts.append(f"OS: {os_name}")
    if cpes:
        joined = ", ".join(cpes[:10])
        if len(cpes) > 10:
            joined += f", ... (+{len(cpes) - 10})"
        parts.append(f"CPE: {joined}")
    if parts:
        out.write("Service Info: " + "; ".join(parts) + "\n")

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
    if rdns and display_target != rdns:
        meta.append(f"rDNS: {rdns}")
    if meta:
        out.write("Host Info: " + "; ".join(meta) + "\n")

    if show_banners:
        banners = [(r.port, r.proto, r.banner.strip()) for r in shown if r.banner and r.banner.strip()]
        if banners:
            out.write("\nService banners:\n")
            for port, proto, banner in banners:
                b = banner.replace("\r", "")
                if banner_max_len > 0 and len(b) > banner_max_len:
                    b = b[: banner_max_len - 3] + "..."
                one_line = " ".join(b.split())
                out.write(f"  - {port}/{proto}: {one_line}\n")

    if include_vulns:
        host_vulns = _extract_vuln_ids_any(raw.get("vulns"))
        per_port: List[Tuple[int, str, Tuple[str, ...]]] = []
        for r in shown:
            if r.vulns:
                per_port.append((r.port, r.proto, r.vulns))

        if host_vulns or per_port:
            out.write("\nHost script results:\n")
        if host_vulns:
            out.write("|_shadowscan-shodan-vulns: " + ", ".join(host_vulns) + "\n")
        for port, proto, vids in per_port:
            out.write(f"|_shadowscan-shodan-vulns-{port}/{proto}: " + ", ".join(vids) + "\n")

    if whois:
        whois_text = _whois_lookup(ip)
        if whois_text:
            out.write("\nWHOIS:\n")
            for line in whois_text.splitlines()[:120]:
                out.write(line.rstrip() + "\n")


def _emit_grepable(*, out: Any, display_target: str, ip: str, services: Sequence[ServiceRow]) -> None:
    name = "" if display_target == ip else display_target
    ports_bits = []
    for r in services:
        ports_bits.append(f"{r.port}/open/{r.proto}//{r.service}//{r.version}//")
    ports_part = ", ".join(ports_bits)
    out.write(f"Host: {ip} ({name})\tStatus: Up\tPorts: {ports_part}\n")


def _emit_xml(*, out: Any, display_target: str, ip: str, raw: Dict[str, Any], services: Sequence[ServiceRow]) -> None:
    start = _now_utc_iso()
    out.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
    out.write(f"<nmaprun scanner=\"ShadowScan\" startstr=\"{start}\">\n")
    out.write("  <host>\n")
    out.write(f"    <address addr=\"{ip}\" addrtype=\"ipv4\"/>\n")
    if display_target != ip:
        out.write(f"    <hostnames><hostname name=\"{_xml_escape(display_target)}\"/></hostnames>\n")
    out.write("    <status state=\"up\" reason=\"shodan\"/>\n")
    out.write("    <ports>\n")
    for r in services:
        out.write(f"      <port protocol=\"{r.proto}\" portid=\"{r.port}\">\n")
        out.write("        <state state=\"open\"/>\n")
        out.write(
            "        <service "
            + f"name=\"{_xml_escape(r.service)}\" "
            + f"product=\"{_xml_escape(r.version)}\""
            + "/>\n"
        )
        out.write("      </port>\n")
    out.write("    </ports>\n")

    last_update = _get_first(raw, "last_update")
    if last_update:
        out.write(f"    <times><lastupdate value=\"{_xml_escape(str(last_update))}\"/></times>\n")

    out.write("  </host>\n")
    out.write("</nmaprun>\n")


def _emit_summary_json(
    *,
    out: Any,
    display_target: str,
    ip: str,
    raw: Dict[str, Any],
    services: Sequence[ServiceRow],
    include_vulns: bool,
) -> None:
    summary = {
        "target": display_target,
        "ip": _get_first(raw, "ip_str", "ip") or ip,
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
        "ports": sorted({r.port for r in services}),
        "services": [
            {
                "port": r.port,
                "transport": r.proto,
                "service": r.service,
                "version": r.version,
                "timestamp": r.timestamp,
            }
            for r in services
        ],
    }

    if include_vulns:
        summary["vulns"] = _extract_vuln_ids_any(raw.get("vulns"))

    json.dump(summary, out, indent=2, sort_keys=True)
    out.write("\n")


def _emit_ndjson(
    *,
    out: Any,
    display_target: str,
    ip: str,
    raw: Dict[str, Any],
    services: Sequence[ServiceRow],
    include_vulns: bool,
) -> None:
    obj: Dict[str, Any] = {
        "target": display_target,
        "ip": _get_first(raw, "ip_str", "ip") or ip,
        "last_update": _get_first(raw, "last_update"),
        "org": _get_first(raw, "org"),
        "asn": _get_first(raw, "asn"),
        "ports": sorted({r.port for r in services}),
        "services": [{"port": r.port, "proto": r.proto, "service": r.service, "version": r.version} for r in services],
    }
    if include_vulns:
        obj["vulns"] = _extract_vuln_ids_any(raw.get("vulns"))

    out.write(json.dumps(obj, sort_keys=True) + "\n")


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ShadowScan: Shodan Host API lookup with Nmap-style output.")
    parser.add_argument("targets", nargs="*", help="IP/hostname targets (or use --input/--cidr).")
    parser.add_argument(
        "--api-key",
        help="Shodan API key (defaults to env var SHODAN_API_KEY).",
        default=os.environ.get("SHODAN_API_KEY"),
    )

    parser.add_argument("--input", help="File with targets (one per line; supports comments with #).")
    parser.add_argument(
        "--cidr",
        action="append",
        default=[],
        help="CIDR range to expand (repeatable).",
    )
    parser.add_argument("--max-targets", type=int, default=4096, help="Max targets allowed without --allow-large.")
    parser.add_argument("--allow-large", action="store_true", help="Allow large CIDR expansions / target lists.")

    parser.add_argument(
        "--authorized-scope",
        help="Allowlist file of CIDRs/IPs; blocks targets outside scope unless --force.",
    )
    parser.add_argument("--force", action="store_true", help="Override --authorized-scope blocks.")
    parser.add_argument("--dry-run", action="store_true", help="Print targets that would be queried, then exit.")

    parser.add_argument("--resolve", action="store_true", help="Resolve hostnames to IPv4 before querying.")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds (default: 15).")
    parser.add_argument("--retries", type=int, default=2, help="Retries for 429/transient errors (default: 2).")
    parser.add_argument("--backoff", type=float, default=2.0, help="Backoff base seconds (default: 2.0).")

    parser.add_argument("--cache-dir", default=".shadowscan-cache", help="Cache directory (default: .shadowscan-cache).")
    parser.add_argument("--cache-ttl", type=int, default=3600, help="Cache TTL seconds (default: 3600).")
    parser.add_argument("--no-cache", action="store_true", help="Disable cache read/write.")

    parser.add_argument(
        "--format",
        choices=["nmap", "summary", "json", "ndjson", "grep", "xml"],
        default="nmap",
        help="Primary stdout format (default: nmap).",
    )
    parser.add_argument("--json", action="store_true", help="Alias for --format json.")
    parser.add_argument("--show-quota", action="store_true", help="Print Shodan quota info when available.")

    parser.add_argument("-oN", dest="out_nmap", help="Write Nmap-style output to file.")
    parser.add_argument("-oG", dest="out_grep", help="Write grepable output to file.")
    parser.add_argument("-oX", dest="out_xml", help="Write XML output to file.")

    parser.add_argument("--ports", help="Port filter (e.g. 22,80,443,8000-8100).")
    parser.add_argument("--proto", help="Protocol filter (tcp/udp; comma-separated).")
    parser.add_argument("--service", help="Service filter (comma-separated; matches SERVICE column).")
    parser.add_argument("--grep", help="Regex filter over service/version/banner (only matching services shown).")
    parser.add_argument("--case-sensitive", action="store_true", help="Make --grep regex case-sensitive.")

    parser.add_argument("--show-banners", action="store_true", help="Show a compact banner section.")
    parser.add_argument("--banner-max-len", type=int, default=200, help="Max banner length (default: 200).")

    parser.add_argument("--dns", action="store_true", help="Do reverse DNS for IP targets.")
    parser.add_argument("--whois", action="store_true", help="Best-effort WHOIS lookup (requires `whois` in PATH).")

    parser.add_argument("--include-vulns", action="store_true", help="Include vulnerability IDs when available.")
    parser.add_argument("--max-services", type=int, default=100, help="Max services to show (default: 100, 0 = no limit).")

    args = parser.parse_args(argv)

    if not args.api_key:
        _eprint("Missing API key. Set SHODAN_API_KEY or pass --api-key.")
        return 2

    try:
        targets = _parse_targets(
            args.targets,
            input_file=args.input,
            cidrs=args.cidr or None,
            resolve=args.resolve,
            max_targets=args.max_targets,
            allow_large=args.allow_large,
        )
    except RuntimeError as e:
        _eprint(str(e))
        return 2

    scope_nets: Optional[List[ipaddress._BaseNetwork]] = None
    if args.authorized_scope:
        try:
            scope_nets = _load_authorized_scope(args.authorized_scope)
        except RuntimeError as e:
            _eprint(str(e))
            return 2

    if scope_nets is not None and not args.force:
        filtered: List[Tuple[str, str]] = []
        blocked: List[str] = []
        for t, ip in targets:
            if _ip_in_scope(ip, scope_nets):
                filtered.append((t, ip))
            else:
                blocked.append(f"{t} -> {ip}")
        if blocked:
            _eprint("Blocked targets outside --authorized-scope (use --force to override):")
            for b in blocked[:50]:
                _eprint(f"  - {b}")
            if len(blocked) > 50:
                _eprint(f"  ... ({len(blocked) - 50} more)")
            targets = filtered

    if not targets:
        _eprint("No targets left after scope filtering.")
        return 2

    if args.dry_run:
        for t, ip in targets:
            print(f"{t}\t{ip}")
        return 0

    ports_allow = _parse_ports(args.ports)
    protos_allow = _parse_csv_lower(args.proto)
    services_allow = _parse_csv_lower(args.service)

    grep_re = None
    if args.grep:
        flags = 0 if args.case_sensitive else re.IGNORECASE
        try:
            grep_re = re.compile(args.grep, flags=flags)
        except re.error as e:
            _eprint(f"Invalid --grep regex: {e}")
            return 2

    fmt = "json" if args.json else args.format

    stdout_chunks: List[str] = []
    out_files_nmap: List[str] = []
    out_files_grep: List[str] = []
    out_files_xml: List[str] = []

    for i, (display_target, ip) in enumerate(targets):
        if i > 0 and fmt in ("nmap", "summary"):
            stdout_chunks.append("\n")

        cache_hit = False
        raw: Optional[Dict[str, Any]] = None
        headers: Dict[str, str] = {}

        if not args.no_cache:
            cpath = _cache_path(args.cache_dir, ip)
            raw = _load_cache(cpath, ttl_s=max(0, int(args.cache_ttl)))
            if raw is not None:
                cache_hit = True

        if raw is None:
            try:
                res = shodan_host_lookup(ip, args.api_key, timeout_s=args.timeout, retries=args.retries, backoff_s=args.backoff)
                raw = res.json
                headers = res.headers
            except RuntimeError as e:
                _eprint(f"{ip}: {e}")
                continue

            if not args.no_cache:
                try:
                    _save_cache(_cache_path(args.cache_dir, ip), raw)
                except OSError:
                    pass

        services_all = _extract_services(raw)
        services = _filter_services(
            services_all,
            ports=ports_allow,
            protos=protos_allow,
            services_allow=services_allow,
            grep_re=grep_re,
        )

        if fmt == "json":
            stdout_chunks.append(json.dumps(raw, indent=2, sort_keys=True))
            stdout_chunks.append("\n")
        elif fmt == "ndjson":
            buf: List[str] = []
            _emit_ndjson(out=_ListWriter(buf), display_target=display_target, ip=ip, raw=raw, services=services, include_vulns=args.include_vulns)
            stdout_chunks.extend(buf)
        elif fmt == "summary":
            buf = []
            _emit_summary_json(out=_ListWriter(buf), display_target=display_target, ip=ip, raw=raw, services=services, include_vulns=args.include_vulns)
            stdout_chunks.extend(buf)
        elif fmt == "grep":
            buf = []
            _emit_grepable(out=_ListWriter(buf), display_target=display_target, ip=ip, services=services)
            stdout_chunks.extend(buf)
        elif fmt == "xml":
            buf = []
            _emit_xml(out=_ListWriter(buf), display_target=display_target, ip=ip, raw=raw, services=services)
            stdout_chunks.extend(buf)
        else:
            buf = []
            _emit_nmap(
                out=_ListWriter(buf),
                display_target=display_target,
                ip=ip,
                raw=raw,
                headers=headers,
                services=services,
                max_services=args.max_services,
                show_banners=args.show_banners,
                banner_max_len=args.banner_max_len,
                include_vulns=args.include_vulns,
                show_quota=args.show_quota,
                dns=args.dns,
                whois=args.whois,
            )
            stdout_chunks.extend(buf)

        if args.out_nmap:
            buf = []
            _emit_nmap(
                out=_ListWriter(buf),
                display_target=display_target,
                ip=ip,
                raw=raw,
                headers=headers,
                services=services,
                max_services=args.max_services,
                show_banners=args.show_banners,
                banner_max_len=args.banner_max_len,
                include_vulns=args.include_vulns,
                show_quota=args.show_quota,
                dns=args.dns,
                whois=args.whois,
            )
            out_files_nmap.append("".join(buf).rstrip("\n"))
        if args.out_grep:
            buf = []
            _emit_grepable(out=_ListWriter(buf), display_target=display_target, ip=ip, services=services)
            out_files_grep.append("".join(buf))
        if args.out_xml:
            buf = []
            _emit_xml(out=_ListWriter(buf), display_target=display_target, ip=ip, raw=raw, services=services)
            out_files_xml.append("".join(buf).rstrip("\n"))

        if cache_hit and args.show_quota:
            pass

    sys.stdout.write("".join(stdout_chunks))

    if args.out_nmap:
        _write_file(args.out_nmap, "\n\n".join(out_files_nmap).rstrip("\n") + "\n")
    if args.out_grep:
        _write_file(args.out_grep, "".join(out_files_grep))
    if args.out_xml:
        _write_file(args.out_xml, "\n\n".join(out_files_xml).rstrip("\n") + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

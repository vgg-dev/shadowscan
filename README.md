# ShadowScan

ShadowScan is a small CLI that queries the Shodan Host API for one or more hosts and prints Nmap-style output.

- Passive lookup only (no scanning).
- Multi-target input: positional targets, `--input`, and `--cidr`.
- Filters: `--ports`, `--proto`, `--service`, `--grep`.
- Output: `--format nmap|summary|json|ndjson|grep|xml` plus `-oN/-oG/-oX`.
- Caching: `--cache-dir`, `--cache-ttl`, `--no-cache`.

## Setup

Set your API key:

```powershell
$env:SHODAN_API_KEY = "YOUR_KEY"
```

## Examples

Single target (default Nmap-style):

```powershell
python .\shadowscan.py 8.8.8.8
python .\shadowscan.py example.com --resolve
```

Multiple targets:

```powershell
python .\shadowscan.py --input targets.txt
python .\shadowscan.py --cidr 10.0.0.0/24
python .\shadowscan.py 1.1.1.1 8.8.8.8
```

Scope safety (allowlist file contains CIDRs/IPs):

```powershell
python .\shadowscan.py --cidr 10.0.0.0/24 --authorized-scope scope.txt
# override (use with care):
python .\shadowscan.py --cidr 10.0.0.0/24 --authorized-scope scope.txt --force
```

Filters + banners:

```powershell
python .\shadowscan.py 8.8.8.8 --ports 80,443 --show-banners
python .\shadowscan.py 8.8.8.8 --grep "nginx" --show-banners
```

Raw JSON / pipelines:

```powershell
python .\shadowscan.py 8.8.8.8 --format json
python .\shadowscan.py --input targets.txt --format ndjson
```

Write Nmap-ish output files:

```powershell
python .\shadowscan.py --input targets.txt -oN out.txt -oG out.grep -oX out.xml
```

## Notes

- Use only on hosts you are authorized to assess.
- Results are whatever Shodan currently has indexed for the host.

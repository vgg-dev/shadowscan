# ShadowScan

ShadowScan is a tiny CLI that queries the Shodan Host API for a single host and prints an Nmap-style summary.

## Setup

- Get a Shodan API key.
- Set `SHODAN_API_KEY`:

PowerShell (current session):

```powershell
$env:SHODAN_API_KEY = "YOUR_KEY"
```

PowerShell (persist for future sessions):

```powershell
setx SHODAN_API_KEY "YOUR_KEY"
```

## Usage

Nmap-style output (default):

```powershell
python .\shadowscan.py 8.8.8.8
python .\shadowscan.py example.com --resolve
```

Raw JSON (full Shodan response):

```powershell
python .\shadowscan.py 8.8.8.8 --format json
# or
python .\shadowscan.py 8.8.8.8 --json
```

Include vulnerability IDs when available:

```powershell
python .\shadowscan.py 8.8.8.8 --include-vulns
```

## Notes

- Use only on hosts you are authorized to assess.
- Output is derived from Shodan data (not an active scan).

# Contributing

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m py_compile .\shadowscan.py .\shodan_host.py
python -m unittest discover -v
```

## Guidelines

- Keep changes focused and avoid adding new dependencies unless necessary.
- Do not hardcode API keys or include sensitive banners in test fixtures.
- Prefer adding small unit tests for parsing/formatting logic.

## Submitting changes

- Open a PR with a clear description and example output.
- If your change affects CLI flags or output formats, update `README.md`.


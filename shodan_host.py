#!/usr/bin/env python3
"""Compatibility shim.

ShadowScan is the canonical entrypoint now:
  python shadowscan.py ...

This file remains to avoid breaking existing usage:
  python shodan_host.py ...
"""

from __future__ import annotations

import shadowscan


if __name__ == "__main__":
    raise SystemExit(shadowscan.main())

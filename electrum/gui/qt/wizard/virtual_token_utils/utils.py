from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

def secure_filename(name: str) -> str:
    """Desktop-safe version akin to Werkzeug's secure_filename."""
    keep = "-_.() "
    cleaned = "".join(c if c.isalnum() or c in keep else "_" for c in name)
    cleaned = cleaned.strip().lstrip(".")
    return cleaned or "file"

def unique_path(base: Path) -> Path:
    if not base.exists():
        return base
    stem, suffix = base.stem, base.suffix
    i = 1
    while True:
        candidate = base.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1

def open_folder(path: Path):
    try:
        if sys.platform.startswith("darwin"):
            os.system(f'open "{path}"')
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            os.system(f'xdg-open "{path}"')
    except Exception:
        traceback.print_exc()
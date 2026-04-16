from __future__ import annotations
import os
import sys
from pathlib import Path


def _get_vt_data_dir() -> Path:
    """Return a user-writable directory for Virtual Token data.

    When packaged as a frozen exe (PyInstaller / cx_Freeze), ``__file__``
    points inside the bundle which is read-only.  We always store mutable
    data under the Electrum user directory instead.

    Resolves to:  <APPDATA>/Electrum/virtual_token   (Windows)
                  ~/.electrum/virtual_token           (Linux/macOS)
    """
    # Re-use Electrum's own user_dir() when available
    try:
        from electrum.util import user_dir
        base = user_dir()
    except Exception:
        # Fallback if electrum.util is not importable (e.g. during tests)
        if "APPDATA" in os.environ:
            base = os.path.join(os.environ["APPDATA"], "Electrum")
        else:
            base = os.path.join(Path.home(), ".electrum")

    vt_dir = Path(base) / "virtual_token"
    vt_dir.mkdir(parents=True, exist_ok=True)
    return vt_dir


def _get_vt_bundle_dir() -> Path:
    """Return the directory where bundled assets (e.g. credentials.json) live.

    In a frozen exe this is the directory containing the .exe itself,
    so credentials.json just needs to sit next to the executable.
    When running from source, it's the project root (the directory
    containing ``run_electrum``).
    """
    if getattr(sys, 'frozen', False):
        return Path(os.path.dirname(sys.executable))
    # Running from source — walk up from this file to the project root.
    # This file lives at: <project>/electrum/gui/qt/wizard/virtual_token_utils/paths.py
    return Path(__file__).resolve().parents[5]


# --- Public paths ---------------------------------------------------------

VT_DATA_DIR = _get_vt_data_dir()
"""User-writable directory for all VT runtime data (DB, uploads, token)."""

VT_BUNDLE_DIR = _get_vt_bundle_dir()
"""Read-only directory for bundled assets (credentials.json, etc.)."""

DB_PATH = str(VT_DATA_DIR / "enrollments.db")
"""Path to the SQLite enrollment database."""

CREDENTIALS_PATH = str(VT_BUNDLE_DIR / "credentials.json")
"""Path to the Google OAuth client secrets file (read-only, bundled)."""

TOKEN_PATH = str(VT_DATA_DIR / "token.json")
"""Path to the Google OAuth cached token (user-writable)."""

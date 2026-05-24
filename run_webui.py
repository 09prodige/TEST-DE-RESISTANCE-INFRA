#!/usr/bin/env python3
"""Launch the RIG Scanner Web UI.

Run with:
    python run_webui.py

Then access:
    http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure src is in the path
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def main() -> None:
    """Run the Flask development server."""
    # Create reports and data directories
    (PROJECT_ROOT / "reports").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "data").mkdir(parents=True, exist_ok=True)

    # Import app only after path is set up
    from src.webui.app import app
    from src import __version__

    print("=" * 60)
    print(f"  RIG Scanner Web UI v{__version__}")
    print("=" * 60)
    print()
    print("  Starting local web server...")
    print()
    print(f"  URL: http://127.0.0.1:5000")
    print(f"  Press CTRL+C to stop")
    print()
    print("=" * 60)

    # Run in debug mode (development only!)
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        threaded=True,
        use_reloader=False,  # Avoids double initialization
    )


if __name__ == "__main__":
    main()

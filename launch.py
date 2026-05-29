#!/usr/bin/env python3
"""
SentinelFlow Quick Launcher
===========================
Double-click this file to start SentinelFlow without a terminal.
Works on Windows, macOS, and Linux.

On macOS: Right-click → Open With → Python Launcher
On Windows: Double-click (if Python is associated with .py files)
On Linux: chmod +x launch.py && ./launch.py
"""

import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent

def main():
    # Try to launch the desktop app
    app_py = ROOT / "desktop" / "app.py"

    if not app_py.exists():
        print("ERROR: desktop/app.py not found. Are you in the sentinelflow directory?")
        input("Press Enter to exit.")
        sys.exit(1)

    # Check dependencies
    missing = []
    for pkg in ["flask", "aiohttp", "aiosqlite", "dnspython", "yaml"]:
        try:
            __import__(pkg if pkg != "yaml" else "yaml")
        except ImportError:
            missing.append(pkg if pkg != "yaml" else "PyYAML")

    if missing:
        print(f"Installing missing packages: {', '.join(missing)}")
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + missing + ["-q"],
            check=True
        )

    # Launch the desktop app
    os.execv(sys.executable, [sys.executable, str(app_py)])


if __name__ == "__main__":
    main()

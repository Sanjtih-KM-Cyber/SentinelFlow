#!/bin/bash
# SentinelFlow macOS Launcher
# Make executable: chmod +x SentinelFlow.command
# Then double-click it in Finder.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   SentinelFlow — Starting Up…        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Find Python 3
PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10 python; do
    if command -v "$candidate" &>/dev/null; then
        VER=$("$candidate" -c "import sys; print(sys.version_info >= (3,10))" 2>/dev/null)
        if [ "$VER" = "True" ]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    osascript -e 'display alert "Python 3.10+ Required" message "Please install Python from https://python.org then try again." as critical'
    exit 1
fi

echo "  Using: $($PYTHON --version)"
echo ""

# Install deps
echo "  Checking dependencies…"
"$PYTHON" -m pip install -r requirements.txt -q 2>/dev/null

# Launch
echo "  Launching desktop app…"
"$PYTHON" desktop/app.py

# If app exits with error, keep window open
if [ $? -ne 0 ]; then
    echo ""
    echo "  SentinelFlow exited with an error."
    echo "  Press Enter to close."
    read
fi

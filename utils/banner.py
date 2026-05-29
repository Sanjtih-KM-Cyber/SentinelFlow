"""
SentinelFlow ASCII Banner
"""

from datetime import datetime


BANNER = r"""
  ____            _   _            _  _____ _
 / ___|  ___ _ __ | |_(_)_ __   ___| ||  ___| | _____      __
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ || |_  | |/ _ \ \ /\ / /
  ___) |  __/ | | | |_| | | | |  __/ ||  _| | | (_) \ V  V /
 |____/ \___|_| |_|\__|_|_| |_|\___|_||_|   |_|\___/ \_/\_/

"""

VERSION = "1.0.0"
TAGLINE = "External Attack Surface Management Pipeline"
AUTHOR = "SentinelFlow Security"


def print_banner():
    """Print the SentinelFlow startup banner."""
    # ANSI colors
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    RED = "\033[91m"

    print(f"{CYAN}{BANNER}{RESET}")
    print(f"  {YELLOW}v{VERSION}{RESET} — {TAGLINE}")
    print(f"  {DIM}{'─' * 55}{RESET}")
    print(f"  {DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print()
    print(f"  {RED}⚠  LEGAL NOTICE{RESET}")
    print(f"  {DIM}Only scan systems you own or have explicit written{RESET}")
    print(f"  {DIM}authorization to test. Unauthorized use is illegal.{RESET}")
    print(f"  {DIM}{'─' * 55}{RESET}")
    print()

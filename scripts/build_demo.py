#!/usr/bin/env python3
"""Regenerate the published demo page in docs/index.html.

The page is produced by the tool itself with `--demo`, so the site can never
drift from what the code actually prints:

    python scripts/build_demo.py

Author: Ankita Salaria | GitHub: https://github.com/Ankitavasudev
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "docs" / "index.html"


def main() -> int:
    result = subprocess.run(
        [sys.executable, str(ROOT / "k8s_monitor.py"), "--demo", "--output", "html"],
        capture_output=True,
        check=True,
    )
    html = result.stdout.decode("utf-8")
    if "<!DOCTYPE html>" not in html:
        print("the CLI did not return an HTML document", file=sys.stderr)
        return 1
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(html, encoding="utf-8", newline="\n")
    print("wrote %s (%d KB)" % (TARGET.relative_to(ROOT), len(html) // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())

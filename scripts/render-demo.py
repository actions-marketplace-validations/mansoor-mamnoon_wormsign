#!/usr/bin/env python3
"""Record real `wormsign --demo` output and render it as docs/demo.gif.

Usage: python3 scripts/render-demo.py /path/to/wormsign

Runs the binary once, online, so the GIF shows the actual OSV.dev lookup
finding the malicious keyv release. Needs `agg` (asciinema gif generator) on
PATH. Typing and line timing are for presentation, not a benchmark.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

COMMAND = "wormsign --demo"
COLS = 104

binary = Path(sys.argv[1]).resolve()
if not shutil.which("agg"):
    sys.exit("render-demo: agg not found (https://github.com/asciinema/agg)")

out = subprocess.run(
    [str(binary), "--demo"],
    env={**os.environ, "FORCE_COLOR": "1"},
    check=True,
    capture_output=True,
    text=True,
).stdout
# Room for the prompt line, a blank line and every output line, so the
# typed command never scrolls off the top of the final frame.
ROWS = out.count("\n") + 4
if "MAL-" not in out:
    sys.exit("render-demo: OSV lookup did not report the keyv release; is the network up?")

events, t = [], 0.4


def emit(text, delay):
    global t
    t += delay
    events.append([round(t, 3), "o", text])


emit("\x1b[32m$\x1b[0m ", 0.0)
for ch in COMMAND:
    emit(ch, 0.07)
emit("\r\n", 0.35)
frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
for i in range(14):
    emit(f"\r\x1b[K{frames[i % len(frames)]} checking 3 packages against OSV.dev...", 0.08)
emit("\r\x1b[K", 0.08)
for line in out.rstrip("\n").split("\n"):
    emit(line + "\r\n", 0.045)
emit("\x1b[?25l", 0.05)  # hide the cursor on the final frame
emit("", 6.0)

target = Path(__file__).resolve().parents[1] / "docs" / "demo.gif"
with tempfile.NamedTemporaryFile("w", suffix=".cast", delete=False) as cast:
    cast.write(json.dumps({"version": 2, "width": COLS, "height": ROWS}) + "\n")
    for e in events:
        cast.write(json.dumps(e, ensure_ascii=False) + "\n")
subprocess.run(
    ["agg", "--font-size", "15", "--theme", "monokai", "--last-frame-duration", "6", cast.name, str(target)],
    check=True,
    capture_output=True,
)
os.unlink(cast.name)
print(f"rendered {target} ({target.stat().st_size // 1024} KB)")

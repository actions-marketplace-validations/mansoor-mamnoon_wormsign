#!/usr/bin/env python3
"""Render real offline demo output as a GIF (requires Pillow).

Usage: python3 scripts/render-demo.py /path/to/wormsign /path/to/monospace.ttf
The command is executed once. Frame timing is for presentation, not a benchmark.
"""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

binary, font_path = sys.argv[1:]
command = "wormsign --demo --offline"
result = subprocess.run(
    [str(Path(binary).resolve()), "--demo", "--offline"],
    env={**os.environ, "NO_COLOR": "1"},
    check=True,
    capture_output=True,
    text=True,
)
output = result.stdout.strip("\n")
lines = []
for line in output.splitlines():
    indent = len(line) - len(line.lstrip())
    lines.extend(textwrap.wrap(
        line, width=112, replace_whitespace=False,
        subsequent_indent=" " * indent,
    ) or [""])

font = ImageFont.truetype(font_path, 19)
cell = font.getlength("M")
line_height, padding, header_height = 27, 28, 48
width = round(112 * cell) + padding * 2
height = header_height + padding * 2 + line_height * (len(lines) + 3)


def frame(typed, visible):
    canvas = Image.new("RGB", (width, height), "#111820")
    draw = ImageDraw.Draw(canvas)
    draw.rectangle((0, 0, width, header_height), fill="#1c2633")
    draw.text((padding, 12), "wormsign | offline demo | harmless fixture", font=font, fill="#aebdcb")
    y = header_height + padding
    draw.text((padding, y), "$ " + command[:typed], font=font, fill="#a8dfab")
    y += line_height * 2
    for line in lines[:visible]:
        draw.text((padding, y), line, font=font, fill="#e0e6ed")
        y += line_height
    return canvas


frames, durations = [], []
for typed in range(0, len(command) + 1, 2):
    frames.append(frame(typed, 0))
    durations.append(80)
frames.append(frame(len(command), 0))
durations.append(250)
for visible in range(4, len(lines), 4):
    frames.append(frame(len(command), visible))
    durations.append(180)
frames.append(frame(len(command), len(lines)))
durations.append(12000)

# One palette keeps terminal colors stable throughout the animation.
palette = frames[-1].quantize(colors=64)
frames = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
target = Path(__file__).resolve().parents[1] / "docs/demo.gif"
frames[0].save(target, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
print(f"Rendered {target}: {width}x{height}, {len(frames)} frames")

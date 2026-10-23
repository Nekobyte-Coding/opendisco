#!/usr/bin/env python3
"""Draw the app icon and write it in every format the platforms want (needs Pillow).

Writes src/opendisco/resources/icon.png (Linux, Android, iOS and Toga's default),
icon.ico (Windows) and icon.icns (macOS). Run: .venv/bin/python packaging/make_icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "src" / "opendisco" / "resources"
SIZE = 1024


def draw() -> Image.Image:
    top, bottom = (31, 111, 235), (11, 61, 145)
    gradient = Image.new("RGB", (SIZE, SIZE))
    pixels = gradient.load()
    for y in range(SIZE):
        t = y / (SIZE - 1)
        row = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom))
        for x in range(SIZE):
            pixels[x, y] = row
    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle((40, 40, SIZE - 40, SIZE - 40), radius=210, fill=255)
    icon = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    icon.paste(gradient, mask=mask)

    pen = ImageDraw.Draw(icon)
    cx, cy = SIZE // 2, 690
    for radius in (170, 320, 470):  # discovery "waves" rising from a device
        pen.arc((cx - radius, cy - radius, cx + radius, cy + radius), start=222, end=318, fill="white", width=74)
    pen.ellipse((cx - 78, cy - 78, cx + 78, cy + 78), fill="white")
    return icon


def main() -> None:
    icon = draw()
    OUT.mkdir(parents=True, exist_ok=True)
    icon.resize((512, 512), Image.LANCZOS).save(OUT / "icon.png")
    icon.save(OUT / "icon.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    icon.save(OUT / "icon.icns")
    print("wrote", ", ".join(str(OUT / f"icon.{ext}") for ext in ("png", "ico", "icns")))


if __name__ == "__main__":
    main()

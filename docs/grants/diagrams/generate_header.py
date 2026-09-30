"""Haze letterhead rail: same L-geometry as the Arcane template, Haze colors, no Arcane mark."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1400, 1981
ACCENT = (31, 107, 98)  # #1f6b62
FLAME = (196, 122, 58)  # #c47a3a
RAIL = (232, 240, 238)  # washed teal
LINE = (176, 204, 199)


def _spark(draw: ImageDraw.ImageDraw, cx: int, cy: int, arm: int, color) -> None:
    draw.polygon(
        [
            (cx, cy - arm),
            (cx + 7, cy - 7),
            (cx + arm, cy),
            (cx + 7, cy + 7),
            (cx, cy + arm),
            (cx - 7, cy + 7),
            (cx - arm, cy),
            (cx - 7, cy - 7),
        ],
        fill=color,
    )


def main() -> None:
    img = Image.new("RGB", (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    rail_w = 92
    draw.rectangle((0, 0, rail_w, H), fill=RAIL)

    y_bar = 118
    draw.rectangle((rail_w, y_bar, W, y_bar + 3), fill=LINE)
    fade = Image.new("L", (W, 4), 0)
    fd = ImageDraw.Draw(fade)
    for x in range(W):
        fd.line((x, 0, x, 3), fill=max(0, 220 - int(x * 220 / 900)))
    overlay = Image.new("RGB", (W, 4), LINE)
    img.paste(overlay, (0, y_bar), fade)

    _spark(draw, rail_w, y_bar + 1, 42, LINE)

    try:
        font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 54)
        mark = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 54)
    except OSError:
        font = ImageFont.load_default()
        mark = font

    word = "Haze"
    bbox = draw.textbbox((0, 0), word, font=mark)
    tw = bbox[2] - bbox[0]
    x = W - tw - 72
    y = 48
    draw.ellipse((x - 38, y + 8, x - 10, y + 36), outline=FLAME, width=3)
    draw.polygon(
        [(x - 24, y + 6), (x - 20, y + 18), (x - 28, y + 18)],
        fill=FLAME,
    )
    draw.text((x, y), word, font=mark if mark else font, fill=ACCENT)

    out = Path(__file__).with_name("header.png")
    img.save(out, "PNG")
    print(f"wrote {out} {img.size}")


if __name__ == "__main__":
    main()

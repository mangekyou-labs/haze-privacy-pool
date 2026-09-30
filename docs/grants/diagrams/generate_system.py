"""System diagram matching Arcane image3 geometry with Haze labels. No Graphviz."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1170, 1302
INK = (20, 20, 20)
FILL = (255, 255, 255)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = (
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
        if bold
        else "/System/Library/Fonts/Supplemental/Arial.ttf"
    )
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def round_rect(draw, box, r, outline=INK, fill=FILL, width=2):
    draw.rounded_rectangle(box, radius=r, outline=outline, fill=fill, width=width)


def stacked_frame(draw, x, y, w, h, layers=3):
    for i in range(layers - 1, -1, -1):
        ox, oy = i * 8, -i * 8
        round_rect(draw, (x + ox, y + oy, x + w + ox, y + h + oy), 8, width=2)


def cylinder(draw, x, y, w, h):
    ry = 28
    draw.ellipse((x, y + h - ry * 2, x + w, y + h), outline=INK, fill=FILL, width=2)
    draw.rectangle((x, y + ry, x + w, y + h - ry), outline=FILL, fill=FILL)
    draw.line((x, y + ry, x, y + h - ry), fill=INK, width=2)
    draw.line((x + w, y + ry, x + w, y + h - ry), fill=INK, width=2)
    draw.ellipse((x, y, x + w, y + ry * 2), outline=INK, fill=FILL, width=2)
    draw.arc((x, y + h - ry * 2, x + w, y + h), 0, 180, fill=INK, width=2)


def actor(draw, cx, cy, label, f):
    r = 18
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=INK, width=2)
    draw.line((cx, cy + r, cx, cy + 56), fill=INK, width=2)
    draw.line((cx - 28, cy + 32, cx + 28, cy + 32), fill=INK, width=2)
    draw.line((cx, cy + 56, cx - 22, cy + 92), fill=INK, width=2)
    draw.line((cx, cy + 56, cx + 22, cy + 92), fill=INK, width=2)
    bbox = draw.textbbox((0, 0), label, font=f)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw / 2, cy + 98), label, font=f, fill=INK)


def labeled_box(draw, box, text, f):
    round_rect(draw, box, 18, width=2)
    cx = (box[0] + box[2]) / 2
    cy = (box[1] + box[3]) / 2
    bbox = draw.textbbox((0, 0), text, font=f)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text((cx - tw / 2, cy - th / 2 - 2), text, font=f, fill=INK)


def arrow(draw, x1, y1, x2, y2, text, f, text_off=(0, -16)):
    draw.line((x1, y1, x2, y2), fill=INK, width=2)
    ang_dx = x2 - x1
    ang_dy = y2 - y1
    length = max((ang_dx**2 + ang_dy**2) ** 0.5, 1)
    ux, uy = ang_dx / length, ang_dy / length
    px, py = -uy, ux
    ah = 12
    draw.polygon(
        [
            (x2, y2),
            (x2 - ux * ah + px * 6, y2 - uy * ah + py * 6),
            (x2 - ux * ah - px * 6, y2 - uy * ah - py * 6),
        ],
        fill=INK,
    )
    mx, my = (x1 + x2) / 2 + text_off[0], (y1 + y2) / 2 + text_off[1]
    bbox = draw.textbbox((0, 0), text, font=f)
    tw = bbox[2] - bbox[0]
    draw.text((mx - tw / 2, my), text, font=f, fill=INK)


def main() -> None:
    img = Image.new("RGB", (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    title_f = font(22)
    box_f = font(20)
    label_f = font(16)
    small_f = font(16)

    stacked_frame(draw, 40, 70, 780, 820, layers=3)
    tb = draw.textbbox((0, 0), "Haze", font=title_f)
    draw.text((40 + (780 - (tb[2] - tb[0])) / 2, 92), "Haze", font=title_f, fill=INK)

    disclosure = (470, 150, 740, 250)
    auth = (120, 300, 390, 400)
    indexer = (80, 560, 360, 660)
    gate = (430, 560, 710, 660)
    labeled_box(draw, disclosure, "Disclosure", box_f)
    labeled_box(draw, auth, "Auth", box_f)
    labeled_box(draw, indexer, "Indexer", box_f)
    labeled_box(draw, gate, "Gatekeeper", box_f)

    cylinder(draw, 160, 900, 500, 220)
    pb = draw.textbbox((0, 0), "Pool contract", font=box_f)
    draw.text((160 + (500 - (pb[2] - pb[0])) / 2, 1005), "Pool contract", font=box_f, fill=INK)

    actor(draw, 980, 150, "Auditor", small_f)
    actor(draw, 980, 720, "User", small_f)

    arrow(draw, 930, 170, 750, 200, "Investigates", label_f, text_off=(10, -22))
    arrow(draw, 470, 220, 390, 330, "Decrypt", label_f, text_off=(-30, -8))
    arrow(draw, 255, 400, 220, 560, "Authorized decrypt", label_f, text_off=(90, -8))
    arrow(draw, 220, 660, 280, 920, "Watches", label_f, text_off=(-70, 40))
    arrow(draw, 930, 760, 720, 620, "Interact", label_f, text_off=(20, -24))
    arrow(draw, 570, 660, 500, 900, "Facilitates", label_f, text_off=(70, 20))

    out = Path(__file__).with_name("system.png")
    img.save(out, "PNG")
    print(f"wrote {out} {img.size}")


if __name__ == "__main__":
    main()

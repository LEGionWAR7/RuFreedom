# -*- coding: utf-8 -*-
"""Иконки RuFreedom из фирменного знака — разорванной цепи.

Источник: assets/logo.png (золотая цепь с искрами разлома, прозрачный фон).
Отсюда собираются:
  assets/icon.ico  — окно, панель задач, трей (7 размеров);
  assets/icon.png  — тот же знак растром, его показывает интерфейс.

ВАЖНО про формат .ico. Pillow по умолчанию кладёт внутрь ВСЕ размеры как PNG,
и Проводник Windows такую иконку не показывает: PNG внутри .ico он понимает
только для 256x256, а для мелких размеров ждёт классический BMP. Из-за этого
у exe была пустая заглушка вместо знака. Поэтому .ico здесь собирается вручную:
BMP для 16..128 и PNG для 256 — ровно та раскладка, которую Windows ожидает.
"""
import io
import os
import re
import struct
import sys
from io import BytesIO

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "assets", "logo.png")

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
PNG_FROM = 256          # с этого размера кладём PNG, ниже — BMP


def load_mark(path=SRC):
    """Знак, обрезанный по содержимому и посаженный в квадрат с полем."""
    im = Image.open(path).convert("RGBA")
    box = im.getchannel("A").point(lambda a: 255 if a > 8 else 0).getbbox()
    if box:
        im = im.crop(box)
    side = max(im.size)
    pad = int(side * 0.06)          # поле, иначе знак упирается в край
    canvas = Image.new("RGBA", (side + pad * 2, side + pad * 2), (0, 0, 0, 0))
    canvas.alpha_composite(im, ((canvas.width - im.width) // 2,
                                (canvas.height - im.height) // 2))
    return canvas


def build(size, mark=None):
    mark = mark if mark is not None else load_mark()
    return mark.resize((size, size), Image.LANCZOS)


def _dib(im):
    """Одна запись .ico в виде BMP: заголовок, пиксели снизу вверх, маска."""
    w, h = im.size
    px = im.load()

    head = struct.pack("<IiiHHIIiiII",
                       40,          # размер заголовка
                       w, h * 2,    # высота удвоена: цвет + маска прозрачности
                       1, 32,       # плоскостей, бит на пиксель
                       0, 0,        # без сжатия, размер картинки не обязателен
                       0, 0, 0, 0)

    rows = []
    for y in range(h - 1, -1, -1):            # BMP хранится снизу вверх
        row = bytearray()
        for x in range(w):
            r, g, b, a = px[x, y]
            row += bytes((b, g, r, a))        # порядок BGRA
        rows.append(bytes(row))
    colour = b"".join(rows)

    # Маска прозрачности. У 32-битных иконок её берут из альфы, но Windows
    # всё равно требует её присутствия, а некоторые места (мелкие размеры в
    # списках) читают именно её. Строка выравнивается на 4 байта.
    stride = ((w + 31) // 32) * 4
    mask = bytearray()
    for y in range(h - 1, -1, -1):
        bits = bytearray(stride)
        for x in range(w):
            if px[x, y][3] < 128:             # прозрачный -> бит 1
                bits[x // 8] |= 0x80 >> (x % 8)
        mask += bits
    return head + colour + bytes(mask)


def write_ico(path, images):
    """Собрать .ico вручную: BMP для мелких размеров, PNG для 256."""
    blobs = []
    for im in images:
        if im.width >= PNG_FROM:
            buf = BytesIO()
            im.save(buf, format="PNG")
            blobs.append((im, buf.getvalue()))
        else:
            blobs.append((im, _dib(im)))

    offset = 6 + 16 * len(blobs)
    head = struct.pack("<HHH", 0, 1, len(blobs))
    entries, body = b"", b""
    for im, blob in blobs:
        w = 0 if im.width >= 256 else im.width
        h = 0 if im.height >= 256 else im.height
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        body += blob
    with open(path, "wb") as fh:
        fh.write(head + entries + body)


UI_SIZE = 128           # знак в окне рисуется 40-54 px, 128 хватает и для HiDPI


def embed_into_pages(mark):
    """Вшить знак прямо в страницы как data-ссылку.

    Ссылаться на файл нельзя: pywebview открывает страницу адресом вида
    file://C:\путь -- с обратными слэшами и двумя косыми. Windows-путь там
    попадает на место имени хоста, базовый адрес выходит битым, и любые
    относительные ссылки (в том числе на картинку) никуда не ведут. Знак
    внутри самой страницы от этого не зависит вовсе.
    """
    import base64
    from io import BytesIO
    buf = BytesIO()
    build(UI_SIZE, mark).save(buf, format="PNG", optimize=True)
    uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

    hit = 0
    for name in ("index.html", "splash.html"):
        path = os.path.join(ROOT, "web", name)
        if not os.path.isfile(path):
            continue
        text = io.open(path, encoding="utf-8").read()
        out, n = re.subn(r'(<img[^>]*class="m?logo"[^>]*src=")[^"]*(")',
                         lambda m: m.group(1) + uri + m.group(2), text)
        if n:
            io.open(path, "w", encoding="utf-8").write(out)
        hit += n
    return hit, len(uri)


def main(out_dir=None):
    out = out_dir or os.path.join(ROOT, "assets")
    mark = load_mark()
    write_ico(os.path.join(out, "icon.ico"), [build(s, mark) for s in ICO_SIZES])
    build(256, mark).save(os.path.join(out, "icon.png"))
    hit, size = embed_into_pages(mark)
    print(f"icon.ico и icon.png собраны; знак вшит в {hit} мест "
          f"({size // 1024} КБ на страницу)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)

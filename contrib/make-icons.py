#!/usr/bin/env python3
"""Рисует иконки для обоих приложений: под iOS и под Android.

ЗАЧЕМ СКРИПТОМ, А НЕ ФАЙЛАМИ ИЗ РЕДАКТОРА. Иконка тут не художество, а необходимость: без
файла 1024x1024 Xcode не соберёт приложение с предупреждением, а без двух картинок в manifest
телефон покажет при установке пустой квадрат. Скриптом — потому что понятно, что нарисовано, и
можно поправить цвет, не открывая ничего.

Запуск: python3 contrib/make-icons.py (нужен Pillow).
"""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IOS = os.path.join(ROOT, "ios")
ANDROID = os.path.join(ROOT, "android")

BG = (11, 18, 32)        # почти чёрный синий
FG = (52, 211, 153)      # тот же зелёный, которым интерфейс показывает «подключено»
DIM = (30, 41, 59)


def draw(size: int) -> Image.Image:
    """Два шеврона вправо: поток, который куда-то направили.

    Рисуется на увеличенном полотне и уменьшается — так края выходят сглаженными без всякой
    возни с прозрачностью и масками.
    """
    s = size * 4
    img = Image.new("RGB", (s, s), BG)
    d = ImageDraw.Draw(img)

    # Кольцо-подложка: отделяет фигуру от фона на мелком размере, где иначе всё сливается.
    pad = int(s * 0.14)
    d.ellipse([pad, pad, s - pad, s - pad], fill=DIM)

    w = int(s * 0.075)          # толщина линии шеврона
    for k, cx in enumerate((0.40, 0.60)):
        x = s * cx
        top = (x - s * 0.085, s * 0.33)
        mid = (x + s * 0.085, s * 0.50)
        bot = (x - s * 0.085, s * 0.67)
        color = FG if k == 1 else (FG[0] // 2, FG[1] // 2, FG[2] // 2)
        d.line([top, mid, bot], fill=color, width=w, joint="curve")

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    out = [
        (os.path.join(IOS, "App/Resources/Assets.xcassets/AppIcon.appiconset/icon-1024.png"), 1024),
        (os.path.join(IOS, "Support/install-page/icon-57.png"), 57),
        (os.path.join(IOS, "Support/install-page/icon-512.png"), 512),
    ]
    # Android берёт иконку под плотность экрана. Размеры — те, что ждёт система; без них
    # запуск получает серый квадрат по умолчанию.
    for dens, size in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96),
                       ("xxhdpi", 144), ("xxxhdpi", 192)):
        out.append((os.path.join(ANDROID, f"app/src/main/res/mipmap-{dens}/ic_launcher.png"), size))
    for path, size in out:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        draw(size).save(path, "PNG", optimize=True)
        print(f"{path}  {size}x{size}")


if __name__ == "__main__":
    main()

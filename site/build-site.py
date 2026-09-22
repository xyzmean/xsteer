#!/usr/bin/env python3
"""Собирает страницу установки из заготовок рядом.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ, А НЕ СТРОКИ В ОПИСАНИИ СБОРКИ. Страницу надо иметь возможность собрать
руками и посмотреть на неё глазами до того, как она уедет в сеть, — а описание сборки запускается
только у бегунка. Здесь же живёт и единственная проверка, которая ловит незакрытую метку: без неё
страница молча не работала бы, указывая ссылкой на «@APK@».

ПОЧЕМУ ОДНА СТРАНИЦА НА ВСЕ ПЛАТФОРМЫ, А НЕ ПО ОДНОЙ НА КАЖДУЮ. У хранилища один сайт, и всякая
выкладка заменяет его ЦЕЛИКОМ. Две сборки, выкладывающие каждая своё, стирали бы работу друг
друга, и заметно это стало бы не сразу: страница iOS исчезала бы при каждом коммите в Android.
Поэтому выкладка одна, а платформы — разделы на ней; раздел без сборки честно говорит, что её нет.

Запуск руками (без файлов сборки — получится страница с пустыми разделами):

    python3 site/build-site.py --out /tmp/site --base https://example.github.io/xsteer
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


def human(n):
    if n >= 1 << 20:
        return "%.1f МБ" % (n / (1 << 20))
    if n >= 1 << 10:
        return "%.0f КБ" % (n / (1 << 10))
    return "%d Б" % n


def qr_svg(text):
    """QR в виде SVG прямо в разметке.

    Картинка не файлом, а внутри страницы: файл — это ещё один адрес, который надо не забыть
    выложить, а QR нужен ровно в одном месте и живёт ровно столько, сколько страница.
    """
    try:
        out = subprocess.run(
            ["qrencode", "-t", "SVG", "--inline", "-m", "2", "-o", "-", text],
            check=True, capture_output=True,
        ).stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError) as e:
        print("QR не нарисован (%s) — раздел обойдётся ссылкой" % e, file=sys.stderr)
        return ""
    # Заголовок XML и объявление типа документа внутри HTML недопустимы: страница с ними
    # разбирается браузером как испорченная. --inline их не печатает, но чужая версия qrencode
    # может, поэтому режем по первому <svg.
    i = out.find("<svg")
    return out[i:] if i >= 0 else out


def fill(text, marks, where):
    for k, v in marks.items():
        text = text.replace("@%s@" % k, v)
    return text


def leftovers(text):
    import re
    return sorted(set(re.findall(r"@[A-Z0-9_]+@", text)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", required=True, help="адрес сайта без косой на конце")
    ap.add_argument("--repo", default="https://github.com/xyzmean/xsteer")
    ap.add_argument("--built", default="")
    ap.add_argument("--apk", default="", help="путь к собранному .apk")
    ap.add_argument("--apk-version", default="")
    ap.add_argument("--apk-built", default="")
    ap.add_argument("--apk-sha", default="")
    ap.add_argument("--apk-signed", default="no", choices=["yes", "no"])
    ap.add_argument("--ipa", default="", help="путь к собранному .ipa")
    ap.add_argument("--ipa-version", default="")
    ap.add_argument("--ipa-built", default="")
    ap.add_argument("--ipa-sha", default="")
    a = ap.parse_args()

    base = a.base.rstrip("/")
    out = a.out
    os.makedirs(out, exist_ok=True)
    for icon in ("icon-512.png", "icon-57.png"):
        shutil.copy(os.path.join(HERE, icon), os.path.join(out, icon))

    # ---- Android ----------------------------------------------------------
    if a.apk and os.path.exists(a.apk):
        name = "xsteer.apk"
        shutil.copy(a.apk, os.path.join(out, name))
        blob = open(a.apk, "rb").read()
        url = "%s/%s" % (base, name)
        if a.apk_signed == "yes":
            sign_title = "Подпись"
            sign_note = ("Сборка подписана ключом проекта: новая версия ставится поверх прежней, "
                         "настройка и разрешение на туннель сохраняются.")
        else:
            sign_title = "Поверх прежней не встанет"
            sign_note = ("Подпись у этой сборки временная, и у каждой сборки она своя. "
                         "Чтобы поставить эту версию, сначала удалите прежнюю — вместе с ней "
                         "удалится и сохранённая настройка.")
        android = fill(read("block-android.html.in"), {
            "APK": name,
            "APKNAME": name,
            "APKSIZE": human(len(blob)),
            "APKSHA256": hashlib.sha256(blob).hexdigest(),
            "APKQR": qr_svg(url),
            "VERSION": a.apk_version or "—",
            "BUILT": a.apk_built or "—",
            "SHA": a.apk_sha or "—",
            "SIGNNOTE_TITLE": sign_title,
            "SIGNNOTE": sign_note,
        }, "block-android")
    else:
        android = read("block-android-none.html")

    # ---- iOS --------------------------------------------------------------
    if a.ipa and os.path.exists(a.ipa):
        name = "Xsteer.ipa"
        shutil.copy(a.ipa, os.path.join(out, name))
        ver = a.ipa_version or "1"
        manifest = fill(read("manifest.plist.in"), {
            "IPA": "%s/%s" % (base, name),
            "ICON57": "%s/icon-57.png" % base,
            "ICON512": "%s/icon-512.png" % base,
            "VERSION": ver,
        }, "manifest.plist")
        bad = leftovers(manifest)
        if bad:
            sys.exit("в манифесте остались незакрытые метки: %s" % bad)
        with open(os.path.join(out, "manifest.plist"), "w", encoding="utf-8") as f:
            f.write(manifest)
        ios = fill(read("block-ios.html.in"), {
            "MANIFEST": "%s/manifest.plist" % base,
            "IPAHREF": name,
            "IPANAME": name,
            "IOSVERSION": ver,
            "IOSBUILT": a.ipa_built or "—",
            "IOSSHA": a.ipa_sha or "—",
        }, "block-ios")
    else:
        ios = read("block-ios-none.html")

    # ---- страница целиком --------------------------------------------------
    page = fill(read("index.html.in"), {
        "ANDROID": android,
        "IOS": ios,
        "RELEASES": "%s/releases" % a.repo.rstrip("/"),
        "INSTALLSH": "%s/raw/main/server/xs-install.sh" % a.repo.rstrip("/"),
        "REPO": a.repo,
        "BUILT": a.built or "—",
    }, "index.html")

    bad = leftovers(page)
    if bad:
        sys.exit("в странице остались незакрытые метки: %s" % bad)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)

    for f in sorted(os.listdir(out)):
        print("%10d  %s" % (os.path.getsize(os.path.join(out, f)), f))


if __name__ == "__main__":
    main()

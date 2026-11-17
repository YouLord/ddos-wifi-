"""
wifi_audit.utils — общие вспомогательные функции:
ANSI-цвета, ASCII-баннер, таблицы, запуск команд, определение производителя по MAC.
"""
from __future__ import annotations

import os
import subprocess
import sys

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

if IS_WINDOWS and sys.stdout.isatty():
    os.system("")  # включает поддержку ANSI-кодов в консоли Windows

_COLOR = sys.stdout.isatty()


# ---------------------------------------------------------------- цвета ----
def c(code: str, text: object) -> str:
    text = str(text)
    return f"{code}{text}\033[0m" if _COLOR else text


def bold(t):    return c("\033[1m", t)
def red(t):     return c("\033[1;31m", t)
def green(t):   return c("\033[1;32m", t)
def yellow(t):  return c("\033[1;33m", t)
def blue(t):    return c("\033[1;34m", t)
def magenta(t): return c("\033[1;35m", t)
def cyan(t):    return c("\033[1;36m", t)
def gray(t):    return c("\033[90m", t)


def ok(t):   return green(f"[+] {t}")
def warn(t): return yellow(f"[!] {t}")
def err(t):  return red(f"[-] {t}")
def info(t): return blue(f"[*] {t}")


# ---------------------------------------------------------------- баннер ----
_LETTERS = {
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██╗", "███████║", "╚══════╝"],
    "W": ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "F": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
}

BANNER = "\n".join(
    " ".join(_LETTERS[ch][i] for ch in "DDOS WIFI" if ch != " ")
    for i in range(6)
)


def print_banner(version: str = "") -> None:
    print(cyan(BANNER))
    if version:
        print(gray(f"  wifi-audit v{version} — аудит собственной сети: "
                   "открытые порты · устройства · Wi-Fi · отчёт по безопасности"))
    print()


def header(title: str, width: int = 64) -> None:
    print()
    print(bold(cyan(f"═" * 2 + f" {title} " + "═" * max(0, width - len(title) - 4))))
    print()


# ---------------------------------------------------------------- таблицы ----
import re as _re

_ANSI_RE = _re.compile(r"\033\[[0-9;]*m")


def _plain_len(v: str) -> int:
    return len(_ANSI_RE.sub("", v))


def render_table(headers, rows) -> str:
    """Простая ASCII-таблица с выравниванием по ширине колонок (без ANSI)."""
    headers = [str(h) for h in headers]
    n = len(headers)
    rows = [list(row) for row in rows]
    rows = [([("" if v is None else str(v)) for v in r] + [""] * n)[:n] for r in rows]
    widths = [max(len(h), *(_plain_len(v) for v in [h])) for h in headers]
    for r in rows:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], _plain_len(v))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, "| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |", sep]
    for r in rows:
        cells = []
        for v, w in zip(r, widths):
            pad = " " * max(0, w - _plain_len(v))
            cells.append(v + pad)
        lines.append("| " + " | ".join(cells) + " |")
    lines.append(sep)
    return "\n".join(lines)


# ---------------------------------------------------------------- команды ----
def run_cmd(cmd, timeout: int = 10):
    """Запускает внешнюю команду, возвращает (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"не найдена утилита: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "таймаут выполнения команды"
    except OSError as e:
        return 126, "", str(e)


# ------------------------------------------------- производитель по MAC ----
# Небольшая встроенная база распространённых префиксов (OUI).
# Полная база IEEE занимает много места — здесь только часто встречающиеся.
OUI = {
    # виртуальные машины
    "00:05:69": "VMware", "00:0c:29": "VMware", "00:50:56": "VMware",
    "00:15:5d": "Microsoft (Hyper-V)",
    # телефоны/компьютеры
    "00:03:93": "Apple", "00:10:fa": "Apple", "ac:de:48": "Apple",
    "f0:18:98": "Apple", "d0:03:4b": "Apple", "a4:83:e7": "Apple",
    "00:16:32": "Samsung",
    "00:13:a9": "Sony", "30:f9:ed": "Sony",
    "00:14:22": "Dell", "00:1f:29": "HP",
    "00:21:86": "Lenovo", "54:ee:75": "Lenovo",
    # роутеры и сетевое оборудование
    "00:09:5b": "NETGEAR", "a0:40:a0": "NETGEAR", "9c:3d:cf": "NETGEAR",
    "00:1a:a1": "Cisco", "00:1b:0d": "Cisco",
    "14:cc:20": "TP-Link", "a4:2b:b0": "TP-Link",
    "00:05:5d": "D-Link",
    "50:2b:73": "Tenda", "c8:3a:35": "Tenda",
    "00:0c:42": "MikroTik", "48:8f:5a": "MikroTik", "dc:2c:6e": "MikroTik",
    "64:d1:54": "MikroTik",
    "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "ac:9e:17": "ASUS", "40:b0:76": "ASUS",
    "00:11:32": "Synology",
    # IoT и умный дом
    "5c:cf:7f": "Espressif (IoT)", "30:ae:a4": "Espressif (IoT)",
    "24:0a:c4": "Espressif (IoT)", "68:c6:3a": "Espressif (IoT)",
    "00:17:88": "Philips (Hue)",
    "40:b4:cd": "Amazon", "74:c2:46": "Amazon", "fc:65:de": "Amazon",
    "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi", "f0:b4:29": "Xiaomi",
    # прочее
    "00:e0:4c": "Realtek",
    "00:1a:11": "Google", "f4:f5:e8": "Google", "f8:8f:bc": "Google",
}


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":").replace(".", ":")
    raw = mac.replace(":", "")
    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return mac


def vendor_for_mac(mac: str):
    if not mac:
        return None
    return OUI.get(normalize_mac(mac)[:8])


# ------------------------------------------------------- подтверждение ----
def confirm_authorization(skip: bool = False, action: str = "сканирование сети") -> bool:
    """Просит подтвердить право на аудит сети (легальное использование)."""
    print()
    print(yellow("  ⚠️  ВНИМАНИЕ"))
    print("  Этот инструмент проверяет безопасность СВОЕЙ сети.")
    print(f"  {bold(action.capitalize())} разрешено только в собственной сети")
    print("  или при явном разрешении её владельца. Несанкционированный")
    print("  доступ к чужим сетям и устройствам — незаконен.")
    if skip:
        print(gray("  Подтверждение пропущено (--no-confirm)."))
        print()
        return True
    try:
        ans = input(cyan(f"  Подтверждаете право на {action}? [y/N]: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    print()
    return ans in ("y", "yes", "д", "да")


def safe_input(prompt: str = ""):
    """input(), который не падает на Ctrl+C / закрытом stdin."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return None

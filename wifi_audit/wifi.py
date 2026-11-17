"""
wifi_audit.wifi — информация о текущем Wi-Fi подключении.

Работает через системные утилиты:
  * Windows: netsh wlan show interfaces
  * macOS:   airport -I / ipconfig getsummary / networksetup
  * Linux:   nmcli / iw / wpa_cli / iwconfig

Никаких сторонних зависимостей — только стандартная библиотека Python.
"""
from __future__ import annotations

import os
import re

from .utils import IS_LINUX, IS_MACOS, IS_WINDOWS, run_cmd


def _dbm_to_percent(dbm):
    """Грубое преобразование RSSI (dBm) в проценты качества сигнала."""
    try:
        dbm = int(str(dbm).replace(" dBm", "").strip())
    except (ValueError, AttributeError):
        return None
    if dbm >= 0:
        return None
    return max(1, min(100, round((dbm + 100) * 2)))


def _freq_to_band(freq):
    """Частота (МГц) → диапазон. Возвращает строку или None."""
    try:
        f = int(float(str(freq).split()[0]))
    except (ValueError, AttributeError, IndexError):
        return None
    if f < 3000:
        return "2.4 ГГц"
    if f < 6000:
        return "5 ГГц"
    if f < 7200:
        return "6 ГГц"
    return None


def _merge(info, new):
    for k, v in new.items():
        if v not in (None, "") and not info.get(k):
            info[k] = v
    return info


# ================================================================ Windows ====
_KEYMAP = {
    "name": "iface", "имя": "iface",
    "description": "adapter", "описание": "adapter",
    "physical address": "mac", "физический адрес": "mac",
    "state": "state", "состояние": "state",
    "ssid": "ssid",
    "bssid": "bssid",
    "radio type": "radio", "тип радиосигнала": "radio",
    "authentication": "auth", "проверка подлинности": "auth",
    "аутентификация": "auth",
    "cipher": "cipher", "шифрование": "cipher",
    "signal": "signal", "сигнал": "signal", "уровень сигнала": "signal",
    "channel": "channel", "канал": "channel",
    "transmit rate": "rate", "скорость передачи": "rate",
}


def _wifi_windows():
    rc, out, err = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=15)
    info = {"os": "Windows", "connected": False}
    if rc != 0:
        info["error"] = (err or "").strip() or "netsh вернул ошибку"
        return info
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        field = _KEYMAP.get(k.strip().lower())
        v = v.strip()
        if field and v:
            info.setdefault(field, v)
    state = (info.get("state") or "").lower()
    if state in ("connected", "подключено", "соединение установлено"):
        info["connected"] = True
    return info


# ================================================================= macOS ====
def _wifi_macos():
    info = {"os": "macOS", "connected": False}
    iface = None
    rc, out, _ = run_cmd(["networksetup", "-listallhardwareports"], timeout=10)
    if rc == 0:
        m = re.search(r"Hardware Port: Wi-Fi\s*\nDevice:\s*(\S+)", out)
        if m:
            iface = m.group(1)
    info["iface"] = iface

    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")
    parsed = {}
    if os.path.exists(airport):
        rc, out, _ = run_cmd([airport, "-I"], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed[k.strip()] = v.strip()
            if parsed.get("SSID"):
                info["connected"] = True
                info["ssid"] = parsed["SSID"]
                info["bssid"] = parsed.get("BSSID")
                ch = (parsed.get("channel") or "").split(",")[0]
                if ch.isdigit():
                    info["channel"] = ch
                rssi = parsed.get("agrCtlRSSI")
                if rssi:
                    info["signal"] = f"{rssi} dBm"
                    pct = _dbm_to_percent(rssi)
                    if pct:
                        info["signal_percent"] = f"{pct}%"

    if not info.get("connected") and iface:
        # новые версии macOS: airport удалён, используем ipconfig
        rc, out, _ = run_cmd(["ipconfig", "getsummary", iface], timeout=10)
        if rc == 0:
            fields = {}
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fields[k.strip().lower()] = v.strip()
            if fields.get("ssid"):
                info["connected"] = True
                info["ssid"] = fields["ssid"]
                info["bssid"] = fields.get("bssid")
                rssi = (fields.get("rssi") or "").split()[0] if fields.get("rssi") else None
                if rssi:
                    info["signal"] = f"{rssi} dBm"
                    pct = _dbm_to_percent(rssi)
                    if pct:
                        info["signal_percent"] = f"{pct}%"
                ch = fields.get("channel", "")
                m = re.match(r"\{?\s*(\d+)", ch)
                if m:
                    info["channel"] = m.group(1)
            sec = fields.get("security mode") or fields.get("security")
            if sec:
                info["auth"] = sec

    if not info.get("connected") and iface:
        rc, out, _ = run_cmd(["networksetup", "-getairportnetwork", iface], timeout=10)
        if rc == 0 and "Wi-Fi Network" in out:
            info["connected"] = True
            info["ssid"] = out.split(":", 1)[1].strip()
    return info


# ================================================================== Linux ====
def wifi_iface():
    """Имя Wi-Fi интерфейса, если он есть (Linux/macOS), иначе None."""
    if IS_LINUX:
        try:
            with open("/proc/net/wireless", encoding="utf-8", errors="replace") as f:
                data = f.read()
            for line in data.splitlines():
                m = re.match(r"\s*([a-zA-Z0-9]+):\s", line)
                if m:
                    return m.group(1)
        except OSError:
            pass
        rc, out, _ = run_cmd(["iw", "dev"])
        if rc == 0:
            m = re.search(r"Interface\s+(\S+)", out)
            if m:
                return m.group(1)
        return None
    if IS_MACOS:
        rc, out, _ = run_cmd(["networksetup", "-listallhardwareports"], timeout=10)
        if rc == 0:
            m = re.search(r"Hardware Port: Wi-Fi\s*\nDevice:\s*(\S+)", out)
            if m:
                return m.group(1)
        return None
    return None


def _wifi_linux():
    info = {"os": "Linux", "connected": False}
    iface = wifi_iface()
    info["iface"] = iface
    if not iface:
        info["error"] = ("Wi-Fi интерфейс не найден — беспроводного адаптера нет, "
                         "или не установлены драйверы")
        return info

    # --- NetworkManager (наиболее частый вариант на десктопах) ---
    rc, out, _ = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE",
                          "device", "status"])
    nm_connected = False
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[0] == iface and parts[1] == "wifi" \
                    and "connected" in parts[2].lower():
                nm_connected = True
                info["connected"] = True
                break

    if nm_connected:
        rc, out, _ = run_cmd(
            ["nmcli", "-f", "IN-USE,SSID,BSSID,MODE,CHAN,SIGNAL,SECURITY",
             "device", "wifi", "list"])
        if rc == 0:
            for line in out.splitlines()[1:]:
                line = line.rstrip()
                if not line.strip() or not line.lstrip().startswith("*"):
                    continue
                m = re.match(
                    r"^\*\s+(.*?)\s+([0-9A-Fa-f:]{17})\s+(\S+)\s+(\d+)\s+(\d+)\s*(.*)$",
                    line)
                if m:
                    _merge(info, {
                        "ssid": m.group(2) or None,
                        "bssid": m.group(3),
                        "channel": m.group(4),
                        "signal": f"{m.group(5)}%",
                        "auth": m.group(6) or None,
                    })
                    break

    # --- iw ---
    rc, out, _ = run_cmd(["iw", "dev", iface, "link"])
    if rc == 0 and "Connected" in out:
        info["connected"] = True
        m = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", out)
        if m:
            info.setdefault("bssid", m.group(1))
        m = re.search(r"^\s*SSID:\s*(.+)$", out, re.M)
        if m:
            info.setdefault("ssid", m.group(1).strip())
        m = re.search(r"signal:\s*(-?\d+)\s*dBm", out)
        if m:
            info.setdefault("signal", f"{m.group(1)} dBm")
            pct = _dbm_to_percent(m.group(1))
            if pct:
                info.setdefault("signal_percent", f"{pct}%")
        m = re.search(r"freq:\s*(\d+)", out)
        if m:
            info.setdefault("freq_mhz", m.group(1))
            band = _freq_to_band(m.group(1))
            if band:
                info.setdefault("band", band)

    # --- wpa_supplicant (тип шифрования) ---
    rc, out, _ = run_cmd(["wpa_cli", "-i", iface, "status"])
    if rc == 0:
        fields = dict(
            line.split("=", 1) for line in out.splitlines() if "=" in line
        )
        if fields.get("wpa_state") == "COMPLETED":
            info["connected"] = True
            _merge(info, {
                "ssid": fields.get("ssid"),
                "bssid": fields.get("bssid"),
                "auth": fields.get("key_mgmt"),
                "freq_mhz": fields.get("freq"),
            })

    # --- iwconfig как последний вариант ---
    rc, out, _ = run_cmd(["iwconfig", iface])
    if rc == 0:
        m = re.search(r'ESSID:"([^"]*)"', out)
        if m and m.group(1):
            info["connected"] = True
            info.setdefault("ssid", m.group(1))
        m = re.search(r"Access Point:\s*([0-9A-Fa-f:]{17})", out)
        if m:
            info.setdefault("bssid", m.group(1))
        m = re.search(r"Frequency[:=]\s*([\d.]+)\s*GHz", out)
        if m:
            mhz = str(int(float(m.group(1)) * 1000))
            info.setdefault("freq_mhz", mhz)
            band = _freq_to_band(mhz)
            if band:
                info.setdefault("band", band)
        m = re.search(r"Signal level[:=]\s*(-?\d+)\s*dBm", out)
        if m:
            info.setdefault("signal", f"{m.group(1)} dBm")
            pct = _dbm_to_percent(m.group(1))
            if pct:
                info.setdefault("signal_percent", f"{pct}%")
        if "Encryption key:on" in out:
            info.setdefault("auth", "включено шифрование")

    band = info.get("band") or _freq_to_band(info.get("freq_mhz"))
    if band:
        info["band"] = band
    return info


# =============================================================== публичное ====
def get_wifi_info() -> dict:
    """Возвращает словарь с информацией о текущем Wi-Fi подключении."""
    try:
        if IS_WINDOWS:
            return _wifi_windows()
        if IS_MACOS:
            return _wifi_macos()
        return _wifi_linux()
    except Exception as e:  # noqa: BLE001 — утилита не должна падать
        return {"connected": False, "error": f"неожиданная ошибка: {e}"}


def protection_label(info: dict) -> str:
    """Короткая человекочитаемая строка защиты сети."""
    auth = info.get("auth") or ""
    cipher = info.get("cipher") or ""
    parts = [p for p in (auth, cipher) if p]
    return " ".join(parts) if parts else "—"

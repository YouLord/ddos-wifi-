"""
wifi_audit.clients — «кто подключён к моей сети/Wi-Fi».

Основа — ARP-таблица + активные проверки (ping/TCP). Каждому хосту
присваивается роль: это устройство / роутер / клиент Wi-Fi / клиент сети.
"""
from __future__ import annotations

import json

from . import discovery, wifi as wifi_mod
from .utils import gray, header, info, render_table, warn, yellow


def collect_clients(cidr=None, use_ping=True, verbose=False):
    """Собирает список клиентов сети с ролями и метаданными."""
    wifi_info = wifi_mod.get_wifi_info() if verbose else {}
    net = discovery.discover_devices(cidr=cidr, use_ping=use_ping, verbose=verbose)
    local_ip = net["local_ip"]
    gateway = net["gateway"]
    wifi_iface = wifi_mod.wifi_iface()

    devices = []
    for d in net["devices"]:
        d = dict(d)
        if d["ip"] == local_ip:
            d["role"] = "это устройство"
        elif d["ip"] == gateway:
            d["role"] = "роутер (шлюз)"
        else:
            iface = d.get("iface")
            if iface and wifi_iface and iface == wifi_iface:
                d["role"] = "Wi-Fi клиент"
            elif iface:
                d["role"] = "проводной клиент?"
            else:
                d["role"] = "клиент сети"
        devices.append(d)

    return {
        "cidr": net["cidr"],
        "local_ip": local_ip,
        "gateway": gateway,
        "wifi": {
            "connected": wifi_info.get("connected", False),
            "ssid": wifi_info.get("ssid"),
            "iface": wifi_iface,
        },
        "devices": devices,
    }


def show_clients(cidr=None, use_ping=True, as_json=False, no_confirm=False):
    from .utils import confirm_authorization

    if not as_json and not no_confirm:
        if not confirm_authorization(action="просмотр устройств в вашей сети"):
            print(warn("Отмена."))
            return 1

    if not as_json:
        print(info("Определяю сеть и собираю список клиентов..."))
    data = collect_clients(cidr=cidr, use_ping=use_ping, verbose=not as_json)

    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    wifi = data["wifi"]
    header("Кто подключён к сети")
    if wifi.get("connected"):
        ssid = f" · SSID: {wifi['ssid']}" if wifi.get("ssid") else ""
        print(gray(f"Wi-Fi подключён{ssid}"))
    print(gray(f"Сеть: {data['cidr']} · шлюз: {data['gateway'] or 'не определён'}"))
    print()
    rows = []
    for d in data["devices"]:
        rows.append([
            d["ip"],
            d["mac"] or "—",
            d["vendor"] or "—",
            (d["hostname"] or "—")[:34],
            d["role"],
        ])
    print(render_table(
        ["IP-адрес", "MAC", "Производитель", "Имя хоста", "Роль"], rows))
    total = len(data["devices"])
    others = sum(1 for d in data["devices"] if d["role"] not in ("это устройство", "роутер (шлюз)"))
    print()
    print(f"Всего устройств: {total} (кроме вас и роутера: {others})")
    print()
    print(yellow("Как это читать:"))
    print("  • Список строится по ARP-таблице и ответам на ping/TCP —")
    print("    видны устройства, активные прямо сейчас или недавно.")
    print("  • Wi-Fi-клиент и проводной клиент различаются не на всех")
    print("    системах. Незнакомое устройство = повод сменить пароль Wi-Fi.")
    print("  • Для точного списка Wi-Fi-клиентов смотрите также панель")
    print("    управления вашего роутера («Список клиентов DHCP/WLAN»).")
    return 0

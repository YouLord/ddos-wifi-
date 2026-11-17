"""
wifi_audit.cli — командный интерфейс и интерактивное меню.

Команды:
  wifi       — информация о текущем Wi-Fi подключении
  devices    — найти устройства в локальной сети
  clients    — кто подключён к моей сети/Wi-Fi
  ports      — сканировать открытые TCP-порты хоста
  report     — отчёт по безопасности сети (оценка + рекомендации)
  network    — параметры локальной сети
  ddos-info  — что такое DDoS и как защититься
  menu       — интерактивное меню
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from . import clients as clients_mod
from . import ddos_info, discovery, ports as ports_mod, wifi as wifi_mod
from .utils import (bold, cyan, err, gray, green, header, info, ok,
                    print_banner, render_table, safe_input, warn, yellow)

# ------------------------------------------------------------------ вывод ----
def _wifi_card(info_dict):
    from .utils import bold, magenta

    rows = []
    def add(k, v):
        if v not in (None, ""):
            rows.append([k, str(v)])

    add("Состояние", green("подключено") if info_dict.get("connected") else yellow("не подключён"))
    add("SSID", info_dict.get("ssid"))
    add("BSSID (роутер)", info_dict.get("bssid"))
    ch = info_dict.get("channel")
    if ch:
        band = info_dict.get("band")
        add("Канал", f"{ch}" + (f" ({band})" if band else ""))
    elif info_dict.get("freq_mhz"):
        add("Частота", f"{info_dict['freq_mhz']} МГц")
    add("Сигнал", " · ".join(x for x in (info_dict.get("signal"),
                                         info_dict.get("signal_percent")) if x))
    add("Защита", wifi_mod.protection_label(info_dict))
    add("Радио", info_dict.get("radio"))
    add("Скорость", info_dict.get("rate"))
    add("Интерфейс", info_dict.get("iface"))
    add("Адаптер", info_dict.get("adapter"))
    add("MAC", info_dict.get("mac"))
    print(render_table(["Параметр", "Значение"], rows))


# --------------------------------------------------------------- команды ----
def cmd_wifi(args):
    wifi_info = wifi_mod.get_wifi_info()
    if args.json:
        print(json.dumps(wifi_info, ensure_ascii=False, indent=2, default=str))
        return 0
    header("Wi-Fi подключение")
    _wifi_card(wifi_info)
    if not wifi_info.get("connected"):
        print()
        if wifi_info.get("error"):
            print(gray(f"Причина: {wifi_info['error']}"))
        from .utils import IS_LINUX, IS_MACOS, IS_WINDOWS
        if IS_WINDOWS:
            print(gray("Проверьте, что Wi-Fi включён: netsh wlan show interfaces"))
        elif IS_MACOS:
            print(gray("Проверьте подключение в «Настройки → Wi-Fi». "
                       "На macOS 14+ системе нужны разрешения на доступ к SSID."))
        else:
            print(gray("Проверьте адаптер: nmcli device status / iw dev"))
    return 0


def cmd_devices(args):
    from .utils import confirm_authorization

    if not args.json and not args.no_confirm:
        if not confirm_authorization(action="сканирование локальной сети"):
            print(warn("Отмена."))
            return 1
    try:
        data = discovery.discover_devices(
            cidr=args.cidr, use_ping=not args.no_ping, verbose=not args.json)
    except RuntimeError as e:
        print(err(str(e)))
        return 1

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    header("Устройства в локальной сети")
    print(gray(f"Сеть: {data['cidr']} · шлюз: {data['gateway'] or 'не определён'} · "
               f"ваш IP: {data['local_ip']}"))
    print()
    rows = []
    for d in data["devices"]:
        rows.append([
            d["ip"],
            d["mac"] or "—",
            d["vendor"] or "—",
            (d["hostname"] or "—")[:34],
            d["source"],
        ])
    if rows:
        print(render_table(["IP-адрес", "MAC", "Производитель", "Имя хоста", "Найден"], rows))
        print()
        print(f"Найдено устройств: {green(len(rows))}")
    else:
        print(warn("Устройств не найдено — проверьте, что вы в одной сети"))
    print()
    print(gray("Видны устройства, ответившие на ping/TCP или попавшие в ARP."))
    print(gray("Тихие хосты с файрволом можно не увидеть — это нормально."))
    return 0


def cmd_clients(args):
    return clients_mod.show_clients(
        cidr=args.cidr, use_ping=not args.no_ping,
        as_json=args.json, no_confirm=args.no_confirm) or 0


def cmd_ports(args):
    from .utils import confirm_authorization

    try:
        ports_list = ports_mod.parse_ports(args.ports)
    except ValueError as e:
        print(err(f"{e}. Примеры: -p top | -p 22,80,443 | -p 1-1024"))
        return 2

    if not args.json and not args.no_confirm:
        if not confirm_authorization(action=f"сканирование портов {args.host}"):
            print(warn("Отмена."))
            return 1

    print(info(f"Сканирую {args.host}: {len(ports_list)} TCP-портов "
               f"(таймаут {args.timeout} с, потоков {args.workers})..."))
    t0 = time.time()
    try:
        ip, results = ports_mod.scan_host(
            args.host, ports_list, workers=args.workers,
            timeout=args.timeout, grab=not args.no_banner)
    except ValueError as e:
        print(err(str(e)))
        return 2
    elapsed = time.time() - t0

    if args.json:
        payload = {"host": args.host, "ip": ip, "elapsed": round(elapsed, 2),
                   "results": results,
                   "risks": [
                       {"port": p, "severity": s, "service": svc, "advice": adv}
                       for s, p, svc, adv in ports_mod.open_risks(results)
                   ]}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    ports_mod.print_results(args.host, ip, results, elapsed)
    return 0


def cmd_report(args):
    try:
        from . import report as report_mod
        payload = report_mod.build_report(
            cidr=args.cidr,
            no_confirm=args.no_confirm,
            as_json=args.json,
            save=True)
    except RuntimeError as e:
        print(err(str(e)))
        return 1
    return 0 if payload is not None else 1


def cmd_network(args):
    try:
        net = discovery.get_network_cidr()
    except Exception as e:  # noqa: BLE001
        net = None
    header("Локальная сеть")
    rows = []
    import platform
    rows.append(["ОС", f"{platform.system()} {platform.release()}"])
    if net:
        cidr, local_ip = net
        rows.append(["Ваш IP-адрес", local_ip])
        rows.append(["Подсеть", cidr])
    else:
        rows.append(["Сеть", yellow("не определена")])
    rows.append(["Шлюз", discovery.get_gateway() or "—"])
    rows.append(["Wi-Fi интерфейс", wifi_mod.wifi_iface() or "—"])
    wifi_info = wifi_mod.get_wifi_info()
    rows.append(["Wi-Fi", green("подключён, SSID: " + str(wifi_info.get("ssid")))
                 if wifi_info.get("connected") else yellow("не подключён")])
    print(render_table(["Параметр", "Значение"], rows))
    return 0


def cmd_ddos_info(args):
    ddos_info.print_info()
    return 0


# ------------------------------------------------------------------ меню ----
MENU_ITEMS = [
    ("1", "Информация о Wi-Fi подключении", "wifi"),
    ("2", "Найти устройства в локальной сети", "devices"),
    ("3", "Кто подключён к моему Wi-Fi / сети", "clients"),
    ("4", "Сканировать открытые порты", "ports"),
    ("5", "Отчёт по безопасности сети", "report"),
    ("6", "Что такое DDoS и как защититься", "ddos-info"),
    ("7", "Параметры локальной сети", "network"),
]


def _run_action(action, args):
    ns = argparse.Namespace(**vars(args))
    ns.json = False
    ns.no_confirm = False
    ns.cidr = None
    if action == "wifi":
        return cmd_wifi(ns)
    if action == "devices":
        ns.no_ping = False
        return cmd_devices(ns)
    if action == "clients":
        ns.no_ping = False
        return cmd_clients(ns)
    if action == "ports":
        default_host = discovery.get_gateway() or "127.0.0.1"
        host = safe_input(cyan(f"Хост для сканирования [{default_host}]: ")).strip()
        if host is None:
            return 0
        spec = safe_input(cyan("Порты [top] (примеры: 22,80,443 или 1-1024): "))
        if spec is None:
            return 0
        ns.host = host or default_host
        ns.ports = spec.strip() or "top"
        ns.timeout = 1.0
        ns.workers = 150
        ns.no_banner = False
        return cmd_ports(ns)
    if action == "report":
        from . import report as report_mod
        report_mod.build_report(no_confirm=False, as_json=False, save=True)
        return 0
    if action == "ddos-info":
        return cmd_ddos_info(ns)
    if action == "network":
        return cmd_network(ns)
    return 0


def interactive_menu():
    args = argparse.Namespace()
    while True:
        print_banner(__version__)
        print(yellow("  Инструмент легального аудита СВОЕЙ Wi-Fi сети.\n"
                     "  Атаковать чужие сети запрещено — здесь только проверка и защита."))
        print()
        for key, label, _ in MENU_ITEMS:
            print(f"  {cyan(bold(key))}. {label}")
        print(f"  {cyan(bold('0'))}. Выход")
        print()
        choice = safe_input(cyan("Выберите пункт: "))
        if choice is None:
            return 0
        choice = choice.strip()
        if choice in ("0", "q", "quit", "exit", "выход", ""):
            return 0
        action = next((a for k, _l, a in MENU_ITEMS if k == choice), None)
        if action is None:
            print(err("Нет такого пункта. Попробуйте ещё раз."))
            continue
        try:
            _run_action(action, args)
        except KeyboardInterrupt:
            print()
            print(gray("Прервано пользователем"))
        except Exception as e:  # noqa: BLE001
            print(err(f"Ошибка: {e}"))
        safe_input("\nНажмите Enter, чтобы продолжить...")


# ----------------------------------------------------------------- парсер ----
def build_parser():
    p = argparse.ArgumentParser(
        prog="wifi-audit",
        description=("Аудит собственной Wi-Fi/локальной сети: открытые порты, "
                     "устройства, «кто подключён», отчёт по безопасности. "
                     "Только для легального использования в своей сети!"),
        epilog=("Примеры:\n"
                "  python -m wifi_audit                 # интерактивное меню\n"
                "  python -m wifi_audit wifi            # инфо о Wi-Fi\n"
                "  python -m wifi_audit ports 192.168.1.1 -p top\n"
                "  python -m wifi_audit ports router.local -p 22,80,443\n"
                "  python -m wifi_audit devices         # устройства в сети\n"
                "  python -m wifi_audit clients         # кто подключён\n"
                "  python -m wifi_audit report          # отчёт безопасности\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version",
                   version=f"wifi-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="команда")

    sp = sub.add_parser("wifi", help="информация о текущем Wi-Fi подключении")
    sp.add_argument("--json", action="store_true", help="вывод в JSON")
    sp.set_defaults(func=cmd_wifi)

    sp = sub.add_parser("devices", help="найти устройства в локальной сети")
    sp.add_argument("--cidr", help="подсеть, напр. 192.168.1.0/24")
    sp.add_argument("--no-ping", action="store_true",
                    help="не опрашивать ping (только ARP и TCP)")
    sp.add_argument("--json", action="store_true", help="вывод в JSON")
    sp.add_argument("--no-confirm", action="store_true",
                    help="не спрашивать подтверждение")
    sp.set_defaults(func=cmd_devices)

    sp = sub.add_parser("clients", help="кто подключён к моей сети/Wi-Fi")
    sp.add_argument("--cidr", help="подсеть, напр. 192.168.1.0/24")
    sp.add_argument("--no-ping", action="store_true")
    sp.add_argument("--json", action="store_true", help="вывод в JSON")
    sp.add_argument("--no-confirm", action="store_true")
    sp.set_defaults(func=cmd_clients)

    sp = sub.add_parser("ports", help="сканировать открытые TCP-порты")
    sp.add_argument("host", help="IP или имя хоста (напр. роутер)")
    sp.add_argument("-p", "--ports", default="top",
                    help="порты: top | 22,80,443 | 1-1024 (по умолчанию top)")
    sp.add_argument("--timeout", type=float, default=1.0,
                    help="таймаут подключения, с (по умолчанию 1.0)")
    sp.add_argument("--workers", type=int, default=150,
                    help="число потоков (по умолчанию 150)")
    sp.add_argument("--no-banner", action="store_true",
                    help="не снимать баннеры служб")
    sp.add_argument("--json", action="store_true", help="вывод в JSON")
    sp.add_argument("--no-confirm", action="store_true")
    sp.set_defaults(func=cmd_ports)

    sp = sub.add_parser("report", help="отчёт по безопасности сети")
    sp.add_argument("--cidr", help="подсеть, напр. 192.168.1.0/24")
    sp.add_argument("--json", action="store_true", help="вывод в JSON")
    sp.add_argument("--no-confirm", action="store_true")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("network", help="параметры локальной сети")
    sp.set_defaults(func=cmd_network)

    sp = sub.add_parser("ddos-info", help="что такое DDoS и как защититься")
    sp.set_defaults(func=cmd_ddos_info)

    sp = sub.add_parser("menu", help="интерактивное меню")
    sp.set_defaults(func=lambda a: interactive_menu())

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None or getattr(args, "func", None) is None:
        return interactive_menu()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        print(gray("Прервано пользователем"))
        return 130

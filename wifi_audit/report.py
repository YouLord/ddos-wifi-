"""
wifi_audit.report — отчёт по безопасности сети.

Что проверяется:
  * шифрование текущей Wi-Fi сети (WEP/WPA/WPA2/WPA3/Open);
  * открытые порты шлюза (роутера) — с оценкой риска каждого;
  * количество устройств в сети;
  * рекомендации по защите, итоговая оценка 0-100.

Отчёт сохраняется в каталог reports/ (TXT + JSON).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import time

from . import discovery, ports as ports_mod, wifi as wifi_mod
from .utils import (bold, confirm_authorization, gray, green, header, info,
                    ok, red, render_table, warn, yellow)

SEV_LABEL = {"critical": "КРИТИЧНО", "high": "Высокий", "medium": "Средний",
             "info": "Замечание", "ok": "Норма"}
SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "info": 2, "ok": 0}

BASE_RECOMMENDATIONS = [
    "Смените пароль администратора роутера на длинный и уникальный",
    "Включите шифрование WPA2 (AES) или WPA3, отключите WPS",
    "Отключите удалённый доступ к админке роутера из интернета (WAN)",
    "Обновите прошивку роутера до последней версии",
    "Отключите Telnet и UPnP, если не пользуетесь ими",
    "Создайте гостевую сеть для гостей и IoT-устройств (камеры, лампочки)",
    "Уберите лишние пробросы портов; для доступа внутрь сети используйте VPN",
    "Регулярно проверяйте список подключённых устройств (команда clients)",
    "Убедитесь, что включён встроенный файрвол роутера (SPI)",
]


def _wifi_risk(info_dict):
    """Оценка защиты Wi-Fi: (severity, заголовок, рекомендация|None)."""
    if not info_dict.get("connected"):
        return ("info", "Wi-Fi не подключён — шифрование сети не проверено",
                "Подключитесь к Wi-Fi и запустите отчёт снова")
    auth = (info_dict.get("auth") or "").upper()
    cipher = (info_dict.get("cipher") or "").upper()
    if "WEP" in auth:
        return ("critical", f"Шифрование WEP ({auth or '—'})",
                "WEP взламывается за минуты. Переключите роутер на WPA2/WPA3")
    if auth and any(x in auth for x in ("OPEN", "NONE", "ОТКРЫТАЯ")):
        return ("critical", "Сеть работает без шифрования (Open)",
                "Любой сосед может подключаться и читать трафик. Включите WPA2/WPA3")
    if "WPA3" in auth:
        return ("ok", f"WPA3 включён ({auth or '—'})", None)
    if "WPA2" in auth:
        if "TKIP" in cipher:
            return ("medium", f"WPA2 со старым шифром TKIP ({auth or '—'})",
                    "Выберите AES/CCMP в настройках роутера")
        return ("ok", f"WPA2 включён ({auth or '—'})", None)
    if "WPA" in auth:
        return ("medium", f"Устаревший WPA ({auth or '—'})",
                "Переключите роутер на WPA2 (AES) или WPA3")
    if info_dict.get("auth"):
        return ("info", f"Тип защиты: {info_dict['auth']}", None)
    return ("info", "Тип защиты Wi-Fi определить не удалось", None)


def build_report(cidr=None, no_confirm=False, as_json=False, save=True):
    """Собирает отчёт, печатает его (или возвращает JSON), сохраняет в reports/."""
    if not as_json and not no_confirm:
        if not confirm_authorization(action="аудит вашей сети"):
            print(warn("Отмена."))
            return None

    started = time.time()
    if not as_json:
        print(info("Шаг 1/3: собираю информацию о сети и Wi-Fi..."))

    wifi_info = wifi_mod.get_wifi_info()
    net = discovery.discover_devices(cidr=cidr, use_ping=True, verbose=not as_json)

    gateway = net["gateway"]

    gateway_results = []
    if gateway:
        if not as_json:
            print(info(f"Шаг 2/3: сканирую порты роутера ({gateway})..."))
        try:
            _, gateway_results = ports_mod.scan_host(
                gateway, ports_mod.parse_ports(None), workers=150, timeout=0.8)
        except (ValueError, OSError) as e:
            gateway_results = []
    else:
        if not as_json:
            print(warn("Шлюз не определён — порты роутера не проверены"))

    if not as_json:
        print(info("Шаг 3/3: формирую риски и рекомендации..."))

    # ---- сбор рисков ----
    risks = []  # (severity, title, advice)
    wsev, wtitle, wadv = _wifi_risk(wifi_info)
    risks.append((wsev, wtitle, wadv))

    for sev, port, svc, advice in ports_mod.open_risks(gateway_results):
        risks.append((sev, f"Роутер {gateway}: открыт порт {port} ({svc or '—'})", advice))

    n_devices = len(net["devices"])
    n_other = sum(1 for d in net["devices"]
                  if d["ip"] not in (net["local_ip"], gateway))
    if n_other > 15:
        risks.append(("info", f"В сети {n_other} сторонних устройств",
                      "Проверьте список (команда clients) — нет ли незнакомых"))
    if not gateway:
        risks.append(("info", "Шлюз не определён", "Проверьте настройки сети"))

    # ---- оценка ----
    score = 100 - min(95, sum(SEV_WEIGHT.get(sev, 2) for sev, _, _ in risks))
    score = max(5, score)

    def verdict(s):
        if s >= 85:
            return "отличная защищённость"
        if s >= 70:
            return "хорошо, но есть что улучшить"
        if s >= 50:
            return "средняя — примите меры"
        return "низкая — срочно примите меры"

    payload = {
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "network": {"cidr": net["cidr"], "local_ip": net["local_ip"],
                    "gateway": gateway},
        "wifi": {k: v for k, v in wifi_info.items() if k != "raw"},
        "devices_total": n_devices,
        "gateway_scan": gateway_results,
        "risks": [{"severity": s, "title": t, "advice": a} for s, t, a in risks],
        "score": score,
        "verdict": verdict(score),
        "recommendations": BASE_RECOMMENDATIONS,
    }

    saved = None
    if save:
        payload["recommendations"] += _dynamic_recommendations(risks)
        saved = _save_reports(payload)

    if as_json:
        if saved:
            payload["saved_to"] = saved
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_report(payload, gateway_results, elapsed=time.time() - started)
        if saved:
            print()
            print(ok(f"Отчёт сохранён: {saved[0]} и {saved[1]}"))
    return payload


def _dynamic_recommendations(risks):
    out = []
    for sev, title, advice in risks:
        if advice and sev in ("critical", "high", "medium"):
            out.append(advice)
    return out


def _save_reports(payload):
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = os.path.join(reports_dir, f"report_{stamp}.txt")
    json_path = os.path.join(reports_dir, f"report_{stamp}.json")

    lines = []
    lines.append("ОТЧЁТ ПО БЕЗОПАСНОСТИ СЕТИ — wifi-audit")
    lines.append(f"Сформирован: {payload['generated']}")
    lines.append(f"Сеть: {payload['network']['cidr']}  "
                 f"Локальный IP: {payload['network']['local_ip']}  "
                 f"Шлюз: {payload['network']['gateway'] or '—'}")
    lines.append("")
    lines.append(f"Wi-Fi: {'подключён' if payload['wifi'].get('connected') else 'не подключён'}"
                 + (f", SSID: {payload['wifi']['ssid']}" if payload['wifi'].get("ssid") else ""))
    lines.append(f"Защита Wi-Fi: {payload['wifi'].get('auth') or '—'} "
                 f"{payload['wifi'].get('cipher') or ''}".rstrip())
    lines.append(f"Устройств в сети: {payload['devices_total']}")
    lines.append("")
    lines.append("РИСКИ:")
    for r in payload["risks"]:
        lines.append(f"  [{SEV_LABEL.get(r['severity'], r['severity'])}] {r['title']}")
        if r.get("advice"):
            lines.append(f"        → {r['advice']}")
    lines.append("")
    lines.append(f"ОЦЕНКА: {payload['score']}/100 — {payload['verdict']}")
    lines.append("")
    lines.append("РЕКОМЕНДАЦИИ:")
    for rec in payload["recommendations"]:
        lines.append(f"  • {rec}")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return txt_path, json_path


def _print_report(payload, gateway_results, elapsed):
    net = payload["network"]
    wifi = payload["wifi"]

    header("Отчёт по безопасности сети")
    print(gray(f"Сеть: {net['cidr']} · ваш IP: {net['local_ip']} · "
               f"шлюз: {net['gateway'] or '—'}"))
    print(gray(f"Устройств в сети: {payload['devices_total']}"))

    print()
    if wifi.get("connected"):
        from .utils import cyan
        print(green(f"  Wi-Fi: подключён"
                    + (f" · SSID: {wifi.get('ssid')}" if wifi.get("ssid") else "")
                    + (f" · канал {wifi.get('channel')}" if wifi.get("channel") else "")))
        print(f"  Защита: {bold(wifi_mod.protection_label(wifi))}")
    else:
        print(yellow("  Wi-Fi: не подключён (защита не проверена)"))
        if wifi.get("error"):
            print(gray(f"  Причина: {wifi['error']}"))

    if gateway_results:
        opened = [r for r in gateway_results if r["state"] == "open"]
        print()
        print(f"  Открытые порты роутера ({payload['network']['gateway']}): "
              + (green(", ".join(str(r['port']) for r in opened)) if opened
                 else gray("не обнаружено")))

    print()
    rows = []
    for r in payload["risks"]:
        sev = r["severity"]
        label = SEV_LABEL.get(sev, sev)
        if sev == "critical":
            label = red(bold(label))
        elif sev == "high":
            label = red(label)
        elif sev == "medium":
            label = yellow(label)
        elif sev == "ok":
            label = green(label)
        else:
            label = gray(label)
        rows.append([label, r["title"], r.get("advice") or "—"])
    print(render_table(["Уровень", "Находка", "Что делать"], rows))

    print()
    score = payload["score"]
    if score >= 85:
        score_s = green(bold(f"{score}/100"))
    elif score >= 70:
        score_s = yellow(bold(f"{score}/100"))
    else:
        score_s = red(bold(f"{score}/100"))
    print(f"  Оценка защищённости: {score_s} — {payload['verdict']}")
    print(f"  (затрачено {elapsed:.1f} c)")

    print()
    print(bold("Рекомендации:"))
    for rec in payload["recommendations"]:
        print(f"  • {rec}")

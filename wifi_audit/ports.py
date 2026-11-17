"""
wifi_audit.ports — TCP-сканер открытых портов.

* TCP connect-сканирование (как у nmap -sT): не требует прав администратора.
* Определяет службу по номеру порта и пытается снять баннер.
* Помечает «опасные» для дома/роутера порты с объяснением, зачем их закрыть.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import gray, green, red, render_table, warn, yellow

# ---- типовые порты для быстрого сканирования ("top") ----
TOP_PORTS = sorted([
    21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143,
    161, 389, 443, 445, 465, 515, 548, 554, 587, 631, 636, 993, 995, 1080,
    1194, 1433, 1521, 1723, 1883, 1900, 3000, 3128, 3306, 3389, 5000, 5060,
    5432, 5555, 5900, 6379, 6667, 7547, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9000, 9090, 9100, 9200, 16992, 2375, 27017,
])

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 81: "HTTP-alt",
    88: "Kerberos", 110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MS RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD-принтер", 548: "AFP", 554: "RTSP",
    587: "SMTP (submission)", 631: "IPP (печать)", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS-прокси", 1194: "OpenVPN",
    1433: "MS SQL", 1521: "Oracle DB", 1723: "PPTP VPN", 1883: "MQTT",
    1900: "UPnP", 2082: "cPanel", 2083: "cPanel SSL", 2375: "Docker API",
    2376: "Docker TLS", 3000: "Node.js/HTTP", 3128: "HTTP-прокси",
    3260: "iSCSI", 3306: "MySQL", 3389: "RDP", 5000: "UPnP/HTTP", 5060: "SIP",
    5432: "PostgreSQL", 5555: "ADB (Android)", 5672: "RabbitMQ", 5900: "VNC",
    5901: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
    6667: "IRC", 7547: "TR-069 (CWMP)", 8000: "HTTP", 8008: "HTTP",
    8009: "Chromecast", 8080: "HTTP-прокси", 8081: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP", 9001: "HTTP-alt",
    9090: "HTTP-alt (Prometheus)", 9100: "Сетевой принтер",
    9200: "Elasticsearch", 16992: "Intel AMT", 27017: "MongoDB",
    49152: "UPnP",
}

# ---- «подозрительные» порты для домашней сети ----
RISKY = {
    21: ("high", "FTP передаёт пароли открытым текстом — используйте SFTP/SSH"),
    23: ("critical", "Telnet — управление без шифрования. Отключите на роутере"),
    25: ("medium", "SMTP: может использоваться для спама, если доступен извне"),
    53: ("medium", "DNS: проверьте, что резолвер не отвечает всему интернету"),
    69: ("medium", "TFTP — передача файлов без аутентификации"),
    80: ("info", "HTTP: часто веб-интерфейс роутера — смените пароль по умолчанию"),
    111: ("medium", "RPCBind: лишняя поверхность атаки, обычно не нужен"),
    139: ("medium", "NetBIOS: устаревший протокол Windows"),
    445: ("high", "SMB: частая цель вирусов (WannaCry). Не открывайте в интернет"),
    1433: ("medium", "MS SQL: база данных должна быть закрыта файрволом"),
    1883: ("medium", "MQTT без TLS: часто остаётся без пароля"),
    1900: ("medium", "UPnP: позволяет программам открывать порты на роутере"),
    2375: ("critical", "Docker API без TLS = полный контроль над хостом"),
    3000: ("info", "Node.js/веб-приложение (нередко отладочное)"),
    3306: ("medium", "MySQL: база данных должна быть закрыта файрволом"),
    3389: ("high", "RDP: постоянная цель брутфорса. Для доступа — VPN"),
    5000: ("info", "UPnP/HTTP-сервис (нередко админка роутера)"),
    5432: ("medium", "PostgreSQL: база данных должна быть закрыта файрволом"),
    5555: ("high", "ADB по сети: отладочный доступ к Android-устройству"),
    5900: ("high", "VNC: часто без шифрования и со слабым паролем"),
    6379: ("high", "Redis по умолчанию работает без пароля"),
    7547: ("medium", "TR-069: известны уязвимости в прошивках роутеров"),
    8080: ("info", "HTTP-прокси или админка устройства"),
    9100: ("info", "Сетевая печать (JetDirect)"),
    16992: ("high", "Intel AMT: удалённое управление, известны уязвимости"),
    2376: ("medium", "Docker TLS API: проверьте сертификаты"),
    27017: ("high", "MongoDB: при открытом доступе случаются утечки данных"),
}

# порты, на которых сервер «молчит» без HTTP-запроса
_HTTP_LIKE = {80, 81, 88, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9001, 9090, 3128}


def parse_ports(spec=None):
    """
    Разбирает описание портов: "22", "20-25", "22,80,443", "1-1024,3306",
    None/''/"top" → типовой набор. Возвращает отсортированный список int.
    """
    if not spec or spec.strip().lower() in ("top", "common", "обычные"):
        return list(TOP_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError(f"неверный диапазон портов: {part!r}") from None
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
                raise ValueError(f"неверный диапазон портов: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"неверный порт: {part!r}") from None
            if not 1 <= p <= 65535:
                raise ValueError(f"порт вне диапазона 1-65535: {p}")
            ports.add(p)
    return sorted(ports)


def resolve_host(host):
    """IP-адрес хоста по имени/строке, либо None."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return infos[0][4][0]
    except OSError:
        return None


def _grab_banner(sock, port):
    data = b""
    try:
        sock.settimeout(0.7)
        try:
            data = sock.recv(256)
        except OSError:
            data = b""
        if not data and port in _HTTP_LIKE:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nUser-Agent: wifi-audit\r\n\r\n")
                data = sock.recv(256)
            except OSError:
                data = b""
        if data:
            text = (data.decode("utf-8", errors="replace")
                    .replace("\r", " ").replace("\n", " ⏎ ").strip())
            return text[:100]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return ""


def _scan_one(host, port, timeout, grab):
    service = SERVICE_NAMES.get(port, "")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"port": port, "service": service, "state": "closed", "banner": ""}
    except (socket.timeout, TimeoutError):
        return {"port": port, "service": service, "state": "filtered", "banner": ""}
    except OSError:
        return {"port": port, "service": service, "state": "filtered", "banner": ""}
    banner = _grab_banner(sock, port) if grab else ""
    return {"port": port, "service": service, "state": "open", "banner": banner}


def scan_host(host, ports, workers=150, timeout=1.0, grab=True):
    """
    Сканирует TCP-порты хоста. Возвращает (ip, results),
    results = [{"port", "service", "state": open|closed|filtered, "banner"}, ...]
    """
    ip = resolve_host(host)
    if ip is None:
        raise ValueError(f"не удалось определить адрес: {host}")
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_scan_one, ip, p, timeout, grab) for p in ports]
        for f in as_completed(futs):
            results.append(f.result())
    results.sort(key=lambda r: r["port"])
    return ip, results


def open_risks(results):
    """Список (severity, port, service, совет) для открытых «опасных» портов."""
    out = []
    for r in results:
        if r["state"] == "open" and r["port"] in RISKY:
            sev, advice = RISKY[r["port"]]
            out.append((sev, r["port"], r["service"], advice))
    return out


def print_results(host, ip, results, elapsed=None):
    """Человекочитаемый вывод результатов сканирования."""
    rows = []
    for r in results:
        if r["state"] == "open":
            state = green("ОТКРЫТ")
        elif r["state"] == "closed":
            state = gray("закрыт")
        else:
            state = yellow("фильтруется")
        rows.append([
            r["port"],
            r["service"] or "—",
            state,
            r["banner"] or "—",
        ])
    open_count = sum(1 for r in results if r["state"] == "open")
    title = f"Порты {host} ({ip})"
    if elapsed is not None:
        title += f" · {len(results)} портов · {elapsed:.1f} с"
    from .utils import header
    header(title)
    if not results:
        print(warn("Не удалось выполнить сканирование"))
        return
    print(render_table(["Порт", "Служба", "Состояние", "Баннер"], rows))
    print()
    print(f"Открыто: {green(open_count)} из {len(results)}")
    risks = open_risks(results)
    if risks:
        print()
        print(warn("Замечания по безопасности:"))
        for sev, port, svc, advice in risks:
            mark = red("⚠") if sev in ("critical", "high") else yellow("⚠")
            print(f"  {mark} порт {port} ({svc or '—'}): {advice}")

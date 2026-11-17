"""
wifi_audit.discovery — обнаружение устройств в локальной сети.

Способы обнаружения (используются вместе, зависит от ОС):
  * ARP-таблица (ip neigh / arp -a) — «горячие» записи о соседях;
  * ping-опрос подсети (параллельный);
  * TCP-проверка типовых портов для хостов, не ответивших на ping.

Всё только для СВОЕЙ сети: код не содержит никакого атакующего функционала.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import (IS_LINUX, IS_MACOS, IS_WINDOWS, gray, info, run_cmd,
                    vendor_for_mac, warn, yellow)

# Порты для TCP-проверки «живости» хоста (если ping не сработал)
_PROBE_PORTS = (22, 80, 443, 445, 8080, 3389)
_MAX_HOSTS = 512


# ------------------------------------------------------------ локальная сеть ----
def get_local_ip():
    """Локальный IP-адрес (маршрут по умолчанию), либо None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _prefix_linux(ip):
    rc, out, _ = run_cmd(["ip", "-4", "-o", "addr", "show"])
    if rc == 0:
        m = re.search(rf"inet {re.escape(ip)}/(\d+)", out)
        if m:
            return int(m.group(1))
    return None


def _prefix_macos(ip):
    rc, out, _ = run_cmd(["ifconfig"])
    if rc == 0:
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x[0-9a-fA-F]+", out):
            if m.group(1) == ip:
                pass
        for m in re.finditer(
                r"inet (\d+\.\d+\.\d+\.\d+)(?:.*?netmask\s+0x([0-9a-fA-F]+))?", out):
            if m.group(1) == ip and m.group(2):
                return bin(int(m.group(2), 16)).count("1")
    return None


def _prefix_windows(ip):
    rc, out, _ = run_cmd(["netsh", "interface", "ipv4", "show", "addresses"], timeout=15)
    if rc == 0:
        for sec in re.split(r"\n\s*\n", out):
            if ip in sec:
                m = re.search(
                    r"(?:Маска подсети|Subnet Mask|Маска)\s*:?\s*(\d+\.\d+\.\d+\.\d+)", sec)
                if m:
                    return sum(bin(int(x)).count("1") for x in m.group(1).split("."))
    return None


def get_network_cidr():
    """Возвращает (cidr, local_ip) или None, если сеть определить не удалось."""
    ip = get_local_ip()
    if not ip:
        return None
    prefix = None
    if IS_LINUX:
        prefix = _prefix_linux(ip)
    elif IS_MACOS:
        prefix = _prefix_macos(ip)
    elif IS_WINDOWS:
        prefix = _prefix_windows(ip)
    if prefix is None:
        prefix = 24  # типовая маска домашней сети
    return f"{ip}/{prefix}", ip


def get_gateway():
    """IP шлюза по умолчанию, либо None."""
    if IS_LINUX:
        rc, out, _ = run_cmd(["ip", "route", "show", "default"])
        if rc == 0:
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        rc, out, _ = run_cmd(["route", "-n"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[1]):
                        return parts[1]
    elif IS_MACOS:
        rc, out, _ = run_cmd(["netstat", "-rn", "-f", "inet"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[1]):
                        return parts[1]
    elif IS_WINDOWS:
        rc, out, _ = run_cmd(["route", "print", "-4"], timeout=15)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    if re.match(r"\d+\.\d+\.\d+\.\d+$", parts[2]):
                        return parts[2]
    return None


# --------------------------------------------------------------- ARP-таблица ----
def parse_arp_table():
    """Текущая ARP-таблица: {ip: {"mac": ..., "iface": ...}}."""
    entries = {}

    if IS_LINUX and shutil.which("ip"):
        rc, out, _ = run_cmd(["ip", "neigh", "show"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[0]):
                    ip = parts[0]
                    dev = parts[parts.index("dev") + 1] if "dev" in parts else None
                    mac = None
                    if "lladdr" in parts:
                        mac = parts[parts.index("lladdr") + 1].lower()
                    if mac and mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff"):
                        entries[ip] = {"mac": mac, "iface": dev}
            if entries:
                return entries

    # универсальный вариант: arp -a (Linux/macOS/Windows)
    rc, out, _ = run_cmd(["arp", "-a"])
    if rc != 0:
        return entries
    for line in out.splitlines():
        if IS_WINDOWS:
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
                r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                line)
            if m:
                ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
                if mac != "00:00:00:00:00:00" and not ip.startswith(("224.", "239.", "255.")):
                    entries[ip] = {"mac": mac, "iface": None}
        else:
            m = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{11,17})"
                r"(?:\s+\[ether\])?\s+on\s+(\S+)", line)
            if m:
                ip, mac, dev = m.group(1), m.group(2).lower(), m.group(3)
                if not mac.startswith("ff:ff") and not ip.startswith(("224.", "239.", "255.")):
                    entries[ip] = {"mac": mac, "iface": dev}
    return entries


# ------------------------------------------------------------ активные проверки ----
def _ping_once(ip):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1500", ip]
    elif IS_MACOS:
        cmd = ["ping", "-c", "1", "-W", "1500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=6)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tcp_alive(ip, timeout=0.5):
    for port in _PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        return None


def _iter_hosts(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:  # /31, /32 — единственный хост
        return str(net.network_address), str(net)
    hosts = [str(h) for h in net.hosts()]
    return str(net), hosts


# ------------------------------------------------------------ главный скан ----
def discover_devices(cidr=None, use_ping=True, probe_tcp=True, workers=128, verbose=True):
    """
    Обнаруживает устройства в локальной сети.

    Возвращает словарь:
      {"cidr", "local_ip", "gateway", "devices": [
          {"ip", "mac", "iface", "vendor", "hostname", "source"}, ...]}
    """
    if cidr is None:
        netinfo = get_network_cidr()
        if not netinfo:
            raise RuntimeError("Не удалось определить локальный IP-адрес и сеть")
        cidr, local_ip = netinfo
    else:
        local_ip = get_local_ip()

    net, hosts = _iter_hosts(cidr)
    if isinstance(hosts, str):
        hosts = [hosts]
    if len(hosts) > _MAX_HOSTS:
        if verbose:
            print(warn(f"Подсеть слишком велика ({len(hosts)} адресов) — "
                       f"сканирую первые {_MAX_HOSTS}"))
        hosts = hosts[:_MAX_HOSTS]

    if verbose:
        print(info(f"Локальная сеть: {str(net)}"))
        print(info("Читаю ARP-таблицу..."))

    arp = parse_arp_table()
    alive = {}  # ip -> источник обнаружения
    for ip in arp:
        alive[ip] = "ARP"

    if use_ping and shutil.which("ping"):
        if verbose:
            print(info(f"Ping-опрос {len(hosts)} адресов (потоков: {workers})..."))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for ip, is_up in zip(hosts, ex.map(_ping_once, hosts)):
                if is_up:
                    alive.setdefault(ip, "ping")
    elif use_ping:
        if verbose:
            print(warn("Утилита ping недоступна — пропускаю ping-опрос"))

    remaining = [h for h in hosts if h not in alive]
    if probe_tcp and remaining and len(remaining) <= _MAX_HOSTS:
        if verbose:
            print(info(f"TCP-проверка остальных {len(remaining)} адресов..."))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_tcp_alive, h): h for h in remaining}
            for f in as_completed(futs):
                if f.result():
                    alive.setdefault(futs[f], "TCP")

    hostnames = {}
    if alive:
        with ThreadPoolExecutor(max_workers=32) as ex:
            futs = {ex.submit(_resolve_host, ip): ip for ip in alive}
            for f in as_completed(futs):
                hostnames[futs[f]] = f.result()

    devices = []
    for ip, src in sorted(alive.items()):
        entry = arp.get(ip, {})
        devices.append({
            "ip": ip,
            "mac": entry.get("mac"),
            "iface": entry.get("iface"),
            "vendor": vendor_for_mac(entry.get("mac")) if entry.get("mac") else None,
            "hostname": hostnames.get(ip) or None,
            "source": src,
        })
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))

    return {
        "cidr": str(net),
        "local_ip": local_ip,
        "gateway": get_gateway(),
        "devices": devices,
    }

"""
Dış ağ (internet) hedefleri için IP katmanında host discovery.
ARP çalışmaz (L2 yerelde kalır) — katmanlı ICMP → TCP SYN ping → UDP ping ile
"ayakta mı" kontrolü yapılır, sonra scanner.scan_device ile aynı detaylı prob
zinciri uygulanır.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import ICMP, IP, TCP, UDP, sr1

from .constants import EXTERNAL_PING_PORTS, MAX_EXTERNAL_HOSTS


def resolve_target(target: str) -> list[str]:
    """
    target bir CIDR/IP ise host listesine genişletir (MAX_EXTERNAL_HOSTS sınırıyla),
    değilse domain kabul edip DNS ile tekil IPv4 adreslerine çözümler.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        hosts = list(net.hosts())
        if len(hosts) > MAX_EXTERNAL_HOSTS:
            print(f"   ⚠️  {len(hosts)} host çok geniş — ilk {MAX_EXTERNAL_HOSTS} host taranacak.")
            hosts = hosts[:MAX_EXTERNAL_HOSTS]
        return [str(h) for h in hosts]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, family=socket.AF_INET)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []


# ── Host Discovery Katmanları ────────────────────────────────────────────────

def icmp_ping(ip: str, timeout: float = 1.5) -> bool:
    try:
        resp = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
        return resp is not None
    except Exception:
        return False


def tcp_syn_ping(ip: str, timeout: float = 1.5) -> bool:
    for port in EXTERNAL_PING_PORTS:
        try:
            resp = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
            if resp is not None and resp.haslayer(TCP):
                return True
        except Exception:
            continue
    return False


def udp_ping(ip: str, timeout: float = 1.5) -> bool:
    for port in (53, 161, 123):
        try:
            resp = sr1(IP(dst=ip) / UDP(dport=port), timeout=timeout, verbose=0)
            if resp is not None:
                return True
        except Exception:
            continue
    return False


def host_discovery(ip: str) -> bool:
    """Katmanlı host discovery: ICMP → TCP SYN ping → UDP ping (ilk True'da durur)."""
    return icmp_ping(ip) or tcp_syn_ping(ip) or udp_ping(ip)


def discover_alive_hosts(ips: list[str], max_workers: int = 32) -> list[str]:
    """Verilen IP listesini paralel host_discovery ile tarar, ayakta olanları IP sırasıyla döner."""
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=min(len(ips), max_workers) or 1) as ex:
        futures = {ex.submit(host_discovery, ip): ip for ip in ips}
        for f in as_completed(futures):
            ip = futures[f]
            if f.result():
                alive.append(ip)
    return sorted(alive, key=socket.inet_aton)

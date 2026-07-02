"""Yerel ağ arayüzlerini keşfeder ve ARP ile aktif cihazları tarar."""

from __future__ import annotations

import ipaddress
import socket

import netifaces
from scapy.all import ARP, Ether, srp


def get_local_subnets() -> list[tuple[str, str]]:
    """
    Tüm aktif ağ arayüzlerini tarar, her biri için (iface, cidr) döner.
    Başarısız olursa varsayılan gateway IP'sinden /24 tahmin eder.
    """
    subnets: list[tuple[str, str]] = []
    ignore = ["lo", "docker0"]

    for iface in netifaces.interfaces():
        if any(ig in iface for ig in ignore):
            continue
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip      = addr.get("addr")
                netmask = addr.get("netmask")
                if not ip or not netmask or ip.startswith("127."):
                    continue
                cidr   = sum(bin(int(x)).count("1") for x in netmask.split("."))
                ip_p   = [int(x) for x in ip.split(".")]
                mask_p = [int(x) for x in netmask.split(".")]
                net    = ".".join(str(ip_p[i] & mask_p[i]) for i in range(4))
                cidr_s = f"{net}/{cidr}"
                if cidr_s not in [s for _, s in subnets] and cidr < 32:
                    subnets.append((iface, cidr_s))
        except (ValueError, KeyError):
            continue

    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            subnets.append(("lan_fallback", ".".join(ip.split(".")[:3]) + ".0/24"))
        except Exception:
            pass

    return subnets


def scan_subnet(ip_range: str, iface: str) -> list[dict]:
    """
    ARP broadcast ile verilen CIDR aralığındaki aktif cihazları döner.
    [{ip, mac}, ...] — IP'ye göre sıralı.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    try:
        kw: dict = {"timeout": 3, "retry": 2, "verbose": 0}
        if "fallback" not in iface:
            kw["iface"] = iface
        answered = srp(pkt, **kw)[0]
        devices  = {r.hwsrc: {"ip": r.psrc, "mac": r.hwsrc} for _, r in answered}
        return sorted(devices.values(), key=lambda x: socket.inet_aton(x["ip"]))
    except Exception:
        return []


def resolve_scan_target(target: str) -> tuple[bool, str | None, str]:
    """
    --target argümanının iç ağ mı dış ağ mı olduğunu belirler.

    (is_local, iface, target) döner:
    - is_local=True  → target yerel bir arayüze ait bir CIDR/IP, ARP ile taranır.
    - is_local=False → target bir domain veya yerel olmayan bir IP/CIDR, dış ağ
      host discovery akışına yönlendirilir. iface bu durumda None'dır.
    """
    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False, None, target  # domain adı

    for iface, cidr in get_local_subnets():
        try:
            if target_net.subnet_of(ipaddress.ip_network(cidr, strict=False)):
                return True, iface, target
        except (ValueError, TypeError):
            continue

    return False, None, target  # yerel olmayan IP/CIDR

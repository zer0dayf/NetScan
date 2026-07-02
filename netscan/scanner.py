"""
Cihaz başına tüm probları paralel olarak koordine eder.
Port taraması + yardımcı problar → tek bir cihaz sonuç sözlüğü döner.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .discovery import (
    extract_apple_model,
    get_hostname,
    netbios_query,
    snmp_query,
)
from .fingerprint import (
    get_ttl_os_hint,
    google_cast_probe,
    ipp_probe,
    probe_port,
    roku_probe,
    tcp_fingerprint,
    wsd_probe,
)
from .vendor import get_mac_vendor


def scan_device(
    device:   dict,
    ports:    list[int],
    timeout:  float,
    upnp_map: dict | None = None,
    mdns_map: dict | None = None,
    dhcp_map: dict | None = None,
) -> dict:
    """
    Tek bir cihaz için tüm parmak izi problarını çalıştırır.

    Paralel iki aşama:
    1. Port taraması (max 24 thread)
    2. Yardımcı problar: hostname, OS, NetBIOS, SNMP,
       Cast/WSD/IPP/Roku (sadece açık portlar)

    Dönen sözlük, output ve export modülleri tarafından kullanılır.
    """
    ip, mac = device["ip"], device.get("mac")

    # ── Aşama 1: Port taraması ────────────────────────────────────────────────
    port_results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(len(ports), 24)) as ex:
        futures = {ex.submit(probe_port, ip, p, timeout): p for p in ports}
        for f in as_completed(futures):
            res = f.result()
            if res:
                port_results.append(res)
    port_results.sort(key=lambda x: x["port"])
    open_ports = [r["port"] for r in port_results]

    # ── Aşama 2: Paralel yardımcı problar ────────────────────────────────────
    with ThreadPoolExecutor(max_workers=8) as ex:
        f_host    = ex.submit(get_hostname, ip)
        f_tcp_os  = ex.submit(tcp_fingerprint, ip, open_ports)
        f_ttl     = ex.submit(get_ttl_os_hint, ip)
        f_netbios = ex.submit(netbios_query, ip)
        f_snmp    = ex.submit(snmp_query, ip)
        f_cast = ex.submit(google_cast_probe, ip) if {8008, 8009} & set(open_ports) else None
        f_wsd  = ex.submit(wsd_probe, ip)          if 5357 in open_ports else None
        f_ipp  = ex.submit(ipp_probe, ip)           if 631  in open_ports else None
        f_roku = ex.submit(roku_probe, ip)          if 8060 in open_ports else None

        hostname  = f_host.result()
        os_hint   = f_tcp_os.result() or f_ttl.result()
        netbios   = f_netbios.result()
        snmp_info = f_snmp.result()
        cast_info = f_cast.result() if f_cast else None
        wsd_info  = f_wsd.result()  if f_wsd  else None
        ipp_info  = f_ipp.result()  if f_ipp  else None
        roku_info = f_roku.result() if f_roku else None

    # ── DHCP verisi ───────────────────────────────────────────────────────────
    dhcp_data = (dhcp_map or {}).get(mac.lower(), {}) if mac else {}

    # ── Cihaz modeli (öncelik sırası) ─────────────────────────────────────────
    mdns_data    = (mdns_map or {}).get(ip, [])
    device_model = (
        extract_apple_model(mdns_data)
        or (cast_info or {}).get("model")
        or (wsd_info  or {}).get("model")
        or (roku_info or {}).get("model")
    )

    return {
        "ip":            ip,
        "mac":           mac,
        "vendor":        get_mac_vendor(mac),
        "hostname":      hostname,
        "netbios":       netbios,
        "dhcp_hostname": dhcp_data.get("hostname"),
        "dhcp_os":       dhcp_data.get("dhcp_os"),
        "device_model":  device_model,
        "os_hint":       os_hint,
        "snmp":          snmp_info,
        "upnp":          (upnp_map or {}).get(ip),
        "mdns":          mdns_data or None,
        "cast":          cast_info,
        "wsd":           wsd_info,
        "ipp":           ipp_info,
        "roku":          roku_info,
        "ports":         port_results,
    }

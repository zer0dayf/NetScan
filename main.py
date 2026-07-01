#!/usr/bin/env python3
"""
NetScan — Gelişmiş Yerel Ağ ve Servis Analizörü
Kullanım: sudo python3 main.py [seçenekler]
         veya: sudo ./netscan.sh [seçenekler]
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading

import urllib3

from netscan import __version__
from netscan.constants import DEFAULT_PORTS, WIRESHARK_MANUF_PATHS
from netscan.discovery import (
    SNMP_AVAILABLE,
    ZEROCONF_AVAILABLE,
    dhcp_only_mode,
    dhcp_passive_sniff,
    extract_apple_model,
    mdns_scan,
    ssdp_scan,
)
from netscan.export import ask_export_format, ensure_ext, export_results
from netscan.network import get_local_subnets, scan_subnet
from netscan.output import print_device
from netscan.scanner import scan_device
from netscan.vendor import _load_mac_vendor_db, db_info, update_mac_vendor_db

import os


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            f"NetScan v{__version__} — Gelişmiş Yerel Ağ ve Servis Analizörü\n"
            "ARP keşfi, MAC vendor lookup, HTTP/mDNS/DHCP/Cast/WSD/IPP parmak izi."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument(
        "--ports", type=str, default=None, metavar="PORTLAR",
        help="Taranacak portlar (örn: 22,80,443).\nVarsayılan: geniş port seti",
    )
    p.add_argument(
        "--timeout", type=float, default=1.0, metavar="SANİYE",
        help="Port bağlantı zaman aşımı. Varsayılan: 1.0",
    )
    p.add_argument(
        "--output", type=str, default=None, metavar="DOSYA",
        help="Çıktı dosyası adı (uzantısız, örn: rapor)",
    )
    p.add_argument(
        "--format", type=str, default=None, dest="fmt",
        choices=["json", "txt", "pdf"],
        help="Export formatı: json / txt / pdf",
    )
    p.add_argument(
        "--update-db", action="store_true",
        help="IEEE OUI veritabanını indir ve güncelle",
    )
    p.add_argument(
        "--dhcp-timeout", type=int, default=8, metavar="SANİYE",
        help="DHCP pasif dinleme süresi. Varsayılan: 8",
    )
    p.add_argument(
        "--dhcp-only", action="store_true",
        help="Sadece DHCP dinle — ağa bağlanan cihazları yakalar (Ctrl+C ile dur)",
    )
    p.add_argument(
        "--version", action="version", version=f"NetScan v{__version__}",
    )
    return p.parse_args()


def main() -> None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if os.getuid() != 0:
        print("❌ ARP ve DHCP taraması için root yetkisi gerekli.")
        print("   Kullanım: sudo python3 main.py")
        sys.exit(1)

    args = parse_args()

    # ── Özel modlar ───────────────────────────────────────────────────────────
    if args.update_db:
        update_mac_vendor_db()
        return

    if args.dhcp_only:
        dhcp_only_mode()
        return

    # ── Port listesi ──────────────────────────────────────────────────────────
    ports = DEFAULT_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("❌ --ports için virgülle ayrılmış sayılar girin (örn: 22,80,443)")
            sys.exit(1)

    # ── Başlık ────────────────────────────────────────────────────────────────
    _load_mac_vendor_db()
    active_mods = ["NetBIOS", "UPnP/SSDP", "TCP-OS", "DHCP", "Cast", "WSD", "IPP", "Roku"]
    if SNMP_AVAILABLE:     active_mods.append("SNMP")
    if ZEROCONF_AVAILABLE: active_mods.append("mDNS")

    print(f"⚡ NetScan v{__version__} — Gelişmiş Ağ ve Servis Analizörü")
    print(f"   Portlar  : {ports}")
    print(f"   Timeout  : {args.timeout}s")
    print(f"   Modüller : {', '.join(active_mods)}")
    print(f"   Vendor DB: {db_info()}")

    # ── Arka plan: DHCP pasif dinleme ─────────────────────────────────────────
    dhcp_result: dict = {}
    print(f"   🔎 DHCP pasif dinleme başlatıldı ({args.dhcp_timeout}s)...")

    def _run_dhcp():
        nonlocal dhcp_result
        dhcp_result = dhcp_passive_sniff(timeout=args.dhcp_timeout)

    dhcp_thread = threading.Thread(target=_run_dhcp, daemon=True)
    dhcp_thread.start()

    # ── Arka plan: mDNS ───────────────────────────────────────────────────────
    mdns_result: dict = {}
    mdns_thread: threading.Thread | None = None
    if ZEROCONF_AVAILABLE:
        print("   📡 mDNS arka planda taranıyor (5s)...")

        def _run_mdns():
            nonlocal mdns_result
            mdns_result = mdns_scan(timeout=5)

        mdns_thread = threading.Thread(target=_run_mdns, daemon=True)
        mdns_thread.start()

    # ── Alt ağ taramaları ─────────────────────────────────────────────────────
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subnets     = get_local_subnets()
    all_results: list[dict] = []

    for iface, subnet in subnets:
        print("\n" + "=" * 90)
        print(f"🌐 AĞ SENSÖRÜ: {iface:<12} | ALT AĞ: {subnet}")
        print("=" * 90)

        devices = scan_subnet(subnet, iface)
        if not devices:
            print("  🔕 Bu alt ağda aktif cihaz tespit edilemedi.")
            all_results.append({"iface": iface, "subnet": subnet, "devices": []})
            continue

        print(f"  ✅ {len(devices)} aktif cihaz — UPnP/SSDP taranıyor...")
        upnp_map = ssdp_scan(timeout=3)
        if upnp_map:
            print(f"  🔊 {len(upnp_map)} UPnP cihazı tespit edildi.")
        print("  🔍 Paralel servis taraması başlıyor...\n")

        subnet_devices: list[dict] = []
        with ThreadPoolExecutor(max_workers=min(len(devices), 10)) as ex:
            futures = {
                ex.submit(scan_device, dev, ports, args.timeout, upnp_map, None, None): dev
                for dev in devices
            }
            for future in as_completed(futures):
                result = future.result()
                subnet_devices.append(result)
                print_device(result)

        subnet_devices.sort(key=lambda x: socket.inet_aton(x["ip"]))
        all_results.append({"iface": iface, "subnet": subnet, "devices": subnet_devices})

    # ── mDNS sonuçlarını entegre et ───────────────────────────────────────────
    if mdns_thread and mdns_thread.is_alive():
        print("\n  ⏳ mDNS sonuçları bekleniyor...")
        mdns_thread.join(timeout=7)
    if mdns_result:
        print(f"  📡 {len(mdns_result)} cihaz mDNS üzerinden keşfedildi.")
        for sn in all_results:
            for dev in sn["devices"]:
                if dev["ip"] in mdns_result:
                    dev["mdns"] = mdns_result[dev["ip"]]
                    model = extract_apple_model(dev["mdns"])
                    if model and not dev.get("device_model"):
                        dev["device_model"] = model

    # ── DHCP sonuçlarını entegre et ───────────────────────────────────────────
    if dhcp_thread.is_alive():
        print("  ⏳ DHCP sonuçları bekleniyor...")
        dhcp_thread.join(timeout=args.dhcp_timeout + 2)
    if dhcp_result:
        print(f"  🔎 {len(dhcp_result)} cihaz DHCP üzerinden tanımlandı.")
        for sn in all_results:
            for dev in sn["devices"]:
                d = dhcp_result.get(dev["mac"].lower(), {})
                if d:
                    dev["dhcp_hostname"] = d.get("hostname")
                    dev["dhcp_os"]       = d.get("dhcp_os")

    # ── Export ────────────────────────────────────────────────────────────────
    if args.output:
        fmt  = args.fmt or ask_export_format()
        path = ensure_ext(args.output, fmt)
        export_results(all_results, path, fmt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⛔ Tarama kullanıcı tarafından durduruldu.")
        sys.exit(0)

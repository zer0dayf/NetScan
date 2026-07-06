"""Terminal çıktısı — renkli, hiyerarşik cihaz raporu."""

from __future__ import annotations

from collections import Counter


def best_hostname(device: dict) -> str:
    """DHCP > DNS > NetBIOS önceliğiyle en iyi hostname'i döner."""
    return (
        device.get("dhcp_hostname")
        or device.get("hostname")
        or device.get("netbios")
        or ""
    )


def print_summary(all_results: list[dict]) -> None:
    """Tarama sonunda toplam cihaz, üretici dağılımı ve açık servis özeti basar."""
    devices = [d for sn in all_results for d in sn.get("devices", [])]
    if not devices:
        print("\n" + "=" * 90)
        print("📊 ÖZET: Hiç aktif cihaz bulunamadı.")
        print("=" * 90)
        return

    vendors: Counter = Counter()
    port_hits: Counter = Counter()
    web_apps: Counter = Counter()
    identified = 0

    for d in devices:
        vendors[d.get("vendor") or "Bilinmeyen"] += 1
        if d.get("hostname") or d.get("dhcp_hostname") or d.get("netbios") or d.get("device_model"):
            identified += 1
        for svc in d.get("ports", []):
            port_hits[svc["port"]] += 1
            if svc.get("type") == "http":
                app = (svc.get("data") or {}).get("identified_as")
                if app and app != "Bilinmeyen Web Uygulaması":
                    web_apps[app] += 1

    print("\n" + "=" * 90)
    print(f"📊 ÖZET: {len(devices)} cihaz | {identified} tanımlı | "
          f"{len(all_results)} alt ağ")
    print("=" * 90)

    top_vendors = ", ".join(f"{v} ({n})" for v, n in vendors.most_common(6))
    print(f"  🏭 Üreticiler : {top_vendors}")

    if port_hits:
        top_ports = ", ".join(f"{p}×{n}" for p, n in
                              sorted(port_hits.items(), key=lambda x: (-x[1], x[0]))[:10])
        print(f"  🔌 Açık portlar: {top_ports}")

    if web_apps:
        apps = ", ".join(f"{a} ({n})" for a, n in web_apps.most_common(8))
        print(f"  🌐 Web servisleri: {apps}")


def print_device(r: dict) -> None:
    host  = best_hostname(r)
    model = r.get("device_model") or ""
    os_h  = r.get("os_hint") or r.get("dhcp_os") or ""

    parts = [f"IP: {r['ip']:<15}", f"MAC: {r['mac'] or 'N/A'}", f"Üretici: {r['vendor']}"]
    if host:  parts.append(f"Host: {host}")
    if model: parts.append(f"Model: {model}")
    if os_h:  parts.append(f"OS: {os_h}")
    print("\n  📱 " + " | ".join(parts))

    if r.get("upnp"):
        u = r["upnp"]
        print(f"     🔊 UPnP : {u.get('friendly_name','')} | "
              f"{u.get('manufacturer','')} {u.get('model','')}".rstrip())
        if u.get("internal_ips"):
            print(f"        🔓 Port Mapping ile Görülen İç IP'ler: {', '.join(u['internal_ips'])}")

    if r.get("cast"):
        c = r["cast"]
        print(f"     📺 Cast : {c.get('name','')} | "
              f"{c.get('manufacturer','')} {c.get('model','')}".rstrip())

    if r.get("roku"):
        rk = r["roku"]
        print(f"     📺 Roku : {rk.get('name','')} | {rk.get('model','')}".rstrip())

    if r.get("wsd"):
        w = r["wsd"]
        print(f"     🖥️  WSD  : {w.get('name','')} | "
              f"{w.get('manufacturer','')} {w.get('model','')}".rstrip())

    if r.get("ipp"):
        pp       = r["ipp"]
        printers = ", ".join(pp.get("printers", [])) or pp.get("title", "")
        print(f"     🖨️  IPP  : {printers}")

    if r.get("mdns"):
        svcs = [s for s in r["mdns"] if "device-info" not in s.get("service", "")]
        if svcs:
            txt = ", ".join(f"{s['service']}:{s['port']}" for s in svcs[:6])
            print(f"     📡 mDNS : {txt}")

    if r.get("snmp"):
        sn  = r["snmp"]
        desc = sn.get("description", "")[:70]
        loc  = sn.get("location", "")
        print(f"     🔧 SNMP : {desc}" + (f" | Konum: {loc}" if loc else ""))
        if sn.get("arp_table"):
            print(f"        🔓 ARP Tablosunda Görülen İç IP'ler ({len(sn['arp_table'])}): "
                  f"{', '.join(sn['arp_table'][:10])}" + (" ..." if len(sn['arp_table']) > 10 else ""))

    for svc in r.get("ports", []):
        t = svc["type"]
        p = svc["port"]
        if t == "banner":
            print(f"    └── 🔌 Port {p}/TCP   : [{svc['data']}]")
        elif t == "smb":
            print(f"    └── 📁 Port 445/TCP  : [SMB Paylaşımı Aktif]")
        elif t == "mqtt":
            print(f"    └── 📨 Port 1883/TCP : [MQTT Broker]")
        elif t == "jetdirect":
            print(f"    └── 🖨️  Port 9100/TCP : [{svc['data']}]")
        elif t == "http":
            w = svc["data"]
            print(f"    └── 🌐 Port {w['port']}/{w['protocol']}: <{w['identified_as']}>")
            print(f"        🔹 Başlık : {w['title']}")
            print(f"        🔹 Sunucu : {w['server']}")
            if w.get("hash"):
                print(f"        🔹 Fav    : {w['hash']}")
            if w.get("internal_ip_leak"):
                print(f"        🔓 İç IP Sızıntısı: {', '.join(w['internal_ip_leak'])}")

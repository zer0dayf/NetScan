"""Terminal çıktısı — renkli, hiyerarşik cihaz raporu."""

from __future__ import annotations


def best_hostname(device: dict) -> str:
    """DHCP > DNS > NetBIOS önceliğiyle en iyi hostname'i döner."""
    return (
        device.get("dhcp_hostname")
        or device.get("hostname")
        or device.get("netbios")
        or ""
    )


def print_device(r: dict) -> None:
    host  = best_hostname(r)
    model = r.get("device_model") or ""
    os_h  = r.get("os_hint") or r.get("dhcp_os") or ""

    parts = [f"IP: {r['ip']:<15}", f"MAC: {r['mac']}", f"Üretici: {r['vendor']}"]
    if host:  parts.append(f"Host: {host}")
    if model: parts.append(f"Model: {model}")
    if os_h:  parts.append(f"OS: {os_h}")
    print("\n  📱 " + " | ".join(parts))

    if r.get("upnp"):
        u = r["upnp"]
        print(f"     🔊 UPnP : {u.get('friendly_name','')} | "
              f"{u.get('manufacturer','')} {u.get('model','')}".rstrip())

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

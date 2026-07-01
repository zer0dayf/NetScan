"""Tarama sonuçlarını JSON / TXT / PDF olarak dışa aktarır."""

from __future__ import annotations

import json
import os

from .output import best_hostname


# ── Yardımcılar ───────────────────────────────────────────────────────────────

def ask_export_format() -> str:
    print("\n📄 Export Formatı Seçin:")
    print("  [1] JSON — Yapılandırılmış veri")
    print("  [2] TXT  — Düz metin raporu")
    print("  [3] PDF  — Görsel rapor")
    while True:
        c = input("  Seçiminiz (1/2/3): ").strip()
        if c == "1": return "json"
        if c == "2": return "txt"
        if c == "3": return "pdf"
        print("  ⚠️  Geçersiz seçim.")


def ensure_ext(path: str, fmt: str) -> str:
    ext = {"json": ".json", "txt": ".txt", "pdf": ".pdf"}[fmt]
    return path if path.endswith(ext) else path + ext


# ── JSON ─────────────────────────────────────────────────────────────────────

def export_json(all_results: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\n✅ JSON kaydedildi: {path}")


# ── TXT ──────────────────────────────────────────────────────────────────────

def export_txt(all_results: list, path: str) -> None:
    sep   = "=" * 70
    lines = [sep, "NETSCAN — Ağ ve Servis Analiz Raporu", sep]

    for sn in all_results:
        lines.append(f"\nArayüz: {sn['iface']}  |  Alt Ağ: {sn['subnet']}")
        lines.append("-" * 70)
        if not sn["devices"]:
            lines.append("  Aktif cihaz bulunamadı.")
            continue

        for dev in sn["devices"]:
            host  = best_hostname(dev)
            model = dev.get("device_model", "")
            os_h  = dev.get("os_hint") or dev.get("dhcp_os") or ""
            row   = (
                f"\n  IP: {dev['ip']:<15}  MAC: {dev['mac']}  "
                f"Üretici: {dev['vendor']}"
            )
            if host:  row += f"  Host: {host}"
            if model: row += f"  Model: {model}"
            if os_h:  row += f"  OS: {os_h}"
            lines.append(row)

            for key, label in [("upnp","UPnP"),("cast","Cast"),
                                ("roku","Roku"),("wsd","WSD")]:
                d = dev.get(key)
                if d:
                    name = d.get("friendly_name") or d.get("name") or ""
                    lines.append(
                        f"  {label}: {name} / {d.get('manufacturer','')} "
                        f"{d.get('model','')}".rstrip()
                    )

            if dev.get("ipp"):
                printers = ", ".join(dev["ipp"].get("printers", []))
                lines.append(f"  IPP: {printers or dev['ipp'].get('title','')}")

            if dev.get("mdns"):
                svcs = [s for s in dev["mdns"]
                        if "device-info" not in s.get("service", "")]
                if svcs:
                    lines.append("  mDNS: " + ", ".join(
                        f"{s['service']}:{s['port']}" for s in svcs
                    ))

            if dev.get("snmp"):
                lines.append(f"  SNMP: {dev['snmp'].get('description','')[:80]}")

            for svc in dev.get("ports", []):
                t = svc["type"]
                if t == "banner":
                    lines.append(f"    Port {svc['port']}/TCP: {svc['data']}")
                elif t == "smb":
                    lines.append("    Port 445/TCP: SMB Paylaşımı Aktif")
                elif t in ("mqtt", "jetdirect"):
                    lines.append(f"    Port {svc['port']}/TCP: {svc['data']}")
                elif t == "http":
                    w = svc["data"]
                    lines.append(f"    Port {w['port']}/{w['protocol']}: {w['identified_as']}")
                    lines.append(f"      Başlık: {w['title']}")
                    lines.append(f"      Sunucu: {w['server']}")
                    if w.get("hash"):
                        lines.append(f"      Fav Hash: {w['hash']}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ TXT kaydedildi: {path}")


# ── PDF ──────────────────────────────────────────────────────────────────────

def export_pdf(all_results: list, path: str) -> None:
    try:
        from fpdf import FPDF
    except ImportError:
        print("❌ PDF için fpdf2 gerekli: pip install fpdf2")
        return

    FONT_PATHS = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    ]
    BOLD_PATHS = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ]
    font_path   = next((p for p in FONT_PATHS if os.path.exists(p)), None)
    bold_path   = next((p for p in BOLD_PATHS if os.path.exists(p)), None)
    use_unicode = font_path is not None

    _TR = str.maketrans("ğüşıöçĞÜŞİÖÇ", "gusiocGUSIOC")

    def s(text) -> str:
        if not text:
            return ""
        return str(text) if use_unicode else str(text).translate(_TR)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    if use_unicode:
        pdf.add_font("UF", "",  font_path)
        pdf.add_font("UF", "B", bold_path or font_path)
        R = B = "UF"
    else:
        R = B = "Helvetica"

    pdf.set_font(B, "B", 16)
    pdf.cell(0, 12, "NetScan - Ag ve Servis Analiz Raporu", ln=True, align="C")
    pdf.ln(4)

    for sn in all_results:
        pdf.set_font(B, "B", 12)
        pdf.set_fill_color(40, 60, 100)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 9, f"  {s(sn['iface'])}  |  {s(sn['subnet'])}", ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        for dev in sn["devices"]:
            host  = best_hostname(dev)
            model = dev.get("device_model", "")
            os_h  = dev.get("os_hint") or dev.get("dhcp_os") or ""

            pdf.set_font(B, "B", 11)
            pdf.set_fill_color(210, 225, 245)
            pdf.cell(0, 8,
                f"  IP: {s(dev['ip'])}   MAC: {s(dev['mac'])}   "
                f"Uretici: {s(dev['vendor'])}",
                ln=True, fill=True)
            pdf.set_font(R, size=10)

            for label, value in [("Host", host), ("Model", model), ("OS", os_h)]:
                if value:
                    pdf.cell(10)
                    pdf.cell(0, 5, f"{label}: {s(value)}", ln=True)

            for key, label in [("upnp","UPnP"),("cast","Cast"),
                                ("roku","Roku"),("wsd","WSD")]:
                d = dev.get(key)
                if d:
                    name = d.get("friendly_name") or d.get("name") or ""
                    pdf.cell(10)
                    pdf.cell(0, 5,
                        f"{label}: {s(name)} / {s(d.get('manufacturer',''))} "
                        f"{s(d.get('model',''))}",
                        ln=True)

            if dev.get("ipp"):
                printers = ", ".join(dev["ipp"].get("printers", []))
                pdf.cell(10)
                pdf.cell(0, 5, f"IPP: {s(printers)}", ln=True)

            if dev.get("snmp"):
                pdf.cell(10)
                pdf.cell(0, 5,
                    f"SNMP: {s(dev['snmp'].get('description',''))[:70]}", ln=True)

            for svc in dev.get("ports", []):
                pdf.cell(10)
                t = svc["type"]
                if t == "banner":
                    pdf.cell(0, 5, f"Port {svc['port']}/TCP: {s(svc['data'])}", ln=True)
                elif t == "smb":
                    pdf.cell(0, 5, "Port 445/TCP: SMB Aktif", ln=True)
                elif t in ("mqtt", "jetdirect"):
                    pdf.cell(0, 5, f"Port {svc['port']}/TCP: {s(svc['data'])}", ln=True)
                elif t == "http":
                    w = svc["data"]
                    pdf.set_font(B, "B", 10)
                    pdf.cell(0, 5,
                        f"Port {w['port']}/{w['protocol']}: {s(w['identified_as'])}",
                        ln=True)
                    pdf.set_font(R, size=10)
                    pdf.cell(20)
                    pdf.cell(0, 5, f"Baslik: {s(w['title'])}", ln=True)
                    pdf.cell(20)
                    pdf.cell(0, 5, f"Sunucu: {s(w['server'])}", ln=True)
                    if w.get("hash"):
                        pdf.cell(20)
                        pdf.cell(0, 5, f"Fav Hash: {w['hash']}", ln=True)
            pdf.ln(3)
        pdf.ln(4)

    pdf.output(path)
    print(f"\n✅ PDF kaydedildi: {path}")


# ── Dispatcher ────────────────────────────────────────────────────────────────

def export_results(all_results: list, path: str, fmt: str) -> None:
    {"json": export_json, "txt": export_txt, "pdf": export_pdf}[fmt](all_results, path)

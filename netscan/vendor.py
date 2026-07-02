"""MAC vendor veritabanı: yükleme, sorgulama ve IEEE OUI güncelleme."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import requests

from .constants import IEEE_OUI_SOURCES, WIRESHARK_MANUF_URL, WIRESHARK_MANUF_PATHS

# Proje kökü → data/mac-vendor.txt
_DATA_DIR = Path(__file__).parent.parent / "data"
_DB_PATH  = _DATA_DIR / "mac-vendor.txt"

_MAC_VENDOR_DB: dict[str, str] = {}


# ── Parser'lar ────────────────────────────────────────────────────────────────

def _parse_ieee_block(raw: str) -> list[tuple[str, str]]:
    entries = []
    for line in raw.split("\n"):
        if "(hex)" in line:
            parts  = line.split("(hex)")
            oui    = parts[0].strip().replace("-", "").upper()
            vendor = parts[1].strip()
            if oui and vendor:
                entries.append((oui, vendor))
    return entries


def _parse_csv_oui(raw: str) -> list[tuple[str, str]]:
    import csv as _csv
    import io
    entries = []
    for parts in _csv.reader(io.StringIO(raw)):
        if len(parts) < 3:
            continue
        if parts[1].strip().upper() in ("ASSIGNMENT", ""):
            continue
        oui    = parts[1].strip().upper()
        vendor = parts[2].strip()
        if oui and vendor:
            entries.append((oui, vendor))
    return entries


def _parse_wireshark_manuf_raw(raw: str) -> list[tuple[str, str]]:
    entries = []
    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].strip()
        vendor = parts[-1].strip() if len(parts) >= 3 else parts[1].strip()
        if "/" in prefix:
            prefix = prefix.split("/")[0]
        key = prefix.replace(":", "").replace("-", "").upper()
        if key and vendor:
            entries.append((key, vendor))
    return entries


def _parse_wireshark_manuf(path: str) -> list[tuple[str, str]]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return _parse_wireshark_manuf_raw(f.read())


# ── Yükleme ───────────────────────────────────────────────────────────────────

def _load_mac_vendor_db() -> None:
    global _MAC_VENDOR_DB
    if _MAC_VENDOR_DB:
        return
    if _DB_PATH.exists():
        with _DB_PATH.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("\t", 1)
                if len(parts) == 2:
                    _MAC_VENDOR_DB[parts[0].upper().strip()] = parts[1].strip()
    for wpath in WIRESHARK_MANUF_PATHS:
        if os.path.exists(wpath):
            for key, vendor in _parse_wireshark_manuf(wpath):
                _MAC_VENDOR_DB[key] = vendor
            break


def get_mac_vendor(mac: str | None) -> str:
    """MAC adresinden üretici adını döner. 24/28/36-bit OUI uzunluk önceliğiyle arar."""
    if not mac:
        return "N/A (Dış Ağ)"
    _load_mac_vendor_db()
    full = mac.replace(":", "").replace("-", "").upper()
    for length in (9, 7, 6):  # MA-S → MA-M → MA-L
        hit = _MAC_VENDOR_DB.get(full[:length])
        if hit:
            return hit
    return "Bilinmeyen / Sanal Üretici"


def db_info() -> str:
    """Yüklü DB hakkında insan okunabilir etiket."""
    _load_mac_vendor_db()
    size      = len(_MAC_VENDOR_DB)
    multibit  = any(len(k) > 6 for k in _MAC_VENDOR_DB)
    ws_found  = any(os.path.exists(p) for p in WIRESHARK_MANUF_PATHS)
    if ws_found:
        return "Wireshark manuf (24/28/36-bit)"
    if multibit or size > 30_000:
        return f"IEEE güncel ({size:,} kayıt, 24/28/36-bit)"
    return f"{size:,} kayıt (24-bit) — güncellemek için: --update-db"


# ── Güncelleme ────────────────────────────────────────────────────────────────

def _fetch_url(url: str, timeout: int = 60) -> str | None:
    """IEEE bot korumasını aşmak için önce curl dener, sonra requests."""
    try:
        result = subprocess.run(
            ["curl", "-sL", "--max-time", str(timeout), url],
            capture_output=True, timeout=timeout + 5,
        )
        if result.returncode == 0 and len(result.stdout) > 100:
            return result.stdout.decode("utf-8", errors="ignore")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                "Gecko/20100101 Firefox/120.0"
            )
        }
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code == 200 and len(resp.text) > 100:
            return resp.text
    except Exception:
        pass
    return None


def update_mac_vendor_db() -> None:
    """IEEE OUI kayıtlarını indirip data/mac-vendor.txt'yi günceller."""
    all_entries: list[tuple[str, str]] = []
    any_failed = False

    for label, urls in IEEE_OUI_SOURCES.items():
        print(f"  ⬇️  {label} indiriliyor...")
        success = False
        for url in urls:
            raw = _fetch_url(url, timeout=60)
            if raw is None:
                continue
            entries = _parse_csv_oui(raw) if url.endswith(".csv") else _parse_ieee_block(raw)
            if entries:
                all_entries.extend(entries)
                print(f"     ✅ {len(entries):,} kayıt  ({url.split('/')[-1]})")
                success = True
                break
        if not success:
            print(f"     ❌ {label} indirilemedi")
            any_failed = True

    if any_failed:
        print("\n  ⬇️  Eksik listeler için Wireshark manuf indiriliyor...")
        raw = _fetch_url(WIRESHARK_MANUF_URL, timeout=90)
        if raw:
            ws_entries = _parse_wireshark_manuf_raw(raw)
            existing   = {oui for oui, _ in all_entries}
            added      = [(oui, v) for oui, v in ws_entries if oui not in existing]
            all_entries.extend(added)
            print(f"     ✅ {len(added):,} ek kayıt tamamlandı")
        else:
            print("     ❌ Wireshark manuf da indirilemedi")

    if not all_entries:
        print("❌ Hiçbir kayıt indirilemedi.")
        return

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _DB_PATH.write_text(
        "\n".join(f"{oui}\t{vendor}" for oui, vendor in all_entries),
        encoding="utf-8",
    )
    print(f"\n✅ Veritabanı güncellendi: {len(all_entries):,} kayıt → {_DB_PATH}")

    # Önbelleği sıfırla
    global _MAC_VENDOR_DB
    _MAC_VENDOR_DB = {}

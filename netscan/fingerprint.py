"""
Port parmak izi modülü:
Banner grabbing, SMB, HTTP (favicon+title), TCP OS tespiti,
Google Cast, WSD, IPP, Roku.
"""

from __future__ import annotations

import codecs
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import mmh3
import requests
from bs4 import BeautifulSoup
from scapy.all import ICMP, IP, TCP, sr1

from .constants import FAVICON_HASHES, HTML_SIGNATURES, TITLE_SIGNATURES


# ── OS Tespiti ────────────────────────────────────────────────────────────────

def get_ttl_os_hint(ip: str) -> str | None:
    """ICMP TTL'den kaba OS tahmini."""
    try:
        pkt = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.ttl
            if ttl <= 64:
                return f"Linux / macOS  (TTL={ttl})"
            if ttl <= 128:
                return f"Windows  (TTL={ttl})"
            return f"Ağ Ekipmanı / Router  (TTL={ttl})"
    except Exception:
        pass
    return None


def tcp_fingerprint(ip: str, open_ports: list[int]) -> str | None:
    """
    TCP SYN yanıt analizi ile OS tespiti.
    Yalnızca zaten açık olan portlara SYN gönderir.
    """
    if not open_ports:
        return None
    try:
        resp = sr1(
            IP(dst=ip) / TCP(
                dport=open_ports[0], flags="S",
                options=[
                    ("MSS", 1460), ("SAckOK", b""),
                    ("Timestamp", (0, 0)), ("NOP", None), ("WScale", 6),
                ],
            ),
            timeout=1, verbose=0,
        )
        if not resp or not resp.haslayer(TCP):
            return None
        ttl    = resp.ttl
        win    = resp[TCP].window
        opts   = dict(resp[TCP].options)
        wscale = opts.get("WScale")

        if ttl > 128:
            return f"Ağ Ekipmanı / Router (TTL={ttl}, Win={win})"
        if ttl > 64:
            return f"Windows (TTL={ttl}, Win={win})"
        # TTL ≤ 64
        if win <= 32768 and wscale is None:
            return f"Embedded Linux / Router (TTL={ttl}, Win={win})"
        if win == 65535 and (wscale is None or wscale <= 2):
            return f"macOS / iOS (TTL={ttl}, Win={win})"
        return f"Linux (TTL={ttl}, Win={win})"
    except Exception:
        return None


# ── Port Kontrol ──────────────────────────────────────────────────────────────

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


# ── Banner Grabbing ───────────────────────────────────────────────────────────

def banner_grabbing(ip: str, port: int) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        raw   = s.recv(1024)
        s.close()
        first = raw.decode("utf-8", errors="ignore").split("\n")[0].strip()
        clean = "".join(c for c in first if c.isprintable()).strip()
        return f"Banner: {clean}" if clean else None
    except Exception:
        return None


# ── SMB ───────────────────────────────────────────────────────────────────────

def smb_discovery(ip: str) -> str | None:
    smb_req = (
        b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
        b"\x00\x00\x40\x00\x00\x11\x00\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31"
        b"\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, 445))
        s.send(smb_req)
        res = s.recv(1024)
        s.close()
        if b"SMBr" in res:
            return "Açık (Samba / Windows)"
    except Exception:
        pass
    return None


# ── HTTP Parmak İzi ───────────────────────────────────────────────────────────

def http_fingerprinting(ip: str, port: int) -> dict | None:
    for proto in ("http", "https"):
        url = f"{proto}://{ip}:{port}"
        try:
            resp  = requests.get(url, timeout=1.5, verify=False)
            soup  = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "Başlıksız"

            detected: str | None = None

            # 1. Başlık tabanlı
            title_l = title.lower()
            for key, name in TITLE_SIGNATURES.items():
                if key in title_l:
                    detected = name
                    break

            # 2. HTML içerik imzaları
            if not detected:
                html_l = resp.text.lower()
                for key, name in HTML_SIGNATURES.items():
                    if key in html_l:
                        detected = name
                        break

            # 3. Favicon MurmurHash3
            server   = resp.headers.get("Server", "Bilinmiyor")
            fav_hash: int | None = None
            icon     = soup.find("link", rel=lambda x: x and "icon" in x.lower())
            fav_url  = (
                urljoin(url, icon.get("href"))
                if icon and icon.get("href")
                else urljoin(url, "/favicon.ico")
            )
            try:
                fr = requests.get(fav_url, timeout=1.0, verify=False)
                if fr.status_code == 200:
                    fav_hash = mmh3.hash(codecs.encode(fr.content, "base64"))
                    if fav_hash in FAVICON_HASHES:
                        detected = FAVICON_HASHES[fav_hash]
            except Exception:
                pass

            return {
                "port":          port,
                "protocol":      proto.upper(),
                "title":         title,
                "server":        server,
                "hash":          fav_hash,
                "identified_as": detected or "Bilinmeyen Web Uygulaması",
            }
        except Exception:
            continue
    return None


# ── Birleşik Port Probu ───────────────────────────────────────────────────────

def probe_port(ip: str, port: int, timeout: float) -> dict | None:
    """Portu açık/kapalı kontrol eder; açıksa protokole göre parmak izi alır."""
    if not is_port_open(ip, port, timeout):
        return None

    if port in (21, 22, 23):
        data = banner_grabbing(ip, port)
        return {"type": "banner", "port": port, "data": data} if data else None

    if port == 445:
        data = smb_discovery(ip)
        return {"type": "smb", "port": port, "data": data} if data else None

    if port == 1883:
        return {"type": "mqtt", "port": port, "data": "MQTT Broker tespit edildi"}

    if port == 9100:
        data = banner_grabbing(ip, port)
        return {"type": "jetdirect", "port": port, "data": data or "JetDirect Print Servisi"}

    data = http_fingerprinting(ip, port)
    return {"type": "http", "port": port, "data": data} if data else None


# ── Google Cast (Chromecast / Android TV) ────────────────────────────────────

def google_cast_probe(ip: str) -> dict | None:
    for port in (8008, 8009):
        try:
            resp = requests.get(
                f"http://{ip}:{port}/setup/eureka_info?options=system_info",
                timeout=2,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {k: v for k, v in {
                    "name":         data.get("name"),
                    "model":        data.get("model_name"),
                    "manufacturer": data.get("manufacturer"),
                    "build":        (data.get("build_info") or {}).get("build_version"),
                    "locale":       data.get("locale"),
                }.items() if v}
        except Exception:
            continue

    # Fallback: UPnP device description
    try:
        resp = requests.get(f"http://{ip}:8008/ssdp/device-desc.xml", timeout=2)
        if resp.status_code == 200:
            root = ET.fromstring(resp.content)
            ns   = "urn:schemas-upnp-org:device-1-0"
            dev  = root.find(f".//{{{ns}}}device")
            if dev is not None:
                def g(tag: str) -> str | None:
                    el = dev.find(f"{{{ns}}}{tag}")
                    return el.text.strip() if el is not None and el.text else None
                return {k: v for k, v in {
                    "name":         g("friendlyName"),
                    "model":        g("modelName"),
                    "manufacturer": g("manufacturer"),
                }.items() if v}
    except Exception:
        pass
    return None


# ── WSD (Windows Devices) ─────────────────────────────────────────────────────

def wsd_probe(ip: str) -> dict | None:
    try:
        resp = requests.get(f"http://{ip}:5357/", timeout=2)
        if resp.status_code not in (200, 400):
            return None
        root   = ET.fromstring(resp.content)
        result: dict = {}
        for elem in root.iter():
            tag  = elem.tag.split("}")[-1].lower() if "}" in elem.tag else elem.tag.lower()
            text = (elem.text or "").strip()
            if not text:
                continue
            if tag in ("friendlyname", "name"):
                result["name"] = text
            elif tag == "manufacturer":
                result["manufacturer"] = text
            elif tag in ("modelname", "model"):
                result["model"] = text
        return result or None
    except Exception:
        return None


# ── IPP (Yazıcı) ──────────────────────────────────────────────────────────────

def ipp_probe(ip: str) -> dict | None:
    try:
        resp = requests.get(f"http://{ip}:631/", timeout=2)
        if resp.status_code != 200:
            return None
        soup  = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.string.strip() if soup.title else ""
        info: dict = {"title": title} if title else {}

        pr = requests.get(f"http://{ip}:631/printers/", timeout=2)
        if pr.status_code == 200:
            psoup    = BeautifulSoup(pr.text, "html.parser")
            printers = [
                a.text.strip()
                for a in psoup.find_all("a", href=True)
                if "/printers/" in a["href"] and a.text.strip()
            ]
            if printers:
                info["printers"] = printers
        return info or None
    except Exception:
        return None


# ── Roku ECP ──────────────────────────────────────────────────────────────────

def roku_probe(ip: str) -> dict | None:
    try:
        resp = requests.get(f"http://{ip}:8060/query/device-info", timeout=2)
        if resp.status_code != 200:
            return None
        root = ET.fromstring(resp.content)

        def g(tag: str) -> str | None:
            el = root.find(tag)
            return el.text.strip() if el is not None and el.text else None

        return {k: v for k, v in {
            "model":    g("model-name") or g("model-number"),
            "name":     g("user-device-name") or g("friendly-device-name"),
            "software": g("software-version"),
            "serial":   g("serial-number"),
        }.items() if v}
    except Exception:
        return None

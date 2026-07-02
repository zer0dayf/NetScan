"""
Pasif/aktif ağ keşif protokolleri:
DHCP dinleme, mDNS/Bonjour, NetBIOS, SNMP, UPnP/SSDP.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests
from scapy.all import BOOTP, DHCP, sniff

from .constants import (
    APPLE_MODELS, MAX_PORT_MAPPING_ENTRIES, MAX_SNMP_ARP_ENTRIES, MDNS_SERVICE_TYPES,
)
from .vendor import get_mac_vendor, _load_mac_vendor_db

# ── Opsiyonel: zeroconf (mDNS) ───────────────────────────────────────────────

try:
    import ipaddress as _ipaddress
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

# ── Opsiyonel: pysnmp ────────────────────────────────────────────────────────

try:
    # pysnmp >= 7 hlapi tamamen asyncio tabanlı; senkron getCmd/nextCmd artık yok.
    # Dışa açık fonksiyonlarımız senkron kalsın diye asyncio.run() ile sarıyoruz.
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, ContextData, ObjectIdentity, ObjectType,
        SnmpEngine, UdpTransportTarget, get_cmd, next_cmd,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False


# ── DNS / Hostname ────────────────────────────────────────────────────────────

def get_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── DHCP Pasif Dinleme ────────────────────────────────────────────────────────

def _dhcp_os_hint(vendor_class: str) -> str | None:
    if not vendor_class:
        return None
    vc = vendor_class.lower()
    if vc.startswith("android-dhcp-"):
        ver = vc.split("-")[-1]
        return f"Android {ver}" if (ver.isdigit() or "." in ver) else "Android"
    if "msft" in vc:
        return "Windows"
    if "apple" in vc or "mac os x" in vc:
        return "macOS / iOS"
    if "dhcpcd" in vc or "linux" in vc:
        return "Linux"
    return vendor_class[:40]


def dhcp_passive_sniff(timeout: int = 8, iface: str | None = None) -> dict:
    """
    UDP 67/68 portlarını pasif olarak dinler — hiçbir paket göndermez.
    {mac: {hostname, vendor_class, dhcp_os}} döner.
    """
    discovered: dict = {}

    def _process(pkt):
        try:
            if DHCP not in pkt or BOOTP not in pkt:
                return
            opts: dict = {}
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) == 2:
                    opts[opt[0]] = opt[1]
            if opts.get("message-type") not in (1, 3):  # DISCOVER / REQUEST
                return

            mac_raw = pkt[BOOTP].chaddr[:6]
            mac     = ":".join(f"{b:02x}" for b in mac_raw)

            hostname = opts.get("hostname", b"")
            if isinstance(hostname, bytes):
                hostname = hostname.decode("utf-8", errors="ignore").strip()

            vendor_class = opts.get("vendor_class_id", b"")
            if isinstance(vendor_class, bytes):
                vendor_class = vendor_class.decode("utf-8", errors="ignore").strip()

            if (hostname or vendor_class) and mac not in discovered:
                discovered[mac] = {
                    "hostname":     hostname or None,
                    "vendor_class": vendor_class or None,
                    "dhcp_os":      _dhcp_os_hint(vendor_class),
                }
        except Exception:
            pass

    try:
        kw: dict = {
            "filter": "udp and (port 67 or port 68)",
            "prn":    _process,
            "timeout": timeout,
            "store":  False,
        }
        if iface:
            kw["iface"] = iface
        sniff(**kw)
    except Exception:
        pass
    return discovered


def dhcp_only_mode() -> None:
    """
    Sonsuz DHCP pasif dinleyici (Ctrl+C ile durdurulur).
    Ağa bağlanan her yeni cihazı tablo olarak basar.
    """
    _load_mac_vendor_db()
    seen: set = set()
    print("🔎 DHCP Pasif Dinleyici — Ctrl+C ile durdur\n")
    print(f"  {'MAC':<19} {'Vendor':<28} {'Hostname':<22} {'OS / Vendor Class'}")
    print("  " + "-" * 85)

    def _process(pkt):
        try:
            if DHCP not in pkt or BOOTP not in pkt:
                return
            opts: dict = {}
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) == 2:
                    opts[opt[0]] = opt[1]
            if opts.get("message-type") not in (1, 3):
                return

            mac_raw = pkt[BOOTP].chaddr[:6]
            mac     = ":".join(f"{b:02x}" for b in mac_raw)
            if mac in seen:
                return
            seen.add(mac)

            hostname = opts.get("hostname", b"")
            if isinstance(hostname, bytes):
                hostname = hostname.decode("utf-8", errors="ignore").strip()

            vendor_class = opts.get("vendor_class_id", b"")
            if isinstance(vendor_class, bytes):
                vendor_class = vendor_class.decode("utf-8", errors="ignore").strip()

            os_hint = _dhcp_os_hint(vendor_class) or vendor_class[:30]
            vendor  = get_mac_vendor(mac)
            print(f"  {mac:<19} {vendor:<28} {hostname:<22} {os_hint}")
        except Exception:
            pass

    sniff(filter="udp and (port 67 or port 68)", prn=_process, store=False)


# ── UPnP / SSDP ──────────────────────────────────────────────────────────────

def ssdp_scan(timeout: int = 3) -> dict:
    """M-SEARCH multicast gönderir, yanıt veren UPnP cihazlarını döner."""
    SSDP_ADDR, SSDP_PORT = "239.255.255.250", 1900
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    )
    discovered: dict = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
        while True:
            try:
                data, (ip, _) = sock.recvfrom(65507)
                if ip in discovered:
                    continue
                location = None
                for line in data.decode("utf-8", errors="ignore").split("\r\n"):
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        break
                info = _fetch_upnp_info(location) if location else {}
                if info:
                    discovered[ip] = info
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return discovered


def _find_igd_control_url(root: ET.Element, ns: str) -> tuple[str, str] | None:
    """WANIPConnection/WANPPPConnection servisinin (serviceType, controlURL) çiftini bulur."""
    for svc in root.iter(f"{{{ns}}}service"):
        st_el = svc.find(f"{{{ns}}}serviceType")
        cu_el = svc.find(f"{{{ns}}}controlURL")
        if st_el is None or cu_el is None or not st_el.text or not cu_el.text:
            continue
        st = st_el.text.strip()
        if "WANIPConnection" in st or "WANPPPConnection" in st:
            return st, cu_el.text.strip()
    return None


def _igd_port_mappings(location_url: str, root: ET.Element, ns: str) -> list[dict]:
    """
    UPnP IGD'nin GetGenericPortMappingEntry (salt okunur) aksiyonunu sırayla çağırarak
    yönlendirilmiş port haritasını (ve dolayısıyla iç ağ istemci IP'lerini) döner.
    Sadece okuma yapar — port ekleme/silme denemez.
    """
    found = _find_igd_control_url(root, ns)
    if not found:
        return []
    service_type, control_path = found
    control_url = urljoin(location_url, control_path)

    mappings: list[dict] = []
    for idx in range(MAX_PORT_MAPPING_ENTRIES):
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
            f'<NewPortMappingIndex>{idx}</NewPortMappingIndex>'
            '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
        )
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction":   f'"{service_type}#GetGenericPortMappingEntry"',
        }
        try:
            resp = requests.post(control_url, data=body, headers=headers, timeout=2, verify=False)
        except Exception:
            break
        if resp.status_code != 200:
            break  # SOAP Fault → index sona erdi

        try:
            entry = ET.fromstring(resp.content)
        except ET.ParseError:
            break

        def find_text(tag: str) -> str | None:
            el = entry.find(f".//{tag}")
            return el.text.strip() if el is not None and el.text else None

        internal_client = find_text("NewInternalClient")
        if not internal_client:
            break
        mappings.append({
            "external_port":   find_text("NewExternalPort"),
            "internal_client": internal_client,
            "internal_port":   find_text("NewInternalPort"),
            "protocol":        find_text("NewProtocol"),
        })
    return mappings


def _fetch_upnp_info(location_url: str) -> dict:
    try:
        resp = requests.get(location_url, timeout=2, verify=False)
        root = ET.fromstring(resp.content)
        ns   = "urn:schemas-upnp-org:device-1-0"
        dev  = root.find(f".//{{{ns}}}device")
        if dev is None:
            return {}

        def g(tag: str) -> str | None:
            el = dev.find(f"{{{ns}}}{tag}")
            return el.text.strip() if el is not None and el.text else None

        info = {k: v for k, v in {
            "friendly_name": g("friendlyName"),
            "manufacturer":  g("manufacturer"),
            "model":         g("modelName"),
            "model_desc":    g("modelDescription"),
            "serial":        g("serialNumber"),
        }.items() if v}

        try:
            mappings = _igd_port_mappings(location_url, root, ns)
        except Exception:
            mappings = []
        if mappings:
            info["port_mappings"] = mappings
            info["internal_ips"]  = sorted({
                m["internal_client"] for m in mappings if m.get("internal_client")
            })
        return info
    except Exception:
        return {}


# ── mDNS / Bonjour ────────────────────────────────────────────────────────────

def mdns_scan(timeout: int = 5) -> dict:
    """
    mDNS servislerini pasif olarak dinler.
    {ip: [{service, name, port, properties}, ...]} döner.
    """
    if not ZEROCONF_AVAILABLE:
        return {}

    discovered: dict = {}
    lock = threading.Lock()

    class _Listener(ServiceListener):
        def add_service(self, zc, type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name, timeout=1000)
                if not info or not info.addresses:
                    return
                props: dict = {}
                if info.properties:
                    for k, v in info.properties.items():
                        key = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                        props[key] = val
                for addr_bytes in info.addresses:
                    ip  = str(_ipaddress.ip_address(addr_bytes))
                    svc = {
                        "service":    type_.replace("._tcp.local.", "").replace("._udp.local.", ""),
                        "name":       name.replace(f".{type_}", ""),
                        "port":       info.port,
                        "properties": props,
                    }
                    with lock:
                        discovered.setdefault(ip, []).append(svc)
            except Exception:
                pass

        def remove_service(self, *_) -> None:
            pass

        def update_service(self, *_) -> None:
            pass

    try:
        zc = Zeroconf()
        _browsers = [ServiceBrowser(zc, st, _Listener()) for st in MDNS_SERVICE_TYPES]
        time.sleep(timeout)
        zc.close()
    except Exception:
        pass
    return discovered


def extract_apple_model(mdns_services: list) -> str | None:
    """mDNS _device-info TXT kaydındaki 'model' alanından Apple model adını çeker."""
    for svc in mdns_services:
        if "device-info" in svc.get("service", ""):
            model_id = svc.get("properties", {}).get("model")
            if model_id:
                return APPLE_MODELS.get(model_id, model_id)
    return None


# ── NetBIOS ───────────────────────────────────────────────────────────────────

_NB_QUERY = (
    b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20"
    b"\x43\x4b"
    + b"\x43\x41" * 14
    + b"\x41\x41"
    + b"\x00\x00\x21\x00\x01"
)


def netbios_query(ip: str) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.sendto(_NB_QUERY, (ip, 137))
        data = s.recv(1024)
        s.close()
        if len(data) < 32:
            return None
        pos = 12
        if data[pos] == 0xC0:
            pos += 2
        elif data[pos] == 0x20:
            pos += 34
        else:
            return None
        pos += 16  # skip resource record header + MAC
        if pos >= len(data):
            return None
        num_names = data[pos]
        pos += 1
        for _ in range(num_names):
            if pos + 18 > len(data):
                break
            name      = data[pos:pos + 15].decode("ascii", errors="ignore").strip()
            name_type = data[pos + 15]
            if name_type == 0x00 and name and "\x00" not in name:
                return name
            pos += 18
    except Exception:
        pass
    return None


# ── SNMP ──────────────────────────────────────────────────────────────────────

_SNMP_OIDS = {
    "description": "1.3.6.1.2.1.1.1.0",
    "hostname":    "1.3.6.1.2.1.1.5.0",
    "location":    "1.3.6.1.2.1.1.6.0",
    "uptime":      "1.3.6.1.2.1.1.3.0",
}

_SNMP_ARP_TABLE_OID = "1.3.6.1.2.1.4.22.1.3"  # ipNetToMediaNetAddress


async def _snmp_walk_arp(ip: str, community: str, timeout: int) -> list[str]:
    from pysnmp.hlapi.v3arch.asyncio import walk_cmd

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
    ips: list[str] = []
    async for err_ind, err_status, _, var_binds in walk_cmd(
        engine,
        CommunityData(community, mpModel=0),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(_SNMP_ARP_TABLE_OID)),
        lexicographicMode=False,
        maxRows=MAX_SNMP_ARP_ENTRIES,
    ):
        if err_ind or err_status:
            break
        for _, val in var_binds:
            addr = str(val).strip()
            if addr and addr not in ips:
                ips.append(addr)
    return ips


def snmp_arp_table(ip: str, community: str = "public", timeout: int = 1) -> list[str]:
    """
    SNMP ARP tablosunu (ipNetToMediaNetAddress) walk ederek cihazın gördüğü
    iç ağ IP'lerini döner. Salt okuma — sadece mevcut bir OID'i sorgular.
    """
    if not SNMP_AVAILABLE:
        return []
    try:
        return asyncio.run(_snmp_walk_arp(ip, community, timeout))
    except Exception:
        return []


async def _snmp_get_all(ip: str, community: str, timeout: int) -> dict:
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
    result: dict = {}
    for key, oid in _SNMP_OIDS.items():
        err_ind, err_status, _, var_binds = await get_cmd(
            engine,
            CommunityData(community, mpModel=0),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if not err_ind and not err_status:
            for vb in var_binds:
                val = str(vb[1]).strip()
                if val:
                    result[key] = val
    return result


def snmp_query(ip: str, community: str = "public", timeout: int = 1) -> dict | None:
    if not SNMP_AVAILABLE:
        return None
    try:
        result = asyncio.run(_snmp_get_all(ip, community, timeout))
    except Exception:
        result = {}

    arp = snmp_arp_table(ip, community, timeout)
    if arp:
        result["arp_table"] = arp

    return result or None

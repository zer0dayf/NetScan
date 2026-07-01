"""Ortak test fixture'ları ve yardımcı fonksiyonlar."""

import sys
import os
import pytest

# Proje kökünü Python path'ine ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Örnek cihaz fixture'ları ──────────────────────────────────────────────────

@pytest.fixture
def sample_device() -> dict:
    """Tek bir cihazın tam tarama sonucu."""
    return {
        "ip":            "192.168.1.100",
        "mac":           "bc:24:11:62:fc:30",
        "vendor":        "Proxmox Server Solutions GmbH",
        "hostname":      "pi.hole",
        "netbios":       None,
        "dhcp_hostname": "pihole",
        "dhcp_os":       "Linux",
        "device_model":  None,
        "os_hint":       "Linux (TTL=64, Win=65160)",
        "snmp":          None,
        "upnp":          None,
        "mdns":          None,
        "cast":          None,
        "wsd":           None,
        "ipp":           None,
        "roku":          None,
        "ports": [
            {"type": "banner", "port": 22,  "data": "Banner: SSH-2.0-OpenSSH_10.0"},
            {"type": "http",   "port": 80,  "data": {
                "port": 80, "protocol": "HTTP",
                "title": "Pi-hole pi-hole",
                "server": "Bilinmiyor",
                "hash": -1746033889,
                "identified_as": "Pi-hole",
            }},
        ],
    }


@pytest.fixture
def sample_scan_result(sample_device) -> list[dict]:
    """scan_subnet + scan_device'ın döndürdüğü tam yapı."""
    return [
        {
            "iface":   "eth0",
            "subnet":  "192.168.1.0/24",
            "devices": [sample_device],
        }
    ]


@pytest.fixture
def mock_vendor_db(monkeypatch):
    """Test için küçük bir vendor DB yükler; gerçek dosyayı okumaz."""
    import netscan.vendor as v
    test_db = {
        "BC2411": "Proxmox Server Solutions GmbH",  # 24-bit
        "A4C138": "Apple, Inc.",                    # 24-bit
        "105A95": "TP-Link Systems Inc.",            # 24-bit
        "00E04C": "REALTEK SEMICONDUCTOR CORP.",    # 24-bit
    }
    monkeypatch.setattr(v, "_MAC_VENDOR_DB", test_db)
    monkeypatch.setattr(v, "_load_mac_vendor_db", lambda: None)
    return test_db


@pytest.fixture
def apple_mdns_services() -> list[dict]:
    """iPhone 13 Pro Max'i temsil eden mDNS servisleri."""
    return [
        {
            "service":    "_device-info._tcp",
            "name":       "Efe's iPhone",
            "port":       0,
            "properties": {"model": "iPhone14,3"},
        },
        {
            "service":    "_http._tcp",
            "name":       "Efe's iPhone HTTP",
            "port":       80,
            "properties": {},
        },
    ]

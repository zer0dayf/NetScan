"""Tüm sabit değerler: hash tabloları, imzalar, port listesi, Apple model tablosu."""

FAVICON_HASHES: dict[int, str] = {
    933706437:    "Nextcloud",
    -1856593110:  "Nextcloud",
    -1165993802:  "Pi-hole",
    -1746033889:  "Pi-hole",
    -1224213758:  "Portainer",
    -346532452:   "Uptime Kuma",
    737326330:    "Uptime Kuma",
    -101180234:   "Proxmox VE",
    213144638:    "Proxmox VE",
    -1677277545:  "WireGuard",
}

HTML_SIGNATURES: dict[str, str] = {
    "pihole":      "Pi-hole",
    "portainer":   "Portainer",
    "nextcloud":   "Nextcloud",
    "uptime-kuma": "Uptime Kuma",
    "pve-manager": "Proxmox VE",
    "wireguard":   "WireGuard",
}

TITLE_SIGNATURES: dict[str, str] = {
    "pi-hole":        "Pi-hole",
    "portainer":      "Portainer",
    "nextcloud":      "Nextcloud",
    "uptime kuma":    "Uptime Kuma",
    "proxmox":        "Proxmox VE",
    "wireguard":      "WireGuard",
    "openwrt":        "OpenWrt",
    "pfsense":        "pfSense",
    "opnsense":       "OPNsense",
    "home assistant": "Home Assistant",
    "grafana":        "Grafana",
    "jellyfin":       "Jellyfin",
    "plex":           "Plex Media Server",
    "synology":       "Synology DSM",
    "truenas":        "TrueNAS",
    "unifi":          "UniFi",
    "adguard":        "AdGuard Home",
    "roku":           "Roku",
    "sonos":          "Sonos",
}

DEFAULT_PORTS: list[int] = [
    21, 22, 23, 53, 80,
    139,    # NetBIOS Session (SMB üzeri)
    443, 445,
    548,    # AFP (Apple File Sharing)
    631,    # IPP (yazıcılar)
    1400,   # Sonos
    1883,   # MQTT
    2049,   # NFS
    3000,   # Grafana / çeşitli
    3001,   # Uptime Kuma
    3306,   # MySQL / MariaDB
    3389,   # RDP (Windows Uzak Masaüstü)
    5000,   # Synology / çeşitli
    5357,   # WSD (Windows)
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    8006,   # Proxmox
    8008,   # Google Cast
    8009,   # Google Cast alt
    8060,   # Roku ECP
    8080,   # HTTP alternatif
    8123,   # Home Assistant
    8443,   # HTTPS alternatif
    9100,   # JetDirect
    9443,   # HTTPS alternatif
    32400,  # Plex
    51821,  # WireGuard UI
    51832,  # WireGuard UI alt
]

# HTTP parmak izinde önce https denenecek portlar (TLS-only servisler) —
# aksi halde http isteği boşuna timeout'a düşer veya çöp döner.
TLS_PREFERRED_PORTS: set[int] = {443, 8006, 8443, 9443, 32400}

# Dış ağ TCP SYN ping'i için yaygın portlar (host discovery amaçlı)
EXTERNAL_PING_PORTS: list[int] = [
    80, 443, 22, 21, 25, 3389, 8080, 53, 110, 143, 445, 3306, 8443, 5900,
]

# Dış ağ CIDR taramasında güvenlik/tamamlanabilirlik sınırı
MAX_EXTERNAL_HOSTS = 256

# UPnP-IGD port mapping enumerasyonunda ve SNMP ARP tablosu walk'ında sınır
MAX_PORT_MAPPING_ENTRIES = 32
MAX_SNMP_ARP_ENTRIES     = 64

MDNS_SERVICE_TYPES: list[str] = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_ftp._tcp.local.",
    "_smb._tcp.local.",
    "_workstation._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_device-info._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_homekit._tcp.local.",
    "_raop._tcp.local.",
]

IEEE_OUI_SOURCES: dict[str, list[str]] = {
    "MA-L (24-bit)": [
        "https://standards-oui.ieee.org/oui/oui.txt",
        "https://standards-oui.ieee.org/oui.csv",
    ],
    "MA-M (28-bit)": [
        "https://standards-oui.ieee.org/oui28/mam.txt",
        "https://standards-oui.ieee.org/oui28.csv",
    ],
    "MA-S (36-bit)": [
        "https://standards-oui.ieee.org/oui36/oui36.txt",
        "https://standards-oui.ieee.org/oui36.csv",
    ],
}

WIRESHARK_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"

WIRESHARK_MANUF_PATHS: list[str] = [
    "/usr/share/wireshark/manuf",
    "/usr/lib/wireshark/manuf",
    "/usr/share/wireshark/wireshark/manuf",
    "/etc/wireshark/manuf",
]

# Apple Model Identifier → insan okunabilir cihaz adı
APPLE_MODELS: dict[str, str] = {
    # ── iPhone ──────────────────────────────────────────────────────────────
    "iPhone8,1": "iPhone 6s",          "iPhone8,2": "iPhone 6s Plus",
    "iPhone8,4": "iPhone SE (1st gen)",
    "iPhone9,1": "iPhone 7",           "iPhone9,2": "iPhone 7 Plus",
    "iPhone9,3": "iPhone 7",           "iPhone9,4": "iPhone 7 Plus",
    "iPhone10,1": "iPhone 8",          "iPhone10,2": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X",          "iPhone10,4": "iPhone 8",
    "iPhone10,5": "iPhone 8 Plus",     "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS",         "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",     "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",         "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2nd gen)",
    "iPhone13,1": "iPhone 12 mini",    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",     "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",     "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd gen)", "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",     "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",         "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",     "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",     "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",         "iPhone17,4": "iPhone 16 Plus",

    # ── iPad ────────────────────────────────────────────────────────────────
    "iPad7,5": "iPad (6th gen)",       "iPad7,6": "iPad (6th gen)",
    "iPad7,11": "iPad (7th gen)",      "iPad7,12": "iPad (7th gen)",
    "iPad11,6": "iPad (8th gen)",      "iPad11,7": "iPad (8th gen)",
    "iPad12,1": "iPad (9th gen)",      "iPad12,2": "iPad (9th gen)",
    "iPad13,18": "iPad (10th gen)",    "iPad13,19": "iPad (10th gen)",
    "iPad13,1": "iPad Air (4th gen)",  "iPad13,2": "iPad Air (4th gen)",
    "iPad13,16": "iPad Air (5th gen)", "iPad13,17": "iPad Air (5th gen)",
    "iPad14,8": 'iPad Air 11" M2',     "iPad14,9": 'iPad Air 11" M2',
    "iPad14,10": 'iPad Air 13" M2',    "iPad14,11": 'iPad Air 13" M2',
    "iPad14,1": "iPad mini (6th gen)", "iPad14,2": "iPad mini (6th gen)",
    "iPad8,9": 'iPad Pro 11" (2nd gen)',  "iPad8,10": 'iPad Pro 11" (2nd gen)',
    "iPad8,11": 'iPad Pro 12.9" (4th gen)', "iPad8,12": 'iPad Pro 12.9" (4th gen)',
    "iPad13,4": 'iPad Pro 11" (3rd gen)', "iPad13,5": 'iPad Pro 11" (3rd gen)',
    "iPad13,8": 'iPad Pro 12.9" (5th gen)', "iPad13,9": 'iPad Pro 12.9" (5th gen)',
    "iPad14,3": 'iPad Pro 11" (4th gen)', "iPad14,4": 'iPad Pro 11" (4th gen)',
    "iPad14,5": 'iPad Pro 12.9" (6th gen)', "iPad14,6": 'iPad Pro 12.9" (6th gen)',
    "iPad16,3": 'iPad Pro 11" M4',    "iPad16,4": 'iPad Pro 11" M4',
    "iPad16,5": 'iPad Pro 13" M4',    "iPad16,6": 'iPad Pro 13" M4',

    # ── Mac ─────────────────────────────────────────────────────────────────
    "MacBookAir10,1": "MacBook Air M1",
    "Mac14,2": 'MacBook Air 13" M2',
    "Mac15,12": 'MacBook Air 13" M3',  "Mac15,13": 'MacBook Air 15" M3',
    "MacBookPro17,1": 'MacBook Pro 13" M1',
    "MacBookPro18,1": 'MacBook Pro 14" M1 Pro', "MacBookPro18,2": 'MacBook Pro 14" M1 Max',
    "MacBookPro18,3": 'MacBook Pro 16" M1 Pro', "MacBookPro18,4": 'MacBook Pro 16" M1 Max',
    "Mac14,5": 'MacBook Pro 14" M2 Pro',  "Mac14,6": 'MacBook Pro 16" M2 Pro',
    "Mac14,9": 'MacBook Pro 14" M2',      "Mac14,10": 'MacBook Pro 16" M2 Max',
    "Mac15,3": 'MacBook Pro 14" M3 Pro',  "Mac15,6": 'MacBook Pro 14" M3',
    "Mac15,7": 'MacBook Pro 14" M3 Max',  "Mac15,8": 'MacBook Pro 16" M3 Pro',
    "Mac15,9": 'MacBook Pro 16" M3 Max',
    "iMac21,1": 'iMac 24" M1',    "iMac21,2": 'iMac 24" M1',
    "Mac15,4": 'iMac 24" M3',     "Mac15,5": 'iMac 24" M3',
    "Macmini9,1": "Mac mini M1",  "Mac14,3": "Mac mini M2",
    "Mac14,12": "Mac mini M2 Pro", "Mac16,10": "Mac mini M4",
    "MacPro7,1": "Mac Pro (2019)", "Mac14,8": "Mac Pro (2023)",

    # ── Apple TV ────────────────────────────────────────────────────────────
    "AppleTV5,3": "Apple TV HD",
    "AppleTV6,2": "Apple TV 4K (1st gen)",
    "AppleTV11,1": "Apple TV 4K (2nd gen)",
    "AppleTV14,1": "Apple TV 4K (3rd gen)",

    # ── HomePod ─────────────────────────────────────────────────────────────
    "AudioAccessory1,1": "HomePod (1st gen)",
    "AudioAccessory5,1": "HomePod mini",
    "AudioAccessory6,1": "HomePod (2nd gen)",

    # ── Apple Watch ─────────────────────────────────────────────────────────
    "Watch6,1": "Apple Watch Series 6 40mm",  "Watch6,2": "Apple Watch Series 6 44mm",
    "Watch6,6": "Apple Watch Series 7 41mm",  "Watch6,7": "Apple Watch Series 7 45mm",
    "Watch6,10": "Apple Watch SE 2 40mm",     "Watch6,11": "Apple Watch SE 2 44mm",
    "Watch6,14": "Apple Watch Series 8 41mm", "Watch6,15": "Apple Watch Series 8 45mm",
    "Watch6,18": "Apple Watch Ultra",
    "Watch7,1": "Apple Watch Series 9 41mm",  "Watch7,2": "Apple Watch Series 9 45mm",
    "Watch7,3": "Apple Watch Ultra 2",
    "Watch7,5": "Apple Watch Series 10 42mm", "Watch7,6": "Apple Watch Series 10 46mm",

    # ── AirPods ─────────────────────────────────────────────────────────────
    "AirPods2,1": "AirPods (2nd gen)",
    "iProd8,1": "AirPods Pro",
    "iProd8,6": "AirPods (3rd gen)",
    "iProd8,5": "AirPods Max",
    "AirPodsPro1,1": "AirPods Pro (2nd gen)",
}

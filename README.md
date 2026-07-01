<div align="center">

# NetScan

**Advanced Local Network & Service Scanner**

[![CI](https://github.com/zer0dayf/NetScan/actions/workflows/ci.yml/badge.svg)](https://github.com/zer0dayf/NetScan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

[🇺🇸 English](#english) · [🇹🇷 Türkçe](#türkçe)

</div>

---

<a name="english"></a>
## 🇺🇸 English

A comprehensive LAN analysis tool — from ARP discovery and MAC vendor lookup to HTTP fingerprinting, DHCP passive listening, and Apple device model detection.

### Features

| Category | What It Detects |
|---|---|
| **Device Discovery** | ARP broadcast, 53K+ MAC vendor records (IEEE 24/28/36-bit) |
| **OS Detection** | TCP/IP stack fingerprint (TTL + window size), DHCP vendor class |
| **HTTP Services** | Pi-hole, Proxmox VE, Nextcloud, WireGuard, Uptime Kuma, Portainer, Home Assistant, Plex, Jellyfin, Grafana, UniFi, AdGuard, and more |
| **Streaming Devices** | Google Cast (Chromecast, Android TV, Google Home), Roku ECP |
| **Printers** | IPP/CUPS (model, printer list), JetDirect |
| **Windows Devices** | WSD device name and model, SMB/Samba shares, NetBIOS hostname |
| **Apple Devices** | mDNS `_device-info` + 130+ Apple model table (iPhone/iPad/Mac/AppleTV/HomePod) |
| **DHCP** | Passive listening — hostname, Android/Windows/iOS OS detection |
| **Discovery Protocols** | UPnP/SSDP, mDNS/Bonjour, NetBIOS, SNMP (optional) |
| **Export** | JSON, TXT, PDF (Unicode) |

### Installation

```bash
git clone https://github.com/zer0dayf/NetScan.git
cd NetScan

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Update vendor database (53K+ IEEE records)
sudo python3 main.py --update-db

# Make executable and run
chmod +x netscan.sh
./netscan.sh
```

### Usage

```bash
# Basic scan
sudo python3 main.py

# Custom ports
sudo python3 main.py --ports 22,80,443,8080

# Export PDF report
sudo python3 main.py --output report --format pdf

# JSON output (for automation/CI)
sudo python3 main.py --output scan --format json

# DHCP passive listener (capture newly connecting devices, Ctrl+C to stop)
sudo python3 main.py --dhcp-only

# Update vendor database
sudo python3 main.py --update-db
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `--ports` | Comma-separated port list | Built-in wide port set |
| `--timeout` | Port connection timeout (seconds) | `1.0` |
| `--output` | Output filename (no extension) | — |
| `--format` | `json` / `txt` / `pdf` | Interactive prompt |
| `--update-db` | Download and update IEEE OUI database | — |
| `--dhcp-timeout` | DHCP listening duration (seconds) | `8` |
| `--dhcp-only` | DHCP-only daemon mode | — |

### Project Structure

```
NetScan/
├── netscan/
│   ├── __init__.py        # Version and metadata
│   ├── constants.py       # Favicon hashes, HTML/title signatures, Apple models
│   ├── vendor.py          # MAC vendor DB loading, lookup, IEEE update
│   ├── network.py         # Subnet discovery, ARP scanning
│   ├── discovery.py       # DHCP, mDNS, NetBIOS, SNMP, UPnP/SSDP
│   ├── fingerprint.py     # Banner, SMB, HTTP, TCP OS, Cast, WSD, IPP, Roku
│   ├── scanner.py         # Per-device parallel probe orchestration
│   ├── output.py          # Terminal output
│   └── export.py          # JSON / TXT / PDF export
├── data/
│   └── mac-vendor.txt     # IEEE OUI database (53K+ records)
├── tests/
│   ├── conftest.py        # Shared fixtures
│   ├── test_vendor.py     # MAC vendor parser & lookup tests
│   ├── test_fingerprint.py# OS detection & banner tests
│   ├── test_discovery.py  # DHCP, Apple model, constants tests
│   ├── test_export.py     # Export function tests
│   └── generated/         # AI-generated tests (auto)
├── scripts/
│   └── ai_test_gen.py     # AI-powered test generation pipeline
├── .github/workflows/
│   ├── ci.yml             # Run tests on every push
│   └── ai-review.yml      # AI test generation + bug review on code changes
├── main.py                # CLI entry point
├── netscan.sh             # Bash wrapper (auto sudo)
└── requirements.txt
```

### AI-Powered Test Pipeline

When code changes are pushed, the AI pipeline automatically:

1. Computes `git diff` on changed `netscan/` files
2. Sends diff + source to an AI model → generates new test cases
3. Runs `pytest` on generated tests
4. Classifies failures:
   - **False positive** → AI fixes the test and re-runs
   - **True positive** → writes `bug_report.md`, posts as PR comment / GitHub issue

**Supported AI providers** — set whichever key you have:

```bash
# Anthropic (Claude)
ANTHROPIC_API_KEY=sk-ant-...

# DeepSeek
DEEPSEEK_API_KEY=sk-...

# OpenAI
OPENAI_API_KEY=sk-...
```

Add the key as a GitHub Actions secret (`Settings → Secrets → Actions`).  
Optionally set `AI_PROVIDER` / `AI_MODEL` as repository variables to override auto-detection.

### Requirements

- Python ≥ 3.10
- Root / sudo privileges (ARP scanning requires raw socket access)

**Required:** `scapy`, `requests`, `beautifulsoup4`, `netifaces`, `mmh3`, `fpdf2`, `urllib3`  
**Optional:** `zeroconf` (mDNS/Bonjour), `pysnmp` (SNMP queries)

### About DHCP Passive Listening

DHCP sniffing is fully passive — no packets are sent and no devices are forced to reconnect. It only captures existing broadcast traffic:

- **During a normal scan** (8 s window): catches any device that reconnects
- **`--dhcp-only` mode**: daemon, prints a live table of every new connection

```
MAC                 Vendor               Hostname               OS / Vendor Class
───────────────────────────────────────────────────────────────────────────────────
aa:bb:cc:dd:ee:ff   Apple, Inc.          Efe's iPhone           macOS / iOS
11:22:33:44:55:66   Samsung Electronics  Galaxy-S24             Android 14
```

---

<a name="türkçe"></a>
## 🇹🇷 Türkçe

ARP keşfinden HTTP parmak izine, DHCP pasif dinlemeden Apple cihaz modeli tespitine kadar tek araçta kapsamlı LAN analizi.

### Özellikler

| Kategori | Neler Tespit Edilir |
|---|---|
| **Cihaz Keşfi** | ARP broadcast, 53K+ MAC vendor kaydı (IEEE 24/28/36-bit) |
| **OS Tespiti** | TCP/IP stack fingerprint (TTL + window size), DHCP vendor class |
| **HTTP Servisleri** | Pi-hole, Proxmox VE, Nextcloud, WireGuard, Uptime Kuma, Portainer, Home Assistant, Plex, Jellyfin, Grafana, UniFi, AdGuard ve daha fazlası |
| **Akış Cihazları** | Google Cast (Chromecast, Android TV, Google Home), Roku ECP |
| **Yazıcılar** | IPP/CUPS (model, yazıcı listesi), JetDirect |
| **Windows Cihazlar** | WSD cihaz adı ve model, SMB/Samba paylaşımı, NetBIOS hostname |
| **Apple Cihazlar** | mDNS `_device-info` + 130+ Apple model tablosu (iPhone/iPad/Mac/AppleTV/HomePod) |
| **DHCP** | Pasif dinleme — hostname, Android/Windows/iOS OS tespiti |
| **Keşif Protokolleri** | UPnP/SSDP, mDNS/Bonjour, NetBIOS, SNMP (opsiyonel) |
| **Export** | JSON, TXT, PDF (Unicode) |

### Kurulum

```bash
git clone https://github.com/zer0dayf/NetScan.git
cd NetScan

# Bağımlılıkları yükle
pip install -r requirements.txt --break-system-packages

# Vendor DB'yi güncelle (53K+ IEEE kaydı)
sudo python3 main.py --update-db

# Çalıştır
chmod +x netscan.sh
./netscan.sh
```

### Kullanım

```bash
# Temel tarama
sudo python3 main.py

# Özel portlar
sudo python3 main.py --ports 22,80,443,8080

# PDF raporu
sudo python3 main.py --output rapor --format pdf

# JSON çıktısı
sudo python3 main.py --output tarama --format json

# DHCP pasif dinleyici (Ctrl+C ile dur)
sudo python3 main.py --dhcp-only

# Vendor DB güncelle
sudo python3 main.py --update-db
```

### AI Test Pipeline

Kod değişikliği push'landığında otomatik olarak:

1. `git diff` ile değişen `netscan/` dosyaları tespit edilir
2. AI modeline diff + kaynak gönderilir → yeni test case'ler üretilir
3. `pytest` çalıştırılır
4. Hatalar sınıflandırılır:
   - **False positive** → AI testi düzeltir, tekrar çalışır
   - **True positive** → `bug_report.md` yazar, PR yorumu / GitHub issue açar

**Desteklenen AI sağlayıcıları** — hangisinin key'i varsa o kullanılır:

| Sağlayıcı | Secret Adı |
|---|---|
| Anthropic (Claude) | `ANTHROPIC_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |

GitHub Actions'ta `Settings → Secrets → Actions` altına ilgili key'i ekle.

---

## Author

**Efe Gungor**
- 📧 [gungor.onerefe@student.atilim.edu.tr](mailto:gungor.onerefe@student.atilim.edu.tr)
- 📧 [onerefegungor@gmail.com](mailto:onerefegungor@gmail.com)

## License

MIT

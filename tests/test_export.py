"""Export ve terminal çıktısı testleri."""

import json
import os
import tempfile
import pytest
from netscan.output import best_hostname
from netscan.export import export_json, export_txt, ensure_ext, ask_export_format


# ── best_hostname ─────────────────────────────────────────────────────────────

class TestBestHostname:
    def test_dhcp_has_priority_over_dns(self):
        dev = {"dhcp_hostname": "pihole-dhcp", "hostname": "pi.hole", "netbios": None}
        assert best_hostname(dev) == "pihole-dhcp"

    def test_dns_fallback_when_no_dhcp(self):
        dev = {"dhcp_hostname": None, "hostname": "pi.hole", "netbios": None}
        assert best_hostname(dev) == "pi.hole"

    def test_netbios_fallback(self):
        dev = {"dhcp_hostname": None, "hostname": None, "netbios": "PIHOLE"}
        assert best_hostname(dev) == "PIHOLE"

    def test_all_none_returns_empty_string(self):
        dev = {"dhcp_hostname": None, "hostname": None, "netbios": None}
        assert best_hostname(dev) == ""

    def test_empty_dhcp_hostname_falls_through(self):
        dev = {"dhcp_hostname": "", "hostname": "pi.hole", "netbios": None}
        # "" falsy → DNS'e düşmeli
        assert best_hostname(dev) == "pi.hole"

    def test_missing_keys_returns_empty(self):
        assert best_hostname({}) == ""


# ── ensure_ext ────────────────────────────────────────────────────────────────

class TestEnsureExt:
    def test_json_ext_added(self):
        assert ensure_ext("rapor", "json") == "rapor.json"

    def test_txt_ext_added(self):
        assert ensure_ext("output", "txt") == "output.txt"

    def test_pdf_ext_added(self):
        assert ensure_ext("scan", "pdf") == "scan.pdf"

    def test_existing_ext_not_doubled(self):
        assert ensure_ext("rapor.json", "json") == "rapor.json"
        assert ensure_ext("scan.pdf", "pdf") == "scan.pdf"

    def test_path_with_directory(self):
        result = ensure_ext("/tmp/netscan/rapor", "json")
        assert result == "/tmp/netscan/rapor.json"


# ── export_json ───────────────────────────────────────────────────────────────

class TestExportJson:
    def test_creates_valid_json_file(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.json")
        export_json(sample_scan_result, path)
        assert os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_json_structure_preserved(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.json")
        export_json(sample_scan_result, path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data[0]["iface"] == "eth0"
        assert data[0]["subnet"] == "192.168.1.0/24"
        assert len(data[0]["devices"]) == 1

    def test_device_fields_in_json(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.json")
        export_json(sample_scan_result, path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        dev = data[0]["devices"][0]
        assert dev["ip"] == "192.168.1.100"
        assert dev["mac"] == "bc:24:11:62:fc:30"
        assert dev["vendor"] == "Proxmox Server Solutions GmbH"

    def test_unicode_characters_preserved(self, tmp_path):
        results = [{"iface": "eth0", "subnet": "192.168.1.0/24", "devices": [
            {"ip": "1.1.1.1", "mac": "aa:bb:cc:dd:ee:ff",
             "vendor": "Üretici Şirketi", "ports": []}
        ]}]
        path = str(tmp_path / "unicode.json")
        export_json(results, path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data[0]["devices"][0]["vendor"] == "Üretici Şirketi"

    def test_empty_devices_list(self, tmp_path):
        results = [{"iface": "eth0", "subnet": "10.0.0.0/24", "devices": []}]
        path = str(tmp_path / "empty.json")
        export_json(results, path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data[0]["devices"] == []


# ── export_txt ────────────────────────────────────────────────────────────────

class TestExportTxt:
    def test_creates_file(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        assert os.path.exists(path)

    def test_contains_ip(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        assert "192.168.1.100" in content

    def test_contains_mac(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        assert "bc:24:11:62:fc:30" in content

    def test_contains_vendor(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        assert "Proxmox Server Solutions GmbH" in content

    def test_contains_port_info(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        assert "Pi-hole" in content or "22" in content

    def test_empty_subnet_handled(self, tmp_path):
        results = [{"iface": "eth0", "subnet": "10.0.0.0/24", "devices": []}]
        path = str(tmp_path / "empty.txt")
        export_txt(results, path)
        content = open(path, encoding="utf-8").read()
        assert "bulunamadı" in content.lower() or "10.0.0.0/24" in content

    def test_host_in_output_when_present(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        # dhcp_hostname = "pihole"
        assert "pihole" in content

    def test_report_header_present(self, sample_scan_result, tmp_path):
        path = str(tmp_path / "result.txt")
        export_txt(sample_scan_result, path)
        content = open(path, encoding="utf-8").read()
        assert "NETSCAN" in content

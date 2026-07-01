"""MAC vendor DB: parser'lar ve lookup mantığı testleri."""

import pytest
from unittest.mock import patch
import netscan.vendor as vendor_mod
from netscan.vendor import (
    _parse_ieee_block,
    _parse_csv_oui,
    _parse_wireshark_manuf_raw,
    get_mac_vendor,
)


# ── _parse_ieee_block ─────────────────────────────────────────────────────────

class TestParseIeeeBlock:
    def test_standard_entry(self):
        raw = "00-00-0C   (hex)\t\tCisco Systems, Inc"
        result = _parse_ieee_block(raw)
        assert ("00000C", "Cisco Systems, Inc") in result

    def test_multiple_entries(self):
        raw = (
            "00-50-C2   (hex)\t\tIEEE Registration Authority\n"
            "BC-24-11   (hex)\t\tProxmox Server Solutions GmbH"
        )
        result = _parse_ieee_block(raw)
        assert len(result) == 2
        assert ("BC2411", "Proxmox Server Solutions GmbH") in result

    def test_empty_input(self):
        assert _parse_ieee_block("") == []

    def test_no_hex_lines(self):
        raw = "Some random text\nwithout hex markers\n"
        assert _parse_ieee_block(raw) == []

    def test_oui_normalized_uppercase(self):
        raw = "a4-c1-38   (hex)\t\tApple, Inc."
        result = _parse_ieee_block(raw)
        # OUI büyük harf olmalı
        assert any(oui.isupper() or oui.isnumeric() for oui, _ in result)
        assert ("A4C138", "Apple, Inc.") in result

    def test_dashes_stripped(self):
        raw = "10-5A-95   (hex)\t\tTP-Link Systems Inc."
        result = _parse_ieee_block(raw)
        assert ("105A95", "TP-Link Systems Inc.") in result


# ── _parse_csv_oui ────────────────────────────────────────────────────────────

class TestParseCsvOui:
    def test_standard_row(self):
        raw = "MA-L,00000C,Cisco Systems Inc\n"
        result = _parse_csv_oui(raw)
        assert ("00000C", "Cisco Systems Inc") in result

    def test_header_row_skipped(self):
        raw = "Registry,Assignment,Organization Name\nMA-L,BC2411,Proxmox Server Solutions GmbH"
        result = _parse_csv_oui(raw)
        assert len(result) == 1
        assert ("BC2411", "Proxmox Server Solutions GmbH") in result

    def test_quoted_vendor_name(self):
        raw = 'MA-L,A4C138,"Apple, Inc."'
        result = _parse_csv_oui(raw)
        assert ("A4C138", "Apple, Inc.") in result

    def test_empty_input(self):
        assert _parse_csv_oui("") == []

    def test_incomplete_row_skipped(self):
        raw = "MA-L,00000C"  # eksik vendor
        result = _parse_csv_oui(raw)
        assert result == []


# ── _parse_wireshark_manuf_raw ────────────────────────────────────────────────

class TestParseWiresharkManufRaw:
    def test_standard_entry(self):
        raw = "00:00:0C\tCisco\tCisco Systems"
        result = _parse_wireshark_manuf_raw(raw)
        assert ("00000C", "Cisco Systems") in result

    def test_comment_skipped(self):
        raw = "# This is a comment\n00:00:0C\tCisco\tCisco Systems"
        result = _parse_wireshark_manuf_raw(raw)
        assert len(result) == 1

    def test_prefix_slash_stripped(self):
        raw = "00:50:C2:00:30/28\tIEEE\tIEEE Registration Authority"
        result = _parse_wireshark_manuf_raw(raw)
        keys = [k for k, _ in result]
        # "/" öncesi prefix kullanılmalı
        assert all("/" not in k for k in keys)

    def test_short_entry_two_columns(self):
        raw = "A4:C1:38\tApple Inc"
        result = _parse_wireshark_manuf_raw(raw)
        assert ("A4C138", "Apple Inc") in result

    def test_empty_input(self):
        assert _parse_wireshark_manuf_raw("") == []

    def test_colon_stripped_from_key(self):
        raw = "BC:24:11\tProxmox\tProxmox Server Solutions GmbH"
        result = _parse_wireshark_manuf_raw(raw)
        assert ("BC2411", "Proxmox Server Solutions GmbH") in result


# ── get_mac_vendor ────────────────────────────────────────────────────────────

class TestGetMacVendor:
    def test_known_24bit_oui(self, mock_vendor_db):
        result = get_mac_vendor("BC:24:11:62:FC:30")
        assert result == "Proxmox Server Solutions GmbH"

    def test_known_apple_oui(self, mock_vendor_db):
        result = get_mac_vendor("A4:C1:38:00:00:01")
        assert result == "Apple, Inc."

    def test_unknown_mac_returns_fallback(self, mock_vendor_db):
        result = get_mac_vendor("FF:FF:FF:FF:FF:FF")
        assert "Bilinmeyen" in result or "Sanal" in result

    def test_mac_format_with_dashes(self, mock_vendor_db):
        result = get_mac_vendor("BC-24-11-00-00-01")
        assert result == "Proxmox Server Solutions GmbH"

    def test_mac_format_lowercase(self, mock_vendor_db):
        result = get_mac_vendor("a4:c1:38:11:22:33")
        assert result == "Apple, Inc."

    def test_locally_administered_mac(self, mock_vendor_db):
        # İkinci bit set ise locally administered (örn: 7e:...)
        result = get_mac_vendor("7E:09:C3:43:BB:ED")
        assert "Bilinmeyen" in result or "Sanal" in result

    def test_28bit_prefix_priority(self, monkeypatch):
        """28-bit MA-M kaydı, 24-bit MA-L kaydına göre öncelikli olmalı."""
        import netscan.vendor as v
        db = {
            "A4C138": "Apple, Inc.",        # 24-bit (6 hex chars)
            "A4C138F": "Apple Watch LLC",   # 28-bit (7 hex chars) — uydurma
        }
        monkeypatch.setattr(v, "_MAC_VENDOR_DB", db)
        monkeypatch.setattr(v, "_load_mac_vendor_db", lambda: None)
        result = get_mac_vendor("A4:C1:38:F0:00:01")
        assert result == "Apple Watch LLC"

    def test_empty_mac(self, mock_vendor_db):
        result = get_mac_vendor("00:00:00:00:00:00")
        # DB'de 000000 yok, fallback dönmeli
        assert isinstance(result, str)

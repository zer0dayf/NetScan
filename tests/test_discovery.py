"""Keşif modülü: DHCP OS tespiti, Apple model çıkarımı, mDNS, NetBIOS testleri."""

import pytest
from netscan.discovery import _dhcp_os_hint, extract_apple_model
from netscan.constants import APPLE_MODELS


# ── DHCP OS tahmini ───────────────────────────────────────────────────────────

class TestDhcpOsHint:
    def test_android_with_version(self):
        result = _dhcp_os_hint("android-dhcp-14")
        assert result is not None
        assert "Android" in result
        assert "14" in result

    def test_android_without_version(self):
        result = _dhcp_os_hint("android-dhcp-foo")
        assert result == "Android"

    def test_windows_msft(self):
        result = _dhcp_os_hint("MSFT 5.0")
        assert result == "Windows"

    def test_windows_msft_lowercase(self):
        result = _dhcp_os_hint("msft 5.0")
        assert result == "Windows"

    def test_apple_keyword(self):
        result = _dhcp_os_hint("Apple MacBook Air")
        assert result is not None
        assert "macOS" in result or "iOS" in result

    def test_mac_os_x_keyword(self):
        result = _dhcp_os_hint("mac os x 10.15")
        assert result is not None
        assert "macOS" in result

    def test_linux_dhcpcd(self):
        result = _dhcp_os_hint("dhcpcd-9.4.1:Linux-6.1")
        assert result == "Linux"

    def test_empty_string_returns_none(self):
        assert _dhcp_os_hint("") is None

    def test_none_input_returns_none(self):
        assert _dhcp_os_hint(None) is None

    def test_unknown_vendor_class_truncated_to_40(self):
        vc = "SomeUnknownVendorClassStringThatIsVeryLongAndShouldBeTruncated"
        result = _dhcp_os_hint(vc)
        assert result is not None
        assert len(result) <= 40

    def test_android_version_with_dot(self):
        result = _dhcp_os_hint("android-dhcp-13.1")
        assert result is not None
        assert "Android" in result
        assert "13.1" in result


# ── Apple model çıkarımı ──────────────────────────────────────────────────────

class TestExtractAppleModel:
    def test_iphone_14_3_is_iphone_13_pro_max(self, apple_mdns_services):
        result = extract_apple_model(apple_mdns_services)
        assert result == "iPhone 13 Pro Max"

    def test_no_device_info_service_returns_none(self):
        services = [
            {"service": "_http._tcp", "name": "test", "port": 80, "properties": {}}
        ]
        result = extract_apple_model(services)
        assert result is None

    def test_empty_list_returns_none(self):
        assert extract_apple_model([]) is None

    def test_unknown_model_id_returned_as_is(self):
        services = [
            {
                "service":    "_device-info._tcp",
                "name":       "Test Device",
                "port":       0,
                "properties": {"model": "UnknownDevice99,1"},
            }
        ]
        result = extract_apple_model(services)
        assert result == "UnknownDevice99,1"

    def test_device_info_without_model_key_returns_none(self):
        services = [
            {
                "service":    "_device-info._tcp",
                "name":       "Test",
                "port":       0,
                "properties": {"color": "black"},
            }
        ]
        assert extract_apple_model(services) is None

    def test_all_apple_model_ids_are_mapped(self):
        """APPLE_MODELS tablosundaki her modelin boş olmayan bir string değeri var."""
        for model_id, name in APPLE_MODELS.items():
            assert isinstance(name, str) and len(name) > 0, (
                f"{model_id} → '{name}' geçersiz"
            )

    @pytest.mark.parametrize("model_id,expected_name", [
        ("iPhone17,1",       "iPhone 16 Pro"),
        ("iPad16,5",         'iPad Pro 13" M4'),
        ("Mac16,10",         "Mac mini M4"),
        ("AppleTV14,1",      "Apple TV 4K (3rd gen)"),
        ("AudioAccessory5,1","HomePod mini"),
        ("Watch7,3",         "Apple Watch Ultra 2"),
    ])
    def test_known_model_ids(self, model_id, expected_name):
        services = [
            {
                "service":    "_device-info._tcp",
                "name":       "Device",
                "port":       0,
                "properties": {"model": model_id},
            }
        ]
        result = extract_apple_model(services)
        assert result == expected_name


# ── mDNS servis parse ─────────────────────────────────────────────────────────

class TestMdnsServiceParsing:
    def test_device_info_service_detected(self, apple_mdns_services):
        device_info = [
            s for s in apple_mdns_services
            if "device-info" in s.get("service", "")
        ]
        assert len(device_info) == 1

    def test_model_key_in_properties(self, apple_mdns_services):
        for svc in apple_mdns_services:
            if "device-info" in svc.get("service", ""):
                assert "model" in svc.get("properties", {})


# ── Sabitler bütünlük kontrolü ────────────────────────────────────────────────

class TestConstants:
    def test_default_ports_no_duplicates(self):
        from netscan.constants import DEFAULT_PORTS
        assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))

    def test_default_ports_are_valid(self):
        from netscan.constants import DEFAULT_PORTS
        for p in DEFAULT_PORTS:
            assert 1 <= p <= 65535, f"Geçersiz port: {p}"

    def test_title_signatures_keys_lowercase(self):
        from netscan.constants import TITLE_SIGNATURES
        for key in TITLE_SIGNATURES:
            assert key == key.lower(), f"Büyük harf anahtar: '{key}'"

    def test_favicon_hashes_values_are_strings(self):
        from netscan.constants import FAVICON_HASHES
        for h, name in FAVICON_HASHES.items():
            assert isinstance(h, int), f"Hash int olmalı: {h}"
            assert isinstance(name, str) and name, f"İsim string olmalı: {name}"

    def test_html_signatures_keys_are_lowercase(self):
        from netscan.constants import HTML_SIGNATURES
        for key in HTML_SIGNATURES:
            assert key == key.lower()

    def test_mdns_service_types_end_with_local(self):
        from netscan.constants import MDNS_SERVICE_TYPES
        for st in MDNS_SERVICE_TYPES:
            assert st.endswith(".local."), f"Geçersiz service type: {st}"

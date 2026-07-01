"""Port fingerprint modülü: OS tespiti ve banner cleaning testleri."""

import pytest
from unittest.mock import MagicMock, patch


# ── TCP OS tespiti ────────────────────────────────────────────────────────────

class TestTcpFingerprint:
    """tcp_fingerprint'in OS kararlarını SYN yanıtını mock'layarak test eder."""

    def _make_response(self, ttl: int, window: int, wscale=None):
        """Sahte bir Scapy paketi oluşturur."""
        resp = MagicMock()
        resp.ttl = ttl
        resp.haslayer.return_value = True
        tcp_layer = MagicMock()
        tcp_layer.window = window
        opts = {}
        if wscale is not None:
            opts["WScale"] = wscale
        tcp_layer.options = list(opts.items())
        resp.__getitem__ = lambda self_, cls: tcp_layer
        return resp

    @patch("netscan.fingerprint.sr1")
    def test_windows_ttl(self, mock_sr1):
        mock_sr1.return_value = self._make_response(ttl=128, window=64240, wscale=8)
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [80])
        assert result is not None
        assert "Windows" in result

    @patch("netscan.fingerprint.sr1")
    def test_network_equipment_high_ttl(self, mock_sr1):
        mock_sr1.return_value = self._make_response(ttl=255, window=4096)
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [80])
        assert result is not None
        assert "Router" in result or "Ekipmanı" in result

    @patch("netscan.fingerprint.sr1")
    def test_linux_ttl_64(self, mock_sr1):
        mock_sr1.return_value = self._make_response(ttl=64, window=65160, wscale=7)
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [22])
        assert result is not None
        assert "Linux" in result

    @patch("netscan.fingerprint.sr1")
    def test_embedded_linux_small_window(self, mock_sr1):
        mock_sr1.return_value = self._make_response(ttl=64, window=5840, wscale=None)
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [80])
        assert result is not None
        assert "Embedded" in result or "Router" in result

    @patch("netscan.fingerprint.sr1")
    def test_macos_window_65535(self, mock_sr1):
        mock_sr1.return_value = self._make_response(ttl=64, window=65535, wscale=None)
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [22])
        assert result is not None
        assert "macOS" in result or "iOS" in result

    @patch("netscan.fingerprint.sr1")
    def test_no_response_returns_none(self, mock_sr1):
        mock_sr1.return_value = None
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [22])
        assert result is None

    def test_empty_open_ports_returns_none(self):
        from netscan.fingerprint import tcp_fingerprint
        result = tcp_fingerprint("192.168.1.1", [])
        assert result is None


# ── ICMP TTL OS tahmini ───────────────────────────────────────────────────────

class TestGetTtlOsHint:
    @patch("netscan.fingerprint.sr1")
    def test_ttl_64_is_linux_or_macos(self, mock_sr1):
        pkt = MagicMock()
        pkt.ttl = 64
        mock_sr1.return_value = pkt
        from netscan.fingerprint import get_ttl_os_hint
        result = get_ttl_os_hint("192.168.1.1")
        assert result is not None
        assert "Linux" in result or "macOS" in result

    @patch("netscan.fingerprint.sr1")
    def test_ttl_128_is_windows(self, mock_sr1):
        pkt = MagicMock()
        pkt.ttl = 128
        mock_sr1.return_value = pkt
        from netscan.fingerprint import get_ttl_os_hint
        result = get_ttl_os_hint("192.168.1.1")
        assert result is not None
        assert "Windows" in result

    @patch("netscan.fingerprint.sr1")
    def test_ttl_255_is_router(self, mock_sr1):
        pkt = MagicMock()
        pkt.ttl = 255
        mock_sr1.return_value = pkt
        from netscan.fingerprint import get_ttl_os_hint
        result = get_ttl_os_hint("192.168.1.1")
        assert result is not None
        assert "Ekipmanı" in result or "Router" in result

    @patch("netscan.fingerprint.sr1")
    def test_no_response_returns_none(self, mock_sr1):
        mock_sr1.return_value = None
        from netscan.fingerprint import get_ttl_os_hint
        result = get_ttl_os_hint("192.168.1.1")
        assert result is None


# ── Banner cleaning ───────────────────────────────────────────────────────────

class TestBannerGrabbing:
    @patch("socket.socket")
    def test_clean_ssh_banner(self, mock_socket_class):
        sock = MagicMock()
        sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\nSome extra"
        mock_socket_class.return_value = sock
        from netscan.fingerprint import banner_grabbing
        result = banner_grabbing("192.168.1.1", 22)
        assert result is not None
        assert "SSH-2.0" in result
        # İkinci satır olmamalı
        assert "extra" not in result

    @patch("socket.socket")
    def test_binary_noise_stripped(self, mock_socket_class):
        sock = MagicMock()
        # Binary garbage + readable text
        sock.recv.return_value = b"\xff\xfe\x00SSH-2.0-Dropbear\n"
        mock_socket_class.return_value = sock
        from netscan.fingerprint import banner_grabbing
        result = banner_grabbing("192.168.1.1", 22)
        # Yazdırılamayan karakterler temizlenmeli
        if result:
            content = result.replace("Banner: ", "")
            assert all(c.isprintable() for c in content)

    @patch("socket.socket")
    def test_empty_response_returns_none(self, mock_socket_class):
        sock = MagicMock()
        sock.recv.return_value = b""
        mock_socket_class.return_value = sock
        from netscan.fingerprint import banner_grabbing
        result = banner_grabbing("192.168.1.1", 22)
        assert result is None

    @patch("socket.socket")
    def test_connection_refused_returns_none(self, mock_socket_class):
        sock = MagicMock()
        sock.connect.side_effect = ConnectionRefusedError()
        mock_socket_class.return_value = sock
        from netscan.fingerprint import banner_grabbing
        result = banner_grabbing("192.168.1.1", 22)
        assert result is None


# ── is_port_open ──────────────────────────────────────────────────────────────

class TestIsPortOpen:
    @patch("socket.socket")
    def test_open_port(self, mock_socket_class):
        sock = MagicMock()
        sock.connect_ex.return_value = 0
        mock_socket_class.return_value = sock
        from netscan.fingerprint import is_port_open
        assert is_port_open("192.168.1.1", 80) is True

    @patch("socket.socket")
    def test_closed_port(self, mock_socket_class):
        sock = MagicMock()
        sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_class.return_value = sock
        from netscan.fingerprint import is_port_open
        assert is_port_open("192.168.1.1", 80) is False

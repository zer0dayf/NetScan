import socket
import pytest
from unittest.mock import patch, MagicMock, call
from netscan.external import (
    resolve_target,
    icmp_ping,
    tcp_syn_ping,
    udp_ping,
    host_discovery,
    discover_alive_hosts,
)
from netscan.constants import EXTERNAL_PING_PORTS, MAX_EXTERNAL_HOSTS


class TestResolveTarget:
    def test_single_ip_returns_list_with_one_ip(self):
        result = resolve_target("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_returns_hosts(self):
        result = resolve_target("192.168.1.0/30")
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_cidr_with_single_address(self):
        result = resolve_target("10.0.0.1/32")
        assert result == ["10.0.0.1"]

    def test_large_cidr_truncated_to_max_external_hosts(self):
        result = resolve_target("10.0.0.0/24")
        assert len(result) <= MAX_EXTERNAL_HOSTS

    def test_domain_resolution_returns_ips(self):
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
            ]
            result = resolve_target("example.com")
            assert result == ["93.184.216.34", "93.184.216.35"]

    def test_domain_resolution_failure_returns_empty(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            result = resolve_target("nonexistent.domain.test")
            assert result == []

    def test_invalid_target_returns_empty(self):
        result = resolve_target("")
        assert result == []


class TestIcmpPing:
    @patch("netscan.external.sr1")
    def test_icmp_ping_success(self, mock_sr1):
        mock_sr1.return_value = MagicMock()
        assert icmp_ping("8.8.8.8") is True
        mock_sr1.assert_called_once()

    @patch("netscan.external.sr1")
    def test_icmp_ping_failure(self, mock_sr1):
        mock_sr1.return_value = None
        assert icmp_ping("8.8.8.8") is False

    @patch("netscan.external.sr1")
    def test_icmp_ping_exception(self, mock_sr1):
        mock_sr1.side_effect = Exception("Network error")
        assert icmp_ping("8.8.8.8") is False


class TestTcpSynPing:
    @patch("netscan.external.sr1")
    def test_tcp_syn_ping_success(self, mock_sr1):
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        mock_sr1.return_value = mock_response
        assert tcp_syn_ping("8.8.8.8") is True

    @patch("netscan.external.sr1")
    def test_tcp_syn_ping_all_ports_fail(self, mock_sr1):
        mock_sr1.return_value = None
        assert tcp_syn_ping("8.8.8.8") is False

    @patch("netscan.external.sr1")
    def test_tcp_syn_ping_exception_on_first_port(self, mock_sr1):
        mock_sr1.side_effect = [Exception("Timeout"), None]
        assert tcp_syn_ping("8.8.8.8") is False

    @patch("netscan.external.sr1")
    def test_tcp_syn_ping_uses_external_ping_ports(self, mock_sr1):
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        mock_sr1.return_value = mock_response
        tcp_syn_ping("8.8.8.8")
        calls = [call(dport=p, flags="S") for p in EXTERNAL_PING_PORTS]
        assert mock_sr1.call_count == 1


class TestUdpPing:
    @patch("netscan.external.sr1")
    def test_udp_ping_success(self, mock_sr1):
        mock_sr1.return_value = MagicMock()
        assert udp_ping("8.8.8.8") is True

    @patch("netscan.external.sr1")
    def test_udp_ping_failure(self, mock_sr1):
        mock_sr1.return_value = None
        assert udp_ping("8.8.8.8") is False

    @patch("netscan.external.sr1")
    def test_udp_ping_exception(self, mock_sr1):
        mock_sr1.side_effect = Exception("Network error")
        assert udp_ping("8.8.8.8") is False

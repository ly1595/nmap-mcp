"""Tests for the nmap scanner module."""

import pytest
from nmap_mcp.scanner import (
    parse_vuln_xml,
    parse_xml_output,
    validate_ports,
    validate_target,
)


class TestValidateTarget:
    """Tests for validate_target function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_target('192.168.1.1') == '192.168.1.1'
        assert validate_target('10.0.0.1') == '10.0.0.1'
        assert validate_target('127.0.0.1') == '127.0.0.1'

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_target('::1') == '::1'
        assert validate_target('fe80::1') == 'fe80::1'

    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        assert validate_target('192.168.1.0/24') == '192.168.1.0/24'
        assert validate_target('10.0.0.0/28') == '10.0.0.0/28'

    def test_valid_hostname(self):
        """Test valid hostnames."""
        assert validate_target('example.com') == 'example.com'
        assert validate_target('sub.example.com') == 'sub.example.com'
        assert validate_target('localhost') == 'localhost'

    def test_rejects_empty(self):
        """Test that empty targets are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_target('')

    def test_rejects_command_injection(self):
        """Test that command injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            validate_target('192.168.1.1; rm -rf /')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_target('192.168.1.1 | cat /etc/passwd')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_target('$(whoami)')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_target('`id`')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_target('192.168.1.1 & echo hacked')

    def test_rejects_large_network(self):
        """Test that overly large networks are rejected."""
        with pytest.raises(ValueError, match='exceeding the maximum'):
            validate_target('10.0.0.0/16')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_target('  192.168.1.1  ') == '192.168.1.1'


class TestValidatePorts:
    """Tests for validate_ports function."""

    def test_single_port(self):
        """Test single port specification."""
        assert validate_ports('22') == '22'
        assert validate_ports('80') == '80'

    def test_port_range(self):
        """Test port range specification."""
        assert validate_ports('1-1024') == '1-1024'

    def test_port_list(self):
        """Test comma-separated port list."""
        assert validate_ports('22,80,443') == '22,80,443'

    def test_protocol_specific(self):
        """Test protocol-specific port specification."""
        assert validate_ports('T:22,80,U:53') == 'T:22,80,U:53'

    def test_rejects_empty(self):
        """Test that empty port spec is rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_ports('')

    def test_rejects_invalid(self):
        """Test that invalid port specs are rejected."""
        with pytest.raises(ValueError, match='Invalid port'):
            validate_ports('abc')

        with pytest.raises(ValueError, match='Invalid port'):
            validate_ports('22;80')


class TestParseXmlOutput:
    """Tests for parse_xml_output function."""

    def test_basic_port_scan(self, sample_nmap_xml):
        """Test parsing a basic port scan result."""
        result = parse_xml_output(sample_nmap_xml)

        assert len(result.hosts) == 1

        host = result.hosts[0]
        assert host.ip == '192.168.1.1'
        assert host.hostname == 'router.local'
        assert host.state == 'up'
        assert len(host.ports) == 3

        # Check SSH port
        ssh = host.ports[0]
        assert ssh.port == 22
        assert ssh.state.value == 'open'
        assert ssh.service is not None
        assert ssh.service.name == 'ssh'
        assert ssh.service.product == 'OpenSSH'
        assert ssh.service.version == '8.9p1'

        # Check HTTP port
        http = host.ports[1]
        assert http.port == 80
        assert http.state.value == 'open'
        assert http.service.name == 'http'

        # Check closed port
        https = host.ports[2]
        assert https.port == 443
        assert https.state.value == 'closed'

    def test_os_detection(self, sample_nmap_os_xml):
        """Test parsing OS detection results."""
        result = parse_xml_output(sample_nmap_os_xml)

        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert len(host.os_matches) == 2

        best_match = host.os_matches[0]
        assert best_match.name == 'Linux 5.4 - 5.15'
        assert best_match.accuracy == 95
        assert best_match.os_family == 'Linux'
        assert best_match.os_gen == '5.X'

    def test_scan_stats(self, sample_nmap_xml):
        """Test parsing scan statistics."""
        result = parse_xml_output(sample_nmap_xml)

        assert result.scan_stats['hosts_up'] == '1'
        assert result.scan_stats['hosts_down'] == '0'
        assert result.scan_stats['hosts_total'] == '1'
        assert result.scan_stats['elapsed'] == '10.00'
        assert result.scan_stats['exit'] == 'success'

    def test_command_extraction(self, sample_nmap_xml):
        """Test that the nmap command is extracted."""
        result = parse_xml_output(sample_nmap_xml)
        assert 'nmap' in result.command
        assert '192.168.1.1' in result.command

    def test_invalid_xml(self):
        """Test handling of invalid XML input."""
        result = parse_xml_output('not valid xml')
        assert result.command == '(xml parse error)'
        assert len(result.warnings) > 0

    def test_discovery_scan(self, sample_discovery_xml):
        """Test parsing a host discovery scan."""
        result = parse_xml_output(sample_discovery_xml)

        assert len(result.hosts) == 3

        up_hosts = [h for h in result.hosts if h.state == 'up']
        down_hosts = [h for h in result.hosts if h.state == 'down']

        assert len(up_hosts) == 2
        assert len(down_hosts) == 1
        assert up_hosts[0].ip == '192.168.1.1'
        assert up_hosts[0].hostname == 'gateway.local'
        assert up_hosts[1].ip == '192.168.1.5'


class TestParseVulnXml:
    """Tests for parse_vuln_xml function."""

    def test_vuln_scan_results(self, sample_nmap_vuln_xml):
        """Test parsing vulnerability scan results."""
        result = parse_vuln_xml(sample_nmap_vuln_xml)

        assert result.hosts_scanned == 1
        assert len(result.vulnerabilities) >= 1

        # Find the actual vulnerability
        vuln_findings = [v for v in result.vulnerabilities if v.state == 'VULNERABLE']
        assert len(vuln_findings) == 1

        vuln = vuln_findings[0]
        assert vuln.host == '192.168.1.1'
        assert vuln.port == 80
        assert vuln.script_id == 'http-vuln-cve2021-41773'
        assert vuln.title == 'Apache HTTP Server Path Traversal'

    def test_invalid_xml(self):
        """Test handling of invalid XML in vuln parser."""
        result = parse_vuln_xml('not valid xml')
        assert result.command == '(xml parse error)'
        assert len(result.warnings) > 0

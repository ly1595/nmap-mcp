"""Tests for the nmap MCP server tools."""

import pytest
from unittest.mock import patch
from nmap_mcp.server import (
    discover_hosts,
    quick_scan,
    scan_ports,
    scan_vulnerabilities,
    detect_services,
    detect_os,
)


class TestScanPorts:
    """Tests for the scan-ports tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_basic_scan(self, mock_run_nmap, mock_context, sample_nmap_xml):
        """Test a basic port scan invocation."""
        mock_run_nmap.return_value = (sample_nmap_xml, '', 0)

        result = await scan_ports(
            ctx=mock_context,
            target='192.168.1.1',
            ports='22,80,443',
            scan_type='connect',
            timing='normal',
            service_detection=False,
            timeout=300,
        )

        assert len(result.hosts) == 1
        assert result.hosts[0].ip == '192.168.1.1'
        mock_run_nmap.assert_called_once()

        # Verify the nmap args contain expected flags
        call_args = mock_run_nmap.call_args[0][0]
        assert '-sT' in call_args  # connect scan
        assert '-T3' in call_args  # normal timing
        assert '-p' in call_args
        assert '22,80,443' in call_args

    @patch('nmap_mcp.server.run_nmap')
    async def test_syn_scan(self, mock_run_nmap, mock_context, sample_nmap_xml):
        """Test SYN scan type."""
        mock_run_nmap.return_value = (sample_nmap_xml, '', 0)

        await scan_ports(
            ctx=mock_context,
            target='192.168.1.1',
            scan_type='syn',
            timing='aggressive',
            service_detection=True,
            timeout=300,
        )

        call_args = mock_run_nmap.call_args[0][0]
        assert '-sS' in call_args
        assert '-T4' in call_args
        assert '-sV' in call_args

    async def test_invalid_scan_type(self, mock_context):
        """Test that invalid scan types are rejected."""
        with pytest.raises(ValueError, match='Invalid scan type'):
            await scan_ports(
                ctx=mock_context,
                target='192.168.1.1',
                scan_type='invalid',
                timing='normal',
                service_detection=False,
                timeout=300,
            )

    async def test_invalid_target(self, mock_context):
        """Test that invalid targets are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            await scan_ports(
                ctx=mock_context,
                target='192.168.1.1; rm -rf /',
                scan_type='connect',
                timing='normal',
                service_detection=False,
                timeout=300,
            )

    async def test_invalid_timing(self, mock_context):
        """Test that invalid timing templates are rejected."""
        with pytest.raises(ValueError, match='Invalid timing'):
            await scan_ports(
                ctx=mock_context,
                target='192.168.1.1',
                scan_type='connect',
                timing='invalid',
                service_detection=False,
                timeout=300,
            )


class TestDiscoverHosts:
    """Tests for the discover-hosts tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_host_discovery(self, mock_run_nmap, mock_context, sample_discovery_xml):
        """Test host discovery scan."""
        mock_run_nmap.return_value = (sample_discovery_xml, '', 0)

        result = await discover_hosts(
            ctx=mock_context,
            target='192.168.1.0/28',
            timing='normal',
            timeout=300,
        )

        assert len(result.hosts_up) == 2
        assert '192.168.1.1' in result.hosts_up
        assert '192.168.1.5' in result.hosts_up
        assert len(result.hosts_down) == 1
        assert result.total_scanned == 3

        call_args = mock_run_nmap.call_args[0][0]
        assert '-sn' in call_args


class TestQuickScan:
    """Tests for the quick-scan tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_quick_scan(self, mock_run_nmap, mock_context, sample_nmap_xml):
        """Test quick scan invocation."""
        mock_run_nmap.return_value = (sample_nmap_xml, '', 0)

        result = await quick_scan(
            ctx=mock_context,
            target='192.168.1.1',
            top_ports=100,
            service_detection=True,
            timeout=300,
        )

        assert len(result.hosts) == 1

        call_args = mock_run_nmap.call_args[0][0]
        assert '--top-ports=100' in call_args
        assert '-T4' in call_args
        assert '-sV' in call_args


class TestScanVulnerabilities:
    """Tests for the scan-vulnerabilities tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_vuln_scan(self, mock_run_nmap, mock_context, sample_nmap_vuln_xml):
        """Test vulnerability scan invocation."""
        mock_run_nmap.return_value = (sample_nmap_vuln_xml, '', 0)

        result = await scan_vulnerabilities(
            ctx=mock_context,
            target='192.168.1.1',
            scripts='vuln',
            timing='normal',
            timeout=300,
        )

        assert result.hosts_scanned == 1
        assert len(result.vulnerabilities) >= 1

        call_args = mock_run_nmap.call_args[0][0]
        assert '--script=vuln' in call_args
        assert '-sV' in call_args


class TestDetectServices:
    """Tests for the detect-services tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_service_detection(self, mock_run_nmap, mock_context, sample_nmap_xml):
        """Test service detection invocation."""
        mock_run_nmap.return_value = (sample_nmap_xml, '', 0)

        result = await detect_services(
            ctx=mock_context,
            target='192.168.1.1',
            ports='22,80,443',
            intensity=7,
            timing='normal',
            timeout=300,
        )

        assert len(result.hosts) == 1

        call_args = mock_run_nmap.call_args[0][0]
        assert '-sV' in call_args
        assert '--version-intensity=7' in call_args


class TestDetectOS:
    """Tests for the detect-os tool."""

    @patch('nmap_mcp.server.run_nmap')
    async def test_os_detection(self, mock_run_nmap, mock_context, sample_nmap_os_xml):
        """Test OS detection invocation."""
        mock_run_nmap.return_value = (sample_nmap_os_xml, '', 0)

        result = await detect_os(
            ctx=mock_context,
            target='192.168.1.1',
            timeout=300,
        )

        assert len(result.hosts) == 1
        assert len(result.hosts[0].os_matches) == 2
        assert result.hosts[0].os_matches[0].name == 'Linux 5.4 - 5.15'

        call_args = mock_run_nmap.call_args[0][0]
        assert '-O' in call_args
        assert '--osscan-guess' in call_args

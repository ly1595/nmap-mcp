"""Pydantic models for the nmap MCP server."""

from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class PortState(str, Enum):
    """Possible states for a scanned port."""

    OPEN = 'open'
    CLOSED = 'closed'
    FILTERED = 'filtered'
    UNFILTERED = 'unfiltered'
    OPEN_FILTERED = 'open|filtered'
    CLOSED_FILTERED = 'closed|filtered'


class ServiceInfo(BaseModel):
    """Information about a detected service on a port."""

    name: str = Field(default='unknown', description='Service name')
    product: Optional[str] = Field(default=None, description='Product name')
    version: Optional[str] = Field(default=None, description='Product version')
    extra_info: Optional[str] = Field(default=None, description='Extra service information')
    cpe: Optional[List[str]] = Field(
        default=None, description='Common Platform Enumeration identifiers'
    )


class PortResult(BaseModel):
    """Result for a single scanned port."""

    port: int = Field(description='Port number')
    protocol: str = Field(default='tcp', description='Protocol (tcp/udp)')
    state: PortState = Field(description='Port state')
    service: Optional[ServiceInfo] = Field(default=None, description='Detected service info')


class OSMatch(BaseModel):
    """Operating system detection match."""

    name: str = Field(description='OS name')
    accuracy: int = Field(description='Match accuracy percentage (0-100)')
    os_family: Optional[str] = Field(
        default=None, description='OS family (e.g., Linux, Windows)'
    )
    os_gen: Optional[str] = Field(default=None, description='OS generation (e.g., 2.6.X, 10)')


class ScriptResult(BaseModel):
    """Result from an NSE script execution."""

    script_id: str = Field(description='NSE script identifier')
    output: str = Field(description='Script output text')


class HostResult(BaseModel):
    """Scan results for a single host."""

    ip: str = Field(description='IP address of the host')
    hostname: Optional[str] = Field(default=None, description='Resolved hostname')
    state: str = Field(default='up', description='Host state (up/down)')
    ports: List[PortResult] = Field(default_factory=list, description='Scanned port results')
    os_matches: List[OSMatch] = Field(
        default_factory=list, description='OS detection results'
    )
    scripts: List[ScriptResult] = Field(
        default_factory=list, description='Host-level script results'
    )


class ScanResult(BaseModel):
    """Complete nmap scan result."""

    command: str = Field(description='The nmap command that was executed (sanitized)')
    hosts: List[HostResult] = Field(default_factory=list, description='Results per host')
    scan_stats: Dict[str, str] = Field(default_factory=dict, description='Scan statistics')
    raw_output: Optional[str] = Field(default=None, description='Raw nmap output text')
    warnings: List[str] = Field(default_factory=list, description='Scan warnings')


class HostDiscoveryResult(BaseModel):
    """Result of a host discovery scan."""

    hosts_up: List[str] = Field(default_factory=list, description='List of hosts that are up')
    hosts_down: List[str] = Field(
        default_factory=list, description='List of hosts that are down'
    )
    total_scanned: int = Field(default=0, description='Total hosts scanned')
    scan_stats: Dict[str, str] = Field(default_factory=dict, description='Scan statistics')


class VulnResult(BaseModel):
    """Vulnerability scan result for a single finding."""

    host: str = Field(description='Host IP address')
    port: Optional[int] = Field(default=None, description='Affected port')
    script_id: str = Field(description='NSE script that found the vulnerability')
    title: Optional[str] = Field(default=None, description='Vulnerability title')
    state: Optional[str] = Field(
        default=None, description='Vulnerability state (VULNERABLE, etc.)'
    )
    output: str = Field(description='Full script output')


class VulnScanResult(BaseModel):
    """Complete vulnerability scan result."""

    command: str = Field(description='The nmap command that was executed (sanitized)')
    vulnerabilities: List[VulnResult] = Field(
        default_factory=list, description='Discovered vulnerabilities'
    )
    hosts_scanned: int = Field(default=0, description='Number of hosts scanned')
    raw_output: Optional[str] = Field(default=None, description='Raw nmap output text')
    warnings: List[str] = Field(default_factory=list, description='Scan warnings')

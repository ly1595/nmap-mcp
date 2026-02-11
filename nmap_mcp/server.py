"""Nmap MCP Server implementation.

This server provides network scanning tools via the Model Context Protocol,
wrapping the nmap network scanner for authorized security testing.
"""

import os
import sys
from nmap_mcp.consts import (
    ALLOWED_SCAN_TYPES,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_TOP_PORTS,
    LOG_LEVEL,
    SAFE_NSE_CATEGORIES,
    SCAN_TYPE_FLAGS,
    TIMING_TEMPLATES,
)
from nmap_mcp.models import (
    HostDiscoveryResult,
    ScanResult,
    VulnScanResult,
)
from nmap_mcp.scanner import (
    parse_vuln_xml,
    parse_xml_output,
    run_nmap,
    validate_ports,
    validate_target,
)
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field
from typing import Optional


# Set up logging
logger.remove()
logger.add(sys.stderr, level=LOG_LEVEL)


mcp = FastMCP(
    'nmap-mcp',
    instructions="""# Nmap Network Scanner MCP Server

This MCP server provides tools for network scanning and security assessment using Nmap.

## IMPORTANT: Authorization Required
CRITICAL: Only use these tools on networks and systems you are explicitly authorized to scan.
Unauthorized network scanning may be illegal. Always ensure you have proper written authorization
before scanning any target.

## Available Tools

### scan-ports
Perform a port scan on a target. Supports multiple scan types (TCP connect, SYN, UDP, etc.),
custom port ranges, timing templates, and service version detection.

### discover-hosts
Perform host discovery on a network range. Finds which hosts are up without doing a full port scan.
Useful as a first step before detailed scanning.

### detect-services
Detect services and their versions running on open ports. Uses nmap's service/version detection
probes to identify what software is running.

### detect-os
Attempt to identify the operating system of a target host using TCP/IP stack fingerprinting.
Note: requires elevated privileges (root/sudo).

### scan-vulnerabilities
Run NSE (Nmap Scripting Engine) vulnerability detection scripts against a target.
Uses safe script categories by default.

### quick-scan
Perform a fast scan of the top N most common ports. Good for a quick security overview.

## Recommended Workflow

1. Start with `discover-hosts` to find live hosts on a network
2. Use `quick-scan` for a fast overview of each discovered host
3. Use `scan-ports` with specific port ranges for deeper investigation
4. Use `detect-services` to identify software versions on open ports
5. Use `scan-vulnerabilities` to check for known vulnerabilities
6. Use `detect-os` if OS identification is needed

## Timing Templates
- paranoid (T0): Very slow, IDS evasion
- sneaky (T1): Slow, IDS evasion
- polite (T2): Slower than normal, less bandwidth
- normal (T3): Default nmap timing
- aggressive (T4): Faster, assumes reliable network
- insane (T5): Fastest, may miss results
""",
    dependencies=['pydantic', 'loguru'],
)


@mcp.tool(name='scan-ports')
async def scan_ports(
    ctx: Context,
    target: str = Field(
        description='Target to scan: IP address (192.168.1.1), hostname (example.com), '
        'or CIDR notation (192.168.1.0/24). Max /24 network size.',
    ),
    ports: Optional[str] = Field(
        default=None,
        description='Port specification. Examples: "22", "1-1024", "22,80,443", '
        '"T:22,80,U:53" for protocol-specific. If omitted, scans nmap default ports.',
    ),
    scan_type: str = Field(
        default='connect',
        description='Scan type: "connect" (TCP connect, no root needed), '
        '"syn" (SYN stealth, needs root), "udp" (UDP, needs root), '
        '"fin", "xmas", "null", "ack". Default: "connect".',
    ),
    timing: str = Field(
        default='normal',
        description='Timing template: "paranoid", "sneaky", "polite", "normal", '
        '"aggressive", "insane". Default: "normal".',
    ),
    service_detection: bool = Field(
        default=False,
        description='Enable service/version detection (-sV). Slower but identifies running software.',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> ScanResult:
    """Scan ports on a target host or network.

    Performs a port scan using nmap with the specified parameters. Validates all inputs
    to prevent command injection.

    IMPORTANT: Only scan targets you are authorized to scan.

    Returns:
        ScanResult with discovered hosts, ports, and their states.
    """
    target = validate_target(target)

    if scan_type not in ALLOWED_SCAN_TYPES:
        raise ValueError(
            f'Invalid scan type "{scan_type}". Allowed: {sorted(ALLOWED_SCAN_TYPES)}'
        )

    if timing not in TIMING_TEMPLATES:
        raise ValueError(
            f'Invalid timing "{timing}". Allowed: {sorted(TIMING_TEMPLATES.keys())}'
        )

    # Build nmap arguments
    args = ['-oX', '-']  # XML output to stdout
    args.append(SCAN_TYPE_FLAGS[scan_type])
    args.append(TIMING_TEMPLATES[timing])

    if ports is not None and isinstance(ports, str):
        ports = validate_ports(ports)
        args.extend(['-p', ports])

    if service_detection:
        args.append('-sV')

    args.append(target)

    await ctx.info(f'Starting port scan on {target}')
    logger.info(f'Port scan: target={target}, type={scan_type}, ports={ports}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        if stderr:
            logger.warning(f'Nmap stderr: {stderr}')

        result = parse_xml_output(stdout)
        if stderr:
            result.warnings.append(stderr.strip())

        await ctx.info(
            f'Scan complete: {len(result.hosts)} host(s) found, '
            f'{sum(len(h.ports) for h in result.hosts)} port(s) scanned'
        )

        return result

    except FileNotFoundError as e:
        await ctx.error(str(e))
        raise
    except Exception as e:
        logger.error(f'Port scan failed: {e}')
        await ctx.error(f'Scan failed: {e}')
        raise


@mcp.tool(name='discover-hosts')
async def discover_hosts(
    ctx: Context,
    target: str = Field(
        description='Network range to scan: CIDR notation (192.168.1.0/24) or '
        'IP range. Max /24 network size.',
    ),
    timing: str = Field(
        default='normal',
        description='Timing template: "paranoid" through "insane". Default: "normal".',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> HostDiscoveryResult:
    """Discover live hosts on a network without performing a port scan.

    Uses nmap ping scan (-sn) to identify which hosts are up on the target network.
    This is typically the first step in a network assessment.

    IMPORTANT: Only scan networks you are authorized to scan.

    Returns:
        HostDiscoveryResult with lists of hosts that are up and down.
    """
    target = validate_target(target)

    if timing not in TIMING_TEMPLATES:
        raise ValueError(
            f'Invalid timing "{timing}". Allowed: {sorted(TIMING_TEMPLATES.keys())}'
        )

    args = ['-oX', '-', '-sn', TIMING_TEMPLATES[timing], target]

    await ctx.info(f'Starting host discovery on {target}')
    logger.info(f'Host discovery: target={target}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        result = parse_xml_output(stdout)

        hosts_up = [h.ip for h in result.hosts if h.state == 'up']
        hosts_down = [h.ip for h in result.hosts if h.state != 'up']

        total = int(result.scan_stats.get('hosts_total', len(result.hosts)))

        await ctx.info(f'Discovery complete: {len(hosts_up)} host(s) up out of {total} scanned')

        return HostDiscoveryResult(
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            total_scanned=total,
            scan_stats=result.scan_stats,
        )

    except Exception as e:
        logger.error(f'Host discovery failed: {e}')
        await ctx.error(f'Host discovery failed: {e}')
        raise


@mcp.tool(name='detect-services')
async def detect_services(
    ctx: Context,
    target: str = Field(
        description='Target to scan: IP address or hostname.',
    ),
    ports: Optional[str] = Field(
        default=None,
        description='Port specification. If omitted, scans nmap default ports.',
    ),
    intensity: int = Field(
        default=7,
        description='Version detection intensity (0-9). '
        'Higher is more accurate but slower. Default: 7.',
        ge=0,
        le=9,
    ),
    timing: str = Field(
        default='normal',
        description='Timing template. Default: "normal".',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> ScanResult:
    """Detect services and versions running on open ports.

    Uses nmap's service detection probes (-sV) to identify software names,
    versions, and CPE identifiers for services running on open ports.

    IMPORTANT: Only scan targets you are authorized to scan.

    Returns:
        ScanResult with service information for each open port.
    """
    target = validate_target(target)

    if timing not in TIMING_TEMPLATES:
        raise ValueError(
            f'Invalid timing "{timing}". Allowed: {sorted(TIMING_TEMPLATES.keys())}'
        )

    args = [
        '-oX', '-', '-sV', f'--version-intensity={intensity}', TIMING_TEMPLATES[timing],
    ]

    if ports is not None and isinstance(ports, str):
        ports = validate_ports(ports)
        args.extend(['-p', ports])

    args.append(target)

    await ctx.info(f'Starting service detection on {target}')
    logger.info(f'Service detection: target={target}, intensity={intensity}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        result = parse_xml_output(stdout)
        if stderr:
            result.warnings.append(stderr.strip())

        services_found = sum(
            1 for h in result.hosts for p in h.ports
            if p.service and p.service.name != 'unknown'
        )

        await ctx.info(f'Service detection complete: {services_found} service(s) identified')

        return result

    except Exception as e:
        logger.error(f'Service detection failed: {e}')
        await ctx.error(f'Service detection failed: {e}')
        raise


@mcp.tool(name='detect-os')
async def detect_os(
    ctx: Context,
    target: str = Field(
        description='Target to scan: IP address or hostname. Single host only.',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> ScanResult:
    """Detect the operating system of a target host.

    Uses nmap TCP/IP stack fingerprinting (-O) to identify the target's operating system.
    NOTE: This typically requires elevated privileges (root/sudo).

    IMPORTANT: Only scan targets you are authorized to scan.

    Returns:
        ScanResult with OS detection matches for the target host.
    """
    target = validate_target(target)

    args = ['-oX', '-', '-O', '--osscan-guess', target]

    await ctx.info(f'Starting OS detection on {target}')
    logger.info(f'OS detection: target={target}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        result = parse_xml_output(stdout)
        if stderr:
            result.warnings.append(stderr.strip())

        for host in result.hosts:
            if host.os_matches:
                best = host.os_matches[0]
                await ctx.info(
                    f'OS detected for {host.ip}: {best.name} ({best.accuracy}% confidence)'
                )

        return result

    except Exception as e:
        logger.error(f'OS detection failed: {e}')
        await ctx.error(f'OS detection failed: {e}')
        raise


@mcp.tool(name='scan-vulnerabilities')
async def scan_vulnerabilities(
    ctx: Context,
    target: str = Field(
        description='Target to scan: IP address or hostname.',
    ),
    ports: Optional[str] = Field(
        default=None,
        description='Port specification. If omitted, scans nmap default ports.',
    ),
    scripts: Optional[str] = Field(
        default=None,
        description='NSE script specification. Examples: "vuln", "auth", "default,safe", '
        '"http-vuln-*". Only categories from {auth, default, discovery, safe, version, vuln} '
        'are allowed. If omitted, uses "vuln" category.',
    ),
    timing: str = Field(
        default='normal',
        description='Timing template. Default: "normal".',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> VulnScanResult:
    """Scan for known vulnerabilities using Nmap Scripting Engine (NSE).

    Runs NSE vulnerability detection scripts against the target. Uses safe script
    categories by default. Results include CVE identifiers when available.

    IMPORTANT: Only scan targets you are authorized to scan. Vulnerability scanning
    may trigger security alerts on the target network.

    Returns:
        VulnScanResult with discovered vulnerabilities and their details.
    """
    target = validate_target(target)

    if timing not in TIMING_TEMPLATES:
        raise ValueError(
            f'Invalid timing "{timing}". Allowed: {sorted(TIMING_TEMPLATES.keys())}'
        )

    # Validate and sanitize script specification
    script_spec = scripts or 'vuln'
    for part in script_spec.replace(',', ' ').split():
        clean = part.strip().rstrip('*').rstrip('-')
        if clean in SAFE_NSE_CATEGORIES:
            continue
        if not all(c.isalnum() or c in '-_*' for c in part):
            raise ValueError(f'Invalid script specification: {part}')

    args = ['-oX', '-', '-sV', f'--script={script_spec}', TIMING_TEMPLATES[timing]]

    if ports is not None and isinstance(ports, str):
        ports = validate_ports(ports)
        args.extend(['-p', ports])

    args.append(target)

    await ctx.info(f'Starting vulnerability scan on {target} with scripts: {script_spec}')
    logger.info(f'Vulnerability scan: target={target}, scripts={script_spec}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        result = parse_vuln_xml(stdout)
        if stderr:
            result.warnings.append(stderr.strip())

        vuln_count = len(result.vulnerabilities)
        await ctx.info(f'Vulnerability scan complete: {vuln_count} finding(s)')

        return result

    except Exception as e:
        logger.error(f'Vulnerability scan failed: {e}')
        await ctx.error(f'Vulnerability scan failed: {e}')
        raise


@mcp.tool(name='quick-scan')
async def quick_scan(
    ctx: Context,
    target: str = Field(
        description='Target to scan: IP address or hostname.',
    ),
    top_ports: int = Field(
        default=DEFAULT_TOP_PORTS,
        description=f'Number of top ports to scan (by frequency). Default: {DEFAULT_TOP_PORTS}.',
        gt=0,
        le=5000,
    ),
    service_detection: bool = Field(
        default=True,
        description='Enable service/version detection. Default: true.',
    ),
    timeout: int = Field(
        default=DEFAULT_SCAN_TIMEOUT,
        description=f'Maximum scan duration in seconds. Default: {DEFAULT_SCAN_TIMEOUT}.',
        gt=0,
        le=600,
    ),
) -> ScanResult:
    """Perform a fast scan of the most common ports.

    Scans the top N most frequently used ports with aggressive timing for quick results.
    Good for getting a fast security overview of a target.

    IMPORTANT: Only scan targets you are authorized to scan.

    Returns:
        ScanResult with discovered hosts and open ports.
    """
    target = validate_target(target)

    args = ['-oX', '-', '-T4', f'--top-ports={top_ports}']

    if service_detection:
        args.append('-sV')

    args.append(target)

    await ctx.info(f'Starting quick scan on {target} (top {top_ports} ports)')
    logger.info(f'Quick scan: target={target}, top_ports={top_ports}')

    try:
        stdout, stderr, returncode = await run_nmap(args, timeout=timeout)

        result = parse_xml_output(stdout)
        if stderr:
            result.warnings.append(stderr.strip())

        open_ports = sum(
            1 for h in result.hosts for p in h.ports if p.state.value == 'open'
        )

        await ctx.info(f'Quick scan complete: {open_ports} open port(s) found')

        return result

    except Exception as e:
        logger.error(f'Quick scan failed: {e}')
        await ctx.error(f'Quick scan failed: {e}')
        raise


def main():
    """Run the MCP server with CLI argument support."""
    logger.info('Starting Nmap MCP Server')
    mcp.run()


if __name__ == '__main__':
    main()

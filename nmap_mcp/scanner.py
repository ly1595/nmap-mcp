"""Nmap scanner wrapper for safe command execution and XML output parsing."""

import asyncio
import ipaddress
import re
import shutil
import xml.etree.ElementTree as ET
from nmap_mcp.consts import (
    DEFAULT_SCAN_TIMEOUT,
    FORBIDDEN_TARGET_CHARS,
    MAX_TARGETS,
    NMAP_BINARY,
)
from nmap_mcp.models import (
    HostDiscoveryResult,
    HostResult,
    OSMatch,
    PortResult,
    PortState,
    ScriptResult,
    ScanResult,
    ServiceInfo,
    VulnResult,
    VulnScanResult,
)
from loguru import logger
from typing import List, Optional


def validate_target(target: str) -> str:
    """Validate and sanitize a scan target to prevent command injection.

    Args:
        target: IP address, hostname, or CIDR notation target.

    Returns:
        The validated target string.

    Raises:
        ValueError: If the target contains forbidden characters or is invalid.
    """
    target = target.strip()

    if not target:
        raise ValueError('Target cannot be empty')

    # Check for command injection characters
    if any(c in target for c in FORBIDDEN_TARGET_CHARS):
        raise ValueError(f'Target contains forbidden characters: {target}')

    # Try parsing as IP address or network
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        pass
    else:
        if network.num_addresses > MAX_TARGETS:
            raise ValueError(
                f'Network {target} contains {network.num_addresses} addresses, '
                f'exceeding the maximum of {MAX_TARGETS}'
            )
        return target

    # Validate as hostname (RFC 1123)
    hostname_re = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    if hostname_re.match(target):
        return target

    raise ValueError(f'Invalid target: {target}')


def validate_ports(ports: str) -> str:
    """Validate a port specification string.

    Args:
        ports: Port specification (e.g., '22', '1-1024', '22,80,443', 'T:22,U:53').

    Returns:
        The validated port string.

    Raises:
        ValueError: If the port specification is invalid.
    """
    ports = ports.strip()

    if not ports:
        raise ValueError('Port specification cannot be empty')

    # Nmap port spec: numbers, commas, hyphens, T:/U: prefixes
    port_re = re.compile(r'^[TU:,\-0-9\s]+$')
    if not port_re.match(ports):
        raise ValueError(f'Invalid port specification: {ports}')

    return ports


def get_nmap_path() -> str:
    """Find the nmap binary.

    Returns:
        Path to the nmap binary.

    Raises:
        FileNotFoundError: If nmap is not found.
    """
    path = shutil.which(NMAP_BINARY)
    if path is None:
        raise FileNotFoundError(
            f'nmap binary not found at "{NMAP_BINARY}". '
            'Install nmap or set the NMAP_BINARY environment variable.'
        )
    return path


async def run_nmap(
    args: List[str],
    timeout: int = DEFAULT_SCAN_TIMEOUT,
) -> tuple[str, str, int]:
    """Execute nmap with the given arguments.

    Args:
        args: List of nmap command-line arguments.
        timeout: Maximum scan duration in seconds.

    Returns:
        Tuple of (stdout, stderr, return_code).

    Raises:
        FileNotFoundError: If nmap binary is not found.
        asyncio.TimeoutError: If the scan exceeds the timeout.
    """
    nmap_path = get_nmap_path()
    cmd = [nmap_path] + args

    logger.info(f'Running nmap: {" ".join(cmd)}')

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise asyncio.TimeoutError(f'Nmap scan timed out after {timeout} seconds')

    stdout = stdout_bytes.decode('utf-8', errors='replace')
    stderr = stderr_bytes.decode('utf-8', errors='replace')

    return stdout, stderr, process.returncode or 0


def parse_xml_output(xml_string: str) -> ScanResult:
    """Parse nmap XML output into structured results.

    Args:
        xml_string: Raw nmap XML output string.

    Returns:
        Parsed ScanResult model.
    """
    warnings: List[str] = []
    hosts: List[HostResult] = []
    scan_stats = {}
    command = ''

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error(f'Failed to parse nmap XML output: {e}')
        return ScanResult(
            command='(xml parse error)',
            warnings=[f'Failed to parse XML output: {e}'],
            raw_output=xml_string[:5000],
        )

    # Extract command and scan info
    command = root.get('args', '')

    # Extract run stats
    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None:
            scan_stats['elapsed'] = finished.get('elapsed', '')
            scan_stats['time_str'] = finished.get('timestr', '')
            scan_stats['exit'] = finished.get('exit', '')

        hosts_elem = runstats.find('hosts')
        if hosts_elem is not None:
            scan_stats['hosts_up'] = hosts_elem.get('up', '0')
            scan_stats['hosts_down'] = hosts_elem.get('down', '0')
            scan_stats['hosts_total'] = hosts_elem.get('total', '0')

    # Parse each host
    for host_elem in root.findall('host'):
        host = _parse_host(host_elem)
        if host:
            hosts.append(host)

    # Extract warnings from verbose/debugging output
    for output_elem in root.findall('.//output'):
        text = output_elem.text or ''
        if 'warning' in text.lower():
            warnings.append(text.strip())

    return ScanResult(
        command=command,
        hosts=hosts,
        scan_stats=scan_stats,
        warnings=warnings,
    )


def _parse_host(host_elem: ET.Element) -> Optional[HostResult]:
    """Parse a single host element from nmap XML."""
    # Get host status
    status = host_elem.find('status')
    state = status.get('state', 'unknown') if status is not None else 'unknown'

    # Get IP address
    ip = ''
    hostname = None
    for addr in host_elem.findall('address'):
        if addr.get('addrtype') in ('ipv4', 'ipv6'):
            ip = addr.get('addr', '')
            break

    if not ip:
        return None

    # Get hostname
    hostnames = host_elem.find('hostnames')
    if hostnames is not None:
        hostname_elem = hostnames.find('hostname')
        if hostname_elem is not None:
            hostname = hostname_elem.get('name')

    # Parse ports
    ports: List[PortResult] = []
    ports_elem = host_elem.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port = _parse_port(port_elem)
            if port:
                ports.append(port)

    # Parse OS matches
    os_matches: List[OSMatch] = []
    os_elem = host_elem.find('os')
    if os_elem is not None:
        for match_elem in os_elem.findall('osmatch'):
            os_match = _parse_os_match(match_elem)
            if os_match:
                os_matches.append(os_match)

    # Parse host scripts
    scripts: List[ScriptResult] = []
    hostscript = host_elem.find('hostscript')
    if hostscript is not None:
        for script_elem in hostscript.findall('script'):
            script = _parse_script(script_elem)
            if script:
                scripts.append(script)

    return HostResult(
        ip=ip,
        hostname=hostname,
        state=state,
        ports=ports,
        os_matches=os_matches,
        scripts=scripts,
    )


def _parse_port(port_elem: ET.Element) -> Optional[PortResult]:
    """Parse a single port element from nmap XML."""
    port_id = port_elem.get('portid')
    protocol = port_elem.get('protocol', 'tcp')

    if port_id is None:
        return None

    state_elem = port_elem.find('state')
    state_str = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

    try:
        state = PortState(state_str)
    except ValueError:
        state = PortState.FILTERED

    # Parse service info
    service = None
    service_elem = port_elem.find('service')
    if service_elem is not None:
        cpe_list = [cpe.text for cpe in port_elem.findall('.//cpe') if cpe.text]
        service = ServiceInfo(
            name=service_elem.get('name', 'unknown'),
            product=service_elem.get('product'),
            version=service_elem.get('version'),
            extra_info=service_elem.get('extrainfo'),
            cpe=cpe_list if cpe_list else None,
        )

    return PortResult(
        port=int(port_id),
        protocol=protocol,
        state=state,
        service=service,
    )


def _parse_os_match(match_elem: ET.Element) -> Optional[OSMatch]:
    """Parse an OS match element from nmap XML."""
    name = match_elem.get('name')
    accuracy = match_elem.get('accuracy')

    if not name or accuracy is None:
        return None

    os_family = None
    os_gen = None
    osclass = match_elem.find('osclass')
    if osclass is not None:
        os_family = osclass.get('osfamily')
        os_gen = osclass.get('osgen')

    return OSMatch(
        name=name,
        accuracy=int(accuracy),
        os_family=os_family,
        os_gen=os_gen,
    )


def _parse_script(script_elem: ET.Element) -> Optional[ScriptResult]:
    """Parse a script result element from nmap XML."""
    script_id = script_elem.get('id')
    output = script_elem.get('output', '')

    if not script_id:
        return None

    return ScriptResult(script_id=script_id, output=output)


def parse_vuln_xml(xml_string: str) -> VulnScanResult:
    """Parse nmap XML output for vulnerability scan results.

    Args:
        xml_string: Raw nmap XML output string.

    Returns:
        Parsed VulnScanResult model.
    """
    warnings: List[str] = []
    vulns: List[VulnResult] = []
    command = ''
    hosts_scanned = 0

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error(f'Failed to parse nmap XML output: {e}')
        return VulnScanResult(
            command='(xml parse error)',
            warnings=[f'Failed to parse XML output: {e}'],
            raw_output=xml_string[:5000],
        )

    command = root.get('args', '')

    for host_elem in root.findall('host'):
        hosts_scanned += 1

        # Get host IP
        ip = ''
        for addr in host_elem.findall('address'):
            if addr.get('addrtype') in ('ipv4', 'ipv6'):
                ip = addr.get('addr', '')
                break

        if not ip:
            continue

        # Check port-level scripts
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_id = int(port_elem.get('portid', '0'))
                for script_elem in port_elem.findall('script'):
                    vuln = _parse_vuln_script(script_elem, ip, port_id)
                    if vuln:
                        vulns.append(vuln)

        # Check host-level scripts
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            for script_elem in hostscript.findall('script'):
                vuln = _parse_vuln_script(script_elem, ip, None)
                if vuln:
                    vulns.append(vuln)

    return VulnScanResult(
        command=command,
        vulnerabilities=vulns,
        hosts_scanned=hosts_scanned,
        warnings=warnings,
    )


def _parse_vuln_script(
    script_elem: ET.Element,
    host: str,
    port: Optional[int],
) -> Optional[VulnResult]:
    """Parse a vulnerability script result."""
    script_id = script_elem.get('id', '')
    output = script_elem.get('output', '')

    if not script_id:
        return None

    # Extract vulnerability state from table elements
    state = None
    title = None
    for table in script_elem.findall('.//table'):
        for elem in table.findall('elem'):
            key = elem.get('key', '')
            if key == 'state':
                state = elem.text
            elif key == 'title':
                title = elem.text

    # Also check direct elem children
    for elem in script_elem.findall('elem'):
        key = elem.get('key', '')
        if key == 'state':
            state = elem.text
        elif key == 'title':
            title = elem.text

    return VulnResult(
        host=host,
        port=port,
        script_id=script_id,
        title=title,
        state=state,
        output=output,
    )

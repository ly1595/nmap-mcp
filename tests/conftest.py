"""Test fixtures for the nmap MCP server."""

import pytest
from unittest.mock import AsyncMock


@pytest.fixture
def mock_context():
    """Create a mock MCP context."""
    context = AsyncMock()
    context.info = AsyncMock()
    context.error = AsyncMock()
    context.warning = AsyncMock()
    return context


@pytest.fixture
def sample_nmap_xml():
    """Sample nmap XML output for a basic port scan."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -sT -T3 -p 22,80,443 192.168.1.1"
    start="1700000000" startstr="Wed Nov 15 00:00:00 2023" version="7.94"
    xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000010">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
        <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"
                extrainfo="Ubuntu Linux; protocol 2.0"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.18.0"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="closed" reason="conn-refused"/>
            <service name="https"/>
        </port>
    </ports>
</host>
<runstats>
    <finished time="1700000010" timestr="Wed Nov 15 00:00:10 2023"
        elapsed="10.00" exit="success"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


@pytest.fixture
def sample_nmap_os_xml():
    """Sample nmap XML output with OS detection."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -O 192.168.1.1"
    start="1700000000" version="7.94" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000020">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <os>
        <osmatch name="Linux 5.4 - 5.15" accuracy="95">
            <osclass osfamily="Linux" osgen="5.X" type="general purpose"
                vendor="Linux" accuracy="95"/>
        </osmatch>
        <osmatch name="Linux 4.15 - 5.8" accuracy="90">
            <osclass osfamily="Linux" osgen="4.X" type="general purpose"
                vendor="Linux" accuracy="90"/>
        </osmatch>
    </os>
</host>
<runstats>
    <finished time="1700000020" elapsed="20.00" exit="success"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


@pytest.fixture
def sample_nmap_vuln_xml():
    """Sample nmap XML output with vulnerability scan results."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -sV --script=vuln 192.168.1.1"
    start="1700000000" version="7.94" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000030">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache" version="2.4.49"/>
            <script id="http-vuln-cve2021-41773" output="VULNERABLE: Path traversal">
                <table key="CVE-2021-41773">
                    <elem key="title">Apache HTTP Server Path Traversal</elem>
                    <elem key="state">VULNERABLE</elem>
                </table>
            </script>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="Apache" version="2.4.49"/>
            <script id="ssl-heartbleed" output="NOT VULNERABLE"/>
        </port>
    </ports>
</host>
<runstats>
    <finished time="1700000030" elapsed="30.00" exit="success"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


@pytest.fixture
def sample_discovery_xml():
    """Sample nmap XML output for host discovery."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -sn 192.168.1.0/28"
    start="1700000000" version="7.94" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000005">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="gateway.local" type="PTR"/></hostnames>
</host>
<host starttime="1700000000" endtime="1700000005">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
</host>
<host starttime="1700000000" endtime="1700000005">
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
</host>
<runstats>
    <finished time="1700000005" elapsed="5.00" exit="success"/>
    <hosts up="2" down="1" total="3"/>
</runstats>
</nmaprun>"""

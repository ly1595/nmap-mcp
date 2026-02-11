"""Constants for the nmap MCP server."""

import os


# Logging
LOG_LEVEL = os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')

# Nmap binary path
NMAP_BINARY = os.getenv('NMAP_BINARY', 'nmap')

# Default scan timeout in seconds
DEFAULT_SCAN_TIMEOUT = int(os.getenv('NMAP_SCAN_TIMEOUT', '600'))

# Maximum allowed targets per scan (safety limit)
MAX_TARGETS = int(os.getenv('NMAP_MAX_TARGETS', '256'))

# Default top ports for quick scans
DEFAULT_TOP_PORTS = 100

# Allowed scan types
ALLOWED_SCAN_TYPES = frozenset({
    'syn',       # -sS (requires root)
    'connect',   # -sT
    'udp',       # -sU (requires root)
    'fin',       # -sF
    'xmas',      # -sX
    'null',      # -sN
    'ack',       # -sA
    'ping',      # -sn
    'version',   # -sV
})

# Scan type to nmap flag mapping
SCAN_TYPE_FLAGS = {
    'syn': '-sS',
    'connect': '-sT',
    'udp': '-sU',
    'fin': '-sF',
    'xmas': '-sX',
    'null': '-sN',
    'ack': '-sA',
    'ping': '-sn',
    'version': '-sV',
}

# Timing templates (T0-T5)
TIMING_TEMPLATES = {
    'paranoid': '-T0',
    'sneaky': '-T1',
    'polite': '-T2',
    'normal': '-T3',
    'aggressive': '-T4',
    'insane': '-T5',
}

# Safe NSE script categories for vulnerability scanning
SAFE_NSE_CATEGORIES = frozenset({
    'auth',
    'default',
    'discovery',
    'safe',
    'version',
    'vuln',
})

# Characters that are forbidden in targets (command injection prevention)
FORBIDDEN_TARGET_CHARS = frozenset({
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r',
})

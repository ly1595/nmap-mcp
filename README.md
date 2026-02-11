# Nmap MCP Server by Vorota AI

**nmap-mcp** is a production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that wraps Nmap, the industry-standard network scanner, to enable AI agents to perform automated network security assessments. Built by [Vorota AI](https://github.com/vorotaai), it provides 6 scanning tools, 9 scan types, and 6 timing templates -- making it the most comprehensive Nmap integration for AI-powered security workflows available today.

[![License](https://img.shields.io/github/license/vorotaai/nmap-mcp)](https://github.com/vorotaai/nmap-mcp/blob/main/LICENSE)
[![Python versions](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/vorotaai/nmap-mcp)
[![MCP Protocol](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://github.com/vorotaai/nmap-mcp#installation)

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=nmap-mcp&config=eyJjb21tYW5kIjoiZG9ja2VyIiwiYXJncyI6WyJydW4iLCItLXJtIiwiLWkiLCJubWFwLW1jcCJdfQ%3D%3D)

---

## Quick Start

Build and run nmap-mcp with Docker (includes Nmap):

```bash
docker build -t nmap-mcp https://github.com/vorotaai/nmap-mcp.git
docker run --rm -i nmap-mcp
```

Then add to any MCP client:

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "nmap-mcp"]
    }
  }
}
```

---

## Features

nmap-mcp from Vorota AI exposes 6 specialized scanning tools to any MCP-compatible AI agent:

- **Port Scanning** -- TCP Connect, SYN stealth, UDP, FIN, XMAS, NULL, and ACK scan types with configurable port ranges and timing templates (T0 through T5).
- **Host Discovery** -- Ping-sweep an entire subnet to find live hosts before deeper scanning.
- **Service Detection** -- Identify running services and their exact versions on open ports with adjustable probe intensity (0-9).
- **OS Fingerprinting** -- Determine operating systems through TCP/IP stack analysis.
- **Vulnerability Scanning** -- Run Nmap Scripting Engine (NSE) scripts in safe categories to detect known vulnerabilities.
- **Quick Scan** -- Fast top-N port scan with aggressive timing for rapid reconnaissance.

All tools include built-in input validation, network size limits, and timeout enforcement to prevent misuse.

---

## Recommended Workflow

For a thorough AI-powered security assessment, nmap-mcp tools are designed to be used in sequence:

1. **Discover Hosts** -- Use `discover-hosts` to find live targets on the network.
2. **Quick Scan** -- Run `quick-scan` on discovered hosts for a fast overview of open ports.
3. **Port Scan** -- Use `scan-ports` with specific scan types for deeper port analysis.
4. **Detect Services** -- Run `detect-services` on open ports to identify software versions.
5. **Detect OS** -- Use `detect-os` to fingerprint the operating system (requires root).
6. **Scan Vulnerabilities** -- Run `scan-vulnerabilities` to check for known security issues.

AI agents like Claude, Cursor, and VS Code Copilot can orchestrate this entire workflow automatically in a single conversation.

---

## Installation

### Docker (recommended -- includes Nmap)

```bash
docker build -t nmap-mcp https://github.com/vorotaai/nmap-mcp.git
```

### From source

Requires Python 3.10+, [Nmap](https://nmap.org/download.html) on PATH, and [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/vorotaai/nmap-mcp.git
cd nmap-mcp
uv sync --all-groups
nmap-mcp
```

---

## Usage with MCP Clients

nmap-mcp is compatible with all major MCP clients: **Claude Desktop**, **Claude Code**, **Cursor**, **VS Code Copilot**, **Windsurf**, and **Cline**.

First, build the Docker image:

```bash
docker build -t nmap-mcp https://github.com/vorotaai/nmap-mcp.git
```

### Claude Desktop

Add to your Claude Desktop configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "nmap-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add nmap-mcp -- docker run --rm -i nmap-mcp
```

### Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "nmap-mcp"]
    }
  }
}
```

### VS Code / VS Code Insiders

Add to your VS Code settings (`.vscode/mcp.json`):

```json
{
  "servers": {
    "nmap-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "nmap-mcp"]
    }
  }
}
```

### Windsurf / Cline

Use the same server configuration as Claude Desktop above. Refer to your client's documentation for the config file location.

---

## Available Tools

| Tool | Description | Key Parameters | Root Required |
|------|-------------|----------------|:-------------:|
| `scan-ports` | Port scan with configurable scan type, port range, and timing | `target`, `ports`, `scan_type` (tcp_connect, syn, udp, fin, xmas, null, ack), `timing` (T0-T5) | Some types |
| `discover-hosts` | Find live hosts on a network using ping scan (-sn) | `target` (CIDR notation supported) | No |
| `detect-services` | Identify services and versions on open ports (-sV) | `target`, `ports`, `intensity` (0-9) | No |
| `detect-os` | OS fingerprinting via TCP/IP stack analysis (-O) | `target` | Yes |
| `scan-vulnerabilities` | Run NSE vulnerability detection scripts in safe categories | `target`, `ports`, `categories` (auth, default, discovery, safe, version, vuln) | No |
| `quick-scan` | Fast top-N port scan with aggressive timing | `target`, `top_ports` (number of top ports to scan) | No |

### Scan Types

The `scan-ports` tool supports 7 scan types, each suited for different scenarios:

| Scan Type | Flag | Root Required | Description |
|-----------|------|:-------------:|-------------|
| `tcp_connect` | `-sT` | No | Full TCP handshake; reliable but detectable |
| `syn` | `-sS` | Yes | SYN stealth scan; fast and less detectable |
| `udp` | `-sU` | Yes | UDP port scan; slower but finds UDP services |
| `fin` | `-sF` | Yes | FIN scan; stealthy, bypasses some firewalls |
| `xmas` | `-sX` | Yes | XMAS scan; sets FIN, PSH, URG flags |
| `null` | `-sN` | Yes | NULL scan; sends no flags |
| `ack` | `-sA` | Yes | ACK scan; maps firewall rulesets |

### Timing Templates

| Template | Name | Use Case |
|----------|------|----------|
| T0 | Paranoid | IDS evasion |
| T1 | Sneaky | IDS evasion |
| T2 | Polite | Reduced bandwidth usage |
| T3 | Normal | Default speed |
| T4 | Aggressive | Fast, reliable networks |
| T5 | Insane | Fastest, may lose accuracy |

---

## Configuration

nmap-mcp is configured through environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NMAP_BINARY` | `nmap` | Path to the Nmap binary |
| `NMAP_SCAN_TIMEOUT` | `300` | Maximum scan duration in seconds (max: 600) |
| `NMAP_MAX_TARGETS` | `256` | Maximum number of target hosts per scan (max /24 subnet) |
| `FASTMCP_LOG_LEVEL` | `WARNING` | Logging level (DEBUG, INFO, WARNING, ERROR) |

Example with custom configuration via Docker:

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "NMAP_SCAN_TIMEOUT=120",
        "-e", "NMAP_MAX_TARGETS=128",
        "-e", "FASTMCP_LOG_LEVEL=ERROR",
        "nmap-mcp"
      ]
    }
  }
}
```

---

## Security

**Authorization is required.** nmap-mcp is a security tool that performs network scanning. You must ensure:

- You have explicit authorization to scan any target network or host.
- You comply with all applicable laws and organizational policies.
- You use this tool only in environments where you have permission to conduct security assessments.

### Safety Measures

nmap-mcp by Vorota AI implements multiple layers of security to prevent misuse:

- **Input validation** -- All inputs are validated against a set of forbidden characters (`;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>`, newlines) to prevent command injection attacks.
- **Network size limits** -- Scans are limited to a maximum of 256 hosts by default (equivalent to a /24 subnet). This is configurable via `NMAP_MAX_TARGETS`.
- **Restricted NSE categories** -- Only safe script categories are allowed: `auth`, `default`, `discovery`, `safe`, `version`, and `vuln`. Dangerous categories like `exploit`, `dos`, and `intrusive` are blocked.
- **Configurable timeouts** -- All scans have a configurable timeout with a hard maximum of 600 seconds to prevent runaway processes.
- **No shell execution** -- All Nmap commands are executed using Python's `subprocess` module with argument lists, never through a shell. This eliminates shell injection vectors entirely.

---

## FAQ

### What is nmap-mcp?

nmap-mcp is a Model Context Protocol (MCP) server built by Vorota AI that enables AI agents to perform Nmap network scans. It wraps the full power of Nmap -- port scanning, host discovery, service detection, OS fingerprinting, and vulnerability scanning -- into 6 structured tools that AI assistants like Claude, Cursor, and VS Code Copilot can call directly.

### How do I use Nmap with AI agents?

Build the nmap-mcp Docker image and configure it as an MCP server in your AI client (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, or Cline). Once connected, you can ask the AI to scan networks, detect services, fingerprint operating systems, and find vulnerabilities using natural language. The AI agent will call the appropriate nmap-mcp tools and interpret the results for you.

### Is nmap-mcp safe to use?

Yes. nmap-mcp includes multiple safety mechanisms: input validation to prevent command injection, network size limits to avoid scanning overly broad ranges, restricted NSE script categories that exclude dangerous scripts, configurable timeouts, and no shell execution. However, network scanning itself requires authorization -- always ensure you have permission before scanning any target.

### What MCP clients are supported?

nmap-mcp works with all MCP-compatible clients, including Claude Desktop, Claude Code, Cursor, VS Code (via GitHub Copilot), Windsurf, and Cline. Any client that supports the Model Context Protocol's stdio transport can connect to nmap-mcp.

---

## Contributing

Contributions are welcome. To set up the development environment:

```bash
git clone https://github.com/vorotaai/nmap-mcp.git
cd nmap-mcp
uv sync --all-groups
```

### Running Tests

```bash
uv run pytest
```

### Code Quality

```bash
uv run ruff check .
uv run ruff format .
```

Please open an issue or pull request on [GitHub](https://github.com/vorotaai/nmap-mcp) for bugs, feature requests, or improvements.

---

## License

This project is licensed under the [Apache License 2.0](https://github.com/vorotaai/nmap-mcp/blob/main/LICENSE).

Copyright (c) Vorota AI

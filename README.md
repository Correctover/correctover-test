# 🔒 correctover-test

**AI Agent Security Audit — 5 seconds to know if your agents are protected.**

[![PyPI version](https://img.shields.io/pypi/v/correctover-test.svg)](https://pypi.org/project/correctover-test/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

## Quick Start

```bash
pip install correctover-test
correctover-test --quick
```

## What It Does

Tests AI agent self-healing capabilities across major frameworks:

- **CrewAI** — Crew auto-recovery from tool failures
- **Smolagents** — HfSmolAgent error handling
- **LlamaIndex** — Agent worker retry patterns

### Key Metrics

| Metric | Value |
|--------|-------|
| Self-heal success rate | 84.1% |
| Test scenarios | 20,071 |
| Verification dimensions | 6 |
| Failover latency | 0.4–0.7ms |

## Free Tier

50 scans/day — no credit card required.

Unlock unlimited: [correctover.com/checkout](https://correctover.com/checkout)

```bash
export CORRECTOVER_LICENSE_KEY=your-key-here
```

## Related Correctover Tools

| Tool | Install | Description |
|------|---------|-------------|
| **Security Scanner** | `npx correctover-scan` | MCP config security audit (14 checks) |
| **Self-Healing Test** | `pip install correctover-test` | Agent self-healing test suite |
| **Vulnerability Scan** | `pip install correctover-security-audit` | 215 fault type scanner |
| **Compliance Check** | `pip install correctover-compliance-check` | OAuth 2.1 + CCS v1.0 |
| **Runtime Guard** | `pip install correctover-runtime-guard` | 22µs RCE/SSRF interception |
| **MCP Server** | `npm install correctover-mcp-server` | 6-dimension validation |

**Website**: [correctover.com](https://correctover.com) · **GitHub**: [github.com/Correctover](https://github.com/Correctover)

# NightWatch — AI-Powered Attack Surface Monitoring Framework

> NightWatch is a modular, extensible reconnaissance and continuous security monitoring framework for security researchers, penetration testers, bug bounty hunters, and DevSecOps teams. It unifies subdomain enumeration, service fingerprinting, CVE correlation, and infrastructure drift detection into a single, orchestrated pipeline.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/BiswasM21/NightWatch/blob/main/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/BiswasM21/NightWatch?style=social)](https://github.com/BiswasM21/NightWatch)
[![Forks](https://img.shields.io/github/forks/BiswasM21/NightWatch?style=social)](https://github.com/BiswasM21/NightWatch)

---

## Key Features

**Comprehensive Reconnaissance Pipeline**
- **Certificate Transparency (CT) Scanner** — Query crt.sh, CertSpotter, and SpySE to discover subdomains from SSL/TLS certificate logs
- **DNS Enumeration** — Fast async DNS bruteforce with custom wordlists, zone transfer detection, reverse DNS lookups
- **HTTP Probing & Fingerprinting** — Technology detection for 40+ frameworks, CMSes, and infrastructure components
- **Port Scanning** — Concurrent TCP scanning with service banner grabbing and version identification
- **CVE Correlation** — Built-in database of 50+ known vulnerable services with CVSS scoring and remediation guidance
- **Change Detection** — Monitor targets over time and detect new subdomains, open ports, or service changes
- **Interactive Reports** — Generate comprehensive HTML, JSON, and Markdown security reports

**Modular Architecture**
- Drop-in module system for extending functionality
- Async-first design for maximum scanning throughput
- SQLite persistence with full API for automation
- Web dashboard for visual result exploration

---

## Installation

```bash
# Clone the repository
git clone https://github.com/BiswasM21/NightWatch.git
cd NightWatch

# Install dependencies
pip install -r requirements.txt

# Install NightWatch
pip install -e .

# Verify installation
nightwatch --version
```

**With web dashboard (optional):**
```bash
pip install -r requirements.txt
pip install flask flask-socketio
nightwatchd  # Starts web dashboard on http://localhost:5000
```

---

## Quick Start

### 1. Create a Project
```bash
nightwatch project create mytarget --target example.com --description "Bug bounty target"
```

### 2. Run a Full Scan
```bash
nightwatch scan mytarget --target example.com --cve
```

### 3. View Results
```bash
nightwatch status mytarget
nightwatch report mytarget --format html
```

### 4. Set Up Continuous Monitoring
```bash
nightwatch monitor mytarget --interval 12
```

---

## Command Reference

### `nightwatch project`
Create and manage security research projects.

```bash
nightwatch project create <name> --target <domain> [-d "description"]
nightwatch project list
nightwatch project delete <name>
```

### `nightwatch scan`
Run reconnaissance scans with configurable modules.

```bash
nightwatch scan <project> --target <domain> [OPTIONS]

Options:
  --subdomains          Enable subdomain enumeration (default: enabled)
  --http                Probe HTTP/HTTPS services (default: enabled)
  --ports               Scan for open ports
  --cve                 Check for known CVEs (default: enabled)
  --scan-type {quick|common|full}  Port scan intensity (default: common)
  --output <file>       Save JSON results to file
```

### `nightwatch monitor`
Run continuous monitoring checks to detect infrastructure changes.

```bash
nightwatch monitor <project> --interval <hours>
```

### `nightwatch report`
Generate comprehensive security reports.

```bash
nightwatch report <project> --format {json|html|markdown|all}
```

### `nightwatch status`
Display a summary of scan results for a project.

```bash
nightwatch status <project>
```

---

## Architecture

```
NightWatch
├── core/
│   ├── engine.py      # Orchestration engine and scan pipeline
│   └── config.py     # Configuration management
├── modules/
│   ├── ct_scanner.py     # Certificate Transparency log scanner
│   ├── dns_enum.py       # DNS enumeration and bruteforce
│   ├── http_probe.py     # HTTP probing and tech fingerprinting
│   ├── port_scanner.py   # TCP port scanning and banner grabbing
│   ├── cve_correlator.py # Vulnerability correlation engine
│   ├── change_detector.py # Infrastructure change detection
│   └── report_generator.py # Multi-format report generation
├── db/
│   ├── database.py    # SQLAlchemy ORM models
│   └── session.py     # Async database session management
├── utils/
│   └── logging_utils.py  # Structured logging with Rich
└── web/
    └── dashboard.py   # Flask web dashboard
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| CLI Framework | Click | Command-line interface |
| Async HTTP | aiohttp | Non-blocking HTTP requests |
| DNS Resolution | dnspython | DNS enumeration and resolution |
| Parsing | BeautifulSoup4 + lxml | HTML parsing and tech detection |
| Database | SQLAlchemy + aiosqlite | Persistent scan results |
| UI | Rich | Terminal output formatting |
| Reports | Jinja2 | HTML/Markdown generation |
| Web Dashboard | Flask | Results visualization |

---

## Use Cases

**Bug Bounty Reconnaissance**
Automate subdomain enumeration and attack surface mapping for bug bounty programs. NightWatch's CT log scanning and DNS bruteforce provide comprehensive coverage of target infrastructure.

**Penetration Testing**
Pre-engagement reconnaissance: discover external-facing assets, fingerprint technologies, identify known vulnerabilities, and generate professional reports.

**Security Research**
Monitor your own infrastructure or research targets for exposed services, subdomain takeovers, and infrastructure changes over time.

**DevSecOps Automation**
Integrate NightWatch into CI/CD pipelines for automated attack surface monitoring. Export JSON reports for SIEM integration.

**CTF & Security Training**
Educational tool for learning reconnaissance techniques, web technology fingerprinting, and vulnerability assessment in controlled lab environments.

---

## CVE Coverage

NightWatch includes built-in CVE correlation for 50+ common vulnerable services including:

- Apache HTTP Server (CVE-2021-41773, CVE-2019-0211)
- nginx (CVE-2021-23017, CVE-2017-7529)
- Redis (CVE-2019-10192, CVE-2017-15088, CVE-2015-4335)
- Elasticsearch (CVE-2015-1427, CVE-2014-3120)
- Jenkins (CVE-2019-1003000, CVE-2018-1999002)
- Grafana (CVE-2021-43798, CVE-2023-3128)
- WordPress (CVE-2019-8942, CVE-2019-8943)
- Drupal (CVE-2018-7600, CVE-2019-6340)
- Spring Framework (CVE-2022-22965, CVE-2018-1273)
- GitLab (CVE-2021-22214, CVE-2022-3064)
- PostgreSQL (CVE-2019-9193, CVE-2021-23214)
- MySQL (CVE-2012-2122, CVE-2021-22931)
- Docker (CVE-2019-13139)
- Kubernetes (CVE-2021-25741, CVE-2019-11247)

---

## Configuration

NightWatch is configured via `~/.NightWatch/config.json`. Key settings:

```json
{
  "dns_resolvers": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
  "dns_timeout": 3.0,
  "http_timeout": 10.0,
  "port_timeout": 3.0,
  "max_concurrent_requests": 50,
  "common_ports": [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080, 8443],
  "default_monitor_interval_hours": 24
}
```

---

## API Keys (Optional)

For enhanced capabilities, set these environment variables:

```bash
export SHODAN_API_KEY="your-shodan-key"      # Port/service enrichment
export VT_API_KEY="your-virustotal-key"       # Threat intelligence
export HUNTER_API_KEY="your-hunter-key"       # Email reconnaissance
```

---

## Contributing

Contributions are welcome! Please read the code style guidelines and ensure all tests pass before submitting pull requests.

```bash
# Run tests
pytest

# Code formatting
black nightwatch/

# Type checking
mypy nightwatch/
```

---

## Disclaimer

NightWatch is designed exclusively for **authorized security testing**, **educational purposes**, and **security research** on systems you own or have explicit written permission to test. Unauthorized scanning of systems you do not own or lack permission for is illegal. The maintainers are not responsible for misuse of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Star the repo if you find it useful!**

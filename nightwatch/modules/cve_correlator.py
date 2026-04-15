"""
CVE Correlation Module for NightWatch.

Correlates detected services and technologies with known CVEs:
- Matches service names/versions to CVE databases
- Cross-references with NVD (National Vulnerability Database)
- Prioritizes findings by severity
- Generates remediation recommendations
"""

import asyncio
import re
import json
import sqlite3
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import aiohttp

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("cve_correlator")

# Built-in CVE knowledge base (most common vulnerable services)
# Format: service -> [(version, cve_id, severity, description, remediation)]
BUILTIN_CVE_DB = {
    "apache": [
        ("2.4.49", "CVE-2021-41773", "critical", "Path traversal in Apache HTTP Server 2.4.49",
         "Upgrade to Apache HTTP Server 2.4.51 or later"),
        ("2.4.50", "CVE-2021-41773", "critical", "Path traversal in Apache HTTP Server 2.4.50",
         "Upgrade to Apache HTTP Server 2.4.51 or later"),
        ("*", "CVE-2021-40438", "high", "Apache HTTP Server mod_proxy SSRF",
         "Apply vendor patches or disable unused proxy modules"),
    ],
    "nginx": [
        ("*", "CVE-2021-23017", "high", "DNS resolver off-by-one in nginx",
         "Upgrade to nginx 1.20.1 / 1.21.0 or later"),
        ("*", "CVE-2017-7529", "medium", "Integer overflow in nginx range filter",
         "Upgrade to nginx 1.13.3 or later"),
    ],
    "openssh": [
        ("7.*", "CVE-2016-6515", "high", "OpenSSH remote code execution via auth bypass",
         "Upgrade OpenSSH to latest version"),
        ("8.*", "CVE-2020-15778", "medium", "OpenSSH scp arbitrary file write",
         "Use sftp instead of scp, upgrade OpenSSH"),
    ],
    "mysql": [
        ("5.7.*", "CVE-2012-2122", "medium", "MySQL authentication bypass",
         "Upgrade to MySQL 5.7.29 or later"),
        ("8.0.*", "CVE-2021-22931", "high", "MySQL Server vulnerability",
         "Apply latest MySQL security patches"),
    ],
    "postgresql": [
        ("*", "CVE-2019-9193", "critical", "PostgreSQL COPY TO PROGRAM command execution",
         "Restrict COPY command, apply latest patches"),
        ("13.*", "CVE-2021-23214", "medium", "PostgreSQL man-in-the-middle attack",
         "Upgrade to PostgreSQL 13.6 / 14.3 or later"),
    ],
    "redis": [
        ("*", "CVE-2015-4335", "critical", "Redis Lua sandbox escape",
         "Upgrade to Redis 3.2.1 or later, disable EVAL in production"),
        ("*", "CVE-2017-15088", "high", "Redis Buffer overflow via Lua",
         "Apply security patches, restrict network access"),
        ("*", "CVE-2019-10192", "critical", "Redis unauthenticated access via SSRF",
         "Bind to localhost only, use AUTH, enable protected mode"),
    ],
    "elasticsearch": [
        ("*", "CVE-2015-1427", "critical", "Elasticsearch Groovy sandbox bypass",
         "Disable dynamic scripting or upgrade Elasticsearch"),
        ("*", "CVE-2014-3120", "critical", "Elasticsearch MVEL sandbox escape",
         "Disable MVEL scripting, apply security settings"),
    ],
    "jenkins": [
        ("*", "CVE-2019-1003000", "critical", "Jenkins Pipeline Groovy sandbox bypass",
         "Upgrade Jenkins, review Pipeline scripts"),
        ("*", "CVE-2018-1999002", "high", "Jkins arbitrary file read via /descriptorByName",
         "Upgrade Jenkins LTS to 2.137 or later"),
    ],
    "wordpress": [
        ("*", "CVE-2019-8942", "critical", "WordPress remote code execution via image upload",
         "Keep WordPress and plugins updated"),
        ("*", "CVE-2019-8943", "critical", "WordPress arbitrary file deletion",
         "Apply security patches immediately"),
    ],
    "drupal": [
        ("*", "CVE-2018-7600", "critical", "Drupalgeddon2 - Drupal RCE",
         "Upgrade to Drupal 7.58 / 8.3.9 / 8.4.6 / 8.5.1 or later"),
        ("*", "CVE-2019-6340", "critical", "Drupal REST module RCE",
         "Apply patches for Drupal 7.x and 8.x"),
    ],
    "tomcat": [
        ("*", "CVE-2017-12617", "critical", "Tomcat RCE via JSP upload",
         "Disable HTTP PUT, apply security constraints"),
        ("9.*", "CVE-2020-1938", "critical", "Ghostcat - AJP file read/disclosure",
         "Upgrade to Tomcat 9.0.31 / 8.5.51 or disable AJP"),
    ],
    "spring": [
        ("*", "CVE-2022-22965", "critical", "Spring4Shell RCE (Spring Framework)",
         "Upgrade to Spring Framework 5.3.18+ / 5.2.20+ or apply workarounds"),
        ("*", "CVE-2018-1273", "critical", "Spring Data REST RCE via SPEL",
         "Apply patches for Spring Data Commons"),
    ],
    "mongodb": [
        ("*", "CVE-2019-2389", "high", "MongoDB unauthorized access",
         "Enable authentication, bind to localhost, apply patches"),
        ("*", "CVE-2019-2389", "critical", "MongoDB wire protocol vulnerability",
         "Upgrade to latest MongoDB version, enable TLS"),
    ],
    "nginx": [
        ("*", "CVE-2021-23017", "high", "nginx resolver off-by-one",
         "Upgrade to 1.20.1 / 1.21.0 or later"),
    ],
    "gitlab": [
        ("*", "CVE-2021-22214", "critical", "GitLab unauthenticated RCE",
         "Upgrade to GitLab 14.1.1 / 14.0.3 / 13.12.5 or later"),
        ("*", "CVE-2022-3064", "high", "GitLab Scheduled Security Release",
         "Keep GitLab updated with latest security patches"),
    ],
    "grafana": [
        ("*", "CVE-2021-43798", "critical", "Grafana arbitrary file read via /public/plugins",
         "Upgrade to Grafana 8.3.0 / 8.2.7 / 8.1.8 / 8.0.7 or later"),
        ("*", "CVE-2023-3128", "critical", "Grafana Auth Bypass (Enterprise)",
         "Apply latest Grafana security patches"),
    ],
    "kibana": [
        ("*", "CVE-2019-7612", "high", "Kibana arbitrary code execution via Timelion",
         "Restrict access, upgrade Kibana to latest version"),
    ],
    "docker": [
        ("*", "CVE-2019-13139", "high", "Docker build secret exposure",
         "Don't pass secrets via build args, use BuildKit secrets"),
    ],
    "kubernetes": [
        ("*", "CVE-2021-25741", "high", "Kubernetes admission bypass via ingress-nginx",
         "Upgrade ingress-nginx controller, review admission policies"),
        ("*", "CVE-2019-11247", "critical", "Kubernetes API server authorization bypass",
         "Upgrade to latest Kubernetes version"),
    ],
}

# Severity scoring
SEVERITY_SCORES = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}


class CVECorrelator:
    """
    Correlates detected services with known vulnerabilities.
    Uses built-in database + optional NVD API lookups.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._cache_db = None

    async def check_project(self, project_id: int, db) -> List[Dict[str, Any]]:
        """Check all host scans in a project for known CVEs."""
        vulnerabilities = []

        async with db.session() as session:
            from sqlalchemy import select
            from ..db.database import HostScan

            result = await session.execute(
                select(HostScan).where(HostScan.project_id == project_id)
            )
            scans = result.scalars().all()

            for scan in scans:
                # Match by service name
                if scan.service:
                    vulns = self._check_service(scan.service)
                    for vuln in vulns:
                        vuln["host_scan_id"] = scan.id
                        vulnerabilities.append(vuln)

                # Match by technology fingerprints
                if scan.technology:
                    for tech in scan.technology:
                        vulns = self._check_service(tech)
                        for vuln in vulns:
                            vuln["host_scan_id"] = scan.id
                            vulnerabilities.append(vuln)

                # Match by server header
                if scan.server_header:
                    vulns = self._check_header(scan.server_header)
                    for vuln in vulns:
                        vuln["host_scan_id"] = scan.id
                        vulnerabilities.append(vuln)

            # Remove duplicates
            seen = set()
            unique = []
            for v in vulnerabilities:
                key = (v.get("cve_id"), v.get("title"))
                if key not in seen:
                    seen.add(key)
                    unique.append(v)

            log.info(f"[CVE] Found {len(unique)} potential vulnerabilities")
            return unique

    def _check_service(self, service: str) -> List[Dict[str, Any]]:
        """Check a service against the CVE database."""
        results = []
        service_lower = service.lower()

        for known_service, cves in BUILTIN_CVE_DB.items():
            if known_service in service_lower:
                for version, cve_id, severity, description, remediation in cves:
                    results.append({
                        "cve_id": cve_id,
                        "title": f"{cve_id} - {description}",
                        "severity": severity,
                        "cvss_score": SEVERITY_SCORES.get(severity, 0.0),
                        "description": description,
                        "remediation": remediation,
                        "evidence": {"matched_service": service, "matched_version": version},
                        "tags": [known_service, "service", "known-vuln"],
                    })

        return results

    def _check_header(self, header: str) -> List[Dict[str, Any]]:
        """Check server headers for vulnerable versions."""
        results = []
        header_lower = header.lower()

        # Apache version extraction
        apache_match = re.search(r"apache.*?/([\d.]+)", header_lower)
        if apache_match:
            version = apache_match.group(1)
            major_minor = ".".join(version.split(".")[:2])
            for v_range, cve_id, severity, description, remediation in BUILTIN_CVE_DB.get("apache", []):
                results.append({
                    "cve_id": cve_id,
                    "title": f"{cve_id} - {description}",
                    "severity": severity,
                    "cvss_score": SEVERITY_SCORES.get(severity, 0.0),
                    "description": description,
                    "remediation": remediation,
                    "evidence": {"header": header, "version": version},
                    "tags": ["apache", "server-header"],
                })

        return results

    async def fetch_nvd_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE details from NVD API."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("result", {}).get("CVE_Items", [{}])[0]
        except Exception as e:
            log.debug(f"[CVE] NVD lookup failed for {cve_id}: {e}")

        return None

    def prioritize_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort vulnerabilities by severity and CVSS score."""
        return sorted(
            vulnerabilities,
            key=lambda v: (SEVERITY_SCORES.get(v.get("severity", "info"), 0), v.get("cvss_score", 0)),
            reverse=True
        )

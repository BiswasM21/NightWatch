"""Core orchestration engine for NightWatch."""

import asyncio
import time
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..db.database import (
    Project, Subdomain, HostScan, Vulnerability,
    ScanHistory, ChangeLog
)
from ..db.session import Database, get_db
from ..core.config import Config, get_config
from ..utils.logging_utils import get_logger

log = get_logger("engine")


class NightWatchEngine:
    """
    Central orchestration engine that coordinates reconnaissance modules,
    stores results, correlates findings, and manages the scan pipeline.
    """

    def __init__(self, config: Optional[Config] = None, db_path: Optional[str] = None):
        self.config = config or get_config()
        self.db = get_db(db_path or self.config.db_path)
        self.console = Console()
        self._active_project: Optional[int] = None
        self._scan_history_id: Optional[int] = None

    # ─── Project Management ───────────────────────────────────────────────

    async def create_project(
        self,
        name: str,
        target_domain: str,
        description: str = "",
        scope: List[str] = None
    ) -> int:
        """Create a new security research project."""
        async with self.db.session() as session:
            project = Project(
                name=name,
                target_domain=target_domain,
                description=description,
                scope=scope or [target_domain],
            )
            session.add(project)
            await session.flush()
            pid = project.id
            log.info(f"[green]Created project[/green] '{name}' (ID: {pid})")
            return pid

    async def get_project(self, name: str) -> Optional[Project]:
        """Get project by name."""
        async with self.db.session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Project).where(Project.name == name)
            )
            return result.scalar_one_or_none()

    async def list_projects(self) -> List[Project]:
        """List all projects."""
        async with self.db.session() as session:
            from sqlalchemy import select
            result = await session.execute(select(Project).order_by(Project.created_at.desc()))
            return list(result.scalars().all())

    # ─── Scan Pipeline ──────────────────────────────────────────────────────

    async def run_full_scan(
        self,
        project_id: int,
        targets: List[str],
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run a complete reconnaissance scan pipeline:
        1. Subdomain enumeration (CT logs + DNS bruteforce)
        2. HTTP probing and tech fingerprinting
        3. Port scanning
        4. CVE correlation
        """
        opts = options or {}
        self._active_project = project_id
        start_time = time.time()

        # Record scan history
        async with self.db.session() as session:
            scan_record = ScanHistory(
                project_id=project_id,
                scan_type="full",
                targets=targets,
                command_args=opts,
                status="running"
            )
            session.add(scan_record)
            await session.flush()
            self._scan_history_id = scan_record.id

        log.info(f"[bold cyan]Starting full scan for project {project_id}[/bold cyan]")
        self.console.print(f"[bold]Targets:[/bold] {', '.join(targets)}")

        results = {
            "subdomains_found": 0,
            "hosts_probed": 0,
            "open_ports_found": 0,
            "vulnerabilities_found": 0,
            "changes_detected": 0,
            "scan_time_seconds": 0,
        }

        # Step 1: Subdomain enumeration
        subdomains = await self._enumerate_subdomains(project_id, targets, opts)
        results["subdomains_found"] = len(subdomains)

        # Step 2: HTTP probing
        probed = await self._probe_hosts(project_id, subdomains, opts)
        results["hosts_probed"] = probed

        # Step 3: Port scanning
        ports = await self._scan_ports(project_id, subdomains, opts)
        results["open_ports_found"] = ports

        # Step 4: CVE correlation
        if opts.get("cve_check", True):
            vulns = await self._correlate_cves(project_id, opts)
            results["vulnerabilities_found"] = vulns

        results["scan_time_seconds"] = round(time.time() - start_time, 2)

        # Update scan history
        async with self.db.session() as session:
            from sqlalchemy import select
            record = await session.execute(
                select(ScanHistory).where(ScanHistory.id == self._scan_history_id)
            )
            rec = record.scalar_one()
            rec.status = "completed"
            rec.completed_at = datetime.now()
            rec.results_summary = results

        log.info(
            f"[green]Scan complete in {results['scan_time_seconds']}s:[/green] "
            f"{results['subdomains_found']} subdomains, "
            f"{results['hosts_probed']} hosts probed, "
            f"{results['open_ports_found']} open ports, "
            f"{results['vulnerabilities_found']} vulnerabilities"
        )

        return results

    async def _enumerate_subdomains(
        self,
        project_id: int,
        targets: List[str],
        options: Dict[str, Any]
    ) -> List[str]:
        """Enumerate subdomains using CT logs and DNS bruteforce."""
        from ..modules.ct_scanner import CTScanner
        from ..modules.dns_enum import DNSEnumerator

        all_subdomains = []
        seen = set()

        # Import modules lazily to avoid circular imports
        ct_scanner = CTScanner(self.config)
        dns_enum = DNSEnumerator(self.config)

        for target in targets:
            log.info(f"[yellow]Enumerating subdomains for:[/yellow] {target}")

            # CT log scan
            ct_results = await ct_scanner.scan(target)
            for sub in ct_results:
                if sub not in seen:
                    seen.add(sub)
                    all_subdomains.append(sub)
                    await self._save_subdomain(project_id, sub, "ct_log")
                    log.debug(f"  [CT] {sub}")

            # DNS bruteforce
            dns_results = await dns_enum.enumerate(target, wordlist=options.get("wordlist"))
            for sub in dns_results:
                if sub not in seen:
                    seen.add(sub)
                    all_subdomains.append(sub)
                    await self._save_subdomain(project_id, sub, "dns_bruteforce")
                    log.debug(f"  [DNS] {sub}")

        return all_subdomains

    async def _save_subdomain(self, project_id: int, domain: str, source: str):
        """Save a subdomain to the database."""
        from ..modules.dns_enum import DNSEnumerator
        resolver = DNSEnumerator(self.config)

        async with self.db.session() as session:
            ip = await resolver.resolve(domain)
            ip_country = None
            ip_asn = None

            if ip:
                # Basic geo lookup (no external API needed)
                import socket
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = None

            sub = Subdomain(
                project_id=project_id,
                domain=domain,
                source=source,
                ip_address=ip,
                ip_country=ip_country,
                ip_asn=ip_asn,
            )
            session.add(sub)

    async def _probe_hosts(
        self,
        project_id: int,
        subdomains: List[str],
        options: Dict[str, Any]
    ) -> int:
        """Probe HTTP/HTTPS services."""
        from ..modules.http_probe import HTTPProfiler

        if not subdomains:
            return 0

        profiler = HTTPProfiler(self.config)
        probed = await profiler.probe_batch(subdomains, project_id, self.db)

        for result in probed:
            async with self.db.session() as session:
                scan = HostScan(
                    project_id=project_id,
                    subdomain_id=result.get("subdomain_id"),
                    host=result["host"],
                    ip_address=result["ip_address"],
                    port=result["port"],
                    service=result.get("service"),
                    banner=result.get("banner"),
                    technology=result.get("technology"),
                    status_code=result.get("status_code"),
                    server_header=result.get("server_header"),
                    title=result.get("title"),
                    extra_data=result.get("metadata"),
                )
                session.add(scan)

        return len(probed)

    async def _scan_ports(
        self,
        project_id: int,
        subdomains: List[str],
        options: Dict[str, Any]
    ) -> int:
        """Scan for open ports on discovered hosts."""
        from ..modules.port_scanner import PortScanner

        if not subdomains:
            return 0

        scanner = PortScanner(self.config)
        port_results = await scanner.scan_hosts(subdomains, options)

        count = 0
        for result in port_results:
            if result.get("open_ports"):
                count += len(result["open_ports"])
                async with self.db.session() as session:
                    for port_info in result["open_ports"]:
                        scan = HostScan(
                            project_id=project_id,
                            host=result["host"],
                            ip_address=result["ip_address"],
                            port=port_info["port"],
                            service=port_info.get("service"),
                            banner=port_info.get("banner"),
                        )
                        session.add(scan)

        return count

    async def _correlate_cves(self, project_id: int, options: Dict[str, Any]) -> int:
        """Correlate detected services with known CVEs."""
        from ..modules.cve_correlator import CVECorrelator

        correlator = CVECorrelator(self.config)
        vulns = await correlator.check_project(project_id, self.db)

        for vuln in vulns:
            async with self.db.session() as session:
                v = Vulnerability(
                    project_id=project_id,
                    host_scan_id=vuln.get("host_scan_id"),
                    title=vuln["title"],
                    severity=vuln["severity"],
                    cvss_score=vuln.get("cvss_score"),
                    cve_id=vuln.get("cve_id"),
                    description=vuln.get("description"),
                    remediation=vuln.get("remediation"),
                    evidence=vuln.get("evidence"),
                    tags=vuln.get("tags"),
                )
                session.add(v)

        return len(vulns)

    # ─── Monitoring ────────────────────────────────────────────────────────

    async def run_monitor_check(self, project_id: int) -> List[Dict[str, Any]]:
        """Run a monitoring check for a project and detect changes."""
        from ..modules.change_detector import ChangeDetector

        detector = ChangeDetector(self.config)
        changes = await detector.check_project(project_id, self.db)

        for change in changes:
            async with self.db.session() as session:
                cl = ChangeLog(
                    project_id=project_id,
                    change_type=change["type"],
                    description=change["description"],
                    old_value=change.get("old_value"),
                    new_value=change.get("new_value"),
                    severity=change.get("severity", "info"),
                )
                session.add(cl)

        return changes

    # ─── Results & Reporting ───────────────────────────────────────────────

    async def get_summary(self, project_id: int) -> Dict[str, Any]:
        """Get a summary of all results for a project."""
        async with self.db.session() as session:
            from sqlalchemy import select, func

            sub_count = await session.scalar(
                select(func.count(Subdomain.id)).where(Subdomain.project_id == project_id)
            )
            vuln_count = await session.scalar(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.project_id == project_id
                )
            )
            host_count = await session.scalar(
                select(func.count(HostScan.id)).where(HostScan.project_id == project_id)
            )
            change_count = await session.scalar(
                select(func.count(ChangeLog.id)).where(
                    ChangeLog.project_id == project_id
                )
            )

            # Severity breakdown
            from sqlalchemy import distinct
            severities = {}
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = await session.scalar(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.project_id == project_id,
                        Vulnerability.severity == sev,
                        Vulnerability.false_positive == False
                    )
                )
                severities[sev] = count or 0

            return {
                "subdomains": sub_count or 0,
                "hosts": host_count or 0,
                "vulnerabilities": vuln_count or 0,
                "severities": severities,
                "changes_detected": change_count or 0,
            }

    def print_summary(self, project_id: int):
        """Print a formatted summary table."""
        summary = asyncio.get_event_loop().run_until_complete(
            self.get_summary(project_id)
        )

        table = Table(title="NightWatch Scan Summary", style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Count")

        table.add_row("Subdomains Discovered", str(summary["subdomains"]))
        table.add_row("Hosts/Ports Scanned", str(summary["hosts"]))
        table.add_row("Vulnerabilities Found", str(summary["vulnerabilities"]))
        for sev, count in summary["severities"].items():
            if count > 0:
                color = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(sev, "")
                table.add_row(f"  {sev.capitalize()}", f"[{color}]{count}[/{color}]")
        table.add_row("Changes Detected", str(summary["changes_detected"]))

        self.console.print(table)

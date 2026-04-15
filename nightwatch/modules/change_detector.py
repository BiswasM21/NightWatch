"""
Change Detection Module for NightWatch.

Monitors targets for changes over time:
- Detects new subdomains
- Identifies new open ports
- Flags service version changes
- Alerts on DNS changes
- Tracks infrastructure drift
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import asyncio

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("change_detector")

SEVERITY_FROM_CHANGE = {
    "new_admin_panel": "high",
    "new_credential_page": "critical",
    "new_api_endpoint": "medium",
    "new_subdomain": "info",
    "new_port": "low",
    "dns_change": "medium",
    "new_service": "info",
    "service_version_change": "high",
    "new_technology": "low",
    "new_ip": "info",
}


class ChangeDetector:
    """
    Detects changes in monitored infrastructure over time.
    Compares current scan results with previous snapshots.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    async def check_project(self, project_id: int, db) -> List[Dict[str, Any]]:
        """Run a change detection check for a project."""
        changes = []

        async with db.session() as session:
            from sqlalchemy import select, and_
            from ..db.database import Subdomain, HostScan, MonitoredTarget

            # Get current state
            subdomains = (await session.execute(
                select(Subdomain).where(Subdomain.project_id == project_id)
            )).scalars().all()

            host_scans = (await session.execute(
                select(HostScan).where(HostScan.project_id == project_id)
            )).scalars().all()

            # Get monitored targets
            targets = (await session.execute(
                select(MonitoredTarget).where(
                    and_(
                        MonitoredTarget.project_id == project_id,
                        MonitoredTarget.is_active == True
                    )
                )
            )).scalars().all()

            # Check each target
            for target in targets:
                target_changes = await self._check_target(
                    target, subdomains, host_scans, session
                )
                changes.extend(target_changes)

            log.info(f"[Monitor] Detected {len(changes)} changes in project {project_id}")

        return changes

    async def _check_target(
        self,
        target,
        current_subdomains,
        current_scans,
        session
    ) -> List[Dict[str, Any]]:
        """Check a single monitored target for changes."""
        changes = []
        target_type = target.target_type
        target_value = target.target_value
        last_snapshot = target.last_snapshot or {}

        if target_type == "domain":
            # Check for new subdomains
            current_subs = {s.domain for s in current_subdomains if target_value in s.domain}
            old_subs = set(last_snapshot.get("subdomains", []))

            new_subs = current_subs - old_subs
            for sub in new_subs:
                changes.append({
                    "type": "new_subdomain",
                    "description": f"New subdomain discovered: {sub}",
                    "new_value": sub,
                    "old_value": None,
                    "severity": "info",
                    "monitored_target_id": target.id,
                })

            # Check for removed subdomains
            removed_subs = old_subs - current_subs
            for sub in removed_subs:
                changes.append({
                    "type": "removed_subdomain",
                    "description": f"Subdomain no longer resolves: {sub}",
                    "new_value": None,
                    "old_value": sub,
                    "severity": "low",
                    "monitored_target_id": target.id,
                })

        elif target_type == "ip":
            # Check for new ports
            current_ips = {s.ip_address for s in current_scans if s.ip_address == target_value}
            old_ports = set(last_snapshot.get("ports", []))

            new_port_scans = [
                s for s in current_scans
                if s.ip_address == target_value and s.port not in old_ports
            ]

            for scan in new_port_scans:
                change_type = "new_port"
                severity = "low"

                # Flag potentially dangerous ports
                dangerous_ports = {22, 23, 3389, 5900, 3306, 5432, 27017, 6379}
                if scan.port in dangerous_ports:
                    change_type = f"new_dangerous_port_{scan.port}"
                    severity = "medium"

                changes.append({
                    "type": change_type,
                    "description": f"New open port detected: {scan.port}/{scan.service or 'unknown'} on {target_value}",
                    "new_value": f"{scan.port}/{scan.service}",
                    "old_value": None,
                    "severity": severity,
                    "monitored_target_id": target.id,
                })

        # Update snapshot
        new_snapshot = {
            "subdomains": list(current_subs) if target_type == "domain" else [],
            "ports": [s.port for s in current_scans if s.ip_address == target_value] if target_type == "ip" else [],
            "checked_at": datetime.now().isoformat(),
        }
        target.last_snapshot = new_snapshot
        target.last_check = datetime.now()
        target.next_check = datetime.now() + timedelta(hours=target.interval_hours)

        return changes

    async def detect_infrastructure_drift(
        self,
        project_id: int,
        db,
        baseline: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Compare current state against a baseline snapshot.
        Useful for compliance and drift detection.
        """
        changes = []
        current_state = await self._get_current_state(project_id, db)

        # Compare subdomains
        baseline_subs = set(baseline.get("subdomains", []))
        current_subs = set(current_state.get("subdomains", []))
        for new_sub in current_subs - baseline_subs:
            changes.append(self._make_change(
                "new_subdomain", new_sub, None, "info"
            ))
        for removed in baseline_subs - current_subs:
            changes.append(self._make_change(
                "removed_subdomain", None, removed, "low"
            ))

        # Compare ports
        baseline_ports = baseline.get("open_ports", [])
        current_ports = current_state.get("open_ports", [])
        new_ports = set(current_ports) - set(baseline_ports)
        for port in new_ports:
            changes.append(self._make_change(
                "new_port", port, None, "medium"
            ))

        # Compare technologies
        baseline_tech = set(baseline.get("technologies", []))
        current_tech = set(current_state.get("technologies", []))
        for new_tech in current_tech - baseline_tech:
            changes.append(self._make_change(
                "new_technology", new_tech, None, "low"
            ))

        return changes

    async def _get_current_state(self, project_id: int, db) -> Dict[str, Any]:
        """Get current state snapshot for a project."""
        async with db.session() as session:
            from sqlalchemy import select
            from ..db.database import Subdomain, HostScan

            subs = (await session.execute(
                select(Subdomain).where(Subdomain.project_id == project_id)
            )).scalars().all()

            scans = (await session.execute(
                select(HostScan).where(HostScan.project_id == project_id)
            )).scalars().all()

            return {
                "subdomains": [s.domain for s in subs],
                "open_ports": [s.port for s in scans if s.port],
                "technologies": list(set(
                    t for s in scans if s.technology
                    for t in s.technology
                )),
            }

    def _make_change(
        self,
        change_type: str,
        new_value: Any,
        old_value: Any,
        severity: str,
        description: str = None
    ) -> Dict[str, Any]:
        """Create a change record."""
        return {
            "type": change_type,
            "description": description or f"{change_type}: {new_value or old_value}",
            "new_value": new_value,
            "old_value": old_value,
            "severity": severity,
        }

"""
NightWatch Web Dashboard — Flask-based results viewer.

Provides a web UI for viewing scan results, vulnerabilities, and changes.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, render_template, jsonify, request
    from flask_socketio import SocketIO, emit
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from ..db.session import Database
from ..utils.logging_utils import get_logger

log = get_logger("dashboard")


def create_app(db_path: str = None):
    """Create the Flask application."""
    if not HAS_FLASK:
        raise ImportError("Flask is required for the web dashboard. Install with: pip install flask flask-socketio")

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "nightwatch-secret-key-change-in-production"
    app.config["NIGHTWATCH_DB"] = db_path or str(Path.home() / "NightWatch" / "nightwatch.db")

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    db = Database(app.config["NIGHTWATCH_DB"])
    db.initialize_sync()

    # ─── Routes ───────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Dashboard home page."""
        return render_template("dashboard.html", title="NightWatch Dashboard")

    @app.route("/api/projects")
    def api_projects():
        """List all projects."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import Project
            projects = session.execute(select(Project)).scalars().all()
            return jsonify([{
                "id": p.id,
                "name": p.name,
                "target_domain": p.target_domain,
                "description": p.description,
                "is_active": p.is_active,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            } for p in projects])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>")
    def api_project(project_id):
        """Get project details."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import Project
            p = session.execute(select(Project).where(Project.id == project_id)).scalar_one_or_none()
            if not p:
                return jsonify({"error": "Project not found"}), 404
            return jsonify({
                "id": p.id,
                "name": p.name,
                "target_domain": p.target_domain,
                "description": p.description,
                "is_active": p.is_active,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            })
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/summary")
    def api_project_summary(project_id):
        """Get project summary."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select, func
            from ..db.database import Project, Subdomain, HostScan, Vulnerability, ChangeLog

            sub_count = session.scalar(
                select(func.count(Subdomain.id)).where(Subdomain.project_id == project_id)
            ) or 0
            host_count = session.scalar(
                select(func.count(HostScan.id)).where(HostScan.project_id == project_id)
            ) or 0
            vuln_count = session.scalar(
                select(func.count(Vulnerability.id)).where(Vulnerability.project_id == project_id)
            ) or 0
            change_count = session.scalar(
                select(func.count(ChangeLog.id)).where(ChangeLog.project_id == project_id)
            ) or 0

            severities = {}
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = session.scalar(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.project_id == project_id,
                        Vulnerability.severity == sev,
                        Vulnerability.false_positive == False
                    )
                ) or 0
                severities[sev] = count

            return jsonify({
                "subdomains": sub_count,
                "hosts": host_count,
                "vulnerabilities": vuln_count,
                "changes": change_count,
                "severities": severities,
            })
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/subdomains")
    def api_subdomains(project_id):
        """Get subdomains for a project."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import Subdomain
            subs = session.execute(
                select(Subdomain).where(Subdomain.project_id == project_id).limit(500)
            ).scalars().all()
            return jsonify([{
                "id": s.id,
                "domain": s.domain,
                "ip_address": s.ip_address,
                "source": s.source,
                "is_alive": s.is_alive,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                "tags": s.tags or [],
            } for s in subs])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/hosts")
    def api_hosts(project_id):
        """Get host scan results for a project."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import HostScan
            hosts = session.execute(
                select(HostScan).where(HostScan.project_id == project_id).limit(500)
            ).scalars().all()
            return jsonify([{
                "id": h.id,
                "host": h.host,
                "ip_address": h.ip_address,
                "port": h.port,
                "service": h.service,
                "status_code": h.status_code,
                "server_header": h.server_header,
                "title": h.title,
                "technology": h.technology or [],
                "scan_time": h.scan_time.isoformat() if h.scan_time else None,
            } for h in hosts])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/vulnerabilities")
    def api_vulnerabilities(project_id):
        """Get vulnerabilities for a project."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import Vulnerability
            vulns = session.execute(
                select(Vulnerability).where(Vulnerability.project_id == project_id).limit(200)
            ).scalars().all()
            return jsonify([{
                "id": v.id,
                "title": v.title,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "description": v.description,
                "remediation": v.remediation,
                "status": v.status,
                "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
                "tags": v.tags or [],
            } for v in vulns])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/changes")
    def api_changes(project_id):
        """Get change log for a project."""
        session = db.get_sync_session()
        try:
            from sqlalchemy import select
            from ..db.database import ChangeLog
            changes = session.execute(
                select(ChangeLog).where(ChangeLog.project_id == project_id).limit(100)
            ).scalars().all()
            return jsonify([{
                "id": c.id,
                "change_type": c.change_type,
                "description": c.description,
                "old_value": c.old_value,
                "new_value": c.new_value,
                "severity": c.severity,
                "detected_at": c.detected_at.isoformat() if c.detected_at else None,
                "acknowledged": c.acknowledged,
            } for c in changes])
        finally:
            session.close()

    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok", "version": "1.0.0"})

    return app, socketio


def main():
    """Run the dashboard server."""
    if not HAS_FLASK:
        print("Error: Flask is required. Install with: pip install flask flask-socketio")
        return

    app, socketio = create_app()
    print("""
    ╔═══════════════════════════════════════════╗
    ║       NightWatch Web Dashboard            ║
    ║  Attack Surface Monitoring Framework      ║
    ╠═══════════════════════════════════════════╣
    ║  Dashboard:  http://localhost:5000       ║
    ║  Press Ctrl+C to stop                    ║
    ╚═══════════════════════════════════════════╝
    """)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()

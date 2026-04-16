"""
NightWatch Web Dashboard — Production WSGI Entry Point for Render.com

Handles: Flask app creation, DB init, health checks, WSGI serving.

Usage (Render build command):
    pip install -r requirements-web.txt && pip install -e .
    gunicorn app:app -w 4 -b 0.0.0.0:$PORT --timeout 120

Usage (local):
    pip install -r requirements-web.txt && pip install -e .
    gunicorn app:app -w 2 -b 0.0.0.0:5000
"""

import os
import sys
from pathlib import Path

# Ensure the editable install of nightwatch is on the path
sys.path.insert(0, os.path.dirname(__file__))

# ── Dependency Check ─────────────────────────────────────────────────────────────
_MISSING = []
for _pkg, _mod in [
    ("flask>=3.0.0", "flask"),
    ("sqlalchemy>=2.0.0", "sqlalchemy"),
    ("aiosqlite>=0.19.0", "aiosqlite"),
    ("click>=8.1.0", "click"),
    ("rich>=13.7.0", "rich"),
]:
    try:
        __import__(_mod)
    except ImportError:
        _MISSING.append(_pkg)

if _MISSING:
    print("ERROR: Missing dependencies. Install with:", file=sys.stderr)
    print(f"  pip install {' '.join(_MISSING)}", file=sys.stderr)
    sys.exit(1)

# ── Flask & DB Setup ────────────────────────────────────────────────────────────
from flask import Flask, render_template, jsonify, request

# DB path: /data is Render's persistent disk mount (Starter+ plans).
# Falls back to ~/NightWatch/ on local or Free plan.
_DB_DIR = Path("/data" if os.path.exists("/data") else Path.home() / "NightWatch")
_DB_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = os.environ.get("NIGHTWATCH_DB", str(_DB_DIR / "nightwatch.db"))

# Import DB after path setup
from nightwatch.db.session import Database
from nightwatch.db.database import (
    Project, Subdomain, HostScan, Vulnerability, ChangeLog, ScanHistory
)

db = Database(_DB_PATH)
db.initialize_sync()

# ── App Factory ────────────────────────────────────────────────────────────────
def create_app():
    # Templates live in nightwatch/web/templates (in the editable install)
    _pkg_root = Path(__file__).parent / "nightwatch" / "web"
    _tmpl_dir = str(_pkg_root / "templates")

    app = Flask(__name__, template_folder=_tmpl_dir, static_folder="static")
    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "nightwatch-change-this-in-production"
    )
    app.config["NIGHTWATCH_DB"] = _DB_PATH

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("dashboard.html", title="NightWatch Dashboard")

    @app.route("/api/status")
    def api_status():
        db_file = Path(_DB_PATH)
        return jsonify({
            "status": "ok",
            "version": "1.0.0",
            "db_path": _DB_PATH,
            "db_exists": db_file.exists(),
            "db_size_kb": round(db_file.stat().st_size / 1024, 1) if db_file.exists() else 0,
        })

    @app.route("/api/projects")
    def api_projects():
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
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
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            p = session.execute(
                select(Project).where(Project.id == project_id)
            ).scalar_one_or_none()
            if not p:
                return jsonify({"error": "Project not found"}), 404
            return jsonify({
                "id": p.id, "name": p.name, "target_domain": p.target_domain,
                "description": p.description, "is_active": p.is_active,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            })
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/summary")
    def api_project_summary(project_id):
        from sqlalchemy import select, func
        session = db.get_sync_session()
        try:
            sub_count = session.scalar(
                select(func.count(Subdomain.id)).where(Subdomain.project_id == project_id)
            ) or 0
            host_count = session.scalar(
                select(func.count(HostScan.id)).where(HostScan.project_id == project_id)
            ) or 0
            vuln_count = session.scalar(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.project_id == project_id,
                    Vulnerability.false_positive == False
                )
            ) or 0
            change_count = session.scalar(
                select(func.count(ChangeLog.id)).where(ChangeLog.project_id == project_id)
            ) or 0

            severities = {}
            for sev in ["critical", "high", "medium", "low", "info"]:
                severities[sev] = session.scalar(
                    select(func.count(Vulnerability.id)).where(
                        Vulnerability.project_id == project_id,
                        Vulnerability.severity == sev,
                        Vulnerability.false_positive == False
                    )
                ) or 0

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
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            subs = session.execute(
                select(Subdomain).where(Subdomain.project_id == project_id).limit(500)
            ).scalars().all()
            return jsonify([{
                "id": s.id, "domain": s.domain, "ip_address": s.ip_address,
                "source": s.source, "is_alive": s.is_alive,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                "tags": s.tags or [],
            } for s in subs])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/hosts")
    def api_hosts(project_id):
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            hosts = session.execute(
                select(HostScan).where(HostScan.project_id == project_id).limit(500)
            ).scalars().all()
            return jsonify([{
                "id": h.id, "host": h.host, "ip_address": h.ip_address,
                "port": h.port, "service": h.service,
                "status_code": h.status_code, "server_header": h.server_header,
                "title": h.title, "technology": h.technology or [],
                "scan_time": h.scan_time.isoformat() if h.scan_time else None,
            } for h in hosts])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/vulnerabilities")
    def api_vulnerabilities(project_id):
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            vulns = session.execute(
                select(Vulnerability).where(Vulnerability.project_id == project_id).limit(200)
            ).scalars().all()
            return jsonify([{
                "id": v.id, "title": v.title, "cve_id": v.cve_id,
                "severity": v.severity, "cvss_score": v.cvss_score,
                "description": v.description, "remediation": v.remediation,
                "status": v.status,
                "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
                "tags": v.tags or [],
            } for v in vulns])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/changes")
    def api_changes(project_id):
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            changes = session.execute(
                select(ChangeLog).where(ChangeLog.project_id == project_id).limit(100)
            ).scalars().all()
            return jsonify([{
                "id": c.id, "change_type": c.change_type,
                "description": c.description, "old_value": c.old_value,
                "new_value": c.new_value, "severity": c.severity,
                "detected_at": c.detected_at.isoformat() if c.detected_at else None,
                "acknowledged": c.acknowledged,
            } for c in changes])
        finally:
            session.close()

    @app.route("/api/project/<int:project_id>/scan-history")
    def api_scan_history(project_id):
        from sqlalchemy import select
        session = db.get_sync_session()
        try:
            history = session.execute(
                select(ScanHistory).where(ScanHistory.project_id == project_id).limit(50)
            ).scalars().all()
            return jsonify([{
                "id": h.id, "scan_type": h.scan_type,
                "started_at": h.started_at.isoformat() if h.started_at else None,
                "completed_at": h.completed_at.isoformat() if h.completed_at else None,
                "status": h.status,
                "command_args": h.command_args,
                "results_summary": h.results_summary,
            } for h in history])
        finally:
            session.close()

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "nightwatch-dashboard"})

    @app.route("/readiness")
    def readiness():
        try:
            session = db.get_sync_session()
            session.execute("SELECT 1")
            session.close()
            return jsonify({"status": "ready"})
        except Exception as e:
            return jsonify({"status": "not ready", "error": str(e)}), 503

    return app


# ── WSGI App (gunicorn looks for this) ─────────────────────────────────────────
app = create_app()

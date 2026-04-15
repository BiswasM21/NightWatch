"""SQLite database models for NightWatch."""

from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, JSON, Text, Float,
    create_engine, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()


class Project(Base):
    """A security research project / target scope."""
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    target_domain = Column(String(512), nullable=False)
    scope = Column(JSON, nullable=True)  # list of in-scope domains/patterns
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<Project {self.name} ({self.target_domain})>"


class Subdomain(Base):
    """Discovered subdomain record."""
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    domain = Column(String(512), nullable=False)
    source = Column(String(64), nullable=False)  # ct_log, dns_bruteforce, passive
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    ip_country = Column(String(64), nullable=True)
    ip_asn = Column(String(128), nullable=True)
    is_alive = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    tags = Column(JSON, nullable=True)  # e.g. ["cdn", "cloud", "deprecated"]
    extra_data = Column(JSON, nullable=True)

    __table_args__ = (
        Index("idx_subdomain_project_domain", "project_id", "domain", unique=True),
    )

    def __repr__(self):
        return f"<Subdomain {self.domain} ({self.ip_address})>"


class HostScan(Base):
    """Host-level scan results."""
    __tablename__ = "host_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    subdomain_id = Column(Integer, nullable=True, index=True)
    host = Column(String(512), nullable=False)
    ip_address = Column(String(45), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="tcp")
    service = Column(String(128), nullable=True)
    banner = Column(Text, nullable=True)
    technology = Column(JSON, nullable=True)  # detected web technologies
    status_code = Column(Integer, nullable=True)
    server_header = Column(String(512), nullable=True)
    title = Column(String(512), nullable=True)
    screenshot_path = Column(String(512), nullable=True)
    scan_time = Column(DateTime, default=func.now())
    extra_data = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<HostScan {self.host}:{self.port} ({self.service})>"


class Vulnerability(Base):
    """Detected vulnerability or finding."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    host_scan_id = Column(Integer, nullable=True, index=True)
    title = Column(String(512), nullable=False)
    severity = Column(String(32), nullable=False)  # critical, high, medium, low, info
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(32), nullable=True)
    cwe_id = Column(String(32), nullable=True)
    description = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)
    remediation = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)
    status = Column(String(32), default="open")  # open, in_progress, resolved, false_positive
    discovered_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    tags = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<Vulnerability {self.cve_id or self.title} [{self.severity}]>"


class ScanHistory(Base):
    """Historical record of scan runs."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    scan_type = Column(String(64), nullable=False)  # full, subdomain, port, http, cve
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="running")  # running, completed, failed, cancelled
    targets = Column(JSON, nullable=True)
    results_summary = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    command_args = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ScanHistory {self.scan_type} ({self.status})>"


class MonitoredTarget(Base):
    """Targets for continuous monitoring."""
    __tablename__ = "monitored_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    target_type = Column(String(32), nullable=False)  # domain, ip, url
    target_value = Column(String(512), nullable=False)
    interval_hours = Column(Integer, default=24)
    last_check = Column(DateTime, nullable=True)
    next_check = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    alert_channels = Column(JSON, nullable=True)  # email, webhook, slack
    last_snapshot = Column(JSON, nullable=True)  # last known state
    created_at = Column(DateTime, default=func.now())

    def __repr__(self):
        return f"<MonitoredTarget {self.target_type}:{self.target_value}>"


class ChangeLog(Base):
    """Detected changes in monitored targets."""
    __tablename__ = "change_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    monitored_target_id = Column(Integer, nullable=True, index=True)
    change_type = Column(String(64), nullable=False)  # new_subdomain, new_port, new_service, dns_change
    description = Column(Text, nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    severity = Column(String(32), default="info")
    detected_at = Column(DateTime, default=func.now())
    acknowledged = Column(Boolean, default=False)

    def __repr__(self):
        return f"<ChangeLog {self.change_type}: {self.description[:60]}>"


def init_db(db_path: str = "nightwatch.db"):
    """Initialize the database and create all tables."""
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    return engine

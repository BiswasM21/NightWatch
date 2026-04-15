"""Configuration management for NightWatch."""

from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
import json
import os

DEFAULT_WORDLIST = [
    "www", "api", "dev", "staging", "test", "admin", "mail", "ftp",
    "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "pop3",
    "rabbitmq", "jenkins", "kibana", "grafana", "elasticsearch",
    "redash", "prometheus", "alertmanager", "consul", "etcd", "vault",
    "status", "docs", "support", "blog", "cdn", "assets", "static",
    "images", "img", "video", "videos", "media", "files", "download",
    "downloads", "app", "apps", "cloud", "store", "shop", "market",
    "forum", "chat", "irc", "vpn", "proxy", "gateway", "router",
    "git", "svn", "ci", "cd", "build", "deploy", "monitor",
    "node", "nodes", "master", "worker", "client", "clients",
    "db", "database", "mysql", "postgres", "postgresql", "mongodb",
    "redis", "memcached", "cache", "queue", "rabbit", "kafka",
    "zookeeper", "hbase", "hadoop", "spark", "flink", "storm",
    "api-gateway", "gateway", "lb", "loadbalancer", "ingress",
    "dns", "ns", "mx", "smtp", "pop", "imap", "mail", "email",
    "vcenter", "vmware", "xen", "hyperv", "proxmox", "openvz",
    "kubernetes", "k8s", "docker", "rancher", "openshift", "helm",
    "s3", "bucket", "storage", "backups", "backup", "archive",
    "releases", "release", "versions", "version", "staging", "prod",
    "production", "development", "demo", "trial", "beta", "alpha",
    "internal", "external", "partner", "vendor", "corp", "corporate",
    "office", "corp1", "corp2", "dmz", "intranet", "extranet",
    "secure", "security", "auth", "oauth", "sso", "ldap", "adfs",
    "saml", "kerberos", "radius", "nps", "tacacs", "sms", "otp",
    "web", "web1", "web2", "web3", "server", "server1", "server2",
    "host", "node", "node1", "node2", "instance", "ec2", "ec1", "ec2",
    "compute", "instance", "vm", "instance1", "instance2", "vps",
]


@dataclass
class Config:
    """NightWatch configuration."""
    # Project settings
    db_path: str = str(Path.home() / "NightWatch" / "nightwatch.db")

    # DNS enumeration
    dns_wordlist: List[str] = field(default_factory=lambda: DEFAULT_WORDLIST)
    dns_resolvers: List[str] = field(default_factory=lambda: [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"
    ])
    dns_timeout: float = 3.0
    dns_retries: int = 2

    # CT log scanning
    ct_logs: List[str] = field(default_factory=lambda: [
        "https://crt.sh/?q=%25.{domain}&output=json",
        "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true",
    ])
    ct_timeout: int = 30

    # Port scanning
    common_ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090,
        10000, 27017, 50000
    ])
    full_port_range: List[int] = field(default_factory=lambda: list(range(1, 10001)))
    port_timeout: float = 3.0
    max_concurrent_ports: int = 100

    # HTTP probing
    http_timeout: float = 10.0
    http_user_agent: str = (
        "NightWatch/1.0 (Security Research Framework; +https://github.com/BiswasM21/NightWatch)"
    )
    http_follow_redirects: bool = True
    screenshot_enabled: bool = False  # Requires playwright/puppeteer

    # CVE checking
    cve_check_enabled: bool = True
    cve_db_path: str = str(Path.home() / "NightWatch" / "cve_cache.db")
    cve_cache_hours: int = 24

    # Rate limiting
    max_concurrent_requests: int = 50
    request_delay: float = 0.0  # seconds between requests
    rate_limit_per_second: int = 100

    # Monitoring
    default_monitor_interval_hours: int = 24
    max_monitor_targets: int = 100

    # API Keys (optional)
    shodan_key: Optional[str] = field(default_factory=lambda: os.getenv("SHODAN_API_KEY"))
    virustotal_key: Optional[str] = field(default_factory=lambda: os.getenv("VT_API_KEY"))
    hunter_key: Optional[str] = field(default_factory=lambda: os.getenv("HUNTER_API_KEY"))

    # Output
    output_dir: str = str(Path.home() / "NightWatch" / "output")
    reports_dir: str = str(Path.home() / "NightWatch" / "reports")

    def save(self, path: str = None):
        """Save config to JSON file."""
        save_path = path or str(Path.home() / "NightWatch" / "config.json")
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        data = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        with open(save_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @classmethod
    def load(cls, path: str = None) -> "Config":
        """Load config from JSON file."""
        load_path = path or str(Path.home() / "NightWatch" / "config.json")
        if not Path(load_path).exists():
            return cls()
        with open(load_path) as f:
            data = json.load(f)
        return cls(**{
            k: v for k, v in data.items()
            if k in cls.__dataclass_fields__
        })


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def update_config(**kwargs):
    global _config
    if _config is None:
        _config = Config()
    for k, v in kwargs.items():
        if hasattr(_config, k):
            setattr(_config, k, v)
    _config.save()

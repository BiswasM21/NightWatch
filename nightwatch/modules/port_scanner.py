"""
Port Scanning Module for NightWatch.

Fast, asynchronous TCP port scanning with:
- Configurable port ranges
- Concurrent scanning
- Service fingerprinting
- Banner grabbing
- Version detection
"""

import asyncio
import socket
import struct
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import time

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("port_scanner")

# Common service fingerprints (banner -> service name)
SERVICE_BANNERS = {
    21: ["ftp", "vsftpd", "proftpd", "filezilla", "wu-ftpd"],
    22: ["ssh", "openssh", "dropbear", "ssh-"],
    23: ["ssh", "telnet", "telnetd"],
    25: ["smtp", "sendmail", "postfix", "exim", "qmail"],
    53: ["dns", "named", "bind", "microsoft dns"],
    80: ["http", "apache", "nginx", "iis", "httpd"],
    110: ["pop3", "courier", "dovecot"],
    111: ["rpcbind", "rpcbind"],
    135: ["msrpc", "epmap"],
    139: ["netbios-ssn", "samba"],
    143: ["imap", "dovecot", "courier-imap"],
    443: ["https", "ssl", "apache", "nginx", "iis"],
    445: ["microsoft-ds", "samba"],
    993: ["imaps", "dovecot"],
    995: ["pop3s", "dovecot"],
    1433: ["mssql", "sql server"],
    1521: ["oracle", "oracle db"],
    1723: ["pptp", "poptop"],
    3306: ["mysql", "mariadb"],
    3389: ["ms-wbt-server", "rdp", "xrdp"],
    5432: ["postgresql", "postgres"],
    5900: ["vnc", "vnc"],
    5901: ["vnc", "vnc"],
    6379: ["redis"],
    8080: ["http-proxy", "apache", "nginx", "tomcat", "jboss"],
    8443: ["https", "ssl", "apache", "nginx"],
    8888: ["http", "jupyter"],
    9090: ["http", "grafana", "prometheus"],
    9200: ["elasticsearch"],
    27017: ["mongodb"],
    50000: ["ibm"],
}

# Top 100 ports for quick scanning
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3001, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
]


@dataclass
class PortResult:
    """Result of a single port scan."""
    host: str
    ip: str
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: float = 0.0


class PortScanner:
    """
    Fast asynchronous TCP port scanner with banner grabbing.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def scan_hosts(
        self,
        hosts: List[str],
        options: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan a list of hosts for open ports.
        Returns results grouped by host.
        """
        opts = options or {}
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_ports)

        ports = opts.get("ports") or self.config.common_ports
        scan_type = opts.get("scan_type", "common")

        if scan_type == "top":
            ports = TOP_PORTS
        elif scan_type == "full":
            ports = self.config.full_port_range
        elif scan_type == "quick":
            ports = [80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080]

        log.info(f"[PortScan] Scanning {len(hosts)} hosts on {len(ports)} ports")

        tasks = [self._scan_host(host, ports) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for result in results:
            if isinstance(result, list):
                output.extend(result)

        open_count = sum(1 for r in output for p in r.get("open_ports", []) if p.get("open"))
        log.info(f"[PortScan] Found {open_count} open ports across {len(hosts)} hosts")

        return results if isinstance(results[0], list) else output

    async def _scan_host(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """Scan a single host for open ports."""
        result = {
            "host": host,
            "ip_address": None,
            "open_ports": [],
            "total_scanned": len(ports),
        }

        # Resolve hostname to IP
        try:
            result["ip_address"] = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyname, host
            )
        except socket.gaierror:
            log.debug(f"[PortScan] Could not resolve {host}")
            return result

        # Scan ports concurrently
        tasks = [
            self._scan_port(result["ip_address"], host, port)
            for port in ports
        ]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        for pr in port_results:
            if isinstance(pr, PortResult) and pr.is_open:
                result["open_ports"].append({
                    "port": pr.port,
                    "service": pr.service,
                    "banner": pr.banner,
                    "response_time_ms": round(pr.response_time_ms, 2),
                    "open": True,
                })

        # Sort by port number
        result["open_ports"].sort(key=lambda x: x["port"])

        return result

    async def _scan_port(
        self,
        ip: str,
        host: str,
        port: int
    ) -> Optional[PortResult]:
        """Scan a single port on a target IP."""
        async with self._semaphore:
            start_time = time.time()
            result = PortResult(host=host, ip=ip, port=port, is_open=False)

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.config.port_timeout
                )

                result.is_open = True
                result.response_time_ms = (time.time() - start_time) * 1000

                # Service fingerprinting
                result.service = SERVICE_BANNERS.get(port, ["unknown"])[0]

                # Banner grabbing
                banner = await self._grab_banner(reader, writer, port)
                if banner:
                    result.banner = banner
                    result.service = self._identify_service(port, banner)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            except asyncio.TimeoutError:
                result.response_time_ms = self.config.port_timeout * 1000
            except (ConnectionRefusedError, ConnectionResetError, OSError):
                pass
            except Exception as e:
                log.debug(f"[PortScan] {ip}:{port} error: {e}")

            return result

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int
    ) -> Optional[str]:
        """Grab the service banner from an open port."""
        try:
            # Send protocol-specific probes
            if port == 80 or port == 8080:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 443 or port == 8443:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 22:
                writer.write(b"SSH-2.0-NightWatch_Scanner\r\n")
            elif port == 25 or port == 587:
                writer.write(b"QUIT\r\n")
            elif port == 21:
                writer.write(b"FEAT\r\n")
            else:
                writer.write(b"\r\n")

            await writer.drain()

            # Read response
            try:
                banner_bytes = await asyncio.wait_for(
                    reader.read(512),
                    timeout=2.0
                )
                if banner_bytes:
                    return banner_bytes.decode("utf-8", errors="ignore").strip()[:200]
            except asyncio.TimeoutError:
                pass

        except Exception:
            pass

        return None

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from banner content."""
        banner_lower = banner.lower()

        # Specific banner patterns
        if "ssh-" in banner_lower:
            return "ssh"
        if "ftp" in banner_lower or "220" in banner:
            return "ftp"
        if "smtp" in banner_lower or "mail" in banner_lower:
            return "smtp"
        if "http" in banner_lower:
            return "http"
        if "mysql" in banner_lower:
            return "mysql"
        if "postgresql" in banner_lower or "postgres" in banner_lower:
            return "postgresql"
        if "redis" in banner_lower:
            return "redis"
        if "mongodb" in banner_lower:
            return "mongodb"
        if "elasticsearch" in banner_lower:
            return "elasticsearch"
        if "vnc" in banner_lower:
            return "vnc"
        if "rdp" in banner_lower or "xrdp" in banner_lower:
            return "rdp"
        if "pop3" in banner_lower or "courier" in banner_lower:
            return "pop3"
        if "imap" in banner_lower or "dovecot" in banner_lower:
            return "imap"
        if "snmp" in banner_lower:
            return "snmp"
        if "ldap" in banner_lower:
            return "ldap"

        # Fall back to port-based service
        if port in SERVICE_BANNERS:
            return SERVICE_BANNERS[port][0]

        return "unknown"

    async def quick_scan(self, host: str, ports: List[int] = None) -> List[int]:
        """Quick scan returning only open port numbers."""
        ports = ports or [80, 443, 22, 21, 25, 3389, 3306, 8080]
        result = await self._scan_host(host, ports)
        return [p["port"] for p in result.get("open_ports", [])]

"""
Certificate Transparency Log Scanner for NightWatch.

Scans Certificate Transparency logs to discover subdomains that have
been issued SSL/TLS certificates. This is one of the most effective
passive reconnaissance techniques for subdomain enumeration.
"""

import asyncio
import re
import json
from typing import List, Set, Optional
from urllib.parse import urlparse
import aiohttp
from bs4 import BeautifulSoup

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("ct_scanner")


class CTScanner:
    """
    Discovers subdomains by querying Certificate Transparency logs.

    Primary sources:
    - crt.sh (full history, free)
    - CertSpotter (API)
    - Google Transparency Report
    - SpySE
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.session: Optional[aiohttp.ClientSession] = None
        self._discovered: Set[str] = set()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.ct_timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def scan(self, domain: str) -> List[str]:
        """
        Scan CT logs for a domain and return discovered subdomains.
        """
        self._discovered.clear()
        tasks = [
            self._scan_crt_sh(domain),
            self._scan_certspotter(domain),
            self._scan_spyse(domain),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        results = list(self._discovered)
        log.info(f"[CT] Found {len(results)} unique subdomains for {domain}")
        return results

    async def _scan_crt_sh(self, domain: str):
        """
        Query crt.sh for certificate history.
        crt.sh provides JSON output via the /?id=<search> endpoint.
        """
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            session = await self._get_session()

            async with session.get(url, headers={"User-Agent": self.config.http_user_agent}) as resp:
                if resp.status != 200:
                    log.warning(f"[CT] crt.sh returned status {resp.status}")
                    return

                text = await resp.text()
                if not text or text.strip() == "[]":
                    # Try HTML parsing fallback
                    await self._scan_crt_sh_html(domain)
                    return

                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    await self._scan_crt_sh_html(domain)
                    return

                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub and self._is_valid_subdomain(sub, domain):
                            # Remove wildcard prefix
                            sub = sub.lstrip("*.")
                            if self._is_valid_subdomain(sub, domain):
                                self._discovered.add(sub)

        except asyncio.TimeoutError:
            log.warning(f"[CT] crt.sh timed out for {domain}")
        except Exception as e:
            log.warning(f"[CT] crt.sh error for {domain}: {e}")

    async def _scan_crt_sh_html(self, domain: str):
        """Fallback: parse crt.sh HTML output."""
        try:
            url = f"https://crt.sh/?q=%.{domain}"
            session = await self._get_session()

            async with session.get(url, headers={"User-Agent": self.config.http_user_agent}) as resp:
                if resp.status != 200:
                    return

                text = await resp.text()
                soup = BeautifulSoup(text, "lxml")

                # Parse table rows with certificate data
                for row in soup.find_all("tr"):
                    cells = row.find_all("td")
                    if len(cells) >= 4:
                        name_cell = cells[3]  # Usually the name_value column
                        text_content = name_cell.get_text()
                        for sub in text_content.split():
                            sub = sub.strip().lower().rstrip(".")
                            if self._is_valid_subdomain(sub, domain):
                                sub = sub.lstrip("*.")
                                if self._is_valid_subdomain(sub, domain):
                                    self._discovered.add(sub)

        except Exception as e:
            log.warning(f"[CT] crt.sh HTML parse error for {domain}: {e}")

    async def _scan_certspotter(self, domain: str):
        """
        Query CertSpotter API for certificate issuances.
        Requires API key for higher rate limits (optional).
        """
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            session = await self._get_session()

            async with session.get(url, headers={"User-Agent": self.config.http_user_agent}) as resp:
                if resp.status != 200:
                    return

                data = await resp.json()
                for entry in data:
                    dns_names = entry.get("dns_names", [])
                    for name in dns_names:
                        name = name.strip().lower().rstrip(".")
                        if self._is_valid_subdomain(name, domain):
                            name = name.lstrip("*.")
                            if self._is_valid_subdomain(name, domain):
                                self._discovered.add(name)

        except asyncio.TimeoutError:
            log.warning(f"[CT] CertSpotter timed out for {domain}")
        except Exception as e:
            log.warning(f"[CT] CertSpotter error for {domain}: {e}")

    async def _scan_spyse(self, domain: str):
        """Query SpySE (SecurityTrails) for certificate data."""
        try:
            # SpySE has a free API with limited queries
            url = f"https://api.spyse.com/v4/data/cert/search?query=*.{domain}&limit=100"
            session = await self._get_session()

            async with session.get(url, headers={"User-Agent": self.config.http_user_agent}) as resp:
                if resp.status != 200:
                    return

                data = await resp.json()
                records = data.get("data", {}).get("records", [])
                for record in records:
                    subject = record.get("subject", "")
                    if isinstance(subject, str):
                        for sub in subject.split():
                            sub = sub.strip().lower().rstrip(".")
                            if self._is_valid_subdomain(sub, domain):
                                self._discovered.add(sub)

        except Exception as e:
            log.warning(f"[CT] SpySE error for {domain}: {e}")

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if a subdomain is valid and in scope."""
        if not subdomain or len(subdomain) < 2:
            return False

        # Must end with the target domain
        if not subdomain.endswith(domain):
            return False

        # Must have at least one label before the domain
        prefix = subdomain[: -len(domain)].rstrip(".")
        if not prefix:
            return False

        # Filter out IPs
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", subdomain):
            return False

        # Filter out unusual characters
        if not re.match(r"^[a-z0-9\-\.\*]+$", subdomain):
            return False

        return True

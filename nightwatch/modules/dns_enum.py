"""
DNS Enumeration Module for NightWatch.

Performs active and passive DNS enumeration including:
- DNS bruteforce with custom wordlists
- NSLOOKUP-style resolution
- Reverse DNS lookups
- Zone transfer attempts
- DNS over HTTPS (DoH) resolution
"""

import asyncio
import socket
import random
from typing import List, Set, Optional, Tuple
import dns.resolver
import dns.zone
import dns.query
import dns.name
from dns.resolver import Resolver, NXDOMAIN, NoAnswer, NoNameservers, Timeout

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("dns_enum")


class DNSEnumerator:
    """
    Active DNS enumeration with bruteforce, resolution, and fingerprinting.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.resolver = self._configure_resolver()

    def _configure_resolver(self) -> Resolver:
        """Configure DNS resolver with custom nameservers."""
        res = Resolver()
        res.nameservers = self.config.dns_resolvers
        res.lifetime = self.config.dns_timeout
        res.retry_servfail = self.config.dns_retries
        res.use_edns(0, 0, 4096)
        return res

    async def enumerate(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Enumerate subdomains via DNS bruteforce.
        Returns list of found subdomains.
        """
        wordlist = wordlist or self.config.dns_wordlist
        found = []

        log.info(f"[DNS] Bruteforcing {len(wordlist)} prefixes for {domain}")

        # Process in batches for performance
        batch_size = 50
        batches = [
            wordlist[i : i + batch_size]
            for i in range(0, len(wordlist), batch_size)
        ]

        for batch in batches:
            tasks = [self._check_subdomain(domain, prefix) for prefix in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for sub in results:
                if sub and isinstance(sub, str):
                    found.append(sub)

        log.info(f"[DNS] Found {len(found)} subdomains via bruteforce")
        return found

    async def _check_subdomain(self, domain: str, prefix: str) -> Optional[str]:
        """Check if a subdomain exists."""
        subdomain = f"{prefix}.{domain}".lower()
        try:
            ip = await asyncio.get_event_loop().run_in_executor(
                None, self._resolve_sync, subdomain
            )
            if ip:
                log.debug(f"  [DNS] {subdomain} -> {ip}")
                return subdomain
        except Exception:
            pass
        return None

    def _resolve_sync(self, hostname: str) -> Optional[str]:
        """Synchronous DNS resolution for use in executor."""
        try:
            answers = self.resolver.resolve(hostname, "A")
            if answers:
                return str(answers[0])
        except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
            pass
        except Exception:
            pass
        return None

    async def resolve(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to IP address."""
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None, self._resolve_sync, hostname
            )
        except Exception:
            return None

    async def resolve_all(self, hostname: str) -> List[str]:
        """Resolve hostname to all available IP addresses (A, AAAA)."""
        results = []
        try:
            loop = asyncio.get_event_loop()
            # A records
            try:
                answers = await loop.run_in_executor(
                    None, lambda: self.resolver.resolve(hostname, "A")
                )
                for rdata in answers:
                    results.append(str(rdata))
            except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
                pass

            # AAAA records
            try:
                answers = await loop.run_in_executor(
                    None, lambda: self.resolver.resolve(hostname, "AAAA")
                )
                for rdata in answers:
                    results.append(str(rdata))
            except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
                pass

        except Exception:
            pass

        return results

    async def reverse_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup on an IP address."""
        results = []
        try:
            reversed_ip = ".".join(ip.split(".")[::-1])
            PTR = f"{reversed_ip}.in-addr.arpa"

            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(PTR, "PTR")
            )
            for rdata in answers:
                results.append(str(rdata))
        except Exception:
            pass
        return results

    async def get_mx_records(self, domain: str) -> List[str]:
        """Get mail server records for a domain."""
        results = []
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, "MX")
            )
            for rdata in answers:
                results.append(f"{rdata.preference} {rdata.exchange}")
        except Exception:
            pass
        return results

    async def get_ns_records(self, domain: str) -> List[str]:
        """Get nameserver records for a domain."""
        results = []
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, "NS")
            )
            for rdata in answers:
                results.append(str(rdata))
        except Exception:
            pass
        return results

    async def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain."""
        results = []
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, "TXT")
            )
            for rdata in answers:
                results.append(" ".join(str(s) for s in rdata.strings))
        except Exception:
            pass
        return results

    async def try_zone_transfer(self, domain: str) -> Optional[str]:
        """
        Attempt a zone transfer (AXFR). Returns zone data if successful.
        Note: Most DNS servers block AXFR, so this is a best-effort approach.
        """
        try:
            # Get authoritative nameservers
            ns_records = await self.get_ns_records(domain)
            if not ns_records:
                return None

            # Try zone transfer on each nameserver
            for ns in ns_records:
                ns = ns.rstrip(".")
                try:
                    zone = await asyncio.get_event_loop().run_in_executor(
                        None, self._axfr_sync, domain, ns
                    )
                    if zone:
                        log.warning(f"[DNS] Zone transfer SUCCESS from {ns}")
                        return zone
                except Exception:
                    continue

        except Exception as e:
            log.debug(f"[DNS] Zone transfer failed for {domain}: {e}")

        return None

    def _axfr_sync(self, domain: str, nameserver: str) -> Optional[str]:
        """Synchronous zone transfer."""
        try:
            zone_name = dns.name.from_text(domain)
            xfr = dns.query.transfer(zone_name, nameserver, lifetime=5)
            if xfr:
                return str(dns.zone.from_xfr(xfr))
        except Exception:
            pass
        return None

    async def get_whois_info(self, domain: str) -> dict:
        """Basic WHOIS-style information via DNS queries."""
        info = {
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": await self.get_mx_records(domain),
            "ns_records": await self.get_ns_records(domain),
            "txt_records": await self.get_txt_records(domain),
        }

        try:
            info["a_records"] = await self.resolve_all(domain)
        except Exception:
            pass

        return info

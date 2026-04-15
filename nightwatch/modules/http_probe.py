"""
HTTP Probing and Technology Fingerprinting Module for NightWatch.

Probes HTTP/HTTPS services to:
- Detect alive hosts and capture banners
- Identify web technologies (CMS, frameworks, servers)
- Extract titles, headers, and fingerprints
- Detect WAF, CDN, and load balancers
- Follow redirects and capture final response
"""

import asyncio
import re
import socket
from typing import List, Dict, Any, Optional, Tuple
import aiohttp
from bs4 import BeautifulSoup
import ssl
import struct
import json

from ..core.config import Config
from ..utils.logging_utils import get_logger

log = get_logger("http_probe")

# Technology fingerprint database (common patterns)
TECH_FINGERPRINTS = {
    # Web Servers
    "apache": ["Apache", "apache", "Apache-Coyote"],
    "nginx": ["nginx", "Nginx", "Server: nginx"],
    "iis": ["Microsoft-IIS", "IIS", "ASP.NET"],
    "lighttpd": ["lighttpd"],
    "caddy": ["Caddy", "caddy"],

    # Frameworks
    "react": ["react", "React", "create-react-app", "_react", "__next"],
    "vue": ["Vue", "vue", "Vue.js", "__nuxt", "/_nuxt"],
    "angular": ["Angular", "angular", "__nguniversal", "ng-version"],
    "nextjs": ["__NEXT_DATA__", "_next/static", "Next.js", "nextjs"],
    "gatsby": ["gatsby", "Gatsby", "__gatsby"],
    "nuxt": ["__nuxt", "/_nuxt", "Nuxt", "nuxtjs"],
    "svelte": ["Svelte", "svelte"],
    "django": ["csrftoken", "csrfmiddlewaretoken", "django"],
    "flask": ["flask", "werkzeug"],
    "fastapi": ["fastapi", "swagger-ui"],
    "rails": ["Ruby on Rails", "_rails_root"],
    "express": ["Express", "x-powered-by: express"],
    "laravel": ["laravel_session", "XSRF-TOKEN", "laravel"],
    "spring": ["Spring", "springframework", "Pivotal"],
    "gatsby": ["gatsby", "GatsbyJS"],

    # CMS
    "wordpress": ["wp-content", "wp-includes", "wordpress", "WordPress"],
    "drupal": ["drupal", "Drupal", "node/1", "sites/default"],
    "joomla": ["joomla", "Joomla", "option=com"],
    "wix": ["wix", "Wix", "wix.com", "_wixData"],
    "shopify": ["shopify", "Shopify", "myshopify", "cdn.shopify"],
    "magento": ["magento", "Magento", "Mage.Cookies"],
    "ghost": ["ghost", "Ghost", "__GHOST_URL__"],
    "ghost": ["ghost", "Ghost.org"],
    "strapi": ["strapi", "Strapi", "_strapi_session"],

    # Infrastructure
    "cloudflare": ["cloudflare", "Cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamai", "Akamai", "akamai-x-cache", "EdgeScape"],
    "aws": ["aws", "aws-", "aws-target", "AmazonS3", "AWS"],
    "azure": ["azure", "x-msedge-ref", "Azure", "AzureFrontDoor"],
    "gcp": ["Google", "gcp", "GoogleCloud", "Google Compute Engine"],
    "fastly": ["fastly", "Fastly", "x-served-by", "x-cache"],
    "cloudfront": ["cloudfront", "CloudFront", "X-Cache: Miss"],
    "sucuri": ["sucuri", "Sucuri", "X-Sucuri-"],
    "incapsula": ["incapsula", "Incapsula", "X-CDN: Incapsula"],
    "ddos-guard": ["ddos-guard", "DDoS-Guard", "ddosguard"],

    # Databases (sometimes leaked in headers)
    "mysql": ["MySQL", "Mysql"],
    "postgresql": ["PostgreSQL", "postgres"],
    "mongodb": ["MongoDB", "mongo"],

    # Dev Tools
    "swagger": ["swagger", "Swagger", "swagger-ui", "/swagger"],
    "grafana": ["grafana", "Grafana", "x-grafana-org-id"],
    "kibana": ["kibana", "Kibana", "kibanaHost"],
    "jenkins": ["jenkins", "Jenkins", "x-jenkins"],
    "gitlab": ["gitlab", "GitLab", "GREENTREE"],
    "jira": ["jira", "JIRA", "x-atlassian-oauth2"],
    "confluence": ["confluence", "Confluence", "AJAX-SERVER"],
    "prometheus": ["prometheus", "Prometheus", "prometheus"],

    # Security
    "waf": ["waf", "WAF", "Security", "ModSecurity"],
    "oauth": ["oauth", "OAuth", "/oauth/", "oidc"],
    "saml": ["saml", "SAML", "/saml/", "saml2"],
}

# Common tech headers
TECH_HEADERS = {
    "x-powered-by": "powered_by",
    "server": "server",
    "x-generator": "generator",
    "x-framework": "framework",
    "x-aspnet-version": "aspnet",
    "x-drupal-cache": "drupal",
    "x-nextjs-cache": "nextjs",
    "x-nuxt-layout": "nuxt",
}

# WAF fingerprints
WAF_PATTERNS = {
    "cloudflare": [r"cf-ray", r"__cfduid", r"Cloudflare"],
    "akamai": [r"akamai", r"EdgeScape", r"akamai-x-cache"],
    "incapsula": [r"incapsula", r"x-cdn: incapsula"],
    "sucuri": [r"sucuri", r"x-sucuri"],
    "imperva": [r"imperva", r"x-cdn: Incapsula"],
    "aws_waf": [r"awswaf", r"aws-waf"],
    "f5_asm": [r"x-cnection", r"F5 Networks"],
    "barracuda": [r"barra", r"barracuda"],
    "modsecurity": [r"mod_security", r"modsecurity"],
}


class HTTPProfiler:
    """
    HTTP/HTTPS probing with technology fingerprinting and WAF detection.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.session: Optional[aiohttp.ClientSession] = None
        self._tech_patterns = self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for speed."""
        compiled = {}
        for tech, signatures in TECH_FINGERPRINTS.items():
            compiled[tech] = [re.compile(p, re.I) for p in signatures]
        return compiled

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
            connector = aiohttp.TCPConnector(
                limit=self.config.max_concurrent_requests,
                ssl=ssl.create_default_context() if hasattr(ssl, 'create_default_context') else False,
            )
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self.config.http_user_agent},
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def probe_batch(
        self,
        hosts: List[str],
        project_id: int,
        db,
        ports: List[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Probe a batch of hosts concurrently.
        Returns list of probe results.
        """
        if ports is None:
            ports = [80, 443, 8080, 8443]

        tasks = []
        for host in hosts:
            for port in ports:
                tasks.append(self._probe_host(host, port, project_id))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r and not isinstance(r, Exception)]

    async def _probe_host(
        self,
        host: str,
        port: int,
        project_id: int
    ) -> Optional[Dict[str, Any]]:
        """Probe a single host on a specific port."""
        is_https = port in (443, 8443, 8443)
        proto = "https" if is_https else "http"
        url = f"{proto}://{host}:{port}" if port not in (443, 80) else f"{proto}://{host}"

        result = {
            "host": host,
            "port": port,
            "ip_address": None,
            "service": "http" if is_https else "http",
            "status_code": None,
            "server_header": None,
            "title": None,
            "technology": [],
            "waf": [],
            "metadata": {},
        }

        try:
            session = await self._get_session()

            async with session.get(url, allow_redirects=self.config.http_follow_redirects) as resp:
                result["status_code"] = resp.status
                result["server_header"] = resp.headers.get("Server")
                result["ip_address"] = str(resp.connection.transport.get_extra_info('peername')[0]) if resp.connection else None

                # Read response body
                body = await resp.text(errors="ignore")
                if body:
                    # Extract title
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:512]

                    # Technology fingerprinting
                    result["technology"] = self._detect_technologies(body, dict(resp.headers))

                # Check for WAF
                result["waf"] = self._detect_waf(dict(resp.headers), body)

                # Extract interesting headers
                interesting = ["x-powered-by", "x-aspnet-version", "strict-transport-security",
                              "content-security-policy", "x-frame-options", "x-xss-protection"]
                result["metadata"] = {
                    h: resp.headers.get(h, "") for h in interesting if h in resp.headers
                }
                result["metadata"]["content_length"] = len(body)

                # Check for interesting paths based on status
                if resp.status == 200:
                    result["metadata"]["interesting_paths"] = self._check_interesting_paths(body)

        except asyncio.TimeoutError:
            return None
        except aiohttp.ClientError as e:
            log.debug(f"[HTTP] {url}: {e}")
            return None
        except Exception as e:
            log.debug(f"[HTTP] {url} error: {e}")
            return None

        # Only return if we got something useful
        if result["status_code"] or result["technology"]:
            log.debug(f"[HTTP] {url}: {result['status_code']} - {result['title'] or 'no title'}")
            return result

        return None

    def _detect_technologies(self, body: str, headers: dict) -> List[str]:
        """Detect technologies from response body and headers."""
        detected = []
        body_lower = body.lower()

        for tech, patterns in self._tech_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, re.Pattern):
                    if pattern.search(body) or pattern.search(str(headers)):
                        if tech not in detected:
                            detected.append(tech)
                        break
                else:
                    if pattern.lower() in body_lower or pattern in str(headers):
                        if tech not in detected:
                            detected.append(tech)
                        break

        # Check headers specifically
        for header_name, header_value in headers.items():
            header_lower = header_value.lower()
            for tech, keywords in [
                ("apache", ["apache"]), ("nginx", ["nginx"]),
                ("iis", ["microsoft-iis"]), ("cloudflare", ["cloudflare"]),
                ("aws", ["amazon", "aws"]), ("vercel", ["vercel"]),
            ]:
                if any(kw in header_lower for kw in keywords) and tech not in detected:
                    detected.append(tech)

        return detected

    def _detect_waf(self, headers: dict, body: str) -> List[str]:
        """Detect Web Application Firewall from headers and body."""
        detected = []
        all_text = str(headers) + " " + body

        for waf_name, patterns in WAF_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.I):
                    if waf_name not in detected:
                        detected.append(waf_name)
                    break

        return detected

    def _check_interesting_paths(self, body: str) -> List[str]:
        """Check for interesting paths/resources in the HTML."""
        found = []

        # Look for admin panels
        admin_patterns = [
            (r"/admin/?", "admin_panel"),
            (r"/wp-admin/?", "wordpress_admin"),
            (r"/wp-login", "wordpress_login"),
            (r"/wp-content/uploads", "wordpress_uploads"),
            (r"/api/?", "api_endpoint"),
            (r"/api/v\d+/?", "api_versioned"),
            (r"/graphql", "graphql"),
            (r"/console/?", "web_console"),
            (r"/manager/html", "tomcat_manager"),
            (r"/phpmyadmin/?", "phpmyadmin"),
            (r"/adminer", "adminer"),
            (r"/swagger/?", "swagger_ui"),
            (r"/swagger-ui", "swagger_ui"),
            (r"/openapi", "openapi"),
            (r"/debug/?", "debug_mode"),
            (r"/actuator/?", "spring_actuator"),
            (r"/env", "environment_variables"),
            (r"/.env", "dotenv_file"),
            (r"/config", "config_exposed"),
            (r"/backup", "backup_exposed"),
            (r"/.git", "git_repo"),
            (r"/.svn", "svn_repo"),
            (r"/composer.json", "composer_config"),
            (r"/package.json", "npm_package"),
            (r"/requirements.txt", "python_deps"),
            (r"/Dockerfile", "dockerfile"),
            (r"/.dockerignore", "dockerfile"),
        ]

        for pattern, name in admin_patterns:
            if re.search(pattern, body, re.I):
                found.append(name)

        return found

    async def fetch_url(self, url: str, method: str = "GET") -> Optional[Dict[str, Any]]:
        """Fetch a specific URL and return detailed response."""
        try:
            session = await self._get_session()

            async with session.request(method, url) as resp:
                body = await resp.text(errors="ignore")
                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body[:10000],  # Cap at 10KB
                    "body_size": len(body),
                    "history": [str(h) for h in resp.history],
                }
        except Exception as e:
            log.warning(f"[HTTP] fetch_url {url}: {e}")
            return None

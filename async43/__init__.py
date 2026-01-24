# -*- coding: utf-8 -*-

import asyncio
import ipaddress
from ipaddress import IPv4Address, IPv6Address
import logging
import socket
import sys
from typing import Optional, Union, Iterator

import tldextract

from async43.exceptions import WhoisError, WhoisNonRoutableIPError, WhoisNetworkError, PywhoisError
from async43.model import Whois, SoaRecord, DnsInfo
from async43.net.resolve import resolve_dns_bundle
from async43.parser import parse
from async43.whois import NICClient

logger = logging.getLogger("async43")
extractor = tldextract.TLDExtract(include_psl_private_domains=True)
IPAddress = Union[IPv4Address, IPv6Address]


def parse_ip(value: str) -> Optional[IPAddress]:
    """
    Return an IPv4Address or IPv6Address if value is a valid IP, otherwise None.
    """
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


async def resolve_ip_to_hostname(ip: IPAddress) -> str:
    """
    Resolve a globally routable IP address to a hostname.
    """
    if not ip.is_global:
        raise WhoisNonRoutableIPError(
            f"IP address {ip} is not globally routable"
        )

    try:
        loop = asyncio.get_running_loop()
        hostname, _ = await loop.getnameinfo((str(ip), 0))
        return hostname
    except (socket.herror, socket.gaierror) as exc:
        raise WhoisNetworkError(
            f"Failed to resolve IP address {ip}"
        ) from exc


class WhoisClient:
    """
    Asynchronous WHOIS client with optional DNS enrichment.

    This client can be reused for multiple WHOIS queries, avoiding
    the overhead of recreating NICClient instances.
    """

    def __init__(
            self,
            command: bool = False,
            executable: str = "whois",
            executable_opts: Optional[list[str]] = None,
            convert_punycode: bool = True,
            timeout: int = 10,
            prefer_ipv6: bool = False,
            ipv6_cycle: Optional[Iterator[str]] = None,
    ):
        """
        Initialize the WHOIS client.

        Args:
            command: whether to use the native whois command (default False)
            executable: executable to use for native whois command (default 'whois')
            executable_opts: additional options for the whois executable
            convert_punycode: whether to convert the given URL punycode (default True)
            timeout: timeout for WHOIS request (default 10 seconds)
            prefer_ipv6: whether to prefer IPv6 connections (default False)
            ipv6_cycle: iterator for cycling through IPv6 addresses
        """
        self.command = command
        self.executable = executable
        self.executable_opts = executable_opts
        self.convert_punycode = convert_punycode
        self.timeout = timeout
        self.prefer_ipv6 = prefer_ipv6
        self.ipv6_cycle = ipv6_cycle

        self._nic_client = None
        if not command:
            self._nic_client = NICClient(
                prefer_ipv6=prefer_ipv6,
                ipv6_cycle=ipv6_cycle
            )

    async def _fetch_whois_text(self, domain: str, flags: int) -> str:
        """Fetch raw WHOIS text for a domain."""
        if self.command:
            # Use native whois command
            whois_command = [self.executable, domain]
            if self.executable_opts and isinstance(self.executable_opts, list):
                whois_command.extend(self.executable_opts)

            proc = await asyncio.create_subprocess_exec(
                *whois_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                raise WhoisError(
                    f"Whois command failed with exit code {proc.returncode}: {stderr.decode()}"
                )

            return stdout.decode()

        # Use builtin client
        punycode_domain = domain
        if self.convert_punycode:
            punycode_domain = domain.encode("idna").decode("utf-8")

        text = await self._nic_client.whois_lookup(
            None, punycode_domain, flags, timeout=self.timeout
        )

        if not text:
            raise WhoisError("Whois command returned no output")

        return text

    async def whois(
            self,
            url: str,
            flags: int = 0,
            enrich_dns: Optional[bool] = False,
    ) -> Whois:
        """
        Perform a WHOIS lookup for the given URL.

        Args:
            url: the URL or domain to search whois
            flags: flags to pass to the whois client (default 0)
            enrich_dns: whether to enrich with DNS information (default False)

        Returns:
            Whois object containing parsed WHOIS data and optional DNS enrichment

        Raises:
            WhoisError: if the WHOIS lookup fails
        """
        domain = await extract_domain(url)

        # Use instance default if not overridden
        if enrich_dns:
            whois_text, dns_result = await asyncio.gather(
                self._fetch_whois_text(domain, flags),
                resolve_dns_bundle(domain),
                return_exceptions=True
            )

            # Whois data is mandatory, if we have an exception, raise it
            if isinstance(whois_text, Exception):
                raise whois_text

            # DNS enriched data is optional, set to None in case of exception
            dns_data = None if isinstance(dns_result, Exception) else dns_result

            if isinstance(dns_result, Exception):
                logger.debug("DNS enrichment failed for %s: %s", domain, dns_result)
        else:
            whois_text = await self._fetch_whois_text(domain, flags)
            dns_data = None

        # Parse WHOIS text
        whois_object = parse(whois_text)

        # Add DNS enrichment if available
        if enrich_dns and dns_data:
            soa_record = None
            if "soa" in dns_data:
                soa_record = SoaRecord(**dns_data["soa"])

            dns_info = DnsInfo(
                nameservers=dns_data.get("nameservers", []),
                soa=soa_record,
                dnssec=dns_data.get("dnssec")
            )
            whois_object.dns_info = dns_info

        return whois_object

    async def __aenter__(self):
        """Support async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Support async context manager."""


async def whois(
        url: str,
        command: bool = False,
        flags: int = 0,
        executable: str = "whois",
        executable_opts: Optional[list[str]] = None,
        convert_punycode: bool = True,
        timeout: int = 10,
        enrich_dns: bool = False,
        prefer_ipv6: bool = False,
        ipv6_cycle: Optional[Iterator[str]] = None,
) -> Whois:
    """
    Convenience function for one-off WHOIS lookups.

    For multiple queries, prefer using WhoisClient directly to avoid
    recreating the NICClient for each query.

    See WhoisClient.whois() for parameter documentation.
    """
    client = WhoisClient(
        command=command,
        executable=executable,
        executable_opts=executable_opts,
        convert_punycode=convert_punycode,
        timeout=timeout,
        prefer_ipv6=prefer_ipv6,
        ipv6_cycle=ipv6_cycle,
    )
    return await client.whois(url, flags=flags, enrich_dns=enrich_dns)


async def extract_domain(url: str) -> str:
    """Extract the domain from the given URL

    >>> logger.info(extract_domain('https://www.google.com.au/tos.html'))
    google.com.au
    >>> logger.info(extract_domain('abc.def.com'))
    def.com
    >>> logger.info(extract_domain(u'www.公司.hk'))
    www.公司.hk
    >>> logger.info(extract_domain('chambagri.fr'))
    None
    >>> logger.info(extract_domain('www.webscraping.com'))
    webscraping.com
    >>> logger.info(extract_domain('198.252.206.140'))
    stackoverflow.com
    >>> logger.info(extract_domain('102.112.2O7.net'))
    2o7.net
    >>> logger.info(extract_domain('globoesporte.globo.com'))
    globo.com
    >>> logger.info(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0.info
    >>> logger.info(extract_domain('2607:f8b0:4006:802::200e'))
    1e100.net
    >>> logger.info(extract_domain('172.217.3.110'))
    1e100.net
    """
    ip = parse_ip(url)
    if ip:
        hostname = await resolve_ip_to_hostname(ip)
        return await extract_domain(hostname)

    ext = extractor(url)
    return ext.top_domain_under_public_suffix


async def main():
    """Entry point to query WHOIS for a domain and get parsed information"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        url = sys.argv[1]
    except IndexError:
        logger.error("Usage: %s url", sys.argv[0])
    else:
        try:
            whois_object = await whois(url, enrich_dns=True)
            logger.info(whois_object.model_dump_json(indent=2, exclude={'raw_text'}))
        except PywhoisError as exception:
            logger.error("could not process %s: %s", url, exception)


if __name__ == "__main__":
    asyncio.run(main())

# -*- coding: utf-8 -*-

import asyncio
import ipaddress
from ipaddress import IPv4Address, IPv6Address
import logging
import socket
import sys
from typing import Optional, Union

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


async def whois(
        url: str,
        command: bool = False,
        flags: int = 0,
        executable: str = "whois",
        executable_opts: Optional[list[str]] = None,
        convert_punycode: bool = True,
        timeout: int = 10,
        enrich_dns: bool = False,
) -> Whois:
    """
    url: the URL to search whois
    command: whether to use the native whois command (default False)
    executable: executable to use for native whois command (default 'whois')
    flags: flags to pass to the whois client (default 0)
    convert_punycode: whether to convert the given URL punycode (default True)
    timeout: timeout for WHOIS request (default 10 seconds)
    enrich_dns: whether to enrich with DNS information (default False)
    """
    domain = await extract_domain(url)

    async def fetch_whois_text():
        if command:
            # try native whois command
            whois_command = [executable, domain]
            if executable_opts and isinstance(executable_opts, list):
                whois_command.extend(executable_opts)

            proc = await asyncio.create_subprocess_exec(
                *whois_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                raise WhoisError(f"Whois command failed with exit code {proc.returncode}: {stderr.decode()}")

            return stdout.decode()

        # try builtin client
        nic_client = NICClient()
        punycode_domain = domain
        if convert_punycode:
            punycode_domain = domain.encode("idna").decode("utf-8")

        text = await nic_client.whois_lookup(None, punycode_domain, flags, timeout=timeout)
        if not text:
            raise WhoisError("Whois command returned no output")
        return text

    if enrich_dns:
        whois_text, dns_result = await asyncio.gather(
            fetch_whois_text(),
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
        whois_text = await fetch_whois_text()
        dns_data = None

    whois_object = parse(whois_text)

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

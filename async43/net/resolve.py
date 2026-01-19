import asyncio
import logging
from typing import Optional, Dict, Any

import dns.asyncresolver
import dns.resolver
import dns.exception

logger = logging.getLogger("async43")

_resolver = dns.asyncresolver.Resolver()
_resolver.lifetime = 3.0
_resolver.timeout = 2.0


async def resolve_ns(domain: str) -> Optional[list[str]]:
    """Returns the list of NS records for the given domain"""
    try:
        answer = await _resolver.resolve(domain, "NS")
        return sorted(str(rdata.target).rstrip(".") for rdata in answer)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None


async def resolve_soa(domain: str) -> Optional[Dict[str, Any]]:
    """Returns SOA information for the given domain"""
    try:
        answer = await _resolver.resolve(domain, "SOA")
        soa = answer[0]
        return {
            "mname": str(soa.mname).rstrip("."),
            "rname": str(soa.rname).rstrip("."),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum,
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None


async def resolve_dnssec(domain: str) -> Optional[bool]:
    """
    DNSSEC detection heuristic:
    presence of DS record at parent OR DNSKEY at zone apex
    """
    try:
        await _resolver.resolve(domain, "DNSKEY")
        return True
    except dns.resolver.NoAnswer:
        return False
    except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None


async def resolve_dns_bundle(domain: str) -> dict[str, Any]:
    """
    DNS enrichment executed in parallel.
    Returns only populated fields.
    """
    tasks = {
        "nameservers": resolve_ns(domain),
        "soa": resolve_soa(domain),
        "dnssec": resolve_dnssec(domain),
    }

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    enriched: dict[str, Any] = {}
    for key, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.debug("DNS resolve failed for %s: %s", key, result)
            continue
        if result:
            enriched[key] = result

    return enriched

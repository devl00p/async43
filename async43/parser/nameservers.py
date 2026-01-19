import ipaddress
import re
from typing import List, Set, Tuple, Dict

import tldextract


def is_global_ip(ip_str: str) -> bool:
    """Check if an IP address is globally routable (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except (ValueError, ipaddress.AddressValueError):
        return False


def extract_ips_from_line(line: str) -> Tuple[List[str], List[str]]:
    """
    Extract and validate IPv4 and IPv6 addresses from a line.
    Only returns globally routable addresses.

    Returns:
        Tuple (ipv4_list, ipv6_list) of valid global IP addresses
    """
    ipv4_list = []
    ipv6_list = []

    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'

    for match in re.finditer(ipv4_pattern, line):
        ip_str = match.group()
        try:
            ipaddress.IPv4Address(ip_str)
            if is_global_ip(ip_str):
                ipv4_list.append(ip_str)
        except (ipaddress.AddressValueError, ValueError):
            pass

    for match in re.finditer(ipv6_pattern, line):
        ip_str = match.group()
        try:
            ipaddress.IPv6Address(ip_str)
            if is_global_ip(ip_str):
                ipv6_list.append(ip_str)
        except (ipaddress.AddressValueError, ValueError):
            pass

    return ipv4_list, ipv6_list


def is_valid_nameserver_hostname(hostname: str) -> bool:
    """
    Validate that a hostname is a valid domain (eTLD+2 with subdomain).
    Nameservers typically have a subdomain (ns1.google.com, dns.example.net).
    """
    try:
        extracted = tldextract.extract(hostname, include_psl_private_domains=True)

        if not extracted.domain or not extracted.suffix:
            return False

        if extracted.suffix.isdigit():
            return False

        if not extracted.subdomain:
            return False

        return True
    except (ValueError, TypeError):
        return False


def _get_line_to_analyze(line: str, ipv6_list: List[str]) -> str:
    """
    Clean the line by removing IPv6 addresses and handling colon-separated labels.

    Args:
        line: The raw line from whois text.
        ipv6_list: List of IPv6 addresses already extracted from the line.

    Returns:
        A cleaned string suitable for hostname extraction.
    """
    line_temp = line
    for ipv6 in ipv6_list:
        line_temp = line_temp.replace(ipv6, '')

    if ':' in line_temp and not re.search(r'https?://', line_temp):
        parts = line.split(':', 1)
        label = parts[0].strip()
        if len(label) < 50:
            return parts[1].strip()

    return line


def _is_probable_nameserver(hostname: str, has_valid_ip: bool, line: str) -> bool:
    """
    Determine if a hostname is likely a nameserver based on patterns and context.

    Args:
        hostname: The extracted hostname to validate.
        has_valid_ip: Boolean indicating if an IP was found on the same line.
        line: The original line for context (e.g., checking for email symbols).

    Returns:
        True if the hostname is likely a nameserver, False otherwise.
    """
    hostname_lower = hostname.lower()

    # Exclude if it looks like an email part
    if '@' in line and hostname in line.split('@')[-1]:
        return False

    # Check for keywords
    ns_indicators = {'ns', 'dns', 'nameserver', 'pdns', 'name-server', 'servidor'}
    if any(indicator in hostname_lower for indicator in ns_indicators):
        return True

    return has_valid_ip


def extract_nameservers_from_raw(text: str) -> Dict[str, List[str]]:
    """
    Extract nameservers and their IPs from raw whois text.

    Args:
        text: The raw text output from a WHOIS query.

    Returns:
        A dictionary mapping nameserver hostnames to a sorted list of their IPs.
    """
    nameservers: Dict[str, Set[str]] = {}
    hostname_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b'
    comment_prefixes = ('%', '>', '#', '//', ';')

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_prefixes):
            continue

        # Extract IPs using the provided external helper
        ipv4_list, ipv6_list = extract_ips_from_line(line)
        all_ips = ipv4_list + ipv6_list

        line_to_analyze = _get_line_to_analyze(line, ipv6_list)
        hostnames = re.findall(hostname_pattern, line_to_analyze)

        for hostname in hostnames:
            hostname_lower = hostname.lower()

            if not is_valid_nameserver_hostname(hostname_lower):
                continue

            if _is_probable_nameserver(hostname, bool(all_ips), line):
                if hostname_lower not in nameservers:
                    nameservers[hostname_lower] = set()
                nameservers[hostname_lower].update(all_ips)

    return {ns: sorted(list(ips)) for ns, ips in sorted(nameservers.items())}

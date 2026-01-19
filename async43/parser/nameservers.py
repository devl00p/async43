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
    except Exception:
        return False


def extract_nameservers_from_raw(text: str) -> Dict[str, List[str]]:
    """
    Extract nameservers and their IPs from raw whois text.

    Returns:
        Dict mapping nameserver hostnames to list of IPs
        Example: {"ns1.google.com": ["1.2.3.4"], "ns2.google.com": ["5.6.7.8", "2001:db8::1"]}
    """
    nameservers: Dict[str, Set[str]] = {}
    hostname_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b'

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith(('%', '>', '#', '//', ';')):
            continue

        ipv4_list, ipv6_list = extract_ips_from_line(line)
        all_ips = ipv4_list + ipv6_list
        has_valid_ip = bool(all_ips)

        line_to_analyze = line
        if ':' in line:
            line_temp = line
            for ipv6 in ipv6_list:
                line_temp = line_temp.replace(ipv6, '')

            colon_count = line_temp.count(':')

            if colon_count == 1 and not re.search(r'https?://', line):
                parts = line.split(':', 1)
                label = parts[0].strip()
                if len(label) < 50:
                    line_to_analyze = parts[1].strip()

        hostnames = re.findall(hostname_pattern, line_to_analyze)

        for hostname in hostnames:
            hostname_lower = hostname.lower()

            if not is_valid_nameserver_hostname(hostname_lower):
                continue

            if '@' in line and hostname in line.split('@')[-1]:
                continue

            is_likely_nameserver = False

            ns_indicators = ['ns', 'dns', 'nameserver', 'pdns', 'name-server', 'servidor']
            if any(indicator in hostname_lower for indicator in ns_indicators):
                is_likely_nameserver = True

            if has_valid_ip:
                is_likely_nameserver = True

            if is_likely_nameserver:
                if hostname_lower not in nameservers:
                    nameservers[hostname_lower] = set()
                nameservers[hostname_lower].update(all_ips)

    return {ns: sorted(ips) for ns, ips in sorted(nameservers.items())}

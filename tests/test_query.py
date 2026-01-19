# coding=utf-8

import unittest

from async43 import whois


class TestQuery(unittest.IsolatedAsyncioTestCase):
    async def test_simple_ascii_domain(self):
        domain = "google.com"
        await whois(domain)

    async def test_simple_unicode_domain(self):
        domain = "нарояци.com"
        await whois(domain)

    async def test_unicode_domain_and_tld(self):
        domain = "россия.рф"
        await whois(domain)

    async def test_ipv4(self):
        """Verify ipv4 addresses."""
        domain = "172.217.3.110"
        whois_results = await whois(domain)
        assert whois_results.domain.lower() == "1e100.net"
        self.assertIn(
            "ns1.google.com", [_.lower() for _ in whois_results.nameservers]
        )

    async def test_ipv6(self):
        """Verify ipv6 addresses."""
        domain = "2607:f8b0:4006:802::200e"
        whois_results = await whois(domain)
        assert whois_results.domain.lower() == "1e100.net"
        self.assertIn(
            "ns1.google.com", [_.lower() for _ in whois_results.nameservers]
        )
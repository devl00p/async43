# coding=utf-8

import unittest

from async43.whois import NICClient


class TestNICClient(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = NICClient()

    async def test_choose_server(self):
        domain = "рнидс.срб"
        chosen = await self.client.choose_server(domain)
        correct = "whois.rnids.rs"
        self.assertEqual(chosen, correct)

import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import socket
import asyncio

from async43.whois import NICClient


class TestNICClientIPv6(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.ipv4_info = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 43))
        self.ipv6_info = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 43, 0, 0))
        self.mock_addr_info = [self.ipv4_info, self.ipv6_info]

    @patch('asyncio.open_connection', new_callable=AsyncMock)
    @patch('asyncio.get_running_loop')
    async def test_connect_prioritizes_ipv6(self, mock_get_running_loop, mock_open_connection):
        # Mock the loop and its getaddrinfo method
        mock_loop = asyncio.get_event_loop()
        mock_loop.getaddrinfo = AsyncMock(return_value=self.mock_addr_info)
        mock_get_running_loop.return_value = mock_loop
        
        # open_connection returns a reader, writer tuple
        # The writer's close() method is sync, but wait_closed() is async.
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_open_connection.return_value = (AsyncMock(), mock_writer)

        client = NICClient(prefer_ipv6=True)
        try:
            async with client._connect("example.com", timeout=10):
                pass  # We just want to check the connection call
        except Exception:
            pass

        # The logic now tries to connect, so we check the arguments of open_connection
        # The sorting should make the IPv6 address the first attempt
        self.assertTrue(mock_open_connection.called)
        first_call_args = mock_open_connection.call_args_list[0][1]
        self.assertEqual(first_call_args['host'], '2001:db8::1')

    @patch('asyncio.open_connection', new_callable=AsyncMock)
    @patch('asyncio.get_running_loop')
    async def test_connect_keeps_default_order(self, mock_get_running_loop, mock_open_connection):
        # Mock the loop and its getaddrinfo method
        mock_loop = asyncio.get_event_loop()
        mock_loop.getaddrinfo = AsyncMock(return_value=self.mock_addr_info)
        mock_get_running_loop.return_value = mock_loop

        # open_connection returns a reader, writer tuple
        # The writer's close() method is sync, but wait_closed() is async.
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_open_connection.return_value = (AsyncMock(), mock_writer)

        client = NICClient(prefer_ipv6=False)
        try:
            async with client._connect("example.com", timeout=10):
                pass # We just want to check the connection call
        except Exception:
            pass

        # The logic now tries to connect, so we check the arguments of open_connection
        # Without prefer_ipv6, the original order is kept, so IPv4 is first
        self.assertTrue(mock_open_connection.called)
        first_call_args = mock_open_connection.call_args_list[0][1]
        self.assertEqual(first_call_args['host'], '1.2.3.4')

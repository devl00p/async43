import asyncio
import logging
import optparse
import os
import re
import socket
import sys
from contextlib import asynccontextmanager
from typing import Optional, Tuple, AsyncGenerator, Iterator

from async_lru import alru_cache
from tldextract import extract

from async43.exceptions import WhoisNetworkError
from async43.servers import WHOIS_SERVERS

logger = logging.getLogger("async43")


class NICClient:
    """
    Asynchronous WHOIS client responsible for selecting and querying
    appropriate NIC (Network Information Center) servers.

    This class handles:
    - Mapping TLDs to their authoritative WHOIS servers
    - Discovering WHOIS servers dynamically via IANA
    - Establishing network connections (IPv4 / IPv6 / SOCKS)
    - Performing low-level WHOIS queries over port 43

    The client is designed to be reused and is safe to use in asynchronous
    contexts.
    """
    ABUSEHOST = "whois.abuse.net"
    ANICHOST = "whois.arin.net"
    BNICHOST = "whois.registro.br"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    INICHOST = "whois.networksolutions.com"
    LNICHOST = "whois.lacnic.net"
    MNICHOST = "whois.ra.net"
    NICHOST = "whois.crsnic.net"
    PNICHOST = "whois.apnic.net"
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"

    IANAHOST = "whois.iana.org"
    PANDIHOST = "whois.pandi.or.id"
    NORIDHOST = "whois.norid.no"

    DENICHOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    QNICHOST_TAIL = ".whois-servers.net"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois: list[str] = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self, prefer_ipv6: bool = False, ipv6_cycle: Optional[Iterator[str]] = None):
        """
        Initialize a NICClient instance.

        :param prefer_ipv6: Whether IPv6 addresses should be preferred when
            resolving WHOIS server hostnames.
        :param ipv6_cycle: Optional iterator of IPv6 source addresses to cycle
            through when establishing IPv6 connections.
        """
        self.use_qnichost: bool = False
        self.prefer_ipv6 = prefer_ipv6
        self.ipv6_cycle = ipv6_cycle

    @staticmethod
    def findwhois_server(buf: str, hostname: str, query: str) -> Optional[str]:
        """
        Attempt to extract a referral WHOIS server from a WHOIS response.

        This method inspects the raw response returned by an initial WHOIS
        query and tries to identify a more specific WHOIS server that should
        be queried next (for example, a registrar or regional registry).

        :param buf: Raw WHOIS response text.
        :param hostname: Hostname of the WHOIS server that returned the response.
        :param query: Original query string (domain or IP).
        :return: The hostname of the referred WHOIS server if found, otherwise None.
        """
        nhost = None
        match = re.compile(
             rf"Domain Name: {re.escape(query)}\s*.*?Whois Server: (.*?)\s",
            flags=re.IGNORECASE | re.DOTALL,
        ).search(buf)
        if match:
            nhost = match.group(1)
            if nhost.count("/") > 0:
                nhost = None
        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break
        return nhost

    @staticmethod
    def get_socks_socket():
        """
        Create and configure a SOCKS5 socket based on the ``SOCKS`` environment
        variable.

        The ``SOCKS`` variable must be defined in the form::

            host:port
            user:password@host:port

        :raises ImportError: If the ``PySocks`` module is not installed.
        :return: A configured SOCKS socket instance.
        """
        try:
            import socks  # pylint: disable=import-outside-toplevel
        except ImportError as e:
            logger.error(
                "You need to install the Python socks module. Install PIP "
                "(https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'"
            )
            raise e
        socks_user, socks_password = None, None
        if "@" in os.environ["SOCKS"]:
            creds, proxy = os.environ["SOCKS"].split("@")
            socks_user, socks_password = creds.split(":")
        else:
            proxy = os.environ["SOCKS"]
        socksproxy, port = proxy.split(":")
        socks_proto = socket.AF_INET
        if socket.AF_INET6 in [
            sock[0] for sock in socket.getaddrinfo(socksproxy, port)
        ]:
            socks_proto = socket.AF_INET6
        s = socks.socksocket(socks_proto)
        s.set_proxy(
            socks.SOCKS5, socksproxy, int(port), True, socks_user, socks_password
        )
        return s

    async def _open_connection(
            self,
            hostname: str,
            timeout: int,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an asynchronous TCP connection to a WHOIS server.

        This method resolves the target hostname, optionally prefers IPv6,
        supports cycling source IPv6 addresses, and falls back across
        available interfaces until a connection succeeds.

        SOCKS proxies are supported via the ``SOCKS`` environment variable.

        :param hostname: WHOIS server hostname.
        :param timeout: Connection timeout in seconds.
        :raises WhoisNetworkError: If no connection could be established.
        :return: A tuple of (StreamReader, StreamWriter).
        """
        port = 43

        if "SOCKS" in os.environ:
            try:
                s = NICClient.get_socks_socket()
                s.settimeout(timeout)
                s.connect((hostname, port))
                return await asyncio.open_connection(sock=s)
            except (OSError, asyncio.TimeoutError) as e:
                raise WhoisNetworkError(f"SOCKS connection failed for {hostname}: {e}") from e

        try:
            loop = asyncio.get_running_loop()
            addr_infos = await loop.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as e:
            raise WhoisNetworkError(f"Could not resolve WHOIS server {hostname}: {e}") from e

        if self.prefer_ipv6:
            addr_infos.sort(key=lambda x: x[0], reverse=True)

        last_err: Exception | None = None

        for family, _, _, _, sockaddr in addr_infos:
            local_addr = None
            if family == socket.AF_INET6 and self.ipv6_cycle:
                source_address = next(self.ipv6_cycle)
                local_addr = (source_address, 0)

            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(
                        host=sockaddr[0],
                        port=sockaddr[1],
                        local_addr=local_addr,
                    ),
                    timeout=timeout,
                )
            except (OSError, asyncio.TimeoutError) as e:
                last_err = e

        msg = f"Interface connection failed for {hostname}"
        if last_err:
            raise WhoisNetworkError(f"{msg}: {last_err}") from last_err

        raise WhoisNetworkError(msg)

    @asynccontextmanager
    async def _connect(
            self,
            hostname: str,
            timeout: int,
    ) -> AsyncGenerator[Tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """
        Asynchronous context manager that opens and safely closes
        a WHOIS network connection.

        This ensures that the underlying socket and stream writer are
        properly closed even if an exception occurs during the query.

        :param hostname: WHOIS server hostname.
        :param timeout: Connection timeout in seconds.
        :yield: A tuple of (StreamReader, StreamWriter).
        """
        writer: asyncio.StreamWriter | None = None

        try:
            reader, writer = await self._open_connection(hostname, timeout)
            yield reader, writer
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    @alru_cache(ttl=86400)
    async def findwhois_iana(self, tld: str, timeout: int = 10) -> Optional[str]:
        """
        Query IANA to discover the authoritative WHOIS server for a TLD.

        The result is cached for 24 hours to reduce network traffic and
        improve performance.

        :param tld: Top-level domain (without leading dot).
        :param timeout: Network timeout in seconds.
        :raises WhoisNetworkError: If the IANA WHOIS server cannot be reached.
        :return: Hostname of the authoritative WHOIS server, or None if not found.
        """
        try:
            # noinspection PyArgumentList
            async with self._connect("whois.iana.org", timeout) as (reader, writer):
                writer.write(bytes(tld, "utf-8") + b"\r\n")
                await writer.drain()
                response = await reader.read()
        except (OSError, asyncio.TimeoutError) as exception:
            raise WhoisNetworkError(f"Network failure for whois.iana.org: {str(exception)}") from exception

        match = re.search(r"whois:[ \t]+(.*?)\n", response.decode("utf-8"))
        return match.group(1) if match and match.group(1) else None

    async def whois(
            self,
            query: str,
            hostname: str,
            flags: int,
            many_results: bool = False,
            timeout: int = 10,
    ) -> str:
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specific whois server and do a lookup
        there for contact details.
        """
        try:
            # noinspection PyArgumentList
            async with self._connect(hostname, timeout) as (reader, writer):
                if hostname == NICClient.DENICHOST:
                    query_bytes = "-T dn,ace -C UTF-8 " + query
                elif hostname == NICClient.DK_HOST:
                    query_bytes = " --show-handles " + query
                elif hostname.endswith(".jp"):
                    query_bytes = query + "/e"
                elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                    query_bytes = "=" + query
                else:
                    query_bytes = query

                writer.write(bytes(query_bytes, "utf-8") + b"\r\n")
                await writer.drain()

                response = await reader.read()
                response_str = response.decode("utf-8", "replace")

            nhost = None
            if 'with "=xxx"' in response_str:
                return await self.whois(query, hostname, flags, True, timeout=timeout)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response_str, hostname, query)
            if nhost is not None and nhost != "":
                response_str += await self.whois(query, nhost, 0, timeout=timeout)

            return response_str
        except (asyncio.TimeoutError, OSError) as e:
            raise WhoisNetworkError(f"Network failure for {hostname}: {str(e)}") from e

    async def choose_server(
            self,
            domain: str,
            timeout: int = 10,
    ) -> Optional[str]:
        """Choose the initial WHOIS NIC host for a domain."""
        domain = domain.encode("idna").decode("utf-8")
        suffix = extract(domain, include_psl_private_domains=True).suffix
        server = WHOIS_SERVERS.get(suffix)
        if server:
            logger.debug("Server %s was selected for %s", server, domain)
            return server

        tld = ""
        if not suffix and "." in domain:
            tld = domain.split(".")[-1]
            if tld[0].isdigit():
                return self.ANICHOST
            return None

        return await self.findwhois_iana(suffix or tld, timeout=timeout)

    async def whois_lookup(
            self, options: Optional[dict], query_arg: str, flags: int, timeout: int = 10
    ) -> str:
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records."""
        if options is None:
            options = {}

        if ("whoishost" not in options or options["whoishost"] is None) and (
                "country" not in options or options["country"] is None
        ):
            self.use_qnichost = True
            options["whoishost"] = NICClient.NICHOST
            if not flags & NICClient.WHOIS_QUICK:
                flags |= NICClient.WHOIS_RECURSE

        if "country" in options and options["country"] is not None:
            result = await self.whois(
                query_arg,
                options["country"] + NICClient.QNICHOST_TAIL,
                flags,
                timeout=timeout
            )
        elif self.use_qnichost:
            nichost = await self.choose_server(query_arg, timeout=timeout)
            if nichost is not None:
                result = await self.whois(query_arg, nichost, flags, timeout=timeout)
            else:
                result = ""
        else:
            result = await self.whois(query_arg, options["whoishost"], flags, timeout=timeout)
        return result


def parse_command_line(argv: list[str]) -> tuple[optparse.Values, list[str]]:
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option(
        "-a",
        "--arin",
        action="store_const",
        const=NICClient.ANICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.ANICHOST,
    )
    parser.add_option(
        "-A",
        "--apnic",
        action="store_const",
        const=NICClient.PNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.PNICHOST,
    )
    parser.add_option(
        "-b",
        "--abuse",
        action="store_const",
        const=NICClient.ABUSEHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.ABUSEHOST,
    )
    parser.add_option(
        "-c",
        "--country",
        action="store",
        type="string",
        dest="country",
        help="Lookup using country-specific NIC",
    )
    parser.add_option(
        "-d",
        "--mil",
        action="store_const",
        const=NICClient.DNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.DNICHOST,
    )
    parser.add_option(
        "-g",
        "--gov",
        action="store_const",
        const=NICClient.GNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.GNICHOST,
    )
    parser.add_option(
        "-h",
        "--host",
        action="store",
        type="string",
        dest="whoishost",
        help="Lookup using specified whois host",
    )
    parser.add_option(
        "-i",
        "--nws",
        action="store_const",
        const=NICClient.INICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.INICHOST,
    )
    parser.add_option(
        "-I",
        "--iana",
        action="store_const",
        const=NICClient.IANAHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.IANAHOST,
    )
    parser.add_option(
        "-l",
        "--lcanic",
        action="store_const",
        const=NICClient.LNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.LNICHOST,
    )
    parser.add_option(
        "-m",
        "--ra",
        action="store_const",
        const=NICClient.MNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.MNICHOST,
    )
    parser.add_option(
        "-p",
        "--port",
        action="store",
        type="int",
        dest="port",
        help="Lookup using specified tcp port",
    )
    parser.add_option(
        "--prefer-ipv6",
        action="store_true",
        dest="prefer_ipv6",
        default=False,
        help="Prioritize IPv6 resolution for WHOIS servers",
    )
    parser.add_option(
        "-Q",
        "--quick",
        action="store_true",
        dest="b_quicklookup",
        help="Perform quick lookup",
    )
    parser.add_option(
        "-r",
        "--ripe",
        action="store_const",
        const=NICClient.RNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.RNICHOST,
    )
    parser.add_option(
        "-R",
        "--ru",
        action="store_const",
        const="ru",
        dest="country",
        help="Lookup Russian NIC",
    )
    parser.add_option(
        "-6",
        "--6bone",
        action="store_const",
        const=NICClient.SNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.SNICHOST,
    )
    parser.add_option(
        "-n",
        "--ina",
        action="store_const",
        const=NICClient.PANDIHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.PANDIHOST,
    )
    parser.add_option(
        "-t",
        "--timeout",
        action="store",
        type="int",
        dest="timeout",
        help="Set timeout for WHOIS request",
    )
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


async def main():
    """Main entry point for getting the RAW Whois data"""
    flags = 0
    options, args = parse_command_line(sys.argv)
    # When used as a script, IPv6 rotation is not available
    # as it depends on an external function to provide the address cycle.
    nic_client = NICClient(prefer_ipv6=options.prefer_ipv6)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK

    result = await nic_client.whois_lookup(options.__dict__, args[1], flags)
    print(result)


if __name__ == "__main__":
    asyncio.run(main())

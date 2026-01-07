import asyncio
import logging
import optparse
import os
import re
import socket
import sys
from contextlib import asynccontextmanager
from typing import Optional, Tuple, AsyncGenerator, Iterator

logger = logging.getLogger(__name__)


class NICClient:
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
    HR_HOST = "whois.dns.hr"
    PPUA_HOST = "whois.pp.ua"

    # Le mapping centralisé
    TLD_WHOIS_MAP = {
        "ae": "whois.aeda.net.ae",
        "ai": "whois.nic.ai",
        "app": "whois.nic.google",
        "ar": "whois.nic.ar",
        "bw": "whois.nic.net.bw",
        "by": "whois.cctld.by",
        "ca": "whois.ca.fury.ca",
        "chat": "whois.nic.chat",
        "cl": "whois.nic.cl",
        "cm": "whois.netcom.cm",
        "cr": "whois.nic.cr",
        "de": "whois.denic.de",
        "dev": "whois.nic.google",
        "dk": "whois.dk-hostmaster.dk",
        "do": "whois.nic.do",
        "games": "whois.nic.games",
        "goog": "whois.nic.google",
        "google": "whois.nic.google",
        "hk": "whois.hkirc.hk",
        "hn": "whois.nic.hn",
        "hr": "whois.dns.hr",
        "jp": "whois.jprs.jp",
        "kz": "whois.nic.kz",
        "lat": "whois.nic.lat",
        "li": "whois.nic.li",
        "live": "whois.nic.live",
        "lt": "whois.domreg.lt",
        "mx": "whois.mx",
        "nl": "whois.domain-registry.nl",
        "pe": "kero.yachay.pe",
        "ru": "whois.tcinet.ru",
        "su": "whois.tcinet.ru",
        "site": "whois.nic.site",
        "ga": "whois.nic.ga",
        "xyz": "whois.nic.xyz",
        # IDNs (Punycode et UTF-8)
        "xn--p1acf": "whois.tcinet.ru",  # .рус
        "xn--p1ai": "whois.registry.tcinet.ru",  # .рф
        "xn--j1amh": "whois.dotukr.com",  # .укр
    }

    SITE_HOST = "whois.nic.site"
    DESIGN_HOST = "whois.nic.design"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois: list[str] = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self, prefer_ipv6: bool = False, ipv6_cycle: Optional[Iterator[str]] = None):
        self.use_qnichost: bool = False
        self.prefer_ipv6 = prefer_ipv6
        self.ipv6_cycle = ipv6_cycle

    @staticmethod
    def findwhois_server(buf: str, hostname: str, query: str) -> Optional[str]:
        """Search the initial TLD lookup results for the regional-specific
        whois server for getting contact details.
        """
        nhost = None
        match = re.compile(
            r"Domain Name: {}\s*.*?Whois Server: (.*?)\s".format(query),
            flags=re.IGNORECASE | re.DOTALL,
        ).search(buf)
        if match:
            nhost = match.group(1)
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
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
        try:
            import socks
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

    @asynccontextmanager
    async def _connect(self, hostname: str, timeout: int) -> AsyncGenerator[Tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Resolve WHOIS IP address and connect to its TCP 43 port."""
        port = 43
        writer = None
        try:
            if "SOCKS" in os.environ:
                s = NICClient.get_socks_socket()
                s.settimeout(timeout)
                s.connect((hostname, port))
                reader, writer = await asyncio.open_connection(sock=s)
                yield reader, writer
                return

            loop = asyncio.get_running_loop()
            addr_infos = await loop.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)

            if self.prefer_ipv6:
                addr_infos.sort(key=lambda x: x[0], reverse=True)

            last_err = None
            for family, sock_type, proto, __, sockaddr in addr_infos:
                local_addr = None
                if family == socket.AF_INET6 and self.ipv6_cycle:
                    source_address = next(self.ipv6_cycle)
                    local_addr = (source_address, 0)
                
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=sockaddr[0], port=sockaddr[1], local_addr=local_addr),
                        timeout=timeout
                    )
                    yield reader, writer
                    return  # Connection successful, exit the generator
                except (socket.error, asyncio.TimeoutError, OSError) as e:
                    last_err = e
                    if writer:
                        writer.close()
                        await writer.wait_closed()
                        writer = None # Reset writer to avoid closing it again in finally
                    continue
            
            raise last_err or socket.error(f"Could not connect to {hostname}")
        
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def findwhois_iana(self, tld: str, timeout: int = 10) -> Optional[str]:
        async with self._connect("whois.iana.org", timeout) as (reader, writer):
            writer.write(bytes(tld, "utf-8") + b"\r\n")
            await writer.drain()
            response = await reader.read()
        
        match = re.search(r"whois:[ \t]+(.*?)\n", response.decode("utf-8"))
        return match.group(1) if match and match.group(1) else None

    async def whois(
        self,
        query: str,
        hostname: str,
        flags: int,
        many_results: bool = False,
        quiet: bool = False,
        timeout: int = 10,
        ignore_socket_errors: bool = True
    ) -> str:
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specific whois server and do a lookup
        there for contact details.
        """
        try:
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
                return await self.whois(query, hostname, flags, True, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response_str, hostname, query)
            if nhost is not None and nhost != "":
                response_str += await self.whois(query, nhost, 0, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
            
            return response_str
        except (socket.error, asyncio.TimeoutError, OSError) as e:
            if not quiet:
                logger.error(f"Error during WHOIS lookup: {e}")
            if ignore_socket_errors:
                return f"Socket not responding: {e}"
            else:
                raise e

    async def choose_server(self, domain: str, timeout: int = 10) -> Optional[str]:
        """Choose initial lookup NIC host"""
        domain = domain.encode("idna").decode("utf-8")
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith("id"):
            return NICClient.PANDIHOST
        if domain.endswith("hr"):
            return NICClient.HR_HOST
        if domain.endswith(".pp.ua"):
            return NICClient.PPUA_HOST

        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            return None

        tld = domain_parts[-1]

        if tld[0].isdigit():
            return self.ANICHOST

        server = self.TLD_WHOIS_MAP.get(tld)
        if server:
            return server

        return await self.findwhois_iana(tld, timeout=timeout)

    async def whois_lookup(
        self, options: Optional[dict], query_arg: str, flags: int, quiet: bool = False, ignore_socket_errors: bool = True, timeout: int = 10
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
            if not (flags & NICClient.WHOIS_QUICK):
                flags |= NICClient.WHOIS_RECURSE

        if "country" in options and options["country"] is not None:
            result = await self.whois(
                query_arg,
                options["country"] + NICClient.QNICHOST_TAIL,
                flags,
                quiet=quiet,
                ignore_socket_errors=ignore_socket_errors,
                timeout=timeout
            )
        elif self.use_qnichost:
            nichost = await self.choose_server(query_arg, timeout=timeout)
            if nichost is not None:
                result = await self.whois(query_arg, nichost, flags, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
            else:
                result = ""
        else:
            result = await self.whois(query_arg, options["whoishost"], flags, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
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
    flags = 0
    options, args = parse_command_line(sys.argv)
    # When used as a script, IPv6 rotation is not available
    # as it depends on an external function to provide the address cycle.
    nic_client = NICClient(prefer_ipv6=options.prefer_ipv6)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    
    # The original code used logger.debug, which doesn't print to stdout by default.
    # To see the output, we'll print it.
    result = await nic_client.whois_lookup(options.__dict__, args[1], flags)
    print(result)

if __name__ == "__main__":
    asyncio.run(main())

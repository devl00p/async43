# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import asyncio
import logging
import optparse
import os
import re
import socket
import sys
from contextlib import asynccontextmanager
from typing import Optional, Pattern, Tuple, AsyncGenerator, Iterator

logger = logging.getLogger(__name__)


class NICClient:
    ABUSEHOST = "whois.abuse.net"
    AI_HOST = "whois.nic.ai"
    ANICHOST = "whois.arin.net"
    APP_HOST = "whois.nic.google"
    AR_HOST = "whois.nic.ar"
    BNICHOST = "whois.registro.br"
    BW_HOST = "whois.nic.net.bw"
    BY_HOST = "whois.cctld.by"
    CA_HOST = "whois.ca.fury.ca"
    CHAT_HOST = "whois.nic.chat"
    CL_HOST = "whois.nic.cl"
    CM_HOST = "whois.netcom.cm"
    CR_HOST = "whois.nic.cr"
    DEFAULT_PORT = "nicname"
    DENICHOST = "whois.denic.de"
    DEV_HOST = "whois.nic.google"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DNICHOST = "whois.nic.mil"
    DO_HOST = "whois.nic.do"
    GAMES_HOST = "whois.nic.games"
    GNICHOST = "whois.nic.gov"
    GOOGLE_HOST = "whois.nic.google"
    GROUP_HOST = "whois.namecheap.com"
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    HR_HOST = "whois.dns.hr"
    IANAHOST = "whois.iana.org"
    INICHOST = "whois.networksolutions.com"
    IST_HOST = "whois.afilias-srs.net"
    JOBS_HOST = "whois.nic.jobs"
    JP_HOST = "whois.jprs.jp"
    KZ_HOST = "whois.nic.kz"
    LAT_HOST = "whois.nic.lat"
    LI_HOST = "whois.nic.li"
    LIVE_HOST = "whois.nic.live"
    LNICHOST = "whois.lacnic.net"
    LT_HOST = "whois.domreg.lt"
    MARKET_HOST = "whois.nic.market"
    MNICHOST = "whois.ra.net"
    MONEY_HOST = "whois.nic.money"
    MX_HOST = "whois.mx"
    NICHOST = "whois.crsnic.net"
    NL_HOST = "whois.domain-registry.nl"
    NORIDHOST = "whois.norid.no"
    ONLINE_HOST = "whois.nic.online"
    OOO_HOST = "whois.nic.ooo"
    PAGE_HOST = "whois.nic.page"
    PANDIHOST = "whois.pandi.or.id"
    PE_HOST = "kero.yachay.pe"
    PNICHOST = "whois.apnic.net"
    QNICHOST_TAIL = ".whois-servers.net"
    QNICHOST_HEAD = "whois.nic."
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"
    WEBSITE_HOST = "whois.nic.website"
    ZA_HOST = "whois.registry.net.za"
    RU_HOST = "whois.tcinet.ru"
    IDS_HOST = "whois.identitydigital.services"
    GDD_HOST = "whois.dnrs.godaddy"
    SHOP_HOST = "whois.nic.shop"
    SG_HOST = "whois.sgnic.sg"
    STORE_HOST = "whois.centralnic.com"
    STUDIO_HOST = "whois.nic.studio"
    DETI_HOST = "whois.nic.xn--d1acj3b"
    MOSKVA_HOST = "whois.registry.nic.xn--80adxhks"
    RF_HOST = "whois.registry.tcinet.ru"
    PIR_HOST = "whois.publicinterestregistry.org"
    NG_HOST = "whois.nic.net.ng"
    PPUA_HOST = "whois.pp.ua"
    UKR_HOST = "whois.dotukr.com"
    TN_HOST = "whois.ati.tn"
    SBS_HOST = "whois.nic.sbs"
    GA_HOST = "whois.nic.ga"
    XYZ_HOST = "whois.nic.xyz"

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
            return NICClient.ANICHOST
        elif tld == "ai":
            return NICClient.AI_HOST
        elif tld == "app":
            return NICClient.APP_HOST
        elif tld == "ar":
            return NICClient.AR_HOST
        elif tld == "bw":
            return NICClient.BW_HOST
        elif tld == "by":
            return NICClient.BY_HOST
        elif tld == "ca":
            return NICClient.CA_HOST
        elif tld == "chat":
            return NICClient.CHAT_HOST
        elif tld == "cl":
            return NICClient.CL_HOST
        elif tld == "cm":
            return NICClient.CM_HOST
        elif tld == "cr":
            return NICClient.CR_HOST
        elif tld == "de":
            return NICClient.DE_HOST
        elif tld == "dev":
            return NICClient.DEV_HOST
        elif tld == "dk":
            return NICClient.DK_HOST
        elif tld == "do":
            return NICClient.DO_HOST
        elif tld == "games":
            return NICClient.GAMES_HOST
        elif tld == "goog" or tld == "google":
            return NICClient.GOOGLE_HOST
        elif tld == "group":
            return NICClient.GROUP_HOST
        elif tld == "hk":
            return NICClient.HK_HOST
        elif tld == "hn":
            return NICClient.HN_HOST
        elif tld == "ist":
            return NICClient.IST_HOST
        elif tld == "jobs":
            return NICClient.JOBS_HOST
        elif tld == "jp":
            return NICClient.JP_HOST
        elif tld == "kz":
            return NICClient.KZ_HOST
        elif tld == "lat":
            return NICClient.LAT_HOST
        elif tld == "li":
            return NICClient.LI_HOST
        elif tld == "live":
            return NICClient.LIVE_HOST
        elif tld == "lt":
            return NICClient.LT_HOST
        elif tld == "market":
            return NICClient.MARKET_HOST
        elif tld == "money":
            return NICClient.MONEY_HOST
        elif tld == "mx":
            return NICClient.MX_HOST
        elif tld == "nl":
            return NICClient.NL_HOST
        elif tld == "online":
            return NICClient.ONLINE_HOST
        elif tld == "ooo":
            return NICClient.OOO_HOST
        elif tld == "page":
            return NICClient.PAGE_HOST
        elif tld == "pe":
            return NICClient.PE_HOST
        elif tld == "website":
            return NICClient.WEBSITE_HOST
        elif tld == "za":
            return NICClient.ZA_HOST
        elif tld == "ru":
            return NICClient.RU_HOST
        elif tld == "bz":
            return NICClient.RU_HOST
        elif tld == "city":
            return NICClient.RU_HOST
        elif tld == "design":
            return NICClient.DESIGN_HOST
        elif tld == "studio":
            return NICClient.STUDIO_HOST
        elif tld == "style":
            return NICClient.RU_HOST
        elif tld == "su":
            return NICClient.RU_HOST
        elif tld == "рус" or tld == "xn--p1acf":
            return NICClient.RU_HOST
        elif tld == "direct":
            return NICClient.IDS_HOST
        elif tld == "group":
            return NICClient.IDS_HOST
        elif tld == "immo":
            return NICClient.IDS_HOST
        elif tld == "life":
            return NICClient.IDS_HOST
        elif tld == "fashion":
            return NICClient.GDD_HOST
        elif tld == "vip":
            return NICClient.GDD_HOST
        elif tld == "shop":
            return NICClient.SHOP_HOST
        elif tld == "store":
            return NICClient.STORE_HOST
        elif tld == "дети" or tld == "xn--d1acj3b":
            return NICClient.DETI_HOST
        elif tld == "москва" or tld == "xn--80adxhks":
            return NICClient.MOSKVA_HOST
        elif tld == "рф" or tld == "xn--p1ai":
            return NICClient.RF_HOST
        elif tld == "орг" or tld == "xn--c1avg":
            return NICClient.PIR_HOST
        elif tld == "ng":
            return NICClient.NG_HOST
        elif tld == "укр" or tld == "xn--j1amh":
            return NICClient.UKR_HOST
        elif tld == "tn":
            return NICClient.TN_HOST
        elif tld == "sbs":
            return NICClient.SBS_HOST
        elif tld == "sg":
            return NICClient.SG_HOST
        elif tld == "site":
            return NICClient.SITE_HOST
        elif tld == "ga":
            return NICClient.GA_HOST
        elif tld == "xyz":
            return NICClient.XYZ_HOST
        else:
            return await self.findwhois_iana(tld, timeout=timeout)

    async def whois_lookup(
        self, options: Optional[dict], query_arg: str, flags: int, quiet: bool = False, ignore_socket_errors: bool = True, timeout: int = 10
    ) -> str:
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records."""
        nichost = None
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

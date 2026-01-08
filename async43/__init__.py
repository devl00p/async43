# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import re
import socket
import sys
from typing import Any, Optional, Pattern

from async43.exceptions import WhoisError
from async43.parsers import load
from async43.parsers.base import WhoisEntry
from async43.whois import NICClient

import tldextract

logger = logging.getLogger(__name__)
extractor = tldextract.TLDExtract(include_psl_private_domains=True)

# thanks to https://www.regextester.com/104038
IPV4_OR_V6: Pattern[str] = re.compile(
    r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))"  # noqa: E501
)


async def whois(
    url: str,
    command: bool = False,
    flags: int = 0,
    executable: str = "whois",
    executable_opts: Optional[list[str]] = None,
    inc_raw: bool = False,
    quiet: bool = False,
    ignore_socket_errors: bool = True,
    convert_punycode: bool = True,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    url: the URL to search whois
    command: whether to use the native whois command (default False)
    executable: executable to use for native whois command (default 'whois')
    flags: flags to pass to the whois client (default 0)
    inc_raw: whether to include the raw text from whois in the result (default False)
    quiet: whether to avoid printing output (default False)
    ignore_socket_errors: whether to ignore socket errors (default True)
    convert_punycode: whether to convert the given URL punycode (default True)
    timeout: timeout for WHOIS request (default 10 seconds)
    """
    # clean domain to expose netloc
    ip_match = IPV4_OR_V6.match(url)
    if ip_match:
        domain = url
        try:
            result = await asyncio.get_running_loop().getnameinfo((url, 0))
        except socket.herror:
            pass
        else:
            domain = await extract_domain(result[0])
    else:
        domain = await extract_domain(url)
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
        
        text = stdout.decode()
    else:
        # try builtin client
        nic_client = NICClient()
        if convert_punycode:
            domain = domain.encode("idna").decode("utf-8")
        text = await nic_client.whois_lookup(None, domain, flags, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
        if not text:
            raise WhoisError("Whois command returned no output")
    entry = load(domain, text)
    if inc_raw:
        entry["raw"] = text
    return entry


suffixes: Optional[set] = None


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
    >>> logger.info(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info
    >>> logger.info(extract_domain('2607:f8b0:4006:802::200e'))
    1e100.net
    >>> logger.info(extract_domain('172.217.3.110'))
    1e100.net
    """
    if IPV4_OR_V6.match(url):
        try:
            result = await asyncio.get_running_loop().getnameinfo((url, 0))
            hostname = result[0]
            return await extract_domain(hostname)
        except (socket.herror, socket.gaierror):
            return url

    ext = extractor(url)
    return ext.top_domain_under_public_suffix


async def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        url = sys.argv[1]
    except IndexError:
        logger.error("Usage: %s url" % sys.argv[0])
    else:
        result = await whois(url)
        logger.info(result)

if __name__ == "__main__":
    asyncio.run(main())

# async43

**async43** is an asynchronous Python module for retrieving and parsing WHOIS data for a given domain.

This project is a fork of the excellent [python-whois](https://github.com/richardpenman/whois/) library by Richard Penman. It has been refactored to be fully asynchronous using `asyncio` and to add modern networking features.

## Key Features

*   **Fully Asynchronous**: Built from the ground up with `asyncio` for high-performance, non-blocking network I/O.
*   **IPv6 Support**: Can query WHOIS servers over IPv6 and prioritizes it if available.
*   **Outbound IP Rotation**: Supports cycling through a list of available IPv6 addresses for outbound connections, useful for bypassing rate-limits.
*   **Direct WHOIS Queries**: Connects directly to the appropriate WHOIS server instead of relying on intermediate web services.
*   **Structured Parsing**: Uses structured text analysis with fuzzy label matching instead of regex patterns for more robust parsing across different WHOIS server formats.
*   **Optional DNS Enrichment**: Can enrich WHOIS results with DNS information (nameservers, SOA records, DNSSEC status) retrieved in parallel.
*   **Parsed Data**: Converts the raw WHOIS text into a structured Pydantic model.

## Installation

Install from PyPI:

```bash
pip install async43
```

Or checkout the latest version from the repository:

```bash
git clone https://github.com/devl00p/async43.git
pip install -r requirements.txt
```

## Example Usage

### Basic Query

The `whois` function is a coroutine and must be awaited.

```python
import asyncio
import async43

async def main():
    domain = 'example.com'
    w = await async43.whois(domain)
    
    print(w.dates.expires)
    # >>> datetime.datetime(2022, 8, 13, 4, 0, tzinfo=tzoffset('UTC', 0))
    
    print(w)
    # Whois(
    #   domain='example.com',
    #   dates=DomainDates(
    #     created='1995-08-14T04:00:00Z',
    #     expires='2022-08-13T04:00:00Z',
    #     ...
    #   ),
    #   ...
    # )

if __name__ == "__main__":
    asyncio.run(main())
```

### WHOIS with DNS Enrichment

You can optionally enrich WHOIS data with DNS information retrieved in parallel:

```python
import asyncio
import async43

async def main():
    # Enable DNS enrichment
    w = await async43.whois('cloudflare.com', enrich_dns=True)
    
    print(f"Domain: {w.domain}")
    print(f"DNSSEC (from WHOIS): {w.dnssec}")
    
    if w.dns_info:
        print(f"DNSSEC (from DNS): {w.dns_info.dnssec}")
        print(f"Nameservers: {w.dns_info.nameservers}")
        if w.dns_info.soa:
            print(f"SOA Serial: {w.dns_info.soa.serial}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Reusable Client for Multiple Queries

For applications performing multiple WHOIS lookups, use `WhoisClient` to avoid recreating network clients:

```python
import asyncio
from async43 import WhoisClient

async def main():
    # Create a reusable client with DNS enrichment enabled
    client = WhoisClient(enrich_dns=True, timeout=15)
    
    # Perform multiple queries efficiently
    domains = ['cloudflare.com', 'google.com', 'example.org']
    
    for domain in domains:
        result = await client.whois(domain)
        print(f"{result.domain}: {result.dates.expires}")

if __name__ == "__main__":
    asyncio.run(main())
```

### IPv6 Outbound IP Rotation

You can provide an iterator of IPv6 addresses to the `WhoisClient` to enable outbound IP rotation. This is useful for distributing your queries across multiple source addresses.

```python
import asyncio
import itertools
from async43 import WhoisClient

async def main():
    # Your external function to get a list of available IPv6 addresses
    my_ipv6_addresses = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    
    # Create a cycle iterator
    ipv6_cycler = itertools.cycle(my_ipv6_addresses)
    
    # Instantiate the client with the IP cycler and IPv6 preference
    client = WhoisClient(prefer_ipv6=True, ipv6_cycle=ipv6_cycler)
    
    # Each query will use the next IP in the cycle if the destination is IPv6
    result = await client.whois("example.com")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

### Using Async Context Manager

```python
import asyncio
from async43 import WhoisClient

async def main():
    async with WhoisClient(enrich_dns=True) as client:
        result1 = await client.whois("cloudflare.com")
        result2 = await client.whois("google.com")

if __name__ == "__main__":
    asyncio.run(main())
```

## Using a Proxy

Set your environment `SOCKS` variable. Note that the underlying `PySocks` library is not asynchronous and will block.

```bash
export SOCKS="username:password@proxy_address:port"
```

## Parsing Approach

Unlike the original `python-whois` which relied heavily on regular expressions, `async43` uses a more robust approach:

1. **Structured Text Analysis**: The raw WHOIS response is split into logical sections and key-value pairs
2. **Fuzzy Label Matching**: Field labels are matched using fuzzy string matching, making the parser more resilient to variations in WHOIS server output formats
3. **Pydantic Models**: Parsed data is returned as strongly-typed Pydantic models for better type safety and validation

This approach provides better accuracy and maintainability across different WHOIS server formats and TLDs.

## Contributing

Pull requests are welcome!

If you want to improve parsing, the logic can be found in `async43/parser`.

## Acknowledgements

This project is a fork of and builds upon the great work done by Richard Penman on [python-whois](https://github.com/richardpenman/whois/).
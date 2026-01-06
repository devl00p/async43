# async43

**async43** is an asynchronous Python module for retrieving and parsing WHOIS data for a given domain.

This project is a fork of the excellent [python-whois](https://github.com/richardpenman/whois/) library by Richard Penman. It has been refactored to be fully asynchronous using `asyncio` and to add modern networking features.

## Key Features

*   **Fully Asynchronous**: Built from the ground up with `asyncio` for high-performance, non-blocking network I/O.
*   **IPv6 Support**: Can query WHOIS servers over IPv6 and prioritizes it if available.
*   **Outbound IP Rotation**: Supports cycling through a list of available IPv6 addresses for outbound connections, useful for bypassing rate-limits.
*   **Direct WHOIS Queries**: Connects directly to the appropriate WHOIS server instead of relying on intermediate web services.
*   **Parsed Data**: Converts the raw WHOIS text into a structured Python dictionary.

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

    print(w.expiration_date)
    # >>> datetime.datetime(2022, 8, 13, 4, 0, tzinfo=tzoffset('UTC', 0))

    print(w)
    # {
    #   "creation_date": "1995-08-14 04:00:00+00:00",
    #   "expiration_date": "2022-08-13 04:00:00+00:00",
    #   ...
    # }

if __name__ == "__main__":
    asyncio.run(main())
```

### IPv6 Outbound IP Rotation

You can provide an iterator of IPv6 addresses to the `NICClient` to enable outbound IP rotation. This is useful for distributing your queries across multiple source addresses.

```python
import asyncio
import itertools
from async43.whois import NICClient

async def main():
    # Your external function to get a list of available IPv6 addresses
    my_ipv6_addresses = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    
    # Create a cycle iterator
    ipv6_cycler = itertools.cycle(my_ipv6_addresses)

    # Instantiate the client with the IP cycler
    client = NICClient(ipv6_cycle=ipv6_cycler)

    # Use the client for your lookups
    # Each await client.whois(...) will use the next IP in the cycle if the destination is IPv6
    result = await client.whois_lookup(None, "example.com", 0)
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

## Using a Proxy

Set your environment `SOCKS` variable. Note that the underlying `PySocks` library is not asynchronous and will block.

```bash
export SOCKS="username:password@proxy_address:port"
```

## Contributing

Pull requests are welcome!

This project maintains the parsing logic from the original `python-whois`. If you want to add or fix a TLD parser, the process remains the same. See the parser classes in `async43/parser.py`.

## Acknowledgements

This project is a fork of and builds upon the great work done by Richard Penman on [python-whois](https://github.com/richardpenman/whois/).

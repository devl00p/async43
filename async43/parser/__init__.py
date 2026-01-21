import logging
import sys

from async43.parser.constants import NO_SUCH_RECORD_LABELS, TEMP_ERROR
from async43.parser.dates import cast_date
from async43.parser.nameservers import extract_nameservers_from_raw
from async43.parser.structure import parse_whois
from async43.parser.engine import normalize_whois_tree_fuzzy
from async43.exceptions import WhoisDomainNotFoundError, WhoisInternalError
from async43.model import Whois


logger = logging.getLogger("async43")


def print_nodes(nodes, indent=0):
    """Recursively print th Node structure."""
    for node in nodes:
        label = getattr(node, 'label', 'NO_LABEL')
        value = getattr(node, 'value', 'NO_VALUE')
        children = getattr(node, 'children', [])

        prefix = "  " * indent
        logger.debug("%s[%s] -> %s", prefix, label, value)
        if children:
            print_nodes(children, indent + 1)

def parse(raw_text: str) -> Whois:
    """
    Parse raw WHOIS text into a structured ``Whois`` object.

    This function is the main entry point of the parser module. It transforms
    the unstructured WHOIS response text into a normalized data model by:

    - Building an indentation-based parse tree from the raw text
    - Normalizing the parsed tree using fuzzy matching heuristics
    - Converting date fields to ``datetime`` objects when possible
    - Extracting and merging name servers discovered in the raw text
    - Preserving the original WHOIS response for traceability

    The function also detects common WHOIS failure modes by inspecting the
    raw response content and raises domain-specific exceptions accordingly.

    :param raw_text: Raw WHOIS response as returned by a WHOIS server.
    :return: A populated ``Whois`` model containing structured WHOIS data.

    :raises WhoisDomainNotFoundError:
        If the WHOIS response explicitly indicates that the domain does not
        exist, or if the parsed result contains no meaningful data.
    :raises WhoisInternalError:
        If the WHOIS server reports a temporary or internal processing error.
    :raises pydantic.ValidationError:
        If the normalized data cannot be validated against the ``Whois`` model.
    """
    tree = parse_whois(raw_text)
    logger.debug("\n--- DEBUG STRUCTURE ---")
    print_nodes(tree)
    logger.debug("-----------------------\n")
    norm = normalize_whois_tree_fuzzy(tree)
    for date_key, date_string in norm.get("dates", {}).items():
        norm["dates"][date_key] = cast_date(date_string)

    name_servers = extract_nameservers_from_raw(raw_text)
    if name_servers:
        if norm.get("nameservers") is None:
            norm["nameservers"] = []

        known_servers = " ".join(norm["nameservers"]).lower()
        for hostname, ips in name_servers.items():
            if hostname.lower() not in known_servers:
                dns_string = hostname
                if ips:
                    dns_string += " [" + ", ".join(ips) + "]"
                norm["nameservers"].append(dns_string)

    norm["raw_text"] = raw_text
    obj = Whois(**norm)
    for no_record_pattern in NO_SUCH_RECORD_LABELS:
        if no_record_pattern in raw_text:
            raise WhoisDomainNotFoundError("No record found in Whois database (explicit message)")

    for internal_error_pattern in TEMP_ERROR:
        if internal_error_pattern in raw_text:
            raise WhoisInternalError("Whois server wasn't able to process the request")

    if obj.is_empty:
        raise WhoisDomainNotFoundError("No record found in Whois database (no data returned)")

    return obj


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    with open(sys.argv[1], encoding="utf-8", errors="replace") as fd:
        whois_obj = parse(fd.read())
        print(whois_obj.model_dump_json(indent=2, exclude={'raw_text'}))

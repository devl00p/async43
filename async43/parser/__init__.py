import sys

from async43.parser.constants import NO_SUCH_RECORD_LABELS, TEMP_ERROR
from async43.parser.dates import cast_date
from async43.parser.structure import parse_whois
from async43.parser.engine import normalize_whois_tree_fuzzy
from async43.exceptions import WhoisDomainNotFoundError, WhoisInternalError
from async43.model import Whois


def print_nodes(nodes, indent=0):
    """Affiche récursivement la structure des Noeuds."""
    for node in nodes:
        label = getattr(node, 'label', 'NO_LABEL')
        value = getattr(node, 'value', 'NO_VALUE')
        children = getattr(node, 'children', [])

        prefix = "  " * indent
        print(f"{prefix}[{label}] -> {value}")
        if children:
            print_nodes(children, indent + 1)

def parse(raw_text: str) -> Whois:
    tree = parse_whois(raw_text)
    print("\n--- DEBUG STRUCTURE ---")
    print_nodes(tree)
    print("-----------------------\n")
    norm = normalize_whois_tree_fuzzy(tree)
    for date_key, date_string in norm.get("dates", {}).items():
        norm["dates"][date_key] = cast_date(date_string)

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
    with open(sys.argv[1], encoding="utf-8", errors="replace") as fd:
        whois_obj = parse(fd.read())
        print(whois_obj.model_dump_json(indent=2, exclude={'raw_text'}))
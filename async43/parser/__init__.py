from .constants import NO_SUCH_RECORD_LABELS, TEMP_ERROR
from .dates import cast_date
from .structure import parse_whois
from .engine import normalize_whois_tree_fuzzy
from ..exceptions import WhoisDomainNotFoundError, WhoisInternalError
from ..model import Whois


def parse(raw_text: str) -> Whois:
    tree = parse_whois(raw_text)
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

from async43.exceptions import WhoisDomainNotFoundError
from async43.parsers.base import EMAIL_REGEX, WhoisEntry


class WhoisCom(WhoisEntry):
    """Whois parser for .com domains"""

    def __init__(self, domain: str, text: str):
        if 'No match for "' in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisEdu(WhoisEntry):
    """Whois parser for .edu domains"""

    regex: dict[str, str] = {
        "domain_name": "Domain name: *(.+)",
        "creation_date": "Domain record activated: *(.+)",
        "updated_date": "Domain record last updated: *(.+)",
        "expiration_date": "Domain expires: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if text.strip() == "No entries found":
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisInfo(WhoisEntry):
    """Whois parser for .info domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "whois_server": r"Whois Server: *(.+)",  # empty usually
        "referral_url": r"Referral URL: *(.+)",  # http url of whois_server: empty usually
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email addresses
        "name": r"Registrant Name: *(.+)",
        "org": r"Registrant Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
    }

    def __init__(self, domain, text):
        if "Domain not found" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNet(WhoisEntry):
    """Whois parser for .net domains"""

    def __init__(self, domain: str, text: str):
        if 'No match for "' in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisOrg(WhoisEntry):
    """Whois parser for .org domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "whois_server": r"Whois Server: *(.+)",  # empty usually
        "referral_url": r"Referral URL: *(.+)",  # http url of whois_server: empty usually
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain: str, text: str):
        if text.strip().startswith("NOT FOUND") or text.strip().startswith(
            "Domain not found"
        ):
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text)

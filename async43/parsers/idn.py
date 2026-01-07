from async43.parsers.base import WhoisEntry
from async43.exceptions import WhoisDomainNotFoundError
from async43.parsers.base import EMAIL_REGEX
from async43.parsers.cctld import WhoisRu


class WhoisUkr(WhoisEntry):
    """Whois parser for .укр domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain name \(UTF8\): *(.+)",
        "domain_id": r"Registry Domain ID: *(.+)",
        "status": r"Registry Status: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_id": r"Registrar ID: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "registrar_email": r"Registrar Abuse Contact Email: *(.+)",
        "registrar_phone": r"Registrar Abuse Contact Phone: *(.+)",
        "registrant_name": r"Registrant Name \(Organization\): *(.+)",
        "registrant_address": r"Registrant Street:(.+)",
        "registrant_city": r"Registrant City:(.+)",
        "registrant_country": r"Registrant Country:(.+)",
        "registrant_postal_code": r"Registrant Postal Code:(.+)",
        "registrant_phone": r"Registrant Phone:(.+)",
        "registrant_fax": r"Registrant Fax:(.+)",
        "registrant_email": r"Registrant Email:(.+)",
        "admin": r"Admin Name: *(.+)",
        "admin_organization": r"Admin Organization: *(.+)",
        "admin_address": r"Admin Street:(.+)",
        "admin_city": r"Admin City:(.+)",
        "admin_country": r"Admin Country:(.+)",
        "admin_postal_code": r"Admin Postal Code:(.+)",
        "admin_phone": r"Admin Phone:(.+)",
        "admin_fax": r"Admin Fax:(.+)",
        "admin_email": r"Admin Email:(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: (.+)",
        "expiration_date": r"Expiration Date: (.+)",
        "name_servers": r"Domain servers in listed order:\s+((?:.+\n)*)",
    }

    def __init__(self, domain: str, text: str):
        if "No match for domain" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == "name_servers":
            return [line.strip() for line in value.split("\n") if line != ""]
        return super(WhoisUkr, self)._preprocess(attr, value)


class WhoisZhongGuo(WhoisEntry):
    """Whois parser for .中国 domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "creation_date": r"Registration Time: *(.+)",
        "registrant_name": r"Registrant: *(.+)",
        "registrar": r"Sponsoring Registrar: *(.+)",
        "expiration_date": r"Expiration Time: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "emails": EMAIL_REGEX,
    }

    def __init__(self, domain: str, text: str):
        if 'No match for "' in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPyc(WhoisRu):
    """Whois parser for .рус domains"""

    def __init__(self, domain: str, text: str):
        WhoisRu.__init__(self, domain, text)

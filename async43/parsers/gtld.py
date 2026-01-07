from async43.exceptions import WhoisDomainNotFoundError
from async43.parsers.base import EMAIL_REGEX, WhoisEntry
from async43.parsers.cctld import WhoisRu, WhoisBz


class WhoisApp(WhoisEntry):
    """Whois parser for .app domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "whois_server": r"Whois Server: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Expir\w+ Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email s
        "registrant_email": r"Registrant Email: *(.+)",  # registrant email
        "registrant_phone": r"Registrant Phone: *(.+)",  # registrant phone
        "dnssec": r"dnssec: *([\S]+)",
        "name": r"Registrant Name: *(.+)",
        "org": r"Registrant\s*Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if text.strip() == "Domain not found.":
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBiz(WhoisEntry):
    """Whois parser for .biz domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain__id": r"Domain ID: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "registrar_id": r"Registrar IANA ID: *(.+)",
        "registrar_email": r"Registrar Abuse Contact Email: *(.+)",
        "registrar_phone": r"Registrar Abuse Contact Phone: *(.+)",
        "status": r"Domain Status: *(.+)",  # list of statuses
        "registrant_id": r"Registrant ID: *(.+)",
        "registrant_name": r"Registrant Name: *(.+)",
        "registrant_address": r"Registrant Street: *(.+)",
        "registrant_city": r"Registrant City: *(.+)",
        "registrant_state_province": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "registrant_country": r"Registrant Country: *(.+)",
        "registrant_country_code": r"Registrant Country Code: *(.+)",
        "registrant_phone_number": r"Registrant Phone: *(.+)",
        "registrant_email": r"Registrant Email: *(.+)",
        "admin_id": r"Registry Admin ID: *(.+)",
        "admin_name": r"Admin Name: *(.+)",
        "admin_organization": r"Admin Organization: *(.+)",
        "admin_address": r"Admin Street: *(.+)",
        "admin_city": r"Admin City: *(.+)",
        "admin_state_province": r"Admin State/Province: *(.+)",
        "admin_postal_code": r"Admin Postal Code: *(.+)",
        "admin_country": r"Admin Country: *(.+)",
        "admin_phone_number": r"Admin Phone: *(.+)",
        "admin_email": r"Admin Email: *(.+)",
        "tech_id": r"Registry Tech ID: *(.+)",
        "tech_name": r"Tech Name: *(.+)",
        "tech_organization": r"Tech Organization: *(.+)",
        "tech_address": r"Tech Street: *(.+)",
        "tech_city": r"Tech City: *(.+)",
        "tech_state_province": r"Tech State/Province: *(.+)",
        "tech_postal_code": r"Tech Postal Code: *(.+)",
        "tech_country": r"Tech Country: *(.+)",
        "tech_phone_number": r"Tech Phone: *(.+)",
        "tech_email": r"Tech Email: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registrar Registration Expiration Date: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "No Data Found" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCat(WhoisEntry):
    """Whois parser for .cat domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",
        "status": r"Domain status: *(.+)",
        "emails": EMAIL_REGEX,
    }

    def __init__(self, domain: str, text: str):
        if "no matching objects" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            # Merge base class regex with specifics
            self._regex.copy().update(self.regex)
            self.regex = self._regex
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCity(WhoisRu):
    """Whois parser for .city domains"""

    def __init__(self, domain: str, text: str):
        WhoisRu.__init__(self, domain, text)


class WhoisClub(WhoisEntry):
    """Whois parser for .us domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain__id": r"Domain ID: *(.+)",
        "registrar": r"Sponsoring Registrar: *(.+)",
        "registrar_id": r"Sponsoring Registrar IANA ID: *(.+)",
        "registrar_url": r"Registrar URL \(registration services\): *(.+)",
        # list of statuses
        "status": r"Domain Status: *(.+)",
        "registrant_id": r"Registrant ID: *(.+)",
        "registrant_name": r"Registrant Name: *(.+)",
        "registrant_address1": r"Registrant Address1: *(.+)",
        "registrant_address2": r"Registrant Address2: *(.+)",
        "registrant_city": r"Registrant City: *(.+)",
        "registrant_state_province": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "registrant_country": r"Registrant Country: *(.+)",
        "registrant_country_code": r"Registrant Country Code: *(.+)",
        "registrant_phone_number": r"Registrant Phone Number: *(.+)",
        "registrant_email": r"Registrant Email: *(.+)",
        "registrant_application_purpose": r"Registrant Application Purpose: *(.+)",
        "registrant_nexus_category": r"Registrant Nexus Category: *(.+)",
        "admin_id": r"Administrative Contact ID: *(.+)",
        "admin_name": r"Administrative Contact Name: *(.+)",
        "admin_address1": r"Administrative Contact Address1: *(.+)",
        "admin_address2": r"Administrative Contact Address2: *(.+)",
        "admin_city": r"Administrative Contact City: *(.+)",
        "admin_state_province": r"Administrative Contact State/Province: *(.+)",
        "admin_postal_code": r"Administrative Contact Postal Code: *(.+)",
        "admin_country": r"Administrative Contact Country: *(.+)",
        "admin_country_code": r"Administrative Contact Country Code: *(.+)",
        "admin_phone_number": r"Administrative Contact Phone Number: *(.+)",
        "admin_email": r"Administrative Contact Email: *(.+)",
        "admin_application_purpose": r"Administrative Application Purpose: *(.+)",
        "admin_nexus_category": r"Administrative Nexus Category: *(.+)",
        "billing_id": r"Billing Contact ID: *(.+)",
        "billing_name": r"Billing Contact Name: *(.+)",
        "billing_address1": r"Billing Contact Address1: *(.+)",
        "billing_address2": r"Billing Contact Address2: *(.+)",
        "billing_city": r"Billing Contact City: *(.+)",
        "billing_state_province": r"Billing Contact State/Province: *(.+)",
        "billing_postal_code": r"Billing Contact Postal Code: *(.+)",
        "billing_country": r"Billing Contact Country: *(.+)",
        "billing_country_code": r"Billing Contact Country Code: *(.+)",
        "billing_phone_number": r"Billing Contact Phone Number: *(.+)",
        "billing_email": r"Billing Contact Email: *(.+)",
        "billing_application_purpose": r"Billing Application Purpose: *(.+)",
        "billing_nexus_category": r"Billing Nexus Category: *(.+)",
        "tech_id": r"Technical Contact ID: *(.+)",
        "tech_name": r"Technical Contact Name: *(.+)",
        "tech_address1": r"Technical Contact Address1: *(.+)",
        "tech_address2": r"Technical Contact Address2: *(.+)",
        "tech_city": r"Technical Contact City: *(.+)",
        "tech_state_province": r"Technical Contact State/Province: *(.+)",
        "tech_postal_code": r"Technical Contact Postal Code: *(.+)",
        "tech_country": r"Technical Contact Country: *(.+)",
        "tech_country_code": r"Technical Contact Country Code: *(.+)",
        "tech_phone_number": r"Technical Contact Phone Number: *(.+)",
        "tech_email": r"Technical Contact Email: *(.+)",
        "tech_application_purpose": r"Technical Application Purpose: *(.+)",
        "tech_nexus_category": r"Technical Nexus Category: *(.+)",
        # list of name servers
        "name_servers": r"Name Server: *(.+)",
        "created_by_registrar": r"Created by Registrar: *(.+)",
        "last_updated_by_registrar": r"Last Updated by Registrar: *(.+)",
        "creation_date": r"Domain Registration Date: *(.+)",
        "expiration_date": r"Domain Expiration Date: *(.+)",
        "updated_date": r"Domain Last Updated Date: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "Not found:" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDesign(WhoisEntry):
    """Whois parser for .design domains"""

    _regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar URL: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Domain Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email s
        "dnssec": r"DNSSEC: *([\S]+)",
        "name": r"Registrant Name: *(.+)",
        "phone": r"Registrant Phone: *(.+)",
        "org": r"Registrant\s*Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "No Data Found" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGroup(WhoisEntry):
    """Whois parser for .group domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain_id": r"Registry Domain ID:(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "updated_date": r"Updated Date: (.+)",
        "creation_date": r"Creation Date: (.+)",
        "expiration_date": r"Expir\w+ Date:\s?(.+)",
        "registrar": r"Registrar:(.+)",
        "status": r"Domain status: *(.+)",
        "registrant_name": r"Registrant Name:(.+)",
        "name_servers": r"Name Server: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "Domain not found" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisJobs(WhoisEntry):
    """Whois parser for .jobs domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain_id": r"Registry Domain ID: *(.+)",
        "status": r"Domain Status: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "registrar_name": r"Registrar: *(.+)",
        "registrar_email": r"Registrar Abuse Contact Email: *(.+)",
        "registrar_phone": r"Registrar Abuse Contact Phone: *(.+)",
        "registrant_name": r"Registrant Name: (.+)",
        "registrant_id": r"Registry Registrant ID: (.+)",
        "registrant_organization": r"Registrant Organization: (.+)",
        "registrant_city": r"Registrant City: (.*)",
        "registrant_street": r"Registrant Street: (.*)",
        "registrant_state_province": r"Registrant State/Province: (.*)",
        "registrant_postal_code": r"Registrant Postal Code: (.*)",
        "registrant_country": r"Registrant Country: (.+)",
        "registrant_phone": r"Registrant Phone: (.+)",
        "registrant_fax": r"Registrant Fax: (.+)",
        "registrant_email": r"Registrant Email: (.+)",
        "admin_name": r"Admin Name: (.+)",
        "admin_id": r"Registry Admin ID: (.+)",
        "admin_organization": r"Admin Organization: (.+)",
        "admin_city": r"Admin City: (.*)",
        "admin_street": r"Admin Street: (.*)",
        "admin_state_province": r"Admin State/Province: (.*)",
        "admin_postal_code": r"Admin Postal Code: (.*)",
        "admin_country": r"Admin Country: (.+)",
        "admin_phone": r"Admin Phone: (.+)",
        "admin_fax": r"Admin Fax: (.+)",
        "admin_email": r"Admin Email: (.+)",
        "billing_name": r"Billing Name: (.+)",
        "billing_id": r"Registry Billing ID: (.+)",
        "billing_organization": r"Billing Organization: (.+)",
        "billing_city": r"Billing City: (.*)",
        "billing_street": r"Billing Street: (.*)",
        "billing_state_province": r"Billing State/Province: (.*)",
        "billing_postal_code": r"Billing Postal Code: (.*)",
        "billing_country": r"Billing Country: (.+)",
        "billing_phone": r"Billing Phone: (.+)",
        "billing_fax": r"Billing Fax: (.+)",
        "billing_email": r"Billing Email: (.+)",
        "tech_name": r"Tech Name: (.+)",
        "tech_id": r"Registry Tech ID: (.+)",
        "tech_organization": r"Tech Organization: (.+)",
        "tech_city": r"Tech City: (.*)",
        "tech_street": r"Tech Street: (.*)",
        "tech_state_province": r"Tech State/Province: (.*)",
        "tech_postal_code": r"Tech Postal Code: (.*)",
        "tech_country": r"Tech Country: (.+)",
        "tech_phone": r"Tech Phone: (.+)",
        "tech_fax": r"Tech Fax: (.+)",
        "tech_email": r"Tech Email: (.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "not found." in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLat(WhoisEntry):
    """Whois parser for .lat domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain_id": r"Registry Domain ID: *(.+)",
        "status": r"Domain Status: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_email": r"Registrar Abuse Contact Email: *(.+)",
        "registrar_phone": r"Registrar Abuse Contact Phone: *(.+)",
        "registrant_name": r"Registrant Name: (.+)",
        "registrant_id": r"Registry Registrant ID: (.+)",
        "registrant_organization": r"Registrant Organization: (.+)",
        "registrant_city": r"Registrant City: (.*)",
        "registrant_street": r"Registrant Street: (.*)",
        "registrant_state_province": r"Registrant State/Province: (.*)",
        "registrant_postal_code": r"Registrant Postal Code: (.*)",
        "registrant_country": r"Registrant Country: (.+)",
        "registrant_phone": r"Registrant Phone: (.+)",
        "registrant_fax": r"Registrant Fax: (.+)",
        "registrant_email": r"Registrant Email: (.+)",
        "admin_name": r"Admin Name: (.+)",
        "admin_id": r"Registry Admin ID: (.+)",
        "admin_organization": r"Admin Organization: (.+)",
        "admin_city": r"Admin City: (.*)",
        "admin_street": r"Admin Street: (.*)",
        "admin_state_province": r"Admin State/Province: (.*)",
        "admin_postal_code": r"Admin Postal Code: (.*)",
        "admin_country": r"Admin Country: (.+)",
        "admin_phone": r"Admin Phone: (.+)",
        "admin_fax": r"Admin Fax: (.+)",
        "admin_email": r"Admin Email: (.+)",
        "tech_name": r"Tech Name: (.+)",
        "tech_id": r"Registry Tech ID: (.+)",
        "tech_organization": r"Tech Organization: (.+)",
        "tech_city": r"Tech City: (.*)",
        "tech_street": r"Tech Street: (.*)",
        "tech_state_province": r"Tech State/Province: (.*)",
        "tech_postal_code": r"Tech Postal Code: (.*)",
        "tech_country": r"Tech Country: (.+)",
        "tech_phone": r"Tech Phone: (.+)",
        "tech_fax": r"Tech Fax: (.+)",
        "tech_email": r"Tech Email: (.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if text.strip() == "No matching record.":
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLife(WhoisEntry):
    """Whois parser for .ir domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name:: *(.+)",
        "registrant_name": r"Registrar: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "emails": EMAIL_REGEX,
    }

    def __init__(self, domain: str, text: str):
        if "Domain not found." in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMarket(WhoisEntry):
    """Whois parser for .market domains"""

    def __init__(self, domain: str, text: str):
        if "No entries found for the selected source(s)." in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMobi(WhoisEntry):
    """Whois parser for .mobi domains"""

    regex: dict[str, str] = {
        "domain_id": r"Registry Domain ID:(.+)",
        "domain_name": r"Domain Name:(.+)",
        "creation_date": r"Creation Date:(.+)",
        "updated_date": r"Updated Date:(.+)",
        "expiration_date": r"Registry Expiry Date: (.+)",
        "registrar": r"Registrar:(.+)",
        "status": r"Domain Status:(.+)",  # list of statuses
        "registrant_id": r"Registrant ID:(.+)",
        "registrant_name": r"Registrant Name:(.+)",
        "registrant_org": r"Registrant Organization:(.+)",
        "registrant_address": r"Registrant Address:(.+)",
        "registrant_address2": r"Registrant Address2:(.+)",
        "registrant_address3": r"Registrant Address3:(.+)",
        "registrant_city": r"Registrant City:(.+)",
        "registrant_state_province": r"Registrant State/Province:(.+)",
        "registrant_country": r"Registrant Country/Economy:(.+)",
        "registrant_postal_code": r"Registrant Postal Code:(.+)",
        "registrant_phone": r"Registrant Phone:(.+)",
        "registrant_phone_ext": r"Registrant Phone Ext\.:(.+)",
        "registrant_fax": r"Registrant FAX:(.+)",
        "registrant_fax_ext": r"Registrant FAX Ext\.:(.+)",
        "registrant_email": r"Registrant E-mail:(.+)",
        "admin_id": r"Admin ID:(.+)",
        "admin_name": r"Admin Name:(.+)",
        "admin_org": r"Admin Organization:(.+)",
        "admin_address": r"Admin Address:(.+)",
        "admin_address2": r"Admin Address2:(.+)",
        "admin_address3": r"Admin Address3:(.+)",
        "admin_city": r"Admin City:(.+)",
        "admin_state_province": r"Admin State/Province:(.+)",
        "admin_country": r"Admin Country/Economy:(.+)",
        "admin_postal_code": r"Admin Postal Code:(.+)",
        "admin_phone": r"Admin Phone:(.+)",
        "admin_phone_ext": r"Admin Phone Ext\.:(.+)",
        "admin_fax": r"Admin FAX:(.+)",
        "admin_fax_ext": r"Admin FAX Ext\.:(.+)",
        "admin_email": r"Admin E-mail:(.+)",
        "tech_id": r"Tech ID:(.+)",
        "tech_name": r"Tech Name:(.+)",
        "tech_org": r"Tech Organization:(.+)",
        "tech_address": r"Tech Address:(.+)",
        "tech_address2": r"Tech Address2:(.+)",
        "tech_address3": r"Tech Address3:(.+)",
        "tech_city": r"Tech City:(.+)",
        "tech_state_province": r"Tech State/Province:(.+)",
        "tech_country": r"Tech Country/Economy:(.+)",
        "tech_postal_code": r"Tech Postal Code:(.+)",
        "tech_phone": r"Tech Phone:(.+)",
        "tech_phone_ext": r"Tech Phone Ext\.:(.+)",
        "tech_fax": r"Tech FAX:(.+)",
        "tech_fax_ext": r"Tech FAX Ext\.:(.+)",
        "tech_email": r"Tech E-mail:(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
    }

    def __init__(self, domain: str, text: str):
        if "NOT FOUND" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMoney(WhoisEntry):
    """Whois parser for .money domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Domain Status: *(.+)",
        "emails": EMAIL_REGEX,  # list of emails
        "registrant_email": r"Registrant Email: *(.+)",
        "registrant_phone": r"Registrant Phone: *(.+)",
        "dnssec": r"DNSSEC: *(.+)",
        "name": r"Registrant Name: *(.+)",
        "org": r"Registrant Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if text.strip() == "Domain not found.":
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisOnline(WhoisEntry):
    """Whois parser for .online domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "domain__id": r"Domain ID: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_id": r"Registrar IANA ID: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "status": r"Domain Status: *(.+)",
        "registrant_email": r"Registrant Email: *(.+)",
        "admin_email": r"Admin Email: *(.+)",
        "billing_email": r"Billing Email: *(.+)",
        "tech_email": r"Tech Email: *(.+)",
        "name_servers": r"Name Server: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "dnssec": r"DNSSEC: *([\S]+)",
    }

    def __init__(self, domain: str, text: str):
        if "Not found:" in text or "The queried object does not exist: DOMAIN NOT FOUND" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisOoo(WhoisEntry):
    """Whois parser for .ooo domains"""

    def __init__(self, domain: str, text: str):
        if "No entries found for the selected source(s)." in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisName(WhoisEntry):
    """Whois parser for .name domains"""

    regex: dict[str, str] = {
        "domain_name_id": r"Domain Name ID: *(.+)",
        "domain_name": r"Domain Name: *(.+)",
        "registrar_id": r"Sponsoring Registrar ID: *(.+)",
        "registrar": r"Sponsoring Registrar: *(.+)",
        "registrant_id": r"Registrant ID: *(.+)",
        "admin_id": r"Admin ID: *(.+)",
        "technical_id": r"Tech ID: *(.+)",
        "billing_id": r"Billing ID: *(.+)",
        "creation_date": r"Created On: *(.+)",
        "expiration_date": r"Expires On: *(.+)",
        "updated_date": r"Updated On: *(.+)",
        "name_server_ids": r"Name Server ID: *(.+)",  # list of name server ids
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Domain Status: *(.+)",  # list of statuses
    }

    def __init__(self, domain: str, text: str):
        if "No match for " in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSite(WhoisEntry):
    """Whois parser for .site domains"""

    _regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "whois_server": r"Whois Server: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Domain Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email s
        "dnssec": r"DNSSEC: *([\S]+)",
        "name": r"Registrant Name: *(.+)",
        "org": r"Registrant\s*Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if "DOMAIN NOT FOUND" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSpace(WhoisEntry):
    """Whois parser for .space domains"""

    def __init__(self, domain: str, text: str):
        if 'No match for "' in text or "The queried object does not exist: DOMAIN NOT FOUND" in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisStudio(WhoisBz):
    """Whois parser for .studio domains"""

    def __init__(self, domain: str, text: str):
        if "Domain not found." in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisStyle(WhoisRu):
    """Whois parser for .style domains"""

    def __init__(self, domain: str, text: str):
        WhoisRu.__init__(self, domain, text)


class WhoisWebsite(WhoisEntry):
    """Whois parser for .website domains"""

    def __init__(self, domain: str, text: str):
        if 'No match for "' in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisXyz(WhoisEntry):
    """Whois parser for .xyz domains"""

    regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registry_domain_id": r"Registry Domain ID: *(.+)",
        "whois_server": r"Registrar WHOIS Server: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Registry Expiry Date: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_id": r"Registrar IANA ID: *(.+)",
        "status": r"Domain Status: *(.+)",  # list of statuses
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "dnssec": r"DNSSEC: *(.+)",
        "registrar_email": r"Registrar Abuse Contact Email: *(.+)",
        "registrar_phone": r"Registrar Abuse Contact Phone: *(.+)",
    }

    def __init__(self, domain: str, text: str):
        if 'The queried object does not exist: DOMAIN NOT FOUND' in text:
            raise WhoisDomainNotFoundError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

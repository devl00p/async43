from datetime import datetime
from typing import List, Optional, Union
from pydantic import BaseModel, Field


class DnsSec(BaseModel):
    """
    Stores DNSSEC information from DNS queries.
    """
    enabled: Optional[bool] = None


class SoaRecord(BaseModel):
    """
    Stores SOA (Start of Authority) record information.
    """
    mname: Optional[str] = None
    rname: Optional[str] = None
    serial: Optional[int] = None
    refresh: Optional[int] = None
    retry: Optional[int] = None
    expire: Optional[int] = None
    minimum: Optional[int] = None


class DnsInfo(BaseModel):
    """
    Stores DNS enrichment data.
    """
    nameservers: List[str] = Field(default_factory=list)
    soa: Optional[SoaRecord] = None
    dnssec: Optional[bool] = None


class Contact(BaseModel):
    """
    Represents a WHOIS contact entity.

    This model is used for registrant, administrative, technical,
    billing, abuse, or registrar contacts as returned by WHOIS servers.
    All fields are optional, as WHOIS data is often incomplete or
    registry-dependent.
    """

    email: Optional[str] = None
    name: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    organization: Optional[str] = None
    phone: Optional[str] = None
    fax: Optional[str] = None
    handle: Optional[str] = None


class DomainContacts(BaseModel):
    """
    Groups all WHOIS contacts related to a domain name.

    Each attribute corresponds to a specific contact role
    defined by registries or registrars.
    """

    registrant: Optional[Contact]
    administrative: Optional[Contact]
    technical: Optional[Contact]
    billing: Optional[Contact]
    abuse: Optional[Contact]


class DomainDates(BaseModel):
    """
    Stores important lifecycle dates of a domain name.

    Date values may be provided either as ISO-formatted strings
    or as datetime objects, depending on parsing capabilities
    and registry formats.
    """

    created: Optional[Union[str, datetime]] = None
    updated: Optional[Union[str, datetime]] = None
    expires: Optional[Union[str, datetime]] = None


class Whois(BaseModel):
    """
    Represents the structured result of a WHOIS lookup.

    This model aggregates parsed WHOIS information including
    domain metadata, contacts, name servers, status flags,
    DNSSEC state, and the original raw WHOIS text.
    """

    domain: Optional[str] = None
    status: List[str] = Field(default_factory=list)
    dates: DomainDates = Field(default_factory=DomainDates)
    nameservers: List[str] = Field(default_factory=list)
    dnssec: Optional[str] = None
    registrar: Optional[Contact] = None
    contacts: DomainContacts
    dns_info: Optional[DnsInfo] = None
    raw_text: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "dates": {
                    "updated": "2026-01-08T14:45:21Z",
                    "created": "2019-08-12T19:10:36Z",
                    "expiry": "2026-08-12T19:10:36Z"
                },
                "registrar": {
                    "name": "https://identity.digital"
                },
                "nameservers": [
                    "a0.nic.xn--fzys8d69uvgm",
                    "b0.nic.xn--fzys8d69uvgm",
                    "c0.nic.xn--fzys8d69uvgm",
                    "a2.nic.xn--fzys8d69uvgm"
                ],
                "status": [
                    "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
                    "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
                    "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"
                ],
                "contacts": {
                    "registrant": {},
                    "admin": {},
                    "technical": {},
                    "abuse": {
                        "email": "abuse@identity.digital",
                        "phone": "+1.6664447777"
                    },
                    "billing": {}
                },
                "other": {
                    "Registry Domain ID": "81fc31bbd3b64727abc899bbacb0ed42-DONUTS",
                    "Registrar WHOIS Server": "whois.identitydigital.services"
                },
                "domain": "nic.xn--fzys8d69uvgm",
                "registrar_iana_id": "9999",
                "dnssec": "signedDelegation",
                "raw_text": "% SOME WHOIS TEXT"
            }
        }
    }

    @property
    def is_empty(self) -> bool:
        """
        Indicates whether the WHOIS result contains any meaningful data.

        The raw WHOIS text is ignored for this check. The method recursively
        inspects all structured fields and considers the object empty if
        all values are either None, empty strings, or empty collections.

        :return: True if no structured WHOIS data is present, False otherwise.
        """
        data = self.model_dump(exclude={"raw_text", "dns_info"})

        def check_empty(v):
            if isinstance(v, dict):
                return all(check_empty(child) for child in v.values())
            if isinstance(v, list):
                return len(v) == 0
            return v is None or v == ""

        return all(check_empty(value) for value in data.values())

from typing import List, Optional
from pydantic import BaseModel, Field


class Contact(BaseModel):
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
    registrant: Optional[Contact]
    administrative: Optional[Contact]
    technical: Optional[Contact]
    billing: Optional[Contact]
    abuse: Optional[Contact]


class DomainDates(BaseModel):
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None


class Whois(BaseModel):
    domain: Optional[str] = None
    status: List[str] = Field(default_factory=list)
    dates: DomainDates = Field(default_factory=DomainDates)
    nameservers: List[str] = Field(default_factory=list)
    dnssec: Optional[str] = None
    registrar: Optional[Contact] = None
    contacts: DomainContacts
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
        data = self.model_dump(exclude={'raw_text'})

        def check_empty(v):
            if isinstance(v, dict):
                return all(check_empty(child) for child in v.values())
            if isinstance(v, list):
                return len(v) == 0
            return v is None or v == ""

        return all(check_empty(value) for value in data.values())

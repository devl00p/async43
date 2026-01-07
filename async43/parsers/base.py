import json
import re
from datetime import datetime, timezone
from typing import Union, Optional, Callable, Any

from dateutil import parser as dp
from dateutil.utils import default_tzinfo

from async43.exceptions import WhoisUnknownDateFormatError, WhoisDomainNotFoundError
from async43.time_zones import tz_data

EMAIL_REGEX: str = (
    r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*["
    r"a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)
KNOWN_FORMATS: list[str] = [
    "%d-%b-%Y",  # 02-jan-2000
    "%d-%B-%Y",  # 11-February-2000
    "%d-%m-%Y",  # 20-10-2000
    "%Y-%m-%d",  # 2000-01-02
    "%d.%m.%Y",  # 2.1.2000
    "%Y.%m.%d",  # 2000.01.02
    "%Y/%m/%d",  # 2000/01/02
    "%Y/%m/%d %H:%M:%S",  # 2011/06/01 01:05:01
    "%Y/%m/%d %H:%M:%S (%z)",  # 2011/06/01 01:05:01 (+0900)
    "%Y%m%d",  # 20170209
    "%Y%m%d %H:%M:%S",  # 20110908 14:44:51
    "%d/%m/%Y",  # 02/01/2013
    "%Y. %m. %d.",  # 2000. 01. 02.
    "%Y.%m.%d %H:%M:%S",  # 2014.03.08 10:28:24
    "%d-%b-%Y %H:%M:%S %Z",  # 24-Jul-2009 13:20:03 UTC
    "%a %b %d %H:%M:%S %Z %Y",  # Tue Jun 21 23:59:59 GMT 2011
    "%a %b %d %Y",  # Tue Dec 12 2000
    "%Y-%m-%dT%H:%M:%S",  # 2007-01-26T19:10:31
    "%Y-%m-%dT%H:%M:%SZ",  # 2007-01-26T19:10:31Z
    "%Y-%m-%dT%H:%M:%SZ[%Z]",  # 2007-01-26T19:10:31Z[UTC]
    "%Y-%m-%d %H:%M:%S.%f",  # 2018-05-19 12:18:44.329522
    "%Y-%m-%dT%H:%M:%S.%fZ",  # 2018-12-01T16:17:30.568Z
    "%Y-%m-%dT%H:%M:%S.%f%z",  # 2011-09-08T14:44:51.622265+03:00
    "%Y-%m-%d %H:%M:%S%z",  # 2018-11-02 11:29:08+02:00
    "%Y-%m-%dT%H:%M:%S%z",  # 2013-12-06T08:17:22-0800
    "%Y-%m-%dT%H:%M:%S%zZ",  # 1970-01-01T02:00:00+02:00Z
    "%Y-%m-%dt%H:%M:%S.%f",  # 2011-09-08t14:44:51.622265
    "%Y-%m-%dt%H:%M:%S",  # 2007-01-26T19:10:31
    "%Y-%m-%dt%H:%M:%SZ",  # 2007-01-26T19:10:31Z
    "%Y-%m-%dt%H:%M:%S.%fz",  # 2007-01-26t19:10:31.00z
    "%Y-%m-%dt%H:%M:%S%z",  # 2011-03-30T19:36:27+0200
    "%Y-%m-%dt%H:%M:%S.%f%z",  # 2011-09-08T14:44:51.622265+03:00
    "%Y-%m-%d %H:%M:%SZ",  # 2000-08-22 18:55:20Z
    "%Y-%m-%d %H:%M:%SZ.0Z",  # 2000-08-22 18:55:20Z.0Z
    "%Y-%m-%d %H:%M:%S",  # 2000-08-22 18:55:20
    "%d %b %Y %H:%M:%S",  # 08 Apr 2013 05:44:00
    "%d/%m/%Y %H:%M:%S",  # 23/04/2015 12:00:07
    "%d/%m/%Y %H:%M:%S %Z",  # 23/04/2015 12:00:07 EEST
    "%d/%m/%Y %H:%M:%S.%f %Z",  # 23/04/2015 12:00:07.619546 EEST
    "%B %d %Y",  # August 14 2017
    "%d.%m.%Y %H:%M:%S",  # 08.03.2014 10:28:24
    "before %Y",  # before 2001
    "before %b-%Y",  # before aug-1996
    "before %Y-%m-%d",  # before 1996-01-01
    "before %Y%m%d",  # before 19960821
    "%Y-%m-%d %H:%M:%S (%Z%z)",  # 2017-09-26 11:38:29 (GMT+00:00)
    "%Y-%m-%d %H:%M:%S (%Z+0:00)",  # 2009-07-01 12:44:02 (GMT+0:00)
    "%Y-%b-%d.",  # 2024-Apr-02.
]


def datetime_parse(s: str) -> Union[datetime, None]:
    for known_format in KNOWN_FORMATS:
        try:
            parsed = datetime.strptime(s, known_format)
        except ValueError:
            pass  # Wrong format, keep trying
        else:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed


def cast_date(
    s: str, dayfirst: bool = False, yearfirst: bool = False
) -> Union[str, datetime]:
    """Convert any date string found in WHOIS to a datetime object."""

    # prefer our conversion before dateutil.parser
    # because dateutil.parser does %m.%d.%Y and ours has %d.%m.%Y which is more logical
    parsed = datetime_parse(s)
    if parsed:
        return parsed

    try:
        # Use datetime.timezone.utc to support < Python3.9
        return default_tzinfo(
            dp.parse(s, tzinfos=tz_data, dayfirst=dayfirst, yearfirst=yearfirst),
            timezone.utc,
        )
    except dp.ParserError:
        raise WhoisUnknownDateFormatError(f"Unknown date format: {s}") from None


class WhoisEntry(dict):
    """Base class for parsing a Whois entries."""

    # regular expressions to extract domain data from whois profile
    # child classes will override this
    _regex: dict[str, str] = {
        "domain_name": r"Domain Name: *(.+)",
        "registrar": r"Registrar: *(.+)",
        "registrar_url": r"Registrar URL: *(.+)",
        "reseller": r"Reseller: *(.+)",
        "whois_server": r"Whois Server: *(.+)",
        "referral_url": r"Referral URL: *(.+)",  # http url of whois_server
        "updated_date": r"Updated Date: *(.+)",
        "creation_date": r"Creation Date: *(.+)",
        "expiration_date": r"Expir\w+ Date: *(.+)",
        "name_servers": r"Name Server: *(.+)",  # list of name servers
        "status": r"Status: *(.+)",  # list of statuses
        "emails": EMAIL_REGEX,  # list of email s
        "dnssec": r"dnssec: *([\S]+)",
        "name": r"Registrant Name: *(.+)",
        "org": r"Registrant\s*Organization: *(.+)",
        "address": r"Registrant Street: *(.+)",
        "city": r"Registrant City: *(.+)",
        "state": r"Registrant State/Province: *(.+)",
        "registrant_postal_code": r"Registrant Postal Code: *(.+)",
        "country": r"Registrant Country: *(.+)",
        "tech_name": r"Tech Name: *(.+)",
        "tech_org": r"Tech Organization: *(.+)",
        "admin_name": r"Admin Name: *(.+)",
        "admin_org": r"Admin Organization: *(.+)"
    }

    # allows for data string manipulation before casting to date
    _data_preprocessor: Optional[Callable[[str], str]] = None

    dayfirst: bool = False
    yearfirst: bool = False

    def __init__(self, domain: str, text: str, regex: Optional[dict[str, str]] = None, data_preprocessor: Optional[Callable[[str], str]] = None):
        if (
            "This TLD has no whois server, but you can access the whois database at"
            in text
        ):
            raise WhoisDomainNotFoundError(text)
        else:
            self.domain = domain
            self.text = text
            if regex is not None:
                self._regex = regex
            if data_preprocessor is not None:
                self._data_preprocessor = data_preprocessor
            self.parse()

    def parse(self) -> None:
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        for attr, regex in list(self._regex.items()):
            if regex:
                values: list[Union[str, datetime]] = []
                for data in re.findall(regex, self.text, re.IGNORECASE | re.M):
                    matches = data if isinstance(data, tuple) else [data]
                    for value in matches:
                        value = self._preprocess(attr, value)
                        if value and str(value).lower() not in [
                            str(v).lower() for v in values
                        ]:
                            # avoid duplicates
                            values.append(value)

                if values and attr in ("registrar", "whois_server", "referral_url"):
                    values = values[-1:]  # ignore junk
                if len(values) == 1:
                    self[attr] = values[0]
                elif values:
                    self[attr] = values
                else:
                    self[attr] = None

    def _preprocess(self, attr: str, value: str) -> Union[str, datetime]:
        value = value.strip()
        if value and isinstance(value, str) and not value.isdigit() and "_date" in attr:
            # try casting to date format

            # if data_preprocessor is set, use it to preprocess the data string
            if self._data_preprocessor:
                value = self._data_preprocessor(value)

            return cast_date(value, dayfirst=self.dayfirst, yearfirst=self.yearfirst)
        return value

    def __setitem__(self, name: str, value: Any) -> None:
        super(WhoisEntry, self).__setitem__(name, value)

    def __getattr__(self, name: str) -> Any:
        return self.get(name)

    def __str__(self) -> str:
        def handler(e):
            return str(e)

        return json.dumps(self, indent=2, default=handler, ensure_ascii=False)

    def __getstate__(self) -> dict:
        return self.__dict__

    def __setstate__(self, state: dict) -> None:
        self.__dict__ = state

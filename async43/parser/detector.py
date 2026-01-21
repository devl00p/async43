import re
from typing import Optional

import phonenumbers
from email_validator import validate_email, EmailNotValidError
from text_scrubber.geo import find_country_in_string


class HeuristicDetector:
    """
        Utility class providing static methods to detect and extract structured data
        (emails, phone numbers, countries) from raw text strings using heuristics.
        """
    EMAIL_CANDIDATE_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

    @staticmethod
    def detect_email(text: str) -> Optional[str]:
        """
                Searches for an email address in the given text and validates it.

                Args:
                    text: The string to scan for an email.

                Returns:
                    The validated email string if found, otherwise None.
                """
        match = HeuristicDetector.EMAIL_CANDIDATE_RE.search(text)
        if match:
            email = match.group(0).strip().rstrip('.')
            try:
                validate_email(email, check_deliverability=False)
                return email
            except EmailNotValidError:
                return None
        return None

    @staticmethod
    def detect_phone(text: str) -> Optional[str]:
        """
                Extracts the first valid phone number from a string and formats it to E.164.

                Args:
                    text: The string to scan for a phone number.

                Returns:
                    The phone number in E.164 format if a valid match is found, otherwise None.
                """
        if sum(c.isdigit() for c in text) < 5:
            return None

        # noinspection PyBroadException
        try:
            for match in phonenumbers.PhoneNumberMatcher(text, region=None):
                return phonenumbers.format_number(
                    match.number,
                    phonenumbers.PhoneNumberFormat.E164
                )
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return None

    @staticmethod
    def get_countries(lines: list[str]) -> set[str]:
        """
        Performs a first pass over multiple lines to extract unique country names.

        Args:
            lines: A list of strings (e.g., lines from a WHOIS record).

        Returns:
            A set of unique canonical country names found in the input.
        """
        countries = set()
        for line in lines:
            matches = find_country_in_string(line)
            for m in matches:
                countries.add(m.location.canonical_name)
        return countries

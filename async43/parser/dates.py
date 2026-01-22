from datetime import datetime, timezone
from typing import Optional, Union

import dateutil.parser as dp


def cast_date(date_string: str) -> Optional[Union[str, datetime]]:
    """Leverages dateutil to try to convert a date string to a datetime object"""
    if not date_string:
        return None

    try:
        parsed = dp.parse(
            date_string,
            fuzzy=True,
            dayfirst=False,
            yearfirst=True,
            default=datetime(2026, 1, 1)
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (dp.ParserError, ValueError, OverflowError):
        return date_string

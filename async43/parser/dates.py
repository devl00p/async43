from typing import Optional

import dateutil.parser as dp
from datetime import datetime, timezone


def cast_date(date_string: str) -> Optional[datetime]:
    try:
        parsed = dp.parse(date_string, fuzzy=True, dayfirst=True)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (dp.ParserError, ValueError, OverflowError):
        return None
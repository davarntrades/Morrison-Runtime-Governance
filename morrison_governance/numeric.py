"""Strict parsing of numeric fields that governance rules compare.

Tool arguments arrive from planners, JSON and HTTP bodies, so a "number" may be
an int, a float, a numeric string, or something malformed. Comparing the raw
value is unsafe in both directions:

  * a string or None raises TypeError inside a rule predicate, so the decision
    is made by error handling instead of policy, and a legitimate numeric
    string ("5000") is refused;
  * NaN compares False with everything, and True compares as 1, so a
    threshold rule can be passed silently.

`parse_number` is the single place those cases are decided. It never maps a
malformed value to 0: callers treat MALFORMED as its own, attributable
condition.
"""

from __future__ import annotations

import math
import numbers
import re
from decimal import Decimal, InvalidOperation
from typing import Optional

# Plain decimal only: no thousands separators (locale-ambiguous), no exponent,
# no currency symbols. "5,000" could mean 5000 or 5.0; refusing it is safer
# than guessing.
_DECIMAL = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)")


def parse_number(value) -> tuple[Optional[float], bool]:
    """Return (number, malformed).

    Well-formed: a finite int/float/Decimal (not bool), or a string that is a
    plain decimal after trimming whitespace. Everything else, including None,
    bool, NaN, +/-inf and non-numeric strings, is malformed: (None, True).
    """
    if isinstance(value, bool) or value is None:
        return None, True
    if isinstance(value, str):
        text = value.strip()
        if not _DECIMAL.fullmatch(text):
            return None, True
        try:
            number = float(Decimal(text))
        except (InvalidOperation, ValueError, OverflowError):
            return None, True
    elif isinstance(value, (numbers.Real, Decimal)):
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return None, True
    else:
        return None, True
    if not math.isfinite(number):
        return None, True
    return number, False


def field(state: dict, key: str, default: float) -> tuple[Optional[float], bool]:
    """Parse `state[key]`. An absent key yields (default, False): a rule that
    does not see the field is not triggered by it. A present-but-malformed
    value (including an explicit None) yields (None, True)."""
    if key not in state:
        return default, False
    return parse_number(state[key])

"""Bounded object-key selectors; never evaluate expressions or perform I/O."""
import re

MISSING = object()
_SEGMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')


def valid_selector(selector):
    return (isinstance(selector, str) and len(selector) <= 256
            and 1 <= len(selector.split('.')) <= 8
            and all(_SEGMENT.fullmatch(part) for part in selector.split('.')))


def extract(value, selector, default=MISSING):
    if not valid_selector(selector):
        return default
    for part in selector.split('.'):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value

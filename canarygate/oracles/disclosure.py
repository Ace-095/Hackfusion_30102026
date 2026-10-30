"""Narrow disclosure signatures for bounded, redacted fixture responses."""
import re


def disclosure_signals(response) -> set[str]:
    # Only scan already-bounded responses. Findings are signature names, not raw
    # body snippets or header values, so fixture evidence cannot expose secrets.
    text = response.text
    signals = set()
    if re.search(r"Traceback \(most recent call last\):", text, re.IGNORECASE):
        signals.add("stack_trace")
    if re.search(r"\bSQLSTATE\s+[A-Z0-9]{5}\b", text, re.IGNORECASE) or re.search(
        r"\bFile\s+[\"']/(?:srv|var|home)/[^\"']+[\"']\s*,\s*line\s+\d+", text, re.IGNORECASE
    ):
        signals.add("internal_error_detail")
    for header in ("server", "x-powered-by"):
        value = response.headers.get(header, "")
        if re.search(r"(?:/|\s)v?\d+\.\d+(?:\.\d+)?\b", value, re.IGNORECASE):
            signals.add("version_header")
    return signals

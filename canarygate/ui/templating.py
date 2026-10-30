"""Jinja2 environment for the local UI.

All templates, CSS and JavaScript are served from this package: the project may
not load external assets, so there are no CDN references anywhere in the UI.
"""
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.templating import Jinja2Templates

UI_ROOT = Path(__file__).resolve().parent
TEMPLATE_ROOT = UI_ROOT / "templates"
STATIC_ROOT = UI_ROOT / "static"

# Badge classes for backend enum values. Anything unknown falls back to neutral.
VERDICT_CLASSES = {
    "CONFIRMED": "badge badge-danger",
    "SUSPECTED": "badge badge-warn",
    "SAFE": "badge badge-ok",
    "INCONCLUSIVE": "badge badge-info",
    "SKIPPED": "badge badge-muted",
}
STATUS_CLASSES = {
    "SUCCESS": "badge badge-ok",
    "PARTIAL": "badge badge-warn",
    "FAILED": "badge badge-danger",
    "SKIPPED": "badge badge-muted",
    "NEEDS_MANUAL_INPUT": "badge badge-info",
    "SYNTHETIC_PREPROVISIONED": "badge badge-info",
    "BLOCKED": "badge badge-warn",
    "RECORDED": "badge badge-ok",
    "NOT_RECORDED": "badge badge-muted",
    "completed": "badge badge-ok",
    "failed": "badge badge-danger",
}


def verdict_class(value: str | None) -> str:
    return VERDICT_CLASSES.get(value or "", "badge badge-muted")


def status_class(value: str | None) -> str:
    return STATUS_CLASSES.get(value or "", "badge badge-muted")


def pretty_json(value) -> str:
    """Render backend data as indented JSON without ever inventing fields."""
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False, default=str)


def flag(value) -> str:
    """Tri-state rendering: true, false, or not recorded (None/absent)."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "not recorded"


def humanize(value: str) -> str:
    """Turn a backend key into a readable label without changing its meaning."""
    return str(value).replace("_", " ").strip()


def pct(value, total) -> int:
    if not total:
        return 0
    return int(round(value / total * 100))


def short_id(value: str | None, keep: int = 8) -> str:
    if not value:
        return "—"
    return value if len(value) <= keep else f"{value[:keep]}…"


def build_templates() -> Jinja2Templates:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_ROOT)),
        autoescape=select_autoescape(("html", "xml")),
        # Undefined template variables are a bug in the UI layer, not data.
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["verdict_class"] = verdict_class
    environment.filters["status_class"] = status_class
    environment.filters["pretty_json"] = pretty_json
    environment.filters["flag"] = flag
    environment.filters["short_id"] = short_id
    environment.filters["humanize"] = humanize
    environment.filters["pct"] = pct
    return Jinja2Templates(env=environment)


templates = build_templates()

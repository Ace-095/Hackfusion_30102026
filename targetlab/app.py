"""Deliberately vulnerable local API used to validate CanaryGate end to end.

DO NOT DEPLOY. The application models three flaws on purpose (see
``targetlab.state.FLAWS``):

* ``GET /records/{id}``          - BOLA: any authenticated account reads any record.
* ``GET /records/{id}/guarded``  - interaction flaw: one read after a rejected
                                   malformed login skips the ownership check.
* ``GET /errors/trace``          - information disclosure: synthetic stack trace.

Everything else is intentionally correct so a scanner's false positives are
observable: ``/records/{id}/secure`` enforces ownership, ``/admin/users`` denies
non-admin accounts, and ``/profile`` requires a valid credential.

Safety: requests whose Host header is not loopback are rejected, and the module
has no outbound HTTP client of any kind.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from targetlab.safety import LOOPBACK_HOSTS, assert_loopback_host, host_name
from targetlab.state import (FLAWS, LAB_ACCOUNTS, LAB_NAME, LAB_VERSION, RECORDS,
                             PRIVATE_MARKERS, TRACE_MARKER, TOKEN_TO_ACCOUNT, LabState)

__all__ = ["LOOPBACK_HOSTS", "assert_loopback_host", "create_lab_app", "host_name"]

_WWW_AUTH = {"WWW-Authenticate": "Bearer"}
# Documents the credential scheme in OpenAPI without auto-rejecting requests, so
# the handlers keep their own bounded 401 responses.
BEARER = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def _account(request: Request):
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return TOKEN_TO_ACCOUNT.get(token.strip())


def _unauthorized():
    return JSONResponse({"error": "unauthorized"}, status_code=401, headers=_WWW_AUTH)


def _forbidden():
    return JSONResponse({"error": "forbidden"}, status_code=403)


def _record(record_id):
    record = RECORDS.get(record_id)
    return None if record is None else dict(record)


def create_lab_app(state: LabState | None = None) -> FastAPI:
    """Build a fresh lab instance with clean state."""
    lab = state or LabState()
    app = FastAPI(
        title="TargetLab",
        version=LAB_VERSION,
        description=("Deliberately vulnerable local test API for CanaryGate validation. "
                     "Loopback only. Never deploy."),
    )

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        if not host_name(request.headers.get("host", "")) in LOOPBACK_HOSTS:
            return JSONResponse({"error": "non_loopback_host_rejected"}, status_code=403,
                                headers={"X-Lab-Instance": lab.instance_id})
        response = await call_next(request)
        # Operational identity only: it says which lab process answered, never
        # anything about its declared flaws.
        response.headers["X-Lab-Instance"] = lab.instance_id
        return response

    @app.get("/health", tags=["lab"])
    def health():
        return {"status": "ok", "lab": LAB_NAME, "version": LAB_VERSION,
                "deliberately_vulnerable": True, **lab.snapshot()}

    @app.post(
        "/login",
        tags=["lab"],
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["username", "password"],
                       "properties": {"username": {"type": "string"},
                                      "password": {"type": "string"}}}}}}},
    )
    async def login(request: Request):
        """Predictable credentials; a rejected malformed body leaves a legacy flag."""
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001 - any parse failure is a malformed request
            payload = None
        username = payload.get("username") if isinstance(payload, dict) else None
        if (not isinstance(payload, dict) or not isinstance(username, str)
                or not isinstance(payload.get("password"), str)
                or set(payload) - {"username", "password"}):
            # The deliberate interaction flaw lives here: a rejected malformed
            # login leaves the account in a legacy compatibility state.
            if isinstance(username, str):
                lab.mark_rejected(username)
            return JSONResponse({"error": "invalid_request"}, status_code=422)
        account = LAB_ACCOUNTS.get(username)
        if account is None or payload["password"] != account["password"]:
            lab.mark_rejected(username) if username in LAB_ACCOUNTS else None
            return JSONResponse({"error": "invalid_credentials"}, status_code=401)
        lab.clear(username)
        lab.record_login()
        return {"token": account["token"], "identity": username, "role": account["role"]}

    @app.get("/profile", tags=["lab"], dependencies=[Depends(BEARER)])
    def profile(request: Request):
        account = _account(request)
        if account is None:
            return _unauthorized()
        return {"identity": account, "role": LAB_ACCOUNTS[account]["role"]}

    @app.get("/admin/users", tags=["lab"], dependencies=[Depends(BEARER)])
    def admin_users(request: Request):
        if _account(request) is None:
            return _unauthorized()
        return _forbidden()

    @app.get("/records", tags=["records"], dependencies=[Depends(BEARER)])
    def list_records(request: Request):
        """Correct collection: every account sees only its own records.

        This is the discovery endpoint the ownership registry needs. It is
        deliberately correct so cross-account list isolation can be verified.
        """
        account = _account(request)
        if account is None:
            return _unauthorized()
        return [dict(record) for record in RECORDS.values() if record["owner"] == account]

    @app.get("/records/{record_id}", tags=["records"], dependencies=[Depends(BEARER)])
    def read_record(record_id: str, request: Request):
        """Deliberate BOLA: ownership is never checked on this route."""
        if _account(request) is None:
            return _unauthorized()
        record = _record(record_id)
        if record is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        return record

    @app.get("/records/{record_id}/secure", tags=["records"], dependencies=[Depends(BEARER)])
    def read_record_secure(record_id: str, request: Request):
        account = _account(request)
        if account is None:
            return _unauthorized()
        record = _record(record_id)
        if record is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        if record["owner"] != account:
            return _forbidden()
        return record

    @app.get("/records/{record_id}/guarded", tags=["records"], dependencies=[Depends(BEARER)])
    def read_record_guarded(record_id: str, request: Request):
        """Interaction flaw: ownership is skipped after a rejected malformed login."""
        account = _account(request)
        if account is None:
            return _unauthorized()
        record = _record(record_id)
        if record is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        if record["owner"] != account and not lab.is_compatible(account):
            return _forbidden()
        return {**record, "compat_state": lab.is_compatible(account)}

    @app.get("/errors/trace", tags=["lab"])
    def errors_trace():
        """Deliberate information disclosure with a synthetic marker."""
        return JSONResponse(
            {"error": "internal", "trace": ("Traceback (most recent call last):\n"
                                            f'  File "app.py", line 42, in handler\n'
                                            f"RuntimeError: {TRACE_MARKER}")},
            status_code=500)

    @app.get("/diagnostics/banner", tags=["lab"])
    def diagnostics_banner():
        """Harmless variation: the banner changes but nothing is granted."""
        return {"banner": "compatibility" if lab.any_compatibility() else "stable"}

    @app.get("/lab/ground-truth", tags=["lab"])
    def ground_truth():
        """Declared flaws, markers and accounts, so a scan can be scored."""
        return {"lab": LAB_NAME, "version": LAB_VERSION, "flaws": FLAWS,
                "secure_paths": ["/records/{record_id}/secure", "/admin/users"],
                "accounts": sorted(LAB_ACCOUNTS), "private_markers": PRIVATE_MARKERS}

    return app

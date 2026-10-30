"""Frontend entrypoint: the backend app plus the UI, mounted at runtime.

This module is the *only* integration point between the frontend and the
backend, and it does not modify the backend: it imports
:func:`canarygate.api.app.create_app`, extends the returned application object
in memory (one static mount, one router) and serves both surfaces from the same
process.

Run it instead of the backend module when you want the interface:

    python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000

The backend module still works on its own and is byte-identical to the backend
branch:

    python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000

Because the UI is mounted on the same FastAPI instance, the backend's lifespan
(which creates the SQLite tables) still runs exactly once, `request.app.state`
still holds the three stores, and the UI calls the same handler functions the
JSON routes use. No backend file is imported for its side effects and none is
patched.
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from canarygate.api.app import create_app as create_backend_app
from canarygate.ui.routes import router as ui_router
from canarygate.ui.templating import ASSET_VERSION, STATIC_ROOT

#: How long a *fingerprinted* asset URL may be cached. A changed file gets a
#: changed URL, so this never hides an update.
IMMUTABLE_MAX_AGE = "public, max-age=31536000, immutable"


def add_cache_policy(application: FastAPI) -> None:
    """Stop the browser from replaying a previous build of the interface.

    Two rules, both needed:

    * HTML is ``no-store``. Without it a browser may heuristically cache the
      page itself, and the visitor reloads into markup from an older run of the
      server.
    * ``/ui/static/*`` is cached forever *because* the URL carries the
      ``?v=<fingerprint>`` the templates append. Editing ``intro.css`` produces
      a new fingerprint, hence a new URL, hence a fresh download.

    The ``X-Asset-Version`` header makes the running build visible from the
    network tab, which is the fastest way to tell "my change did not apply"
    apart from "my browser is showing an old copy".
    """

    @application.middleware("http")
    async def cache_policy(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/ui/static/"):
            # Fingerprinted URL: safe to keep for a year.
            response.headers["Cache-Control"] = IMMUTABLE_MAX_AGE
        elif response.headers.get("content-type", "").startswith("text/html"):
            # The document itself is regenerated on every request.
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        else:
            # JSON and the rest: revalidate, never serve blind.
            response.headers.setdefault("Cache-Control", "no-cache")
        response.headers["X-Asset-Version"] = ASSET_VERSION
        return response


def create_ui_app(database_path: str | None = None) -> FastAPI:
    """Return the untouched backend application with the UI attached.

    ``create_backend_app`` is called without arguments when no path is supplied so
    its default (``CANARYGATE_DB_PATH`` or ``.canarygate/fixture.sqlite3``) still
    applies, exactly as when the backend runs alone.
    """
    application = create_backend_app(database_path) if database_path else create_backend_app()
    application.mount("/ui/static", StaticFiles(directory=STATIC_ROOT), name="ui-static")
    application.include_router(ui_router)
    add_cache_policy(application)
    return application


app = create_ui_app()

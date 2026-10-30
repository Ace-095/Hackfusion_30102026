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
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from canarygate.api.app import create_app as create_backend_app
from canarygate.ui.routes import router as ui_router
from canarygate.ui.templating import STATIC_ROOT


def create_ui_app(database_path: str | None = None) -> FastAPI:
    """Return the untouched backend application with the UI attached.

    ``create_backend_app`` is called without arguments when no path is supplied so
    its default (``CANARYGATE_DB_PATH`` or ``.canarygate/fixture.sqlite3``) still
    applies, exactly as when the backend runs alone.
    """
    application = create_backend_app(database_path) if database_path else create_backend_app()
    application.mount("/ui/static", StaticFiles(directory=STATIC_ROOT), name="ui-static")
    application.include_router(ui_router)
    return application


app = create_ui_app()

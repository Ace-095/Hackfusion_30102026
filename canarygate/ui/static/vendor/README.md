# Vendored assets

`htmx.min.js` — HTMX **2.0.4**, unmodified build from the published npm package
(`htmx.org@2.0.4`, `dist/htmx.min.js`). Licence: BSD 2-Clause, see
`htmx.LICENSE` in this directory.

It is vendored rather than linked so the local UI makes **no external requests**.
The project specification requires all UI assets to be served locally: no CDN, no
web fonts, no analytics.

To replace it: download the same file from the pinned npm version, keep the
licence next to it, and re-run `python -m pytest tests/integration/test_ui_pages.py`.

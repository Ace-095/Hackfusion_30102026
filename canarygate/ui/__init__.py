"""Server-rendered frontend (Jinja2 + locally vendored HTMX).

The UI is a read-mostly view layer over the existing fixture API handlers. It
adds no endpoints of its own beyond HTML routes and form actions, never invents
data, and always labels results with the backend's own ``mode`` value.
"""

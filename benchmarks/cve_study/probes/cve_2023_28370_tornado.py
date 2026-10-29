"""CVE-2023-28370 -- Tornado redirects to a protocol-relative path.

6.3.1 -> 6.3.2. ``StaticFileHandler`` appends a trailing slash by redirecting to
``self.request.path + "/"``. A path beginning with ``//`` is protocol-relative,
so the browser reads the next segment as a *hostname*: the redirect leaves the
site. 6.3.2 raises ``HTTPError(403)`` instead.

Oracle, declared before execution: the handler's own ``redirect()`` sink is
called with a target beginning ``//``. The oracle observes what the library
decided to do, captured at the sink, rather than inspecting the input the probe
supplied. Capturing the sink is not a modification of the code under test: the
decision has already been made by the time the sink is reached.

No socket is bound. The handler is constructed against a real temporary
directory, and the connection object is a stub that records nothing.
"""

from __future__ import annotations

import os
import tempfile

from ._support import pinned_version

DIST = "tornado"
MODULE = "tornado"

_HOSTILE_PATH = "//redirect-target.example"


class _Connection:
    """The minimum a RequestHandler needs to exist. It is never written to."""

    def set_close_callback(self, callback: object) -> None:
        return None


def _handler(request_path: str):
    from tornado.httputil import HTTPServerRequest
    from tornado.web import Application, StaticFileHandler

    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    with open(os.path.join(root, "sub", "index.html"), "w", encoding="utf-8") as handle:
        handle.write("index")

    request = HTTPServerRequest(method="GET", uri=request_path, connection=_Connection())
    request.path = request_path
    handler = StaticFileHandler(Application([]), request, path=root, default_filename="index.html")
    handler.path = "sub"
    captured: dict[str, str] = {}
    handler.redirect = (  # type: ignore[method-assign]
        lambda url, permanent=False, status=None: captured.setdefault("url", url)
    )
    return handler, root, captured


def _attempt(request_path: str) -> tuple[str | None, str]:
    """Return ``(redirect target or None, note)`` for one request path."""
    from tornado.web import HTTPError

    handler, root, captured = _handler(request_path)
    try:
        handler.validate_absolute_path(root, os.path.join(root, "sub"))
    except HTTPError as exc:
        return None, f"HTTPError {exc.status_code}: {exc.log_message}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return captured.get("url"), "redirect issued" if captured else "no redirect"


def liveness(ctx: dict) -> tuple[bool, str]:
    """An ordinary directory path must still redirect, and the pin must match."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    target, note = _attempt("/assets/sub")
    ok = target == "/assets/sub/"
    return ok, f"benign path -> redirect={target!r} ({note}) from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle on a single-slash path. Must NOT fire."""
    target, note = _attempt("/assets/sub")
    offsite = bool(target and target.startswith("//"))
    return offsite, f"single-slash path -> redirect={target!r} ({note})"


def exploit(ctx: dict) -> tuple[bool, str]:
    target, note = _attempt(_HOSTILE_PATH)
    offsite = bool(target and target.startswith("//"))
    return offsite, f"protocol-relative path -> redirect={target!r} ({note})"

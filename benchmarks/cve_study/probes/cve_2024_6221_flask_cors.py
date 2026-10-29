"""CVE-2024-6221 -- Flask-Cors allows private-network access by default.

4.0.2 -> 5.0.0. ``allow_private_network`` defaulted to ``True``, so a default
``CORS(app)`` answered a private-network preflight with
``Access-Control-Allow-Private-Network: true`` and invited a public web page to
reach a service on the user's own network.

Oracle, declared before execution: that response header is present with the
value ``true`` under a default ``CORS()`` configuration. A response header the
application never set, read off the response object.

The probe drives Flask's own in-process test client. Nothing binds a socket and
no address outside the process is contacted; the ``Origin`` it sends uses the
reserved ``.example`` domain.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "flask-cors"
MODULE = "flask_cors"

_HEADER = "Access-Control-Allow-Private-Network"


def _app(**cors_options: object):
    from flask import Flask
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app, **cors_options)

    @app.route("/resource")
    def resource() -> str:
        return "ok"

    return app


def _request(app, extra_headers: dict | None = None):
    headers = {"Origin": "http://caller.example"}
    headers.update(extra_headers or {})
    return app.test_client().get("/resource", headers=headers)


def liveness(ctx: dict) -> tuple[bool, str]:
    """CORS must answer an ordinary cross-origin request, and the pin must match."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    response = _request(_app())
    allowed = response.headers.get("Access-Control-Allow-Origin")
    ok = response.status_code == 200 and allowed is not None
    return ok, (
        f"benign CORS request -> {response.status_code} "
        f"Access-Control-Allow-Origin={allowed!r} from {os.path.basename(origin)}"
    )


def control(ctx: dict) -> tuple[bool, str]:
    """With the option explicitly off, the header must NOT say true on either pin.

    This is what distinguishes "the default is unsafe" from "the library always
    sends this header regardless". Without it the exploit arm would not be
    measuring the default at all.
    """
    response = _request(
        _app(allow_private_network=False),
        {"Access-Control-Request-Private-Network": "true"},
    )
    value = response.headers.get(_HEADER)
    return value == "true", f"explicitly disabled -> {_HEADER}={value!r}"


def exploit(ctx: dict) -> tuple[bool, str]:
    response = _request(
        _app(),
        {"Access-Control-Request-Private-Network": "true"},
    )
    value = response.headers.get(_HEADER)
    return value == "true", f"default CORS() -> {_HEADER}={value!r}"

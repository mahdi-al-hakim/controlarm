"""A deliberately flawed local target. Loopback only, zero credentials."""

from examples.local_target.app import (
    ALLOWLIST,
    APPROVED_TOOLS,
    MODES,
    PLACEHOLDER_TOKEN,
    Response,
    Target,
    fetch_host,
    guard_host,
    serve,
)

__all__ = [
    "ALLOWLIST",
    "APPROVED_TOOLS",
    "MODES",
    "PLACEHOLDER_TOKEN",
    "Response",
    "Target",
    "fetch_host",
    "guard_host",
    "serve",
]

"""Resolve the study's fixtures at run time. Nothing third-party is committed.

What is committed is ``fixtures.lock.json``: for every pinned distribution, the
SHA-256 of the exact artefact PyPI served. What is *not* committed is the
artefacts or the unpacked trees -- those live under ``.cache/``, which is
gitignored. A fresh clone therefore runs ``--acquire`` once and reproduces the
study; ``--check`` then reproduces the committed numbers with no network at all.

Three properties are load-bearing, and each exists because the alternative was
tried and was worse:

* **``--no-deps``.** Only the package under test is pinned, because only it is
  the independent variable. Pulling dependency trees is what turned an earlier
  version of this directory into 184 MB of other people's source code, and a
  URL-parsing differential does not become better measured by also vendoring
  ``yarl``. Support libraries a probe needs in order to import at all are
  installed **unpinned**, once, into a shared directory, and
  :attr:`Target.support_requirements` records them as what they are: scaffolding,
  not the thing under measurement.

* **The digest is verified on every run, not only on acquisition.**
  :func:`verify_lock` re-hashes each cached artefact before any measurement is
  taken. A pinned version whose bytes changed under us invalidates every number
  computed from it, and a study that noticed only at acquisition time would
  publish results attributed to code that is no longer the code that produced
  them. A mismatch raises; it never overwrites the pin.

* **A new digest is recorded, an existing one is never rewritten.** The first
  acquisition of a pin learns its hash. Every acquisition after that must agree
  with it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

__all__ = [
    "CACHE",
    "LOCKFILE",
    "acquire",
    "ensure_support",
    "load_lock",
    "pin_dir",
    "pin_key",
    "support_dir",
    "verify_lock",
]

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"
ARCHIVES = CACHE / "archives"
PINS = CACHE / "pins"
LOCKFILE = HERE / "fixtures.lock.json"


def pin_key(package: str, version: str) -> str:
    return f"{package}=={version}"


def pin_dir(package: str, version: str) -> Path:
    """The importable tree for one pin. One directory per pin, never shared."""
    return PINS / f"{package}-{version}"


def support_dir() -> Path:
    """Unpinned scaffolding, shared by every probe that needs it."""
    return CACHE / "support"


def load_lock() -> dict:
    if LOCKFILE.exists():
        return json.loads(LOCKFILE.read_text(encoding="utf-8"))
    return {}


def _save_lock(data: dict) -> None:
    LOCKFILE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pip(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pip", "--disable-pip-version-check", *args],
        capture_output=True,
        text=True,
    )


def verify_lock(keys: list[str] | None = None) -> dict[str, str]:
    """Re-hash every cached artefact against the committed lock. Raise on drift.

    Returns ``{pin: sha256}`` for the pins checked. A pin in the lock whose
    artefact is missing from the cache is reported as ``"absent"`` rather than
    raising, because that is the ordinary state of a fresh clone and the caller
    decides whether it matters.
    """
    lock = load_lock()
    wanted = keys if keys is not None else sorted(lock)
    seen: dict[str, str] = {}
    for key in wanted:
        entry = lock.get(key)
        if entry is None:
            seen[key] = "unlocked"
            continue
        archive = ARCHIVES / entry["artifact"]
        if not archive.exists():
            seen[key] = "absent"
            continue
        digest = _sha256(archive)
        if digest != entry["sha256"]:
            raise RuntimeError(
                f"{key}: cached artefact {entry['artifact']} hashes {digest} but the lock "
                f"pins {entry['sha256']}. Refusing to measure against an artefact that is "
                "not the one the committed numbers came from."
            )
        seen[key] = digest
    return seen


def _sdist_subtree(archive: Path, dest: Path, subtree: str) -> int:
    """Extract one pure-Python subtree of an sdist, plus its licence files.

    For pins with no wheel for the running interpreter whose importable package
    is nonetheless pure Python. The licence files come along deliberately: this
    unpacks someone else's released source, and doing that without the licence
    would not be acceptable even inside a gitignored cache.
    """
    count = 0
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        root = members[0].name.split("/")[0]
        prefix = f"{root}/{subtree}/"
        licences = {f"{root}/{n}" for n in ("LICENSE", "LICENCE", "COPYING", "NOTICE")}
        for member in members:
            if member.name.startswith(prefix):
                rel = member.name[len(prefix) :]
            elif member.name in licences:
                rel = member.name.split("/", 1)[1]
            else:
                continue
            if not rel:
                continue
            target = dest / rel
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            source = tf.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
            count += 1
    if not count:
        raise RuntimeError(f"{archive.name} has no subtree {subtree!r}")
    return count


def acquire(package: str, version: str, *, sdist_subtree: str | None = None) -> dict:
    """Fetch one pin into the cache, lock its digest, and install it with no deps."""
    lock = load_lock()
    key = pin_key(package, version)
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    staging = CACHE / "_dl" / f"{package}-{version}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    download = ["download", "--no-deps", "-d", str(staging), key]
    if sdist_subtree is not None:
        download += ["--no-binary", ":all:", "--no-build-isolation"]
    got = _pip(download)
    if got.returncode != 0:
        raise RuntimeError(f"pip download failed for {key}:\n{got.stdout}\n{got.stderr}")
    candidates = sorted(p for p in staging.iterdir() if p.is_file())
    if not candidates:
        raise RuntimeError(f"pip download produced no artefact for {key}")
    archive = candidates[0]
    digest = _sha256(archive)

    recorded = lock.get(key, {}).get("sha256")
    if recorded and recorded != digest:
        raise RuntimeError(
            f"{key} hashed {digest} but the lock pins {recorded}. A pinned artefact's bytes "
            "changed, which invalidates every number computed from it. Refusing to overwrite."
        )

    kept = ARCHIVES / archive.name
    shutil.copy2(archive, kept)

    dest = pin_dir(package, version)
    if dest.exists():
        shutil.rmtree(dest)
    if sdist_subtree is not None:
        files = _sdist_subtree(kept, dest, sdist_subtree)
        how = f"sdist subtree {sdist_subtree!r} ({files} files)"
    else:
        put = _pip(["install", "--no-deps", "--no-compile", "--target", str(dest), key])
        if put.returncode != 0:
            raise RuntimeError(f"pip install failed for {key}:\n{put.stdout}\n{put.stderr}")
        how = "pip install --no-deps --target"

    entry = {
        "package": package,
        "version": version,
        "artifact": archive.name,
        "sha256": digest,
        "installed_by": how,
    }
    lock[key] = entry
    _save_lock(lock)
    shutil.rmtree(staging, ignore_errors=True)
    return entry


def ensure_support(requirements: list[str]) -> Path:
    """Install the unpinned scaffolding a probe needs in order to import.

    These are deliberately **not** pinned and deliberately **not** locked: they
    are not the independent variable, and pinning them would invite a reader to
    think the study is measuring them. The one thing that must hold is that the
    pin under test shadows any copy of itself that arrives here, which every
    probe's liveness arm asserts by checking the version it actually imported.
    """
    dest = support_dir()
    if not requirements:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    missing = sorted(set(requirements))
    put = _pip(["install", "--no-compile", "--target", str(dest), *missing])
    if put.returncode != 0:
        raise RuntimeError(f"pip install of support libraries failed:\n{put.stdout}\n{put.stderr}")
    return dest

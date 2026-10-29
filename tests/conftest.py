"""Put the repository root on ``sys.path`` so ``benchmarks`` and ``examples`` import.

``pyproject.toml`` adds ``src`` for the package itself. The benchmark and the
example target deliberately live outside the package -- a benchmark that ships
inside the thing it measures is harder for a reviewer to trust -- so they need
the root as well.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

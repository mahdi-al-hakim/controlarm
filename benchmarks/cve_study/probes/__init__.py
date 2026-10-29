"""One module per CVE. Each exposes ``liveness``, ``control`` and ``exploit``.

Every probe obeys the same contract, and the contract is the point:

``liveness(ctx) -> (bool, str)``
    Must succeed. Confirms the target works at all AND that the pin the
    study believes it imported is the pin it actually imported. A run whose
    liveness arm fails is ``VOID``, which is what stops a broken rig from
    being reported as a clean target.

``control(ctx) -> (bool, str)``
    Must be refused, i.e. must return ``False``. The same oracle applied to
    benign input: it proves the oracle discriminates rather than firing
    unconditionally. Rule C6 of ``SELECTION_RULE.md``.

``exploit(ctx) -> (bool, str)``
    ``True`` iff the mechanical oracle declared in ``targets.py`` observed
    the vulnerable behaviour.

No probe imports its target at module level: the import must happen inside
the subprocess that has the right pin at the front of ``sys.path``.
"""

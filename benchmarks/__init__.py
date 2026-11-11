"""The measurement. Three claims, one scorer, results committed to the tree.

``gates.py`` is the thing measured, ``fp_corpus/`` is the ground truth,
``scoring.py`` does the arithmetic, ``oracle_experiment.py`` runs the one
experiment that separates the target from the oracle, and
``run_benchmark.py --check`` fails if any committed number has moved.
"""

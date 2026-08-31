"""
scenario_m6.py  --  Scenario with deterministic and non-deterministic tasks (M6).

Extends the M4 generator with a determinism flag on records tasks. A
fraction of honest records summaries carry a free-text clinical note that
varies each time the task runs, so their output is non-deterministic. This
is the condition that separates V1 from V2: V1 cannot verify a varying
output, V2 verifies the procedure regardless.

Everything is synthetic and seeded (Data Protection Act 2018).
"""

import random

from scenario import make_patients, make_task_stream  # reuse M4 base


def add_determinism(tasks, nondeterministic_fraction, seed):
    """Mark a fraction of records tasks as non-deterministic. Schedule
    tasks and attacks are left as they are: the flag only affects how an
    honest records summary is produced."""
    rng = random.Random(seed + 7)
    for task in tasks:
        if task["kind"] == "records":
            task["deterministic"] = rng.random() >= nondeterministic_fraction
        else:
            task["deterministic"] = True
    return tasks


def build_scenario(n_tasks, n_patients, attack_rate, nondet_fraction, seed):
    """Patients, a labelled task stream, and the determinism flags, all
    from one seed so the whole scenario is reproducible."""
    patients = make_patients(n_patients, seed)
    tasks = make_task_stream(n_tasks, attack_rate, seed, patients)
    tasks = add_determinism(tasks, nondet_fraction, seed)
    return patients, tasks

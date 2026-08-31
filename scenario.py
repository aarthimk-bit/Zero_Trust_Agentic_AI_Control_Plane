"""
scenario.py  --  Synthetic scenario generator (Milestone M4).

Implements Chapter 3, sections 3.9 and 3.10: fifty synthetic patients,
a seeded stream of two hundred delegated tasks, and attack episodes
injected at known points so that every metric has ground truth.

Everything here is synthetic and generated in code: no real names, no
real records, no personal data (Data Protection Act 2018).

Why seeding matters: random.Random(seed) makes the "random" stream
repeatable. The same seed always produces the same patients, the same
task order, and the same attack positions, so an experiment can be rerun
and checked, and Chapter 5 can report results others could reproduce.
"""

import random

# A tiny synthetic formulary. Medication lists are drawn from this.
FORMULARY = [
    "Aspirin 75mg", "Metformin 500mg", "Amoxicillin 250mg",
    "Atorvastatin 20mg", "Lisinopril 10mg", "Salbutamol inhaler",
    "Omeprazole 20mg", "Levothyroxine 50mcg",
]

APPOINTMENT_SLOTS = ["09:00", "10:30", "14:00", "15:30"]


def make_patients(n_patients: int, seed: int) -> dict:
    """The synthetic Records API: patient id -> sorted medication list.
    Sorted, so that the honest summary is deterministic (V1 needs that)."""
    rng = random.Random(seed)
    return {
        f"SYN-{i:04d}": sorted(rng.sample(FORMULARY, rng.randint(1, 4)))
        for i in range(1, n_patients + 1)
    }


def make_task_stream(n_tasks: int, attack_rate: float, seed: int, patients: dict) -> list:
    """A labelled task stream. Labels are the ground truth:
       normal | unauth_access | excess_priv | task_mismatch.
    The attack budget is split evenly across the three attack cases and
    the positions are shuffled with the seeded generator, so attacks land
    at known but scattered points."""
    rng = random.Random(seed + 1)  # separate stream from patient generation
    ids = list(patients)

    n_attacks = round(n_tasks * attack_rate)
    per_case = n_attacks // 3
    labels = (["unauth_access"] * per_case
              + ["excess_priv"] * per_case
              + ["task_mismatch"] * (n_attacks - 2 * per_case))
    labels += ["normal"] * (n_tasks - len(labels))
    rng.shuffle(labels)

    tasks = []
    for i, label in enumerate(labels, start=1):
        # Excessive privilege is a scheduler behaviour; the other two
        # attack cases belong to the records agent. Normal work is a mix.
        if label == "excess_priv":
            kind = "schedule"
        elif label in ("unauth_access", "task_mismatch"):
            kind = "records"
        else:
            kind = "records" if rng.random() < 0.6 else "schedule"

        task = {
            "task_id": f"T-{i:04d}",
            "kind": kind,
            "label": label,
            "patient": rng.choice(ids),
        }
        if kind == "schedule":
            # The slot is set by the delegator, so the expected booking is
            # fully determined at commitment time (V1 needs determinism).
            task["slot"] = f"2026-08-{rng.randint(1, 28):02d} {rng.choice(APPOINTMENT_SLOTS)}"
        if label == "unauth_access":
            task["wrong_patient"] = rng.choice([p for p in ids if p != task["patient"]])
        tasks.append(task)
    return tasks

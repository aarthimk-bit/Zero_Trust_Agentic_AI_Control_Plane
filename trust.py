"""
trust.py  --  Dynamic trust engine (Milestone M5).

Chapter 3, section 3.8. Every agent carries a score in [0, 1], initialised
at 0.70. The update rule is asymmetric by design, which is the behavioural
counterpart of least privilege: trust is earned slowly and lost quickly.

    verified, compliant task     score = min(1.0, score + 0.02)
    flagged event                score = score * 0.8
    verified violation           score = score * 0.7

Tiers convert the score into authority (enforced by the policy engine):

    score >= 0.70   full permitted set (including writes)
    0.40 - 0.70     reads and delegation only; writes withheld
    score <  0.40   quarantined: every request blocked pending review

Because the score is read at step 3 of every decision, a lying agent's
authority contracts within a bounded number of interactions after its
first detected mismatch. The experiment measures that bound as
time-to-quarantine (Table 3.5).

In M2 to M4 this store held a static score. M5 adds the update rules and
the history needed to measure time-to-quarantine. The interface
(score, set_score) is unchanged, so earlier code keeps working.
"""

QUARANTINE = 0.40   # below this, all requests are blocked
WRITE_TIER = 0.70   # at or above this, writes are permitted


class TrustStore:
    DEFAULT = 0.7

    # Update constants, named so the dissertation and the code agree.
    REWARD = 0.02       # additive gain on a verified, compliant task
    FLAG_FACTOR = 0.8   # multiplicative penalty on a flagged event
    VIOLATION_FACTOR = 0.7  # multiplicative penalty on a verified violation

    def __init__(self):
        self._scores = {}
        # Per-agent count of tasks handled since start, used to express
        # time-to-quarantine as "interactions after the first violation".
        self._interactions = {}
        self._first_violation_at = {}   # agent_id -> interaction index
        self._quarantined_at = {}       # agent_id -> interaction index

    # ---- read / write (unchanged interface) ----
    def score(self, agent_id: str) -> float:
        return self._scores.get(agent_id, self.DEFAULT)

    def set_score(self, agent_id: str, value: float) -> None:
        self._scores[agent_id] = max(0.0, min(1.0, value))

    def is_quarantined(self, agent_id: str) -> bool:
        return self.score(agent_id) < QUARANTINE

    # ---- the update rules (new in M5) ----
    def _apply(self, agent_id: str, new_value: float, event: str) -> None:
        before = self.score(agent_id)
        self.set_score(agent_id, new_value)
        after = self.score(agent_id)
        self._interactions[agent_id] = self._interactions.get(agent_id, 0) + 1
        idx = self._interactions[agent_id]
        if event == "violation" and agent_id not in self._first_violation_at:
            self._first_violation_at[agent_id] = idx
        if after < QUARANTINE and agent_id not in self._quarantined_at:
            self._quarantined_at[agent_id] = idx

    def reward(self, agent_id: str) -> None:
        self._apply(agent_id, self.score(agent_id) + self.REWARD, "reward")

    def penalise_flag(self, agent_id: str) -> None:
        self._apply(agent_id, self.score(agent_id) * self.FLAG_FACTOR, "flag")

    def penalise_violation(self, agent_id: str) -> None:
        self._apply(agent_id, self.score(agent_id) * self.VIOLATION_FACTOR, "violation")

    # ---- metric: interactions from first violation to quarantine ----
    def time_to_quarantine(self, agent_id: str):
        """Interactions between an agent's first violation and the point
        its score first fell below the quarantine threshold. None if the
        agent never violated or never crossed the threshold."""
        first = self._first_violation_at.get(agent_id)
        quar = self._quarantined_at.get(agent_id)
        if first is None or quar is None:
            return None
        return quar - first

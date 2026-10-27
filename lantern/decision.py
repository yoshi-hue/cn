"""Alert and Decision Manager (report section 5.2, component 9).

Receives alerts from every detector, suppresses repeats, assigns an action, and
decides which detector is permitted to actuate.

That last responsibility is the one that makes or breaks the experiment. If
both detectors install drop rules, whichever fires first destroys the traffic
the other still needed to observe, and the detection comparison measures the
race rather than the detectors. Detection-comparison runs therefore use
mitigator mode "none": both detectors score, neither blocks.
"""

import time
import uuid

from lantern import config
from lantern.alerts import (
    CLASS_BRUTEFORCE,
    CLASS_DOS,
    CLASS_GRAPH_ANOMALY,
    CLASS_LATERAL,
    CLASS_PORTSCAN,
    SEVERITY_HIGH,
)

ACTION_DROP_SOURCE = "drop_source"
ACTION_DROP_PAIR = "drop_pair"
ACTION_REDIRECT = "redirect"
ACTION_LOG_ONLY = "log_only"


class Decision:
    """An alert plus what should be done about it."""

    def __init__(self, alert, action, reason, actuate):
        self.decision_id = uuid.uuid4().hex
        self.decided_mono = time.monotonic()
        self.decided_wall = time.time()
        self.alert = alert
        self.action = action
        self.reason = reason
        self.actuate = actuate  # False => recorded for analysis, not installed

    def to_dict(self):
        return {
            "action": self.action,
            "actuate": self.actuate,
            "reason": self.reason,
            "alert": self.alert.to_dict(),
        }


class AlertManager:
    """Deduplicates alerts, chooses actions, and gates actuation."""

    def __init__(self, mitigator=None, cfg=config, clock=None, on_decision=None,
                 policy=None):
        mitigator = mitigator or cfg.DEFAULT_MITIGATOR
        if mitigator not in cfg.MITIGATOR_MODES:
            raise ValueError(
                "mitigator must be one of %s, got %r" % (cfg.MITIGATOR_MODES, mitigator)
            )
        self.mitigator = mitigator
        self.cfg = cfg
        self.clock = clock
        self.on_decision = on_decision
        self.policy = policy or "class"
        if self.policy not in cfg.MITIGATION_POLICY_MODES:
            raise ValueError("unknown mitigation policy: %s" % self.policy)

        self._last_alert_at = {}  # dedupe_key -> ts
        self.suppressed_count = 0
        self.alert_count = 0

    # ------------------------------------------------------------------

    def may_actuate(self, detector_name):
        """Is this detector allowed to install rules in the current mode?"""
        if self.mitigator == "none":
            return False
        if self.mitigator == "both":
            return True
        return self.mitigator == detector_name

    def submit(self, alerts):
        """Process a batch of alerts; returns the Decisions that survived."""
        decisions = []
        for alert in alerts:
            decision = self._submit_one(alert)
            if decision is not None:
                decisions.append(decision)
        return decisions

    def _submit_one(self, alert):
        now = alert.ts if self.clock is None else self.clock()

        # Suppress repeats of an ongoing event. Without this, a port scan
        # spanning six windows produces six identical alerts, which would
        # inflate the alert count and distort precision.
        previous = self._last_alert_at.get(alert.dedupe_key)
        if previous is not None and (now - previous) < self.cfg.ALERT_COOLDOWN_SECONDS:
            self.suppressed_count += 1
            return None
        self._last_alert_at[alert.dedupe_key] = now

        self.alert_count += 1
        action, reason = self._choose_action(alert)
        decision = Decision(
            alert=alert,
            action=action,
            reason=reason,
            actuate=self.may_actuate(alert.detector),
        )
        if self.on_decision is not None:
            self.on_decision(decision)
        return decision

    # ------------------------------------------------------------------

    def _choose_action(self, alert):
        """Pick a mitigation action proportionate to the alert.

        Blocking the source host outright is the heaviest available response,
        so it is reserved for behaviour that is about the source itself
        (scanning, lateral movement). A brute-force or DoS alert names a
        specific victim, so blocking just that pair contains the attack without
        cutting the source off from services it may legitimately be using --
        which is what the legitimate-traffic disruption metric measures.
        """
        if self.policy == "source":
            return ACTION_DROP_SOURCE, "scope policy: source-wide block"
        if self.policy == "pair":
            if alert.dst_ip:
                return ACTION_DROP_PAIR, "scope policy: pair-only block"
            return ACTION_LOG_ONLY, "scope policy: pair-only cannot name a victim"

        policy_action = self.cfg.MITIGATION_POLICY.get(alert.attack_class)
        if policy_action == ACTION_LOG_ONLY:
            return ACTION_LOG_ONLY, "equivalent policy: log-only for structural anomaly"
        if policy_action == ACTION_DROP_SOURCE:
            return (
                ACTION_DROP_SOURCE,
                "equivalent policy: source-wide block for source-implicating behaviour",
            )

        if policy_action == ACTION_DROP_PAIR or alert.attack_class in (CLASS_BRUTEFORCE, CLASS_DOS):
            if alert.dst_ip:
                return (
                    ACTION_DROP_PAIR,
                    "pair block: the attack names a specific victim",
                )
            return (
                ACTION_DROP_SOURCE,
                "source-wide block: no specific victim identified",
            )

        if alert.attack_class == CLASS_GRAPH_ANOMALY:
            # The graph detector saw a host's communication structure change
            # sharply but could not say it was lateral movement. That is a
            # real signal and worth an analyst's attention, but it is not a
            # confident enough identification to cut a host off the network on
            # its own -- so it is recorded unless the score was extreme.
            if alert.severity == SEVERITY_HIGH:
                return (
                    ACTION_DROP_SOURCE,
                    "structural anomaly well above threshold",
                )
            return (
                ACTION_LOG_ONLY,
                "structural anomaly without a lateral-movement signature",
            )

        if alert.severity == SEVERITY_HIGH:
            return (ACTION_DROP_SOURCE, "high severity, unclassified")
        return (ACTION_LOG_ONLY, "insufficient confidence to actuate")

    # ------------------------------------------------------------------

    def snapshot(self):
        return {
            "mitigator": self.mitigator,
            "policy": self.policy,
            "alerts": self.alert_count,
            "suppressed": self.suppressed_count,
        }

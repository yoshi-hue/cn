"""Mitigation engine (Algorithm D, report section 5.7).

Converts a Decision into an installed OpenFlow rule, and measures how long that
actually took.

The measurement is the point. Most of the surveyed literature reports classifier
accuracy and stops; Research Gap 4 is that almost nobody measures the time from
alert to *installed* rule. So this module does not time the send -- it sends a
FlowMod, immediately follows it with an OFPBarrierRequest, and treats the
BarrierReply as the moment the switch confirms the rule exists. A send-time
measurement would silently report the controller's own latency and call it the
mitigation latency.
"""

from lantern import config
from lantern.decision import (
    ACTION_DROP_PAIR,
    ACTION_DROP_SOURCE,
    ACTION_LOG_ONLY,
    ACTION_REDIRECT,
)


class InstalledRule:
    def __init__(self, dpid, action, match_description, sent_at, cookie):
        self.dpid = dpid
        self.action = action
        self.match_description = match_description
        self.sent_at = sent_at
        self.confirmed_at = None
        self.cookie = cookie

    @property
    def install_latency(self):
        if self.confirmed_at is None:
            return None
        return self.confirmed_at - self.sent_at

    def to_dict(self):
        return {
            "dpid": self.dpid,
            "action": self.action,
            "match": self.match_description,
            "sent_at": self.sent_at,
            "confirmed_at": self.confirmed_at,
            "install_latency": self.install_latency,
            "cookie": self.cookie,
        }


class MitigationEngine:
    """Installs and tracks OpenFlow mitigation rules."""

    def __init__(self, logger, clock, cfg=config, on_event=None):
        self.logger = logger
        self.clock = clock
        self.cfg = cfg
        self.on_event = on_event or (lambda kind, payload: None)

        self._datapaths = {}
        self._pending_barriers = {}  # (dpid, xid) -> InstalledRule
        self.installed = []
        self._next_cookie = 0x10000

    def register(self, datapath):
        self._datapaths[datapath.id] = datapath

    def unregister(self, dpid):
        self._datapaths.pop(dpid, None)

    @property
    def rule_count(self):
        """Currently active mitigation rules; hardware TCAM is not measured."""
        return sum(rule.active for rule in self.installed)

    # ------------------------------------------------------------------

    def apply(self, decision):
        """Algorithm D: turn a decision into rules on every switch.

        The rule is installed on *every* switch rather than only the one that
        reported the traffic. A host blocked at one switch but not another is
        not contained -- it can still reach anything on the other switch, which
        for lateral movement is precisely the traffic that matters.
        """
        if not decision.actuate or decision.action == ACTION_LOG_ONLY:
            return []

        if decision.action == ACTION_REDIRECT:
            raise ValueError("redirect mitigation is not implemented")
        alert = decision.alert
        self.on_event(
            "mitigation_targeted",
            {
                "decision_id": decision.decision_id,
                "alert_id": alert.alert_id,
                "switches": sorted(self._datapaths),
                "decided_mono": decision.decided_mono,
            },
        )
        rules = []
        for datapath in list(self._datapaths.values()):
            rule = self._install(datapath, decision, alert)
            if rule is not None:
                rules.append(rule)
        return rules

    def _install(self, datapath, decision, alert):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match_fields = {"eth_type": 0x0800, "ipv4_src": alert.src_ip}
        description = "ipv4_src=%s" % alert.src_ip

        if decision.action in (ACTION_DROP_PAIR, ACTION_REDIRECT) and alert.dst_ip:
            match_fields["ipv4_dst"] = alert.dst_ip
            description += ",ipv4_dst=%s" % alert.dst_ip
            if alert.protocol and alert.dst_port:
                match_fields["ip_proto"] = alert.protocol
                if alert.protocol == 6:
                    match_fields["tcp_dst"] = alert.dst_port
                elif alert.protocol == 17:
                    match_fields["udp_dst"] = alert.dst_port
                description += ",dst_port=%s" % alert.dst_port
        elif decision.action != ACTION_DROP_SOURCE:
            return None

        # An empty action list is how OpenFlow expresses "drop".
        actions = []

        cookie = self._next_cookie
        self._next_cookie += 1

        sent_at = self.clock()
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie,
                priority=self.cfg.MITIGATION_PRIORITY,
                match=parser.OFPMatch(**match_fields),
                instructions=[
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
                ],
                idle_timeout=self.cfg.MITIGATION_IDLE_TIMEOUT,
                hard_timeout=self.cfg.MITIGATION_HARD_TIMEOUT,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
            )
        )

        rule = InstalledRule(
            dpid=datapath.id,
            action=decision.action,
            match_description=description,
            sent_at=sent_at,
            cookie=cookie,
        )
        rule.decision_id = decision.decision_id
        rule.alert_id = alert.alert_id
        rule.active = True
        self.installed.append(rule)

        # The barrier is what converts "we sent a FlowMod" into "the switch has
        # the rule". Its reply timestamp is the honest end of the mitigation path.
        barrier = parser.OFPBarrierRequest(datapath)
        datapath.send_msg(barrier)
        self._pending_barriers[(datapath.id, barrier.xid)] = rule

        self.on_event(
            "flowmod_sent",
            {
                "decision_id": decision.decision_id,
                "alert_id": alert.alert_id,
                "ts": sent_at,
                "dpid": datapath.id,
                "action": decision.action,
                "match": description,
                "detector": alert.detector,
                "attack_class": alert.attack_class,
                "cookie": cookie,
            },
        )
        self.logger.info(
            "MITIGATE [%s] %s -> %s on switch %016x",
            alert.detector,
            alert.attack_class,
            description,
            datapath.id,
        )
        return rule

    # ------------------------------------------------------------------

    def handle_barrier_reply(self, msg):
        """Record the moment a switch confirmed the rule is in place."""
        key = (msg.datapath.id, msg.xid)
        rule = self._pending_barriers.pop(key, None)
        if rule is None:
            return None

        rule.confirmed_at = self.clock()
        self.on_event(
            "barrier_reply",
            {
                "decision_id": rule.decision_id,
                "alert_id": rule.alert_id,
                "ts": rule.confirmed_at,
                "dpid": rule.dpid,
                "cookie": rule.cookie,
                "install_latency": rule.install_latency,
                "match": rule.match_description,
            },
        )
        return rule

    def handle_flow_removed(self, msg):
        for rule in self.installed:
            if rule.dpid == msg.datapath.id and rule.cookie == msg.cookie:
                rule.active = False
                self.on_event(
                    "mitigation_expired",
                    {
                        "cookie": rule.cookie,
                        "dpid": rule.dpid,
                        "decision_id": rule.decision_id,
                    },
                )

    def blocked_matches(self):
        """Every match currently installed, for the disruption analysis."""
        return [rule.to_dict() for rule in self.installed if rule.active]

    def snapshot(self):
        confirmed = [r for r in self.installed if r.confirmed_at is not None]
        latencies = [r.install_latency for r in confirmed]
        return {
            "rules_installed": len(self.installed),
            "active_mitigation_rules": self.rule_count,
            "rules_confirmed": len(confirmed),
            "mean_install_latency": (
                sum(latencies) / len(latencies) if latencies else None
            ),
        }

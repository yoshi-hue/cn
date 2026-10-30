"""LanternIDS -- the Ryu application (report section 5.2).

Wires the ten architectural components into one control loop:

    Mininet -> OpenFlow switches -> PacketIn + FlowStats
        -> FlowCollector -> WindowAggregator
            -> BaselineDetector  ]  same Window object, so neither detector
            -> GraphDetector     ]  can see traffic the other cannot
                -> AlertManager -> MitigationEngine -> OpenFlow FlowMod
                    -> EventLog (timing, overhead, disruption)

Run with:
    ryu-manager lantern/app.py

configured through the environment (see SETTINGS below):
    LANTERN_LOG, LANTERN_MITIGATOR, LANTERN_CASE, LANTERN_TRIAL
"""

import os
import signal
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from lantern import config
from lantern.collector import FlowCollector
from lantern.decision import AlertManager
from lantern.detector_baseline import BaselineDetector
from lantern.detector_graph import GraphDetector
from lantern.detector_hybrid import HybridDetector
from lantern.graph_builder import GraphBuilder
from lantern.features import summarise_window
from lantern.metrics import EventLog, ResourceSampler
from lantern.mitigation import MitigationEngine

# Run configuration arrives through the environment rather than through Ryu's
# own CLI. ryu-manager parses its command line *before* it imports application
# modules, so options an app registers at import time are rejected as unknown
# arguments; the documented escape hatch (--user-flags) would mean carrying a
# second file whose only job is to declare four strings. The runner launches
# this process, so it sets the environment directly.
SETTINGS = {
    "log": os.environ.get("LANTERN_LOG", "results/raw/live.jsonl"),
    "mitigator": os.environ.get("LANTERN_MITIGATOR", config.DEFAULT_MITIGATOR),
    "case": os.environ.get("LANTERN_CASE", "adhoc"),
    "trial": int(os.environ.get("LANTERN_TRIAL", "0")),
    "detector_mode": os.environ.get("LANTERN_DETECTOR_MODE", "both"),
    "policy": os.environ.get("LANTERN_POLICY", "class"),
}


class LanternIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LanternIDS, self).__init__(*args, **kwargs)

        self.epoch = time.monotonic()
        self.wall_epoch = time.time()
        self.event_log = EventLog(SETTINGS["log"], epoch=self.epoch)
        self._closed = False
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        self.mac_to_port = {}
        self.datapaths = {}

        self.collector = FlowCollector(
            logger=self.logger,
            clock=self.clock,
            epoch=0.0,  # collector clock is already run-relative
            on_window_closed=self.on_window_closed,
        )
        self.baseline = BaselineDetector()
        self.graph_builder = GraphBuilder()
        self.graph = GraphDetector(self.graph_builder)
        self.hybrid = HybridDetector(self.baseline, self.graph)
        self.mitigation = MitigationEngine(
            logger=self.logger, clock=self.clock, on_event=self.event_log.write
        )
        self.alerts = AlertManager(
            mitigator=SETTINGS["mitigator"],
            clock=self.clock,
            on_decision=self._log_decision,
            policy=SETTINGS["policy"],
        )
        self.sampler = ResourceSampler(
            self.event_log, extra_snapshot=self._overhead_snapshot
        )

        self.event_log.write(
            "run_start",
            {
                "case": SETTINGS["case"],
                "trial": SETTINGS["trial"],
                "mitigator": self.alerts.mitigator,
                "window_seconds": config.WINDOW_SECONDS,
                "poll_interval": config.POLL_INTERVAL_SECONDS,
                "graph_threshold": config.GRAPH_SCORE_THRESHOLD,
                "graph_weights": config.GRAPH_WEIGHTS,
                "profile_warmup_windows": config.PROFILE_WARMUP_WINDOWS,
                "detector_mode": SETTINGS["detector_mode"],
                "mitigation_policy": config.MITIGATION_POLICY_NAME,
                "policy": SETTINGS["policy"],
                "topology_size": len(config.HOSTS),
                "profile_alpha": config.PROFILE_ALPHA,
            },
        )
        self.logger.info(
            "Lantern started: case=%s trial=%s mitigator=%s log=%s",
            SETTINGS["case"],
            SETTINGS["trial"],
            self.alerts.mitigator,
            SETTINGS["log"],
        )

        self.collector.start()
        self.sampler.start(hub.spawn)

    # ------------------------------------------------------------------
    # Clock
    # ------------------------------------------------------------------

    def clock(self):
        """Run-relative monotonic seconds; every timestamp in the log uses it."""
        return time.monotonic() - self.epoch

    # ------------------------------------------------------------------
    # Switch lifecycle
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.datapaths[datapath.id] = datapath
        self.collector.register(datapath)
        self.mitigation.register(datapath)

        # Table miss -> controller, with the full packet (not just the header),
        # because the collector needs the IP and TCP layers to build a record.
        self._add_flow(
            datapath,
            priority=0,
            match=parser.OFPMatch(),
            actions=[
                parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                )
            ],
        )
        self.logger.info("switch %016x connected", datapath.id)
        self.event_log.write("switch_connected", {"dpid": datapath.id})

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == DEAD_DISPATCHER and datapath.id in self.datapaths:
            del self.datapaths[datapath.id]
            self.collector.unregister(datapath.id)
            self.mitigation.unregister(datapath.id)
            self.event_log.write("switch_disconnected", {"dpid": datapath.id})

    def _add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
        buffer_id=None,
    ):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ],
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    # ------------------------------------------------------------------
    # PacketIn: forwarding + collection
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Detection first: a packet that is about to be dropped by a mitigation
        # rule still happened, and the record of it belongs in the window.
        self.collector.handle_packet_in(msg)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = self._forwarding_match(parser, pkt, eth, in_port)
            if match is not None:
                # Microflow rules, not L2 rules, are installed deliberately.
                #
                # An L2-only rule (match on MAC pair) would mean that after the
                # first packet between two hosts, every subsequent connection
                # between them -- every new port a scanner touches, every login
                # retry -- is forwarded by the switch without the controller
                # ever seeing it. Port-scan and brute-force detection would be
                # blind by construction.
                #
                # The cost is more PacketIn events and more flow-table entries.
                # That cost is not hidden: it is exactly the controller overhead
                # and TCAM usage this project sets out to measure (Gap 4).
                self._add_flow(
                    datapath,
                    priority=config.LEARNING_SWITCH_PRIORITY,
                    match=match,
                    actions=actions,
                    idle_timeout=10,
                )

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
        )

    @staticmethod
    def _forwarding_match(parser, pkt, eth, in_port):
        """Build the narrowest match that still forwards this conversation.

        IPv4 traffic gets a 5-tuple match so that each new port is a new flow
        and therefore a new PacketIn. Everything else falls back to L2.
        """
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)

        fields = {
            "in_port": in_port,
            "eth_type": ether_types.ETH_TYPE_IP,
            "ipv4_src": ip.src,
            "ipv4_dst": ip.dst,
            "ip_proto": ip.proto,
        }
        segment = pkt.get_protocol(tcp.tcp)
        if segment is not None:
            fields["tcp_src"] = segment.src_port
            fields["tcp_dst"] = segment.dst_port
        else:
            datagram = pkt.get_protocol(udp.udp)
            if datagram is not None:
                fields["udp_src"] = datagram.src_port
                fields["udp_dst"] = datagram.dst_port
        return parser.OFPMatch(**fields)

    # ------------------------------------------------------------------
    # Flow statistics
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.collector.handle_flow_stats_reply(ev.msg)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        self.collector.handle_flow_removed(ev.msg)
        self.mitigation.handle_flow_removed(ev.msg)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        self.mitigation.handle_barrier_reply(ev.msg)

    # ------------------------------------------------------------------
    # The detection loop
    # ------------------------------------------------------------------

    def on_window_closed(self, window):
        """Score one closed window with both detectors and act on the result."""
        self.event_log.write("window_closed", summarise_window(window))

        warming_up = self.graph_builder.warming_up
        eligible = [h for h in window.hosts if self.graph_builder.profile_for(h).ready]
        mode = SETTINGS["detector_mode"]
        if mode == "hybrid":
            baseline_alerts = []
            graph_alerts = self.hybrid.detect(window)
        else:
            baseline_alerts = self.baseline.detect(window)
            graph_alerts = self.graph.detect(window)

        timing = {"baseline_seconds": round(self.baseline.last_compute_seconds, 6)}
        timing.update(self.graph.timing_snapshot())
        if mode == "hybrid":
            timing.update(self.hybrid.timing_snapshot())
        timing["window_index"] = window.index
        timing["hosts"] = len(window.active_hosts())
        timing["complete_window"] = window.end <= self.clock()
        timing["warming_up"] = warming_up
        timing["window_start_wall"] = self.wall_epoch + window.start
        timing["window_end_wall"] = self.wall_epoch + window.end
        timing["eligible_hosts"] = eligible if not warming_up else []
        timing["baseline_features"] = {
            "PORTSCAN_PORTS": max(
                [len(h.initiated_ports) for h in window.hosts.values()] or [0]
            ),
            "PORTSCAN_HOSTS": max(
                [len(h.initiated_hosts) for h in window.hosts.values()] or [0]
            ),
            "DOS_PPS": max(
                [p.packets / window.seconds for p in window.pairs.values()] or [0]
            ),
            "BRUTEFORCE_ATTEMPTS": max(
                [v for h in window.hosts.values() for v in h.auth_attempts.values()]
                or [0]
            ),
        }
        self.event_log.write("detector_timing", timing)

        for alert in baseline_alerts + graph_alerts:
            alert.window_start_wall = self.wall_epoch + window.start
            alert.window_end_wall = self.wall_epoch + window.end
            self.event_log.write(
                "detector_candidate", dict(alert.to_dict(), warming_up=warming_up)
            )
        for decision in self.alerts.submit(baseline_alerts + graph_alerts):
            self.mitigation.apply(decision)

    def _log_decision(self, decision):
        alert = decision.alert
        self.event_log.write("alert", alert.to_dict())
        self.event_log.write(
            "mitigation_decided",
            {
                "decision_id": decision.decision_id,
                "alert_id": alert.alert_id,
                "created_mono": alert.created_mono,
                "decided_mono": decision.decided_mono,
                "decided_wall": decision.decided_wall,
                "action": decision.action,
                "actuate": decision.actuate,
                "reason": decision.reason,
                "detector": alert.detector,
                "attack_class": alert.attack_class,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "alert_ts": alert.ts,
            },
        )
        self.logger.info(
            "ALERT [%s] %s src=%s score=%.2f -- %s%s",
            alert.detector,
            alert.attack_class,
            alert.src_ip,
            alert.score,
            alert.reason,
            "" if decision.actuate else "  (scoring only, not actuating)",
        )

    # ------------------------------------------------------------------

    def _overhead_snapshot(self):
        snapshot = self.collector.overhead_snapshot()
        snapshot.update(self.mitigation.snapshot())
        snapshot.update(self.alerts.snapshot())
        snapshot["profiled_hosts"] = len(self.graph_builder.profiles)
        snapshot["windows_seen"] = self.graph_builder.windows_seen
        return snapshot

    def _handle_shutdown(self, _signum, _frame):
        """Flush the run terminator before Ryu tears down the app."""
        self.close()
        raise KeyboardInterrupt

    def close(self):
        """Called by Ryu on shutdown."""
        if self._closed:
            return
        self._closed = True
        try:
            self.collector.stop()
            self.sampler.stop()
            self.event_log.write("run_end", self._overhead_snapshot())
        finally:
            self.event_log.close()

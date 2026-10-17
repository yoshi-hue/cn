"""Flow collector: turns OpenFlow events into FlowRecords (Algorithm A).

Two ingest paths feed one record stream:

* **PacketIn** -- every packet that misses the flow table. This is the only
  path that sees a conversation's *first* packet, so it is what makes
  sub-second new-edge detection possible. Flow-statistics polling alone would
  floor mean-time-to-detect at the poll interval.
* **Flow-statistics polling** -- periodic per-entry packet and byte counters,
  which is the only path that sees the volume of a conversation once the
  switch is forwarding it without controller involvement.

Neither path is sufficient alone, which is why both are collected.
"""

from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, icmp, ipv4, packet, tcp, udp

from lantern import config
from lantern.features import (
    TCP_ACK,
    TCP_SYN,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    SRC_FLOW_STATS,
    SRC_PACKET_IN,
    FlowRecord,
    FlowStatsDiffer,
    WindowAggregator,
)

# Ports at or above this are treated as ephemeral (client-side) rather than as
# a service a host would deliberately connect to.
EPHEMERAL_PORT_FLOOR = 32768


class FlowCollector:
    """Owns the record stream, the counter differ and the window aggregator."""

    def __init__(
        self,
        logger,
        clock,
        epoch,
        on_window_closed,
        window_seconds=None,
        poll_interval=None,
    ):
        self.logger = logger
        self.clock = clock  # callable -> float, monotonic
        self.on_window_closed = on_window_closed
        self.differ = FlowStatsDiffer()
        self.aggregator = WindowAggregator(
            window_seconds=window_seconds or config.WINDOW_SECONDS,
            epoch=epoch,
        )
        self.poll_interval = poll_interval or config.POLL_INTERVAL_SECONDS

        # Counters reported as controller-overhead metrics (Research Gap 4).
        self.packet_in_count = 0
        self.flow_stats_request_count = 0
        self.flow_stats_reply_count = 0
        self.records_ingested = 0
        self.records_from_packet_in = 0
        self.records_from_flow_stats = 0
        self.packet_in_non_ip = 0
        self.records_rejected_late = 0

        self.flow_tables = {}
        self._datapaths = {}
        self._poll_thread = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def register(self, datapath):
        self._datapaths[datapath.id] = datapath

    def unregister(self, dpid):
        self._datapaths.pop(dpid, None)

    def start(self):
        if self._running:
            return
        self._running = True
        self._poll_thread = hub.spawn(self._poll_loop)

    def stop(self):
        self._running = False
        for window in self.aggregator.close_all():
            self.on_window_closed(window)

    # ------------------------------------------------------------------
    # Ingest path 1: PacketIn
    # ------------------------------------------------------------------

    def handle_packet_in(self, msg):
        """Extract a FlowRecord from a PacketIn, if it carries one.

        Returns the record, or None for traffic with no IP layer (ARP, LLDP),
        which is still forwarded but carries no host-communication signal we
        model.
        """
        self.packet_in_count += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP,):
            self.packet_in_non_ip += 1
            return None

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            self.packet_in_non_ip += 1
            # ARP still tells us two hosts are about to talk, but it is
            # broadcast-driven and would add an edge to every host on the
            # segment, which would swamp the graph with noise. Excluded.
            return None

        record = FlowRecord(
            ts=self.clock(),
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=ip.proto,
            packets=1,
            bytes=len(msg.data),
            dpid=msg.datapath.id,
            source=SRC_PACKET_IN,
        )

        if ip.proto == PROTO_TCP:
            segment = pkt.get_protocol(tcp.tcp)
            if segment is not None:
                record.src_port = segment.src_port
                record.dst_port = segment.dst_port
                record.tcp_flags = segment.bits
                # A bare SYN is the definition of a host opening a connection.
                record.is_initiation = bool(segment.bits & TCP_SYN) and not (
                    segment.bits & TCP_ACK
                )
        elif ip.proto == PROTO_UDP:
            datagram = pkt.get_protocol(udp.udp)
            if datagram is not None:
                record.src_port = datagram.src_port
                record.dst_port = datagram.dst_port
                # UDP has no handshake, so direction is inferred from the port:
                # a request goes to a service port, a reply comes back to an
                # ephemeral one.
                record.is_initiation = datagram.dst_port < EPHEMERAL_PORT_FLOOR
        elif ip.proto == PROTO_ICMP:
            message = pkt.get_protocol(icmp.icmp)
            if message is not None:
                record.is_initiation = message.type == icmp.ICMP_ECHO_REQUEST

        self._ingest(record)
        return record

    # ------------------------------------------------------------------
    # Ingest path 2: flow-statistics polling
    # ------------------------------------------------------------------

    def _poll_loop(self):
        while self._running:
            self.request_flow_stats()
            self.drain_windows()
            hub.sleep(self.poll_interval)

    def request_flow_stats(self):
        for datapath in list(self._datapaths.values()):
            parser = datapath.ofproto_parser
            datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
            self.flow_stats_request_count += 1

    def handle_flow_stats_reply(self, msg):
        """Convert one FlowStatsReply into per-entry delta records."""
        self.flow_stats_reply_count += 1
        now = self.clock()
        dpid = msg.datapath.id
        records = []
        self.flow_tables[str(dpid)] = {
            "observed_at": now,
            "forwarding": sum(
                s.priority == config.LEARNING_SWITCH_PRIORITY for s in msg.body
            ),
            "mitigation": sum(
                s.priority == config.MITIGATION_PRIORITY for s in msg.body
            ),
            "total": len(msg.body),
            "drops": [
                {
                    "cookie": s.cookie,
                    "packets": s.packet_count,
                    "match": dict(s.match.items()),
                }
                for s in msg.body
                if s.priority == config.MITIGATION_PRIORITY
            ],
        }

        for stat in msg.body:
            if stat.priority != config.LEARNING_SWITCH_PRIORITY:
                continue  # dropped packets must not feed the detector
            fields = stat.match
            src_ip = fields.get("ipv4_src")
            dst_ip = fields.get("ipv4_dst")
            if not src_ip or not dst_ip:
                # Table-miss and L2-only entries carry no host pair.
                continue

            protocol = fields.get("ip_proto", 0)
            src_port = fields.get("tcp_src") or fields.get("udp_src") or 0
            dst_port = fields.get("tcp_dst") or fields.get("udp_dst") or 0
            flow_key = (src_ip, dst_ip, protocol, src_port, dst_port, stat.priority)

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            delta_packets, delta_bytes = self.differ.diff(
                dpid, flow_key, stat.packet_count, stat.byte_count, duration
            )
            if delta_packets <= 0 and delta_bytes <= 0:
                continue

            record = FlowRecord(
                ts=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packets=delta_packets,
                bytes=delta_bytes,
                duration=duration,
                dpid=dpid,
                source=SRC_FLOW_STATS,
            )
            self._ingest(record)
            records.append(record)

        return records

    def handle_flow_removed(self, msg):
        """Forget an evicted entry so its counters are not diffed against."""
        fields = msg.match
        src_ip = fields.get("ipv4_src")
        dst_ip = fields.get("ipv4_dst")
        if not src_ip or not dst_ip:
            return
        flow_key = (
            src_ip,
            dst_ip,
            fields.get("ip_proto", 0),
            fields.get("tcp_src") or fields.get("udp_src") or 0,
            fields.get("tcp_dst") or fields.get("udp_dst") or 0,
            msg.priority,
        )
        self.differ.forget(msg.datapath.id, flow_key)

    # ------------------------------------------------------------------
    # Windowing
    # ------------------------------------------------------------------

    def _ingest(self, record):
        if self.aggregator.add(record):
            self.records_ingested += 1
            if record.source == SRC_PACKET_IN:
                self.records_from_packet_in += 1
            else:
                self.records_from_flow_stats += 1
        else:
            # The record's window had already been scored. Counted rather than
            # silently dropped: a large number here would mean windows are
            # closing before their traffic arrives, which would quietly starve
            # both detectors.
            self.records_rejected_late += 1

    def drain_windows(self):
        """Close every elapsed window and hand each to the detectors."""
        for window in self.aggregator.close_due(self.clock()):
            self.on_window_closed(window)

    # ------------------------------------------------------------------
    # Overhead reporting
    # ------------------------------------------------------------------

    def overhead_snapshot(self):
        return {
            "flow_tables": self.flow_tables,
            "packet_in_count": self.packet_in_count,
            "flow_stats_requests": self.flow_stats_request_count,
            "flow_stats_replies": self.flow_stats_reply_count,
            "records_ingested": self.records_ingested,
            "records_from_packet_in": self.records_from_packet_in,
            "records_from_flow_stats": self.records_from_flow_stats,
            "packet_in_non_ip": self.packet_in_non_ip,
            "records_rejected_late": self.records_rejected_late,
            "tracked_flow_entries": len(self.differ),
        }

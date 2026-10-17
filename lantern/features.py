"""Flow records, counter diffing and per-window aggregation (Algorithm A).

This module is deliberately free of any Ryu import so that it can be unit
tested with synthetic records, with no controller, no Mininet and no root.
`collector.py` is the only place that knows about OpenFlow messages; it turns
them into the `FlowRecord`s defined here, and everything downstream -- both
detectors -- sees only this vocabulary.
"""

import math

try:  # Python 3.7+
    from dataclasses import dataclass, field
except ImportError:  # pragma: no cover
    raise

from lantern import config

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# Sources a FlowRecord can come from. Kept explicit because the two have very
# different timing characteristics and the analysis needs to tell them apart.
SRC_PACKET_IN = "packet_in"
SRC_FLOW_STATS = "flow_stats"

# TCP flag bits we care about for the failed-connection heuristic.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


@dataclass
class FlowRecord:
    """One observation of traffic from one host to another.

    A record is *not* a flow; it is a delta. A PacketIn record describes the
    single packet that reached the controller, and a flow-stats record
    describes the packets and bytes a switch counted for one flow entry since
    the previous poll.
    """

    ts: float
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int = 0
    dst_port: int = 0
    packets: int = 1
    bytes: int = 0
    duration: float = 0.0
    dpid: int = 0
    source: str = SRC_PACKET_IN
    tcp_flags: int = 0
    # True when this record is a host *initiating* a conversation, rather than
    # replying to one. Without this distinction a server answering many clients
    # looks exactly like a host scanning many ports: its replies are addressed
    # to a different ephemeral port every time. The collector decides this,
    # because it is the only component that sees protocol semantics.
    is_initiation: bool = False

    @property
    def key(self):
        return (self.src_ip, self.dst_ip, self.protocol, self.src_port, self.dst_port)


@dataclass
class PairStats:
    """Everything observed between one ordered pair of hosts in one window."""

    src: str
    dst: str
    packets: int = 0
    bytes: int = 0
    flows: int = 0
    dst_ports: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    syns: int = 0
    resets: int = 0

    @property
    def duration(self):
        return max(self.last_seen - self.first_seen, 0.0)


@dataclass
class HostStats:
    """Everything one host did as a source in one window."""

    host: str
    packets: int = 0
    bytes: int = 0
    flows: int = 0
    dst_hosts: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)
    # Restricted to conversations this host started. These, not the totals
    # above, are what the port-scan rule is allowed to look at.
    initiated_hosts: set = field(default_factory=set)
    initiated_ports: set = field(default_factory=set)
    auth_attempts: dict = field(
        default_factory=dict
    )  # dst_ip -> SYN count on auth ports
    failed_connections: int = 0

    def rate(self, window_seconds):
        return self.packets / window_seconds if window_seconds > 0 else 0.0

    def byte_rate(self, window_seconds):
        return self.bytes / window_seconds if window_seconds > 0 else 0.0


@dataclass
class Window:
    """A closed time window: the unit of work both detectors operate on.

    Both detectors receive the *same* Window object. That is the mechanism that
    makes the comparison fair -- neither can see traffic the other cannot.
    """

    index: int
    start: float
    end: float
    pairs: dict = field(default_factory=dict)  # (src, dst) -> PairStats
    hosts: dict = field(default_factory=dict)  # src        -> HostStats
    record_count: int = 0

    @property
    def seconds(self):
        return self.end - self.start

    def active_hosts(self):
        """Every host seen in the window, as a source or a destination."""
        seen = set(self.hosts)
        for src, dst in self.pairs:
            seen.add(src)
            seen.add(dst)
        return seen


class FlowStatsDiffer:
    """Converts cumulative OpenFlow counters into per-poll deltas.

    Flow-statistics replies report counters that accumulate for the lifetime of
    a flow *entry*, so consecutive polls must be differenced. Two cases need
    care, and getting either wrong silently inflates every rate the detectors
    see:

    * A flow entry that is evicted (idle timeout) and later recreated restarts
      its counters at zero. A naive subtraction then yields a negative delta.
    * An entry seen for the first time has no predecessor; its whole counter is
      the delta.

    Both are handled by treating any non-increasing counter as a fresh entry.
    """

    def __init__(self):
        self._previous = {}

    def diff(self, dpid, flow_key, packets, bytes_, duration=0.0):
        """Return (delta_packets, delta_bytes) for one flow entry."""
        index = (dpid, flow_key)
        previous = self._previous.get(index)
        self._previous[index] = (packets, bytes_, duration)

        if previous is None:
            return packets, bytes_

        prev_packets, prev_bytes, prev_duration = previous
        if packets < prev_packets or bytes_ < prev_bytes or duration < prev_duration:
            # Counter went backwards: the entry was evicted and recreated.
            return packets, bytes_

        return packets - prev_packets, bytes_ - prev_bytes

    def forget(self, dpid, flow_key):
        """Drop a remembered entry (called on FlowRemoved)."""
        self._previous.pop((dpid, flow_key), None)

    def __len__(self):
        return len(self._previous)


class WindowAggregator:
    """Buckets FlowRecords into fixed-length windows and closes them on time.

    Windows are aligned to an absolute epoch rather than to the first record,
    so that a run's window boundaries are reproducible and every component
    (detectors, metrics, analysis) agrees on which window an event fell in.
    """

    def __init__(self, window_seconds=None, epoch=0.0):
        self.window_seconds = window_seconds or config.WINDOW_SECONDS
        self.epoch = epoch
        self._open = {}  # index -> Window
        self._highest_closed = -1

    def window_index(self, ts):
        return int(math.floor((ts - self.epoch) / self.window_seconds))

    def add(self, record):
        """File one record into its window. Late records are dropped."""
        index = self.window_index(record.ts)
        if index <= self._highest_closed:
            # The window this belongs to has already been scored; counting it
            # now would corrupt an already-reported result.
            return False

        window = self._open.get(index)
        if window is None:
            start = self.epoch + index * self.window_seconds
            window = Window(index=index, start=start, end=start + self.window_seconds)
            self._open[index] = window

        self._apply(window, record)
        return True

    def _apply(self, window, record):
        window.record_count += 1

        src, dst = record.src_ip, record.dst_ip

        pair = window.pairs.get((src, dst))
        if pair is None:
            pair = PairStats(src=src, dst=dst, first_seen=record.ts)
            window.pairs[(src, dst)] = pair
        pair.packets += record.packets
        pair.bytes += record.bytes
        pair.flows += 1
        pair.protocols.add(record.protocol)
        pair.last_seen = record.ts
        if record.dst_port:
            pair.dst_ports.add(record.dst_port)

        host = window.hosts.get(src)
        if host is None:
            host = HostStats(host=src)
            window.hosts[src] = host
        host.packets += record.packets
        host.bytes += record.bytes
        host.flows += 1
        host.dst_hosts.add(dst)
        if record.dst_port:
            host.dst_ports.add(record.dst_port)
        if record.is_initiation:
            host.initiated_hosts.add(dst)
            if record.dst_port:
                host.initiated_ports.add(record.dst_port)

        if record.protocol == PROTO_TCP:
            self._apply_tcp_flags(window, record, pair, host)

    @staticmethod
    def _apply_tcp_flags(window, record, pair, host):
        """Track connection attempts for the brute-force heuristic.

        This counts SYNs that are not answered by a SYN-ACK in the same window.
        It is a heuristic, not a real TCP state machine: the controller only
        sees packets that miss the flow table, so a genuinely established
        connection's later packets are invisible here. It is sufficient to
        distinguish "many attempts, few completions" from normal traffic, which
        is all the brute-force rule needs.
        """
        flags = record.tcp_flags
        if not flags:
            return

        is_syn = bool(flags & TCP_SYN) and not (flags & TCP_ACK)
        is_syn_ack = bool(flags & TCP_SYN) and bool(flags & TCP_ACK)
        is_reset = bool(flags & TCP_RST)

        if is_syn:
            pair.syns += record.packets
            if record.dst_port in config.AUTH_PORTS:
                host.auth_attempts[record.dst_ip] = (
                    host.auth_attempts.get(record.dst_ip, 0) + record.packets
                )
        if is_reset:
            pair.resets += record.packets

        # A SYN-ACK or RST travelling back tells us about the *reverse* pair.
        if is_syn_ack or is_reset:
            reverse = window.pairs.get((record.dst_ip, record.src_ip))
            if reverse is not None:
                if is_syn_ack:
                    reverse.syns = max(reverse.syns - record.packets, 0)
                else:
                    reverse.resets += record.packets

    def close_due(self, now):
        """Close and return every window that has fully elapsed, in order."""
        due_indices = sorted(
            index for index, window in self._open.items() if window.end <= now
        )
        closed = []
        for index in due_indices:
            window = self._open.pop(index)
            self._finalise(window)
            self._highest_closed = max(self._highest_closed, index)
            closed.append(window)
        return closed

    def close_all(self):
        """Close every open window regardless of time (end of a run)."""
        closed = []
        for index in sorted(self._open):
            window = self._open.pop(index)
            self._finalise(window)
            self._highest_closed = max(self._highest_closed, index)
            closed.append(window)
        return closed

    @staticmethod
    def _finalise(window):
        """Derive the per-host figures that need the whole window to compute."""
        for host in window.hosts.values():
            failed = 0
            for (src, dst), pair in window.pairs.items():
                if src == host.host:
                    failed += pair.syns
            host.failed_connections = failed


def summarise_window(window):
    """Compact dict form of a window, for the JSONL event log."""
    return {
        "index": window.index,
        "start": window.start,
        "end": window.end,
        "records": window.record_count,
        "hosts": len(window.active_hosts()),
        "pairs": len(window.pairs),
    }

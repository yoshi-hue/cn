"""Host-communication graph and per-host behavioural profiles.

This is Algorithm C steps 1-4, plus the profile machinery the scoring step
needs. Formally, for each time window t we build

    G_t = (V_t, E_t)

where V_t is the set of hosts active during window t and E_t the set of
observed communication relationships, each edge carrying flow, packet, byte
and port attributes.

The profiles are the part that makes this a *detector* rather than a drawing.
A host is scored against its own established normal, not against a global
threshold or against other hosts: a busy server legitimately has a high degree,
and comparing it to a workstation would flag it forever. What is suspicious is
a host departing from its own history.
"""

import math
import time

import networkx as nx

from lantern import config

# The per-host features that carry a rolling profile. Kept as a tuple so the
# profile, the scorer and the weight table cannot silently drift apart.
PROFILED_FEATURES = (
    "degree",
    "weighted_degree",
    "new_neighbour_ratio",
    "port_diversity",
    "betweenness",
)


class HostProfile:
    """Rolling EWMA mean and variance of one host's graph features.

    An exponentially weighted moving average is used rather than a fixed
    training window so the profile keeps adapting to slow, legitimate change in
    a host's behaviour, while still reacting sharply to a sudden departure.
    """

    def __init__(self, host, alpha=None):
        self.host = host
        self.alpha = alpha if alpha is not None else config.PROFILE_ALPHA
        self.observations = 0
        self._mean = {feature: 0.0 for feature in PROFILED_FEATURES}
        self._variance = {feature: 0.0 for feature in PROFILED_FEATURES}

        # Every host this one has ever been seen *reaching out to*. The
        # new-neighbour ratio is computed against this, not against the
        # previous window, so a host revisiting a familiar peer is not treated
        # as novel. It records contacts made rather than contacts received, to
        # match the directional feature it is compared against -- otherwise
        # being scanned would teach a victim that the scanner is a normal peer.
        self.seen_neighbours = set()

        # Peer membership set from the previous window (independent of labels).
        self.last_community = None

    @property
    def ready(self):
        """Has this host been observed enough for its profile to be trusted?"""
        return self.observations >= config.MIN_PROFILE_WINDOWS

    def mean(self, feature):
        return self._mean.get(feature, 0.0)

    def sigma(self, feature):
        """Standard deviation, floored per feature.

        A host whose behaviour is perfectly constant has a true sigma of zero,
        which would send the z-score of any deviation whatsoever to infinity
        and make the detector alert on a single extra packet. The floor stops a
        quiet host from being a hair trigger, and it is per-feature because the
        features are not on a common scale -- see MIN_SIGMA_BY_FEATURE.
        """
        return max(
            math.sqrt(max(self._variance.get(feature, 0.0), 0.0)),
            config.min_sigma(feature),
        )

    def zscore(self, feature, value):
        """How unusual `value` is for this host, clamped."""
        if not self.ready:
            return 0.0
        z = (value - self.mean(feature)) / self.sigma(feature)
        # Only *upward* deviation is suspicious for these features: a host
        # talking to fewer machines than usual is not an intrusion signal.
        z = max(z, 0.0)
        return min(z, config.Z_CLAMP)

    def update(self, features, neighbours, community=None):
        """Fold one window's observation into the profile."""
        alpha = self.alpha
        for feature in PROFILED_FEATURES:
            value = float(features.get(feature, 0.0))
            if self.observations == 0:
                self._mean[feature] = value
                self._variance[feature] = 0.0
            else:
                previous_mean = self._mean[feature]
                new_mean = previous_mean + alpha * (value - previous_mean)
                # West's incremental EWMA variance.
                self._variance[feature] = (1 - alpha) * (
                    self._variance[feature] + alpha * (value - previous_mean) ** 2
                )
                self._mean[feature] = new_mean

        self.observations += 1
        self.seen_neighbours.update(neighbours)
        if community is not None:
            self.last_community = community


class GraphBuilder:
    """Builds G_t from a window and maintains every host's profile."""

    def __init__(self, cfg=config):
        self.cfg = cfg
        self.profiles = {}
        self.windows_seen = 0
        self.last_build_seconds = 0.0

    # ------------------------------------------------------------------

    def profile_for(self, host):
        profile = self.profiles.get(host)
        if profile is None:
            profile = HostProfile(host, alpha=self.cfg.PROFILE_ALPHA)
            self.profiles[host] = profile
        return profile

    @property
    def warming_up(self):
        """True while the profiles are still learning what normal looks like.

        No host may be scored during warmup. Scoring against an empty profile
        would make the very first windows of every run alert on everything.
        """
        return self.windows_seen < self.cfg.PROFILE_WARMUP_WINDOWS

    # ------------------------------------------------------------------

    def build(self, window):
        """Algorithm C steps 1-4: construct the undirected host graph.

        The graph is undirected because the question it answers -- "does this
        host talk to that host?" -- is symmetric. Direction is preserved inside
        the edge attributes for the features that need it.
        """
        started = time.perf_counter()
        graph = nx.Graph()

        for host in window.active_hosts():
            graph.add_node(host)

        for (src, dst), pair in window.pairs.items():
            if src == dst:
                continue
            if graph.has_edge(src, dst):
                edge = graph[src][dst]
                edge["flows"] += pair.flows
                edge["packets"] += pair.packets
                edge["bytes"] += pair.bytes
                edge["ports"] = edge["ports"] | pair.dst_ports
                edge["first_seen"] = min(edge["first_seen"], pair.first_seen)
                edge["last_seen"] = max(edge["last_seen"], pair.last_seen)
            else:
                graph.add_edge(
                    src,
                    dst,
                    flows=pair.flows,
                    packets=pair.packets,
                    bytes=pair.bytes,
                    ports=set(pair.dst_ports),
                    first_seen=pair.first_seen,
                    last_seen=pair.last_seen,
                )

        self.last_build_seconds = time.perf_counter() - started
        return graph

    # ------------------------------------------------------------------

    def commit(self, graph, features_by_host, communities_by_host):
        """Fold this window into every host's profile. Call after scoring.

        Ordering matters: a host must be scored against the profile as it stood
        *before* this window, otherwise an attack partly trains the profile that
        is supposed to catch it.
        """
        for host in graph.nodes():
            profile = self.profile_for(host)
            features = features_by_host.get(host, {})
            profile.update(
                features,
                # Contacts made, not graph neighbours: see seen_neighbours.
                neighbours=set(features.get("_contacted", ())),
                community=communities_by_host.get(host),
            )
        self.windows_seen += 1

"""Graph-based lateral-movement detector (Algorithm C steps 5-9).

This is the project's research contribution and a response to the SDN-specific
research gap examined here: the controller builds a network-wide model of
which hosts talk to which other hosts, so behaviour that is only suspicious in
aggregate can be scored across the SDN fabric. This claim is intentionally
narrower than claiming that no lateral-movement detector uses graphs anywhere
in networking or security.

For each host h in window t the detector computes graph features, converts each
to a z-score against that host's own established normal, and combines them:

    S(h,t) = sum_i w_i * z_i(h,t)        alert if S(h,t) > theta

The feature that does most of the work is the new-neighbour ratio. Lateral
movement is precisely the pattern of a host contacting machines it has never
contacted before, while each individual connection stays perfectly ordinary --
a single TCP session to a normal port, nothing volumetrically remarkable.
"""

import time

import networkx as nx

from lantern import config
from lantern.alerts import (
    CLASS_GRAPH_ANOMALY,
    CLASS_LATERAL,
    DETECTOR_GRAPH,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Alert,
)

# A host must be contacting this fraction of unfamiliar peers before an anomaly
# is called lateral movement rather than a generic structural anomaly.
LATERAL_NEW_NEIGHBOUR_MINIMUM = 0.3

try:
    from networkx.algorithms.community import louvain_communities

    _HAS_LOUVAIN = True
except ImportError:  # networkx < 3.0
    _HAS_LOUVAIN = False
    from networkx.algorithms.community import greedy_modularity_communities


class GraphDetector:
    """Scores hosts on how far this window's graph departs from their normal."""

    name = DETECTOR_GRAPH

    def __init__(self, builder, cfg=config):
        self.builder = builder
        self.cfg = cfg
        self.last_compute_seconds = 0.0
        self.last_betweenness_seconds = 0.0
        self.last_scores = {}

    # ------------------------------------------------------------------

    def detect(self, window):
        """Build G_t, score every host, then fold the window into the profiles."""
        started = time.perf_counter()

        graph = self.builder.build(window)
        features_by_host, communities_by_host = self._compute_features(graph, window)

        alerts = []
        if not self.builder.warming_up:
            alerts = self._score(graph, features_by_host, communities_by_host, window)

        # Committed only after scoring, so an attack never trains the profile
        # that is meant to catch it within the same window.
        self.builder.commit(graph, features_by_host, communities_by_host)

        self.last_compute_seconds = time.perf_counter() - started
        return alerts

    # ------------------------------------------------------------------
    # Feature computation (Algorithm C steps 5-6)
    # ------------------------------------------------------------------

    def _compute_features(self, graph, window):
        """Compute per-host features.

        Two kinds of feature are computed from two different views, and the
        distinction is load-bearing:

        * **Directional** features -- degree, new-neighbour ratio, port
          diversity, weighted degree -- count only conversations the host
          *started*. The graph itself is undirected, so a host that an attacker
          contacts gains a new neighbour too. Scoring on undirected neighbours
          therefore flags the attacker's victims as hard as the attacker, and
          since mitigation blocks the host an alert names, that would mean
          blocking innocent machines *because* they were attacked.
        * **Structural** features -- betweenness and community membership --
          are properties of the graph's shape, and stay undirected. "Does this
          host sit between two groups that do not otherwise talk?" has no
          direction to it.
        """
        communities_by_host = self._communities(graph)

        # Betweenness is timed separately: it is by far the most expensive
        # feature here (roughly O(V*E)), so it is the one that would decide
        # whether this approach survives a larger topology. That makes it the
        # only empirical handle this project has on Research Gap 5.
        betweenness_started = time.perf_counter()
        if graph.number_of_nodes() > 2:
            betweenness = nx.betweenness_centrality(graph)
        else:
            betweenness = {node: 0.0 for node in graph.nodes()}
        self.last_betweenness_seconds = time.perf_counter() - betweenness_started

        features_by_host = {}
        for host in graph.nodes():
            profile = self.builder.profile_for(host)
            activity = window.hosts.get(host)

            # Peers this host reached out to, and the service ports it asked
            # for -- not everyone it exchanged packets with.
            contacted = set(activity.initiated_hosts) if activity else set()
            ports = set(activity.initiated_ports) if activity else set()
            weighted_degree = activity.packets if activity else 0

            if contacted:
                unseen = contacted - profile.seen_neighbours
                new_neighbour_ratio = len(unseen) / float(len(contacted))
            else:
                unseen = set()
                new_neighbour_ratio = 0.0

            features_by_host[host] = {
                "degree": float(len(contacted)),
                "weighted_degree": float(weighted_degree),
                "new_neighbour_ratio": new_neighbour_ratio,
                "port_diversity": float(len(ports)),
                "betweenness": float(betweenness.get(host, 0.0)),
                # Not profiled; carried for evidence and for the commit step.
                "_new_neighbours": sorted(unseen),
                "_contacted": sorted(contacted),
                "_ports": sorted(ports),
            }

        return features_by_host, communities_by_host

    @staticmethod
    def _communities(graph):
        """Map each host to a community id.

        Community membership answers "which group of machines does this host
        normally sit with?". A host whose traffic starts crossing between
        groups that do not normally communicate is the structural signature of
        an attacker moving through a network.
        """
        if graph.number_of_edges() == 0:
            return {node: frozenset() for node in graph.nodes()}

        try:
            if _HAS_LOUVAIN:
                groups = louvain_communities(graph, seed=42)
            else:
                groups = greedy_modularity_communities(graph)
        except Exception:
            # Community detection is a nice-to-have; its failure must not take
            # the whole detector down mid-run.
            return {node: frozenset() for node in graph.nodes()}

        membership = {}
        for community_id, members in enumerate(groups):
            for node in members:
                membership[node] = frozenset(members) - {node}
        return membership

    # ------------------------------------------------------------------
    # Scoring (Algorithm C steps 7-9)
    # ------------------------------------------------------------------

    def _score(self, graph, features_by_host, communities_by_host, window):
        weights = self.cfg.GRAPH_WEIGHTS
        alerts = []
        self.last_scores = {}

        for host, features in features_by_host.items():
            profile = self.builder.profile_for(host)
            if not profile.ready:
                continue

            contributions = {}
            for feature, weight in weights.items():
                if feature == "community_change":
                    continue
                z = profile.zscore(feature, features.get(feature, 0.0))
                contributions[feature] = weight * z

            # Community change is binary rather than a z-score: a host either
            # moved between communities since the last window or it did not.
            community = communities_by_host.get(host)
            changed = (
                profile.last_community is not None
                and community is not None
                and community != profile.last_community
            )
            contributions["community_change"] = (
                weights.get("community_change", 0.0) if changed else 0.0
            )

            score = sum(contributions.values())
            self.last_scores[host] = score

            if score <= self.cfg.GRAPH_SCORE_THRESHOLD:
                continue

            new_neighbours = features.get("_new_neighbours", [])
            alerts.append(
                Alert(
                    detector=self.name,
                    attack_class=self._classify(features, contributions),
                    src_ip=host,
                    ts=window.end,
                    window_index=window.index,
                    severity=(
                        SEVERITY_HIGH
                        if score > 2 * self.cfg.GRAPH_SCORE_THRESHOLD
                        else SEVERITY_MEDIUM
                    ),
                    score=score,
                    reason=self._explain(features, contributions, changed),
                    evidence={
                        "degree": features["degree"],
                        "new_neighbour_ratio": round(
                            features["new_neighbour_ratio"], 3
                        ),
                        "new_neighbours": new_neighbours,
                        "port_diversity": features["port_diversity"],
                        "betweenness": round(features["betweenness"], 4),
                        "community_changed": changed,
                        "contributions": {
                            k: round(v, 3) for k, v in contributions.items()
                        },
                        "threshold": self.cfg.GRAPH_SCORE_THRESHOLD,
                    },
                )
            )

        return alerts

    @staticmethod
    def _classify(features, contributions):
        """Name what the anomaly actually looks like.

        Lateral movement has a specific, observable shape: a host reaching
        machines it has never reached before. So the test is the evidence --
        did it contact unfamiliar hosts, and were enough of its peers new? --
        and nothing else.

        An earlier version also required the new-neighbour ratio to be the
        single largest contributor to the score. That was wrong, and the run
        data showed it: in every lateral detection the ratio was exactly 0.50,
        identical evidence each time, yet the label flipped between "lateral"
        and "graph anomaly" depending on whether degree or port diversity
        happened to come out on top. Both were pinned at the z-score clamp in
        those windows, so the tiebreak between them was essentially arbitrary
        -- and it was deciding what an analyst would be told, and (through the
        severity rules) whether the host was blocked or merely logged. Twelve
        of seventeen detections were mislabelled that way.
        """
        ratio = features.get("new_neighbour_ratio", 0.0)
        new_neighbours = features.get("_new_neighbours", ())

        if ratio >= LATERAL_NEW_NEIGHBOUR_MINIMUM and len(new_neighbours) > 0:
            return CLASS_LATERAL
        return CLASS_GRAPH_ANOMALY

    @staticmethod
    def _explain(features, contributions, community_changed):
        """A human-readable reason naming the features that actually fired.

        An alert that cannot be explained cannot be acted on, and a detector
        whose output an analyst cannot interpret is not deployable regardless of
        its accuracy.
        """
        ranked = sorted(
            (c for c in contributions.items() if c[1] > 0.01),
            key=lambda item: item[1],
            reverse=True,
        )
        if not ranked:
            return "anomaly score exceeded threshold"

        parts = []
        for feature, contribution in ranked[:3]:
            if feature == "new_neighbour_ratio":
                parts.append(
                    "%.0f%% of its neighbours were never seen before (%d new)"
                    % (
                        100 * features.get("new_neighbour_ratio", 0.0),
                        len(features.get("_new_neighbours", [])),
                    )
                )
            elif feature == "degree":
                parts.append("contacted %d hosts" % int(features.get("degree", 0)))
            elif feature == "port_diversity":
                parts.append(
                    "used %d distinct ports" % int(features.get("port_diversity", 0))
                )
            elif feature == "community_change" and community_changed:
                parts.append("moved between host communities")
            elif feature == "betweenness":
                parts.append("sits between otherwise separate host groups")
            elif feature == "weighted_degree":
                parts.append("unusual traffic volume across its peers")
        return "; ".join(parts)

    # ------------------------------------------------------------------

    def timing_snapshot(self):
        snapshot = {
            "graph_total_seconds": round(self.last_compute_seconds, 6),
            "graph_build_seconds": round(self.builder.last_build_seconds, 6),
            "betweenness_seconds": round(self.last_betweenness_seconds, 6),
        }
        # The highest score in the window, whether or not it alerted. This is
        # what makes the threshold tunable from a C1 run: "no alerts" alone
        # cannot tell you whether the margin was comfortable or a hair's width.
        if self.last_scores:
            top = max(self.last_scores.items(), key=lambda item: item[1])
            snapshot["top_score_host"] = top[0]
            snapshot["top_score"] = round(top[1], 3)
        else:
            snapshot["top_score"] = None
        return snapshot

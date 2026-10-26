"""Threshold baseline over per-source and per-pair window statistics.

Calibration uses normal-only data. The comparison concerns this concrete
baseline, not all per-flow methods or the entire surveyed literature.
"""

import time

from lantern import config
from lantern.alerts import (
    CLASS_BRUTEFORCE,
    CLASS_DOS,
    CLASS_LATERAL,
    CLASS_PORTSCAN,
    DETECTOR_BASELINE,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Alert,
)


class BaselineDetector:
    """Threshold rules over per-window, per-host flow statistics."""

    name = DETECTOR_BASELINE

    def __init__(self, cfg=config):
        self.cfg = cfg
        # (src, dst) -> number of consecutive windows above the DoS rate. A
        # single burst is not a denial of service; persistence is what
        # distinguishes one from a legitimate transfer.
        self._dos_streak = {}
        # Source -> cumulative set of destinations first contacted during the
        # run. This is the requested control baseline: unlike the graph model
        # it has no topology or learned profile, only a cumulative count.
        self._seen_destinations = {}
        self._lateral_reported = set()
        self.last_compute_seconds = 0.0

    def detect(self, window):
        """Score one window. Pure with respect to the window; returns Alerts."""
        started = time.perf_counter()
        alerts = []

        alerts.extend(self._detect_portscan(window))
        alerts.extend(self._detect_dos(window))
        alerts.extend(self._detect_bruteforce(window))
        if self.cfg.CUMULATIVE_LATERAL_ENABLED:
            alerts.extend(self._detect_cumulative_lateral(window))

        self.last_compute_seconds = time.perf_counter() - started
        return alerts

    def _detect_cumulative_lateral(self, window):
        """Control rule: label a source after N distinct new destinations.

        Destinations are added only after scoring the current window. The
        first crossing emits one alert per source, making the rule cumulative
        across windows while keeping alert counts comparable with the graph
        detector's cooldown semantics.
        """
        alerts = []
        for host in window.hosts.values():
            seen = self._seen_destinations.setdefault(host.host, set())
            new = set(host.initiated_hosts) - seen
            cumulative = seen | new
            if (
                len(cumulative) >= self.cfg.CUMULATIVE_NEW_DESTINATIONS
                and host.host not in self._lateral_reported
            ):
                alerts.append(
                    Alert(
                        detector=self.name,
                        attack_class=CLASS_LATERAL,
                        src_ip=host.host,
                        ts=window.end,
                        window_index=window.index,
                        severity=SEVERITY_HIGH,
                        score=float(len(cumulative)),
                        reason="%d cumulative distinct new destinations (>= %d)"
                        % (len(cumulative), self.cfg.CUMULATIVE_NEW_DESTINATIONS),
                        evidence={
                            "new_destinations": sorted(new),
                            "cumulative_distinct_destinations": len(cumulative),
                            "threshold": self.cfg.CUMULATIVE_NEW_DESTINATIONS,
                        },
                    )
                )
                self._lateral_reported.add(host.host)
            seen.update(new)
        return alerts

    # ------------------------------------------------------------------

    def _detect_portscan(self, window):
        alerts = []
        for host in window.hosts.values():
            # Only conversations this host *started*. Counting replies here
            # would flag every server in the network continuously, since each
            # reply is addressed to a different ephemeral client port.
            port_count = len(host.initiated_ports)
            host_count = len(host.initiated_hosts)

            by_ports = port_count > self.cfg.PORTSCAN_PORTS
            by_hosts = host_count > self.cfg.PORTSCAN_HOSTS
            if not (by_ports or by_hosts):
                continue

            reason = []
            if by_ports:
                reason.append(
                    "%d distinct destination ports (> %d)"
                    % (port_count, self.cfg.PORTSCAN_PORTS)
                )
            if by_hosts:
                reason.append(
                    "%d distinct destination hosts (> %d)"
                    % (host_count, self.cfg.PORTSCAN_HOSTS)
                )

            alerts.append(
                Alert(
                    detector=self.name,
                    attack_class=CLASS_PORTSCAN,
                    src_ip=host.host,
                    ts=window.end,
                    window_index=window.index,
                    severity=SEVERITY_MEDIUM,
                    score=float(max(port_count, host_count)),
                    reason="; ".join(reason),
                    evidence={
                        "initiated_port_count": port_count,
                        "initiated_host_count": host_count,
                        "all_dst_ports": len(host.dst_ports),
                        "packets": host.packets,
                    },
                )
            )
        return alerts

    def _detect_dos(self, window):
        alerts = []
        seconds = window.seconds or self.cfg.WINDOW_SECONDS
        seen_pairs = set()

        for (src, dst), pair in window.pairs.items():
            seen_pairs.add((src, dst))
            rate = pair.packets / seconds

            if rate <= self.cfg.DOS_PPS:
                self._dos_streak.pop((src, dst), None)
                continue

            streak = self._dos_streak.get((src, dst), 0) + 1
            self._dos_streak[(src, dst)] = streak
            if streak < self.cfg.DOS_SUSTAINED_WINDOWS:
                continue

            alerts.append(
                Alert(
                    detector=self.name,
                    attack_class=CLASS_DOS,
                    src_ip=src,
                    dst_ip=dst,
                    ts=window.end,
                    window_index=window.index,
                    severity=SEVERITY_HIGH,
                    score=rate,
                    reason="%.0f packets/s to a single destination over %d windows (> %.0f)"
                    % (rate, streak, self.cfg.DOS_PPS),
                    evidence={
                        "packet_rate": round(rate, 2),
                        "packets": pair.packets,
                        "bytes": pair.bytes,
                        "sustained_windows": streak,
                    },
                )
            )

        # A pair that went quiet this window has its streak broken.
        for key in list(self._dos_streak):
            if key not in seen_pairs:
                del self._dos_streak[key]

        return alerts

    def _detect_bruteforce(self, window):
        alerts = []
        for host in window.hosts.values():
            for dst_ip, attempts in host.auth_attempts.items():
                if attempts <= self.cfg.BRUTEFORCE_ATTEMPTS:
                    continue

                pair = window.pairs.get((host.host, dst_ip))
                auth_ports = sorted(
                    p
                    for p in (pair.dst_ports if pair else set())
                    if p in self.cfg.AUTH_PORTS
                )

                alerts.append(
                    Alert(
                        detector=self.name,
                        attack_class=CLASS_BRUTEFORCE,
                        src_ip=host.host,
                        dst_ip=dst_ip,
                        dst_port=auth_ports[0] if auth_ports else None,
                        protocol=6,
                        ts=window.end,
                        window_index=window.index,
                        severity=SEVERITY_HIGH,
                        score=float(attempts),
                        reason="%d connection attempts to an authentication port (> %d)"
                        % (attempts, self.cfg.BRUTEFORCE_ATTEMPTS),
                        evidence={
                            "attempts": attempts,
                            "auth_ports": auth_ports,
                        },
                    )
                )
        return alerts

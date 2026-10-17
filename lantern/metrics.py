"""Event logging and controller resource sampling.

Everything the controller observes is written as one append-only JSONL file per
run. Nothing is aggregated here: means, rates and coverage are all derived in
`experiments/analyze.py` from the raw events. Keeping derivation out of the
controller means a metric can be recomputed or corrected after the fact without
re-running an experiment, and it keeps measurement overhead off the detection
path.

Both a wall-clock and a monotonic timestamp are recorded on every event. The
monotonic clock is what durations are computed from -- it cannot jump backwards
-- while the wall clock is what lets a controller event be lined up against a
ground-truth marker written by a separate attack process.
"""

import json
import os
import time

from lantern import config


class EventLog:
    """Append-only JSONL writer."""

    def __init__(self, path, epoch=None):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(path, "a", buffering=1)
        self.epoch = epoch if epoch is not None else time.monotonic()
        self.count = 0

    def write(self, kind, payload=None):
        record = {
            "schema_version": 2,
            "mono": time.monotonic(),
            "kind": kind,
            "t": time.monotonic() - self.epoch,  # seconds since run start
            "wall": time.time(),
        }
        if payload:
            record.update(payload)
        self._fh.write(json.dumps(record, default=_json_default) + "\n")
        self.count += 1
        return record

    def close(self):
        try:
            self._fh.flush()
            self._fh.close()
        except (ValueError, OSError):
            pass


def _json_default(value):
    if isinstance(value, set):
        return sorted(value)
    return str(value)


class ResourceSampler:
    """Samples the controller process's own CPU and memory.

    This is the other half of Research Gap 4: a detector that is more accurate
    but eats the controller is not an improvement, and almost none of the
    surveyed papers report what their detector costs the control plane.
    """

    def __init__(self, event_log, interval=None, extra_snapshot=None):
        self.event_log = event_log
        self.interval = interval or config.RESOURCE_SAMPLE_INTERVAL
        self.extra_snapshot = extra_snapshot or (lambda: {})
        self._running = False
        self._thread = None
        self._process = None

        try:
            import psutil

            self._process = psutil.Process(os.getpid())
            # First call establishes the baseline; it always returns 0.0.
            self._process.cpu_percent(None)
        except Exception:
            self._process = None

    def start(self, spawn):
        """Start sampling. `spawn` is the green-thread spawner (ryu.lib.hub)."""
        if self._running:
            return
        self._running = True
        self._thread = spawn(self._loop)

    def stop(self):
        self._running = False
        self.sample()

    def _loop(self):
        from ryu.lib import hub

        while self._running:
            self.sample()
            hub.sleep(self.interval)

    def sample(self):
        payload = dict(self.extra_snapshot())
        if self._process is not None:
            try:
                memory = self._process.memory_info()
                payload.update(
                    {
                        "cpu_percent": self._process.cpu_percent(None),
                        "rss_bytes": memory.rss,
                        "num_threads": self._process.num_threads(),
                    }
                )
            except Exception:
                pass
        self.event_log.write("resource_sample", payload)


def run_log_path(case, trial, directory=None):
    directory = directory or config.RESULTS_RAW_DIR
    return os.path.join(directory, "%s_trial%02d.jsonl" % (case, trial))


def truth_log_path(case, trial, directory=None):
    directory = directory or config.RESULTS_RAW_DIR
    return os.path.join(directory, "%s_trial%02d_truth.jsonl" % (case, trial))


def write_truth_marker(path, marker):
    """Append one ground-truth marker from an attack script."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", buffering=1) as fh:
        fh.write(json.dumps(marker, default=_json_default) + "\n")

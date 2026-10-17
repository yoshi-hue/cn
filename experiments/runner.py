"""Orchestration for one experimental run: controller, topology, workload.

The lifecycle is fixed and identical for every case, because the comparison is
only meaningful if the two detectors meet the same conditions every time:

    start controller -> start topology -> WARMUP -> workload -> drain -> stop

The warmup is not padding. The graph detector scores each host against its own
established normal, so a run without warmup would either score against an empty
profile (alerting on everything) or refuse to score at all. Every case gets the
same warmup, attack cases included.
"""

import os
import signal
import json
import socket
import subprocess
import sys
import time


from lantern import config  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_for_port(port, host="127.0.0.1", timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((host, port)) == 0:
                return True
        finally:
            sock.close()
        time.sleep(0.25)
    return False


class Controller:
    """The Ryu process, run out-of-process so its CPU can be measured cleanly.

    Running the controller as a separate process rather than in-thread is what
    makes the resource metric honest: psutil then samples the detector's real
    cost, not the cost of the detector plus Mininet plus the harness.
    """

    def __init__(self, case, trial, mitigator, log_path, port=None, quiet=False):
        self.case = case
        self.trial = trial
        self.mitigator = mitigator
        self.log_path = log_path
        self.port = port or config.CONTROLLER_PORT
        self.quiet = quiet
        self.process = None
        self.stdout_path = log_path.replace(".jsonl", ".ryu.log")

    def start(self):
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        command = [
            "ryu-manager",
            "--ofp-tcp-listen-port",
            str(self.port),
            "lantern/app.py",
        ]
        environment = dict(
            os.environ,
            PYTHONPATH=REPO_ROOT,
            LANTERN_LOG=self.log_path,
            LANTERN_MITIGATOR=self.mitigator,
            LANTERN_CASE=self.case,
            LANTERN_TRIAL=str(self.trial),
        )
        # Re-created immediately before use rather than only at the top of
        # this method: the repository is a bind mount, and the host deleting
        # or recreating results/raw can leave the container's view of the
        # directory stale for a moment. Cheap insurance against losing a run
        # to a mount race.
        os.makedirs(os.path.dirname(self.stdout_path) or ".", exist_ok=True)
        self._stdout = open(self.stdout_path, "w", buffering=1)
        self.process = subprocess.Popen(
            command,
            cwd=REPO_ROOT,
            stdout=self._stdout,
            stderr=subprocess.STDOUT,
            env=environment,
        )

        if not wait_for_port(self.port):
            self.stop()
            raise RuntimeError(
                "controller did not start listening on port %d; see %s"
                % (self.port, self.stdout_path)
            )
        return self

    def stop(self, grace=8.0):
        """Interrupt rather than terminate.

        Ryu only runs its applications' close() hooks on KeyboardInterrupt, so
        SIGTERM would kill the process before the final overhead snapshot and
        any still-open window were written.
        """
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            deadline = time.time() + grace
            while time.time() < deadline and self.process.poll() is None:
                time.sleep(0.2)
            if self.process.poll() is None:
                self.process.kill()
        try:
            self._stdout.close()
        except Exception:
            pass
        self.process = None


class Workload:
    """Background traffic processes running inside Mininet host namespaces."""

    def __init__(self, net, case, trial):
        self.net = net
        self.case = case
        self.trial = trial
        self.processes = []
        self._log_handles = []
        self.attack_process = None
        self.controller = None

    # The attacker host runs normal traffic too, and that is not an oversight.
    #
    # The threat model is a *compromised workstation*: an ordinary machine that
    # behaved normally until an attacker took it over. Without a normal history
    # the attacker has no profile, and the graph detector -- which scores every
    # host against its own established normal -- would skip it entirely. It
    # would also be an unrealistically easy problem: a host whose very first
    # act on the network is to contact five machines needs no graph to spot.
    DEFAULT_NORMAL_HOSTS = list(config.WORKSTATIONS) + [config.ATTACKER]

    def start_normal(
        self,
        duration,
        rate=1.5,
        hosts=None,
        seed=None,
        peer_after=None,
        rate_switch_after=None,
    ):
        """Start the background client-server workload."""
        hosts = hosts or self.DEFAULT_NORMAL_HOSTS
        for index, name in enumerate(hosts):
            host = self.net.get(name)
            command = [
                "python3",
                "-m",
                "traffic.normal",
                "--src",
                config.HOST_TO_IP[name],
                "--duration",
                str(duration),
                "--rate",
                str(rate),
                "--case",
                self.case,
                "--trial",
                str(self.trial),
            ]
            if peer_after is not None:
                command += ["--peer-after", str(peer_after)]
            if rate_switch_after is not None:
                command += ["--rate-switch-after", str(rate_switch_after)]
            if seed is not None:
                command += ["--seed", str(seed + index)]
            # Redirected to a file rather than discarded: a background traffic
            # generator that dies silently would leave the graph detector with
            # no normal to profile, and the run would look merely quiet rather
            # than broken.
            log_path = os.path.join(
                config.RESULTS_RAW_DIR,
                "%s_trial%02d_normal_%s.log" % (self.case, self.trial, name),
            )
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            handle = open(log_path, "w", buffering=1)
            self._log_handles.append(handle)
            self.processes.append(
                host.popen(
                    command, cwd=REPO_ROOT, stdout=handle, stderr=subprocess.STDOUT
                )
            )
        return self

    def run_attack(self, module, host_name=None, extra_args=None):
        """Run one attack script to completion in its host's namespace."""
        host = self.net.get(host_name or config.ATTACKER)
        command = [
            "python3",
            "-m",
            module[:-3].replace("/", "."),
            "--case",
            self.case,
            "--trial",
            str(self.trial),
            "--src",
            config.HOST_TO_IP[host_name or config.ATTACKER],
        ] + list(extra_args or [])

        process = host.popen(
            command, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.attack_process = process
        while process.poll() is None:
            self.assert_alive()
            time.sleep(0.5)
        output, _ = process.communicate()
        if output:
            for line in output.decode("utf-8", "replace").splitlines():
                print("    [%s] %s" % (os.path.basename(module), line))
        return process.returncode

    def assert_alive(self):
        if self.controller and self.controller.process.poll() is not None:
            raise RuntimeError("controller exited during attack")
        dead = [p.returncode for p in self.processes if p.poll() is not None]
        if dead:
            raise RuntimeError("background process exited prematurely: %r" % dead)

    def start_measurements(self):
        prefix = os.path.join(
            config.RESULTS_RAW_DIR, "%s_trial%02d" % (self.case, self.trial)
        )
        for name, (ip, _, _, _) in config.HOSTS.items():
            host = self.net.get(name)
            for command in (
                ["python3", "-m", "traffic.service"],
                [
                    "python3",
                    "-m",
                    "traffic.observe",
                    "--ip",
                    ip,
                    "--iface",
                    str(host.defaultIntf()),
                    "--output",
                    prefix + "_receiver_" + name + ".jsonl",
                ],
            ):
                handle = open(prefix + "_" + name + "_" + command[2] + ".log", "w")
                self._log_handles.append(handle)
                self.processes.append(
                    host.popen(command, cwd=REPO_ROOT, stdout=handle, stderr=handle)
                )
        self.check_receivers(prefix)
        for name in self.DEFAULT_NORMAL_HOSTS:
            command = [
                "python3",
                "-m",
                "traffic.probe",
                "--source",
                config.HOST_TO_IP[name],
                "--target",
                config.HOST_TO_IP[config.APP_SERVER],
                "--output",
                prefix + "_probe_" + name + ".jsonl",
            ]
            handle = open(prefix + "_probe_" + name + ".log", "w")
            self._log_handles.append(handle)
            self.processes.append(
                self.net.get(name).popen(
                    command, cwd=REPO_ROOT, stdout=handle, stderr=handle
                )
            )

    def check_receivers(self, prefix):
        from experiments.validation import read_events, receiver_healthy

        paths = {name: prefix + "_receiver_" + name + ".jsonl" for name in config.HOSTS}
        deadline = time.monotonic() + 7
        while True:
            self.assert_alive()
            if all(os.path.exists(p) and any(e.get("ready") for e in read_events(p))
                   for p in paths.values()):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("receiver readiness timeout")
            time.sleep(0.1)
        for name, (ip, _, _, _) in config.HOSTS.items():
            sender = self.net.get("h1" if name != "h1" else "h2")
            code = (
                'from scapy.all import IP, UDP, send; '
                'send(IP(dst=%r,tos=32)/UDP(dport=29999),count=5,inter=0.02,verbose=False)' % ip
            )
            process = sender.popen(["python3", "-c", code], cwd=REPO_ROOT,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise RuntimeError("receiver health sender timeout: " + name)
            if process.returncode:
                raise RuntimeError("receiver health sender failed: " + name)
            deadline = time.monotonic() + 5
            while not receiver_healthy(read_events(paths[name])):
                self.assert_alive()
                if time.monotonic() >= deadline:
                    raise RuntimeError("receiver did not capture five health packets: " + name)
                time.sleep(0.1)

    def stop(self):
        if self.attack_process is not None and self.attack_process.poll() is None:
            self.attack_process.kill()
            self.attack_process.wait()
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.terminate()
            except Exception:
                pass
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        self.processes = []
        for handle in self._log_handles:
            try:
                handle.close()
            except Exception:
                pass
        self._log_handles = []


def dump_flows(net, path):
    """Record every switch's flow table at the end of a run.

    This is the independent check on the mitigation path: the JSONL log says
    the controller believes it installed a drop rule, and this says whether the
    switch actually has one.
    """
    lines = []
    for name in config.SWITCHES:
        switch = net.get(name)
        output = switch.dpctl("dump-flows", "-O", "OpenFlow13")
        lines.append("=== %s ===\n%s" % (name, output))
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    return "\n".join(lines)

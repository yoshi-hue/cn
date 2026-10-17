"""Isolated real-service forwarding, source/pair blocking, and expiry gates."""

import json
from pathlib import Path
import subprocess
import time
from lantern import config


def main():
    from experiments.runner import Controller
    from topo.lantern_topo import build_network, disable_offloads
    from mininet.log import setLogLevel

    setLogLevel("warning")
    directory = Path(config.RESULTS_RAW_DIR) / ("integration-%d" % time.time_ns())
    directory.mkdir(parents=True, exist_ok=False)
    controller = Controller(
        "integration", 0, "none", str(directory / "controller.jsonl")
    )
    net = None
    services = []
    checks = []

    def request(source, target):
        command = [
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--max-time",
            "1",
            "http://%s:8000/" % config.HOST_TO_IP[target],
        ]
        process = net.get(source).popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output, _ = process.communicate()
        return process.returncode == 0 and output.strip() == b"lantern-ok"

    def check(name, condition):
        checks.append(dict(check=name, passed=condition))
        if not condition:
            raise RuntimeError(name)

    try:
        controller.start()
        net = build_network()
        net.start()
        disable_offloads(net)
        net.staticArp()
        time.sleep(3)
        for name in ["server", "h5"]:
            services.append(
                net.get(name).popen(
                    ["python3", "-m", "traffic.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        time.sleep(2)
        check("service forwarding", request("h1", "server") and request("h1", "h5"))
        for pair in [False, True]:
            match = "ip,nw_src=10.0.0.1" + (",nw_dst=10.0.0.10" if pair else "")
            rule = "cookie=12345,priority=100,idle_timeout=3," + match + ",actions=drop"
            for switch in config.SWITCHES:
                subprocess.run(
                    ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", switch, rule],
                    check=True,
                )
                table = subprocess.check_output(
                    ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch], text=True
                )
                check("rule visible on " + switch, "cookie=0x3039" in table)
            check(
                ("pair" if pair else "source") + " blocked", not request("h1", "server")
            )
            check("innocent client remains connected", request("h2", "server"))
            if pair:
                check("pair block preserves other destination", request("h1", "h5"))
            else:
                check("source block covers other destination", not request("h1", "h5"))
            time.sleep(4)  # no packets from blocked source: idle expiry
            check("service recovers after idle expiry", request("h1", "server"))
        print(json.dumps(dict(passed=True, checks=checks)), flush=True)
    finally:
        for process in services:
            process.terminate()
            process.wait()
        if net:
            net.stop()
        controller.stop()
        (directory / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")


if __name__ == "__main__":
    main()

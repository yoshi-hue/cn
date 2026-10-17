"""Mininet topology for the Lantern experiments (report section 5.8).

    Ryu Controller
          |
    +-----+-----+
    |           |
  s1            s2
 / | \         / | \
h1 h2 h3     h4 h5 server

h1-h3 are ordinary workstations, h4 is the attacker, h5 is an authentication
server and `server` is the application/database host.

Datapath note
-------------
Docker Desktop runs a LinuxKit kernel with no `openvswitch` kernel module, so
every bridge here is forced onto the *userspace* (netdev) datapath. This is the
single most fragile part of the environment, which is why `--self-test` exists:
run it before anything else.
"""

import argparse
import sys

from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

from lantern import config  # noqa: E402


class UserspaceSwitch(OVSSwitch):
    """OVS bridge pinned to the netdev datapath and OpenFlow 1.3.

    Without datapath_type=netdev the bridge silently comes up but forwards
    nothing, because the kernel module it wants is absent.
    """

    def __init__(self, name, **params):
        params.setdefault("datapath", "user")
        params.setdefault("protocols", "OpenFlow13")
        OVSSwitch.__init__(self, name, **params)


class LanternTopo(Topo):
    """Two switches, six hosts, roles as declared in lantern/config.py."""

    # Links are plain veth pairs, with no traffic shaping.
    #
    # Shaping adds HTB queuing delay and jitter to every link, directly on top
    # of the millisecond-scale rule-installation and detection latencies this
    # project sets out to measure. Detection here is rate-based at the
    # controller rather than congestion-based, so shaping bought nothing and
    # cost measurement precision -- while emitting an HTB quantum warning on
    # every link setup, which buried real errors in the run logs.

    def build(self):
        switch_dpids = {}
        for index, name in enumerate(config.SWITCHES, start=1):
            switch_dpids[name] = self.addSwitch(name, dpid="%016x" % index)

        for host_name, (ip, mac, switch, _role) in config.HOSTS.items():
            host = self.addHost(host_name, ip="%s/24" % ip, mac=mac)
            self.addLink(host, switch_dpids[switch])

        for left, right in config.SWITCH_LINKS:
            self.addLink(switch_dpids[left], switch_dpids[right])


def build_network(controller_ip=None, controller_port=None):
    """Construct (but do not start) the Mininet network."""
    controller_ip = controller_ip or config.CONTROLLER_IP
    controller_port = controller_port or config.CONTROLLER_PORT

    net = Mininet(
        topo=LanternTopo(),
        switch=UserspaceSwitch,
        controller=None,
        autoSetMacs=False,
        cleanup=True,
    )
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )
    return net


def disable_offloads(net):
    """Userspace OVS cannot complete veth checksum/segmentation offloads.

    Without this, synthetic Scapy packets and ICMP pass but kernel TCP SYNs
    arrive with unfinished checksums and real HTTP connections time out.
    """
    for node in net.hosts + net.switches:
        for interface in node.intfList():
            if interface.name != "lo":
                node.cmd(
                    "ethtool -K %s tx off rx off tso off gso off gro off sg off"
                    % interface.name
                )


def self_test():
    """Gate 1: prove the userspace datapath forwards traffic under this kernel.

    Deliberately uses Mininet's built-in reference controller rather than the
    Lantern app, so that a failure here can only mean the environment is broken,
    never that our controller logic is.
    """
    from mininet.node import OVSController

    setLogLevel("info")
    info("*** Datapath self-test: userspace (netdev) OVS + reference controller\n")

    net = Mininet(
        topo=LanternTopo(),
        switch=UserspaceSwitch,
        controller=OVSController,
        cleanup=True,
    )
    try:
        net.start()
        loss = net.pingAll()
    finally:
        net.stop()

    if loss == 0.0:
        info("*** PASS: userspace datapath forwards traffic (0% loss)\n")
        return 0

    info("*** FAIL: %.1f%% packet loss on the userspace datapath.\n" % loss)
    info("*** Next step: run under Colima with a real kernel:\n")
    info("***   colima start --vm-type=vz --cpu 4 --memory 8\n")
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify the userspace datapath forwards traffic, then exit",
    )
    parser.add_argument("--controller-ip", default=config.CONTROLLER_IP)
    parser.add_argument("--controller-port", type=int, default=config.CONTROLLER_PORT)
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    from mininet.cli import CLI

    setLogLevel("info")
    net = build_network(args.controller_ip, args.controller_port)
    try:
        net.start()
        CLI(net)
    finally:
        net.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())

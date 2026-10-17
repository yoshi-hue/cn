# Third-party components

Lantern uses the following projects through their public packages or tools:

- Ryu: SDN controller framework (Apache-2.0).
- Mininet: network emulation (BSD-3-Clause), tag 2.3.0 verified against commit
  `d7f399d7a1200b602bd6a95ae88bae1009664d4a`.
- Open vSwitch: software switching (Apache-2.0).
- NetworkX: graph algorithms (BSD-3-Clause).
- Scapy: packet generation and observation (GPL-2.0).
- pytest: tests (MIT).
- NumPy, pandas, Matplotlib, and psutil: numerical support, visualization, and
  process measurement; their upstream distributions contain their license texts.
- Ubuntu and the Python standard library: container OS and runtime; individual
  package terms are retained in the installed distributions.

Exact installed package versions accompany each campaign in `dependencies.txt`.
The repository does not redistribute third-party source code or container layers
in its submission archive. This attribution does not assign a license to the
team's project. Upstream license files remain authoritative.

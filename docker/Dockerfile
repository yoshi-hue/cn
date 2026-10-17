# Lantern — Graph-Based SDN Controller-Integrated IDS
#
# Ubuntu 20.04 is chosen deliberately: its default Python is 3.8, which is the
# newest interpreter Ryu 4.34 works on reliably (Ryu depends on eventlet, whose
# monkey-patching broke on Python 3.10+ and on eventlet >= 0.31). Ubuntu 22.04
# would give us a Python 3 Mininet package but a Python 3.10 that Ryu cannot use.
FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# numpy/pandas/matplotlib/psutil come from apt rather than pip: PyPI has no
# Python 3.8 aarch64 wheels for them, so pip would compile each from source on
# an Apple Silicon host. build-essential remains for the few small C extensions
# pip still builds (greenlet, msgpack) and for Mininet's mnexec.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-dev python3-setuptools build-essential git \
        python3-numpy python3-pandas python3-matplotlib python3-psutil \
        openvswitch-switch openvswitch-common openvswitch-testcontroller \
        iproute2 iputils-ping net-tools ethtool socat iperf3 tcpdump curl telnet \
        procps psmisc ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && (service openvswitch-testcontroller stop 2>/dev/null || true) \
    && update-rc.d openvswitch-testcontroller disable 2>/dev/null || true

# Ubuntu 20.04's `mininet` package is Python 2 only, so Mininet is built from
# source at the 2.3.0 tag, which is the first release with full Python 3
# support. mnexec is a small C helper Mininet shells out to for namespace entry.
RUN git clone --depth 1 --branch 2.3.0 https://github.com/mininet/mininet.git /tmp/mininet \
    && cd /tmp/mininet \
    && test "$(git rev-parse HEAD)" = d7f399d7a1200b602bd6a95ae88bae1009664d4a \
    && make mnexec \
    && install -m 755 mnexec /usr/local/bin/mnexec \
    && python3 setup.py install \
    && rm -rf /tmp/mininet

# Ryu 4.34 is the last release; it is unmaintained, so every transitive
# dependency that has since broken compatibility is pinned explicitly here.
COPY docker/requirements.txt docker/constraints.txt /tmp/
RUN python3 -m pip install --no-cache-dir --upgrade "pip==21.3.1" "setuptools==59.8.0" "wheel==0.45.1" \
    && python3 -m pip install --no-cache-dir -c /tmp/constraints.txt -r /tmp/requirements.txt

WORKDIR /opt/lantern
ENV PYTHONPATH=/opt/lantern
# Headless container: matplotlib must not try to find a display.
ENV MPLBACKEND=Agg

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]

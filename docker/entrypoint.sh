#!/usr/bin/env bash
# Bring up Open vSwitch inside the container before handing over to the command.
#
# Docker Desktop's LinuxKit kernel has no openvswitch kernel module, so every
# bridge must run on the userspace (netdev) datapath. ovs-vswitchd is started
# without --detach-controller-probes tweaks; Mininet sets the rest per-bridge.
set -euo pipefail

OVS_RUN=/var/run/openvswitch
OVS_DB=/etc/openvswitch/conf.db

mkdir -p "$OVS_RUN" /var/log/openvswitch /etc/openvswitch

if [ ! -f "$OVS_DB" ]; then
    ovsdb-tool create "$OVS_DB" /usr/share/openvswitch/vswitch.ovsschema
fi

if ! pgrep -x ovsdb-server >/dev/null 2>&1; then
    ovsdb-server "$OVS_DB" \
        --remote=punix:"$OVS_RUN/db.sock" \
        --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
        --pidfile --detach --log-file
    ovs-vsctl --no-wait init
fi

if ! pgrep -x ovs-vswitchd >/dev/null 2>&1; then
    ovs-vswitchd --pidfile --detach --log-file
fi

# Mininet needs this; the image has no running init to create it.
mkdir -p /var/run/netns

exec "$@"

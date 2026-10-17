"""Shared fixtures: synthetic FlowRecords, so no Mininet or root is needed."""

import sys

import pytest


from lantern.features import PROTO_TCP, FlowRecord, WindowAggregator  # noqa: E402

TCP_SYN = 0x02


def record(
    src,
    dst,
    ts=1.0,
    port=80,
    packets=1,
    bytes_=64,
    protocol=PROTO_TCP,
    flags=0,
    src_port=40000,
    is_initiation=None,
):
    # Synthetic records default to being initiations, because every fixture
    # here models a host reaching out rather than replying. Reply traffic is
    # constructed explicitly with is_initiation=False.
    if is_initiation is None:
        is_initiation = True
    return FlowRecord(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=port,
        packets=packets,
        bytes=bytes_,
        tcp_flags=flags,
        is_initiation=is_initiation,
    )


def build_window(records, window_seconds=10.0):
    """Push records through the aggregator and return the one closed window."""
    aggregator = WindowAggregator(window_seconds=window_seconds, epoch=0.0)
    for item in records:
        aggregator.add(item)
    closed = aggregator.close_all()
    assert len(closed) == 1, "fixture expects all records inside one window"
    return closed[0]


@pytest.fixture
def make_record():
    return record


@pytest.fixture
def make_window():
    return build_window

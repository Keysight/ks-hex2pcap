"""Tests for pcap writer."""

import struct
import os

from hex2pcap.pcap_writer import write_pcap


def test_write_single_packet(tmp_path):
    # Minimal Ethernet frame (14 bytes header + 4 bytes payload)
    pkt = bytes.fromhex("ffffffffffff001122334455080600010800")
    out = str(tmp_path / "test.pcap")

    write_pcap(out, [pkt], base_timestamp=1000000.0)

    with open(out, "rb") as f:
        data = f.read()

    # Global header: 24 bytes
    assert len(data) == 24 + 16 + len(pkt)

    # Check magic number
    magic = struct.unpack_from("<I", data, 0)[0]
    assert magic == 0xA1B2C3D4

    # Check link type (Ethernet)
    link_type = struct.unpack_from("<I", data, 20)[0]
    assert link_type == 1

    # Check packet record header
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", data, 24)
    assert ts_sec == 1000000
    assert ts_usec == 0
    assert incl_len == len(pkt)
    assert orig_len == len(pkt)

    # Check packet data
    assert data[40:] == pkt


def test_timestamp_increment(tmp_path):
    pkt = bytes(18)  # 18-byte dummy packet
    out = str(tmp_path / "multi.pcap")

    write_pcap(out, [pkt, pkt, pkt], base_timestamp=500.0)

    with open(out, "rb") as f:
        data = f.read()

    # 3 packets: global header + 3 * (16 + 18)
    assert len(data) == 24 + 3 * 34

    offsets = [24, 24 + 34, 24 + 68]
    for i, off in enumerate(offsets):
        ts_sec, ts_usec = struct.unpack_from("<II", data, off)
        assert ts_sec == 500
        assert ts_usec == i  # 0, 1, 2 microseconds


def test_default_timestamp(tmp_path):
    pkt = bytes(14)
    out = str(tmp_path / "default_ts.pcap")

    write_pcap(out, [pkt])

    assert os.path.exists(out)
    assert os.path.getsize(out) == 24 + 16 + 14


def test_per_packet_timestamps(tmp_path):
    pkt = bytes(18)
    out = str(tmp_path / "per_pkt.pcap")

    write_pcap(out, [pkt, pkt, pkt],
               timestamps=[1000.5, 2000.75, 3000.0])

    with open(out, "rb") as f:
        data = f.read()

    record_size = 16 + 18
    offsets = [24, 24 + record_size, 24 + 2 * record_size]
    expected = [(1000, 500000), (2000, 750000), (3000, 0)]

    for off, (exp_sec, exp_usec) in zip(offsets, expected):
        ts_sec, ts_usec = struct.unpack_from("<II", data, off)
        assert ts_sec == exp_sec
        assert ts_usec == exp_usec


def test_mixed_timestamps_and_fallback(tmp_path):
    pkt = bytes(18)
    out = str(tmp_path / "mixed_ts.pcap")

    write_pcap(out, [pkt, pkt, pkt],
               base_timestamp=500.0,
               timestamps=[1000.0, None, 2000.0])

    with open(out, "rb") as f:
        data = f.read()

    record_size = 16 + 18

    # Packet 1: explicit timestamp 1000.0
    ts_sec, ts_usec = struct.unpack_from("<II", data, 24)
    assert ts_sec == 1000
    assert ts_usec == 0

    # Packet 2: fallback to base_timestamp 500.0 + 0us (first fallback)
    ts_sec, ts_usec = struct.unpack_from("<II", data, 24 + record_size)
    assert ts_sec == 500
    assert ts_usec == 0

    # Packet 3: explicit timestamp 2000.0
    ts_sec, ts_usec = struct.unpack_from("<II", data, 24 + 2 * record_size)
    assert ts_sec == 2000
    assert ts_usec == 0


def test_timestamps_none_uses_base(tmp_path):
    pkt = bytes(18)
    out = str(tmp_path / "none_ts.pcap")

    write_pcap(out, [pkt, pkt], base_timestamp=500.0, timestamps=None)

    with open(out, "rb") as f:
        data = f.read()

    record_size = 16 + 18
    for i in range(2):
        ts_sec, ts_usec = struct.unpack_from("<II", data, 24 + i * record_size)
        assert ts_sec == 500
        assert ts_usec == i

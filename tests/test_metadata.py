"""Tests for metadata extraction and vendor plugins."""

import os
import struct

import pytest

from hex2pcap.metadata import MetadataPlugin, MetadataResult, extract_metadata
from hex2pcap.parser import ParsedPacket
from hex2pcap.vendors import get_vendor, available_vendors
from hex2pcap.vendors.edav2 import Edav2Plugin
from hex2pcap.md_writer import write_metadata_md
from hex2pcap.csv_parser import parse_csv_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# --- Plugin registry tests ---

def test_get_vendor_edav2():
    plugin = get_vendor("edav2")
    assert isinstance(plugin, Edav2Plugin)
    assert plugin.name == "edav2"


def test_get_vendor_unknown():
    with pytest.raises(ValueError, match="Unknown vendor"):
        get_vendor("nonexistent")


def test_available_vendors():
    vendors = available_vendors()
    assert "edav2" in vendors


# --- extract_metadata tests ---

def _make_packet(meta_bytes, eth_bytes, ts=None):
    return ParsedPacket(data=meta_bytes + eth_bytes, timestamp=ts)


class DummyPlugin(MetadataPlugin):
    name = "dummy"

    def parse(self, raw, packet_id):
        return MetadataResult(
            packet_id=packet_id,
            raw_bytes=raw,
            metadata_type="DUMMY",
            fields={"size": len(raw)},
        )


def test_extract_metadata_splits_correctly():
    meta = b"\x01\x02\x03\x04"
    eth = bytes(42)
    packets = [_make_packet(meta, eth, ts=100.0)]

    trimmed, results = extract_metadata(packets, 4, DummyPlugin())

    assert len(trimmed) == 1
    assert len(results) == 1
    assert trimmed[0].data == eth
    assert trimmed[0].timestamp == 100.0
    assert results[0].raw_bytes == meta
    assert results[0].packet_id == 1


def test_extract_metadata_short_packet(capsys):
    packets = [ParsedPacket(data=b"\x01\x02")]
    trimmed, results = extract_metadata(packets, 10, DummyPlugin())

    assert len(trimmed) == 0
    assert len(results) == 0
    assert "shorter than eth_offset" in capsys.readouterr().out


def test_extract_metadata_preserves_timestamps():
    packets = [
        _make_packet(b"\x00" * 4, bytes(20), ts=1.0),
        _make_packet(b"\x00" * 4, bytes(20), ts=2.0),
    ]
    trimmed, _ = extract_metadata(packets, 4, DummyPlugin())
    assert [p.timestamp for p in trimmed] == [1.0, 2.0]


def test_extract_metadata_empty_eth_part():
    """Metadata-only packet (no Ethernet) is excluded from trimmed but in results."""
    packets = [ParsedPacket(data=b"\x00" * 8)]
    trimmed, results = extract_metadata(packets, 8, DummyPlugin())

    assert len(trimmed) == 0  # no Ethernet data
    assert len(results) == 1  # metadata still recorded


# --- EDA v2 plugin tests ---

def _make_edav2_rx_pkt(flags=2, emu_time=1000000, latency=500):
    hdr = struct.pack("<HH", 1, 3)  # mrg=1, type=EDA_RX_PKT
    payload = struct.pack("<IQQ", flags, emu_time, latency)
    payload += b"\x00" * (44 - 20)
    return hdr + payload


def _make_edav2_tx_pkt(flags=1, ifg=2000):
    hdr = struct.pack("<HH", 1, 2)  # mrg=1, type=EDA_TX_PKT
    payload = struct.pack("<IQ", flags, ifg)
    payload += b"\x00" * (44 - 12)
    return hdr + payload


def _make_edav2_heartbeat(flags=0, emu_time=2000000):
    hdr = struct.pack("<HH", 1, 4)  # mrg=1, type=EDA_ET_HEARTBEAT
    payload = struct.pack("<IQ", flags, emu_time)
    payload += b"\x00" * (44 - 12)
    return hdr + payload


def test_edav2_parse_rx_pkt():
    plugin = Edav2Plugin()
    raw = _make_edav2_rx_pkt(flags=0x02, emu_time=12345, latency=678)
    result = plugin.parse(raw, 1)

    assert result.metadata_type == "EDA_RX_PKT"
    assert result.fields["mrg_num_buffers"] == 1
    assert result.fields["flags"] == "0x00000002"
    assert result.fields["emulator_time"] == 12345
    assert result.fields["latency"] == 678


def test_edav2_parse_tx_pkt():
    plugin = Edav2Plugin()
    raw = _make_edav2_tx_pkt(flags=0x01, ifg=5000)
    result = plugin.parse(raw, 2)

    assert result.metadata_type == "EDA_TX_PKT"
    assert result.fields["flags"] == "0x00000001"
    assert result.fields["ifg"] == 5000


def test_edav2_parse_heartbeat():
    plugin = Edav2Plugin()
    raw = _make_edav2_heartbeat(flags=0, emu_time=9999)
    result = plugin.parse(raw, 3)

    assert result.metadata_type == "EDA_ET_HEARTBEAT"
    assert result.fields["flags"] == "0x00000000"
    assert result.fields["emulator_time"] == 9999


def test_edav2_parse_nop():
    plugin = Edav2Plugin()
    raw = struct.pack("<HH", 1, 0) + b"\x00" * 44
    result = plugin.parse(raw, 1)
    assert result.metadata_type == "EDA_NOP"


def test_edav2_parse_register_port():
    plugin = Edav2Plugin()
    hdr = struct.pack("<HH", 1, 1)
    payload = struct.pack("<IQB", 42, 12345678, 0)
    payload += b"\x00" * (44 - 13)
    raw = hdr + payload
    result = plugin.parse(raw, 1)

    assert result.metadata_type == "EDA_REGISTER_PORT"
    assert result.fields["event"] == 42
    assert result.fields["port_id"] == 12345678


def test_edav2_parse_short_metadata():
    plugin = Edav2Plugin()
    result = plugin.parse(b"\x01\x02", 1)
    assert result.metadata_type == "UNKNOWN"


# --- Markdown writer tests ---

def test_write_metadata_md(tmp_path):
    results = [
        MetadataResult(
            packet_id=1, raw_bytes=b"\x00",
            metadata_type="EDA_RX_PKT",
            fields={"metadata_type": "EDA_RX_PKT", "flags": "0x02", "emulator_time": 1000},
        ),
        MetadataResult(
            packet_id=2, raw_bytes=b"\x00",
            metadata_type="EDA_TX_PKT",
            fields={"metadata_type": "EDA_TX_PKT", "flags": "0x01", "ifg": 2000},
        ),
    ]

    md_path = str(tmp_path / "meta.md")
    write_metadata_md(md_path, results, "edav2")

    content = open(md_path).read()
    assert "# Packet Metadata (vendor: edav2)" in content
    assert "## Packet 1" in content
    assert "## Packet 2" in content
    assert "EDA_RX_PKT" in content
    assert "EDA_TX_PKT" in content
    assert "| flags | 0x02 |" in content


# --- Integration test with CSV fixture ---

def test_edav2_csv_end_to_end():
    """Full pipeline: CSV with metadata -> extract -> verify."""
    parsed = parse_csv_file(os.path.join(FIXTURES, "edav2_metadata.csv"))
    assert len(parsed) == 3

    plugin = Edav2Plugin()
    trimmed, metadata = extract_metadata(parsed, 48, plugin)

    # Packets 1 and 2 have Ethernet frames, packet 3 is heartbeat-only
    assert len(trimmed) == 2
    assert len(metadata) == 3

    # Packet 1: ARP
    assert len(trimmed[0].data) == 42
    assert trimmed[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"

    # Metadata for packet 1: EDA_RX_PKT
    assert metadata[0].metadata_type == "EDA_RX_PKT"
    assert metadata[0].fields["emulator_time"] == 1000000
    assert metadata[0].fields["latency"] == 500

    # Metadata for packet 2: EDA_TX_PKT
    assert metadata[1].metadata_type == "EDA_TX_PKT"
    assert metadata[1].fields["ifg"] == 2000

    # Metadata for packet 3: EDA_ET_HEARTBEAT (no Ethernet)
    assert metadata[2].metadata_type == "EDA_ET_HEARTBEAT"
    assert metadata[2].fields["emulator_time"] == 2000000


def test_edav2_csv_md_output(tmp_path):
    """Full pipeline including markdown output."""
    parsed = parse_csv_file(os.path.join(FIXTURES, "edav2_metadata.csv"))
    plugin = Edav2Plugin()
    trimmed, metadata = extract_metadata(parsed, 48, plugin)

    md_path = str(tmp_path / "output_metadata.md")
    write_metadata_md(md_path, metadata, plugin.name)

    content = open(md_path).read()
    assert "## Packet 1" in content
    assert "## Packet 2" in content
    assert "## Packet 3" in content
    assert "EDA_RX_PKT" in content
    assert "EDA_TX_PKT" in content
    assert "EDA_ET_HEARTBEAT" in content


def test_edav2_cap_metadata():
    """Real-world edav2_cap.csv with EDA v2 metadata at eth_offset=48."""
    parsed = parse_csv_file(os.path.join(FIXTURES, "edav2_cap.csv"))
    assert len(parsed) == 266

    plugin = Edav2Plugin()
    trimmed, metadata = extract_metadata(parsed, 48, plugin)

    assert len(trimmed) == 266
    assert len(metadata) == 266

    # All packets have EDA_RX_PKT metadata
    assert all(m.metadata_type == "EDA_RX_PKT" for m in metadata)

    # First packet metadata
    m0 = metadata[0]
    assert m0.fields["mrg_num_buffers"] == 1
    assert m0.fields["metadata_type"] == "EDA_RX_PKT"
    assert m0.fields["flags"] == "0x00000002"
    assert m0.fields["emulator_time"] == 14683052179900
    assert m0.fields["latency"] == 0

    # Trimmed packets start with Ethernet (dst MAC 52:54:00:00:00:00)
    assert trimmed[0].data[:6] == b"\x52\x54\x00\x00\x00\x00"
    # EtherType 0x86dd = IPv6
    assert trimmed[0].data[12:14] == b"\x86\xdd"

    # Timestamps from system_ns column (auto-detected)
    assert all(p.timestamp is not None for p in trimmed)

    # Emulator times should be monotonically non-decreasing
    emu_times = [m.fields["emulator_time"] for m in metadata]
    for i in range(1, len(emu_times)):
        assert emu_times[i] >= emu_times[i - 1]

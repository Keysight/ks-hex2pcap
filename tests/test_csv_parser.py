"""Tests for CSV hex dump parser."""

import os

import pytest

from hex2pcap.csv_parser import parse_csv_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_basic_single_hex_column():
    packets = parse_csv_file(os.path.join(FIXTURES, "basic_hex.csv"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"
    assert packets[0].data[12:14] == b"\x08\x06"
    assert packets[0].timestamp is None


def test_consecutive_hex_columns_merged():
    packets = parse_csv_file(os.path.join(FIXTURES, "multi_col_hex.csv"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"
    assert packets[0].data[12:14] == b"\x08\x06"


def test_single_and_multi_col_produce_same_data():
    single = parse_csv_file(os.path.join(FIXTURES, "basic_hex.csv"))
    multi = parse_csv_file(os.path.join(FIXTURES, "multi_col_hex.csv"))
    assert [p.data for p in single] == [p.data for p in multi]


def test_timestamp_ns_column():
    packets = parse_csv_file(os.path.join(FIXTURES, "timestamp_ns.csv"))
    assert len(packets) == 2
    # 1705314600123456000 ns = 1705314600.123456 seconds
    assert packets[0].timestamp == pytest.approx(1705314600.123456, rel=1e-6)
    assert packets[1].timestamp == pytest.approx(1705314601.654321, rel=1e-6)


def test_timestamp_ms_column():
    packets = parse_csv_file(os.path.join(FIXTURES, "timestamp_ms.csv"))
    assert len(packets) == 2
    # 1705314600123.456 ms = 1705314600.123456 seconds
    assert packets[0].timestamp == pytest.approx(1705314600.123456, rel=1e-6)
    assert packets[1].timestamp == pytest.approx(1705314601.654321, rel=1e-6)


def test_multiple_ts_columns_picks_first():
    """When multiple columns have time units, the first one is used."""
    packets = parse_csv_file(os.path.join(FIXTURES, "multi_ts_cols.csv"))
    assert len(packets) == 2
    # elapsed_us comes first: 500000 us = 0.5 seconds
    assert packets[0].timestamp == pytest.approx(0.5)
    assert packets[1].timestamp == pytest.approx(1.5)


def test_empty_csv(tmp_path):
    f = tmp_path / "empty.csv"
    f.write_text("col1,col2\n")
    packets = parse_csv_file(str(f))
    assert packets == []


def test_no_hex_columns(tmp_path):
    f = tmp_path / "no_hex.csv"
    f.write_text("name,value\nfoo,123\nbar,456\n")
    packets = parse_csv_file(str(f))
    assert packets == []


def test_skip_invalid_rows(tmp_path):
    f = tmp_path / "bad_row.csv"
    f.write_text(
        "hex_data\n"
        "ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
        "ZZZZ_not_hex\n"
        "001122334455aabbccddeeff08004500003c00010000400100007f0000017f0000010800000000010001\n"
    )
    packets = parse_csv_file(str(f), skip_invalid=True)
    assert len(packets) == 2


def test_space_separated_hex_in_csv(tmp_path):
    f = tmp_path / "spaced.csv"
    f.write_text(
        "hex_data\n"
        "ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01 08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01 00 00 00 00 00 00 c0 a8 00 02\n"
    )
    packets = parse_csv_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42


def test_backslash_x_hex_in_csv(tmp_path):
    f = tmp_path / "bx.csv"
    f.write_text(
        "hex_data\n"
        "\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x11\\x22\\x33\\x44\\x55\\x08\\x06\\x00\\x01\\x08\\x00\\x06\\x04\\x00\\x01\\x00\\x11\\x22\\x33\\x44\\x55\\xc0\\xa8\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\xc0\\xa8\\x00\\x02\n"
    )
    packets = parse_csv_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42


def test_timestamp_column_variations(tmp_path):
    """Various time unit header formats are recognized."""
    for header in ["time_us", "ts (microseconds)", "elapsed_sec",
                    "capture_ps", "delta_milliseconds"]:
        f = tmp_path / "ts_var.csv"
        f.write_text(
            f"{header},hex_data\n"
            "1000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
        )
        packets = parse_csv_file(str(f))
        assert len(packets) == 1
        assert packets[0].timestamp is not None, f"Failed for header: {header}"


def test_bpftrace_csv():
    """Real-world bpftrace capture with \\x hex and nsecs timestamp column."""
    packets = parse_csv_file(os.path.join(FIXTURES, "bpftrace_28gbps.csv"))
    assert len(packets) == 263
    # All packets are 60 bytes (Ethernet + IPv6 + partial TCP/UDP)
    assert all(len(p.data) == 60 for p in packets)
    # First packet starts with dst MAC 52:54:00:00:00:00
    assert packets[0].data[:6] == b"\x52\x54\x00\x00\x00\x00"
    # EtherType 0x86dd = IPv6
    assert packets[0].data[12:14] == b"\x86\xdd"
    # Timestamps from sys_nsecs column (nanoseconds -> seconds)
    assert all(p.timestamp is not None for p in packets)
    assert packets[0].timestamp == pytest.approx(10175.982028632, rel=1e-9)
    # Timestamps should be monotonically non-decreasing
    for i in range(1, len(packets)):
        assert packets[i].timestamp >= packets[i - 1].timestamp


def test_nsec_header_variations(tmp_path):
    """Headers like nsec, nsecs, usec, msec are recognized."""
    for header, unit_s in [("sys_nsecs", 1e-9), ("delta_nsec", 1e-9),
                           ("time_usec", 1e-6), ("elapsed_msecs", 1e-3),
                           ("capture_psec", 1e-12), ("duration_secs", 1.0)]:
        f = tmp_path / "ts_var.csv"
        f.write_text(
            f"{header},hex_data\n"
            "1000000000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
        )
        packets = parse_csv_file(str(f))
        assert len(packets) == 1
        assert packets[0].timestamp == pytest.approx(1000000000 * unit_s), \
            f"Failed for header: {header}"


def test_explicit_timestamp_column():
    """User can specify which column to use as timestamp."""
    packets = parse_csv_file(
        os.path.join(FIXTURES, "bpftrace_28gbps.csv"),
        timestamp_column="rx_eda_ts",
    )
    assert len(packets) == 263
    # rx_eda_ts doesn't have a time unit in the header, so treated as seconds
    assert packets[0].timestamp == pytest.approx(2430854071100.0)


def test_explicit_timestamp_column_with_unit(tmp_path):
    """Explicit column with time unit in header gets correct conversion."""
    f = tmp_path / "explicit.csv"
    f.write_text(
        "seq,elapsed_us,capture_ns,hex_data\n"
        "1,500000,1705314600123456000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    # Pick capture_ns explicitly (second ts column, not the first)
    packets = parse_csv_file(str(f), timestamp_column="capture_ns")
    assert len(packets) == 1
    assert packets[0].timestamp == pytest.approx(1705314600.123456, rel=1e-6)


def test_explicit_timestamp_column_not_found(tmp_path):
    """Specifying a non-existent column raises ValueError."""
    f = tmp_path / "missing.csv"
    f.write_text(
        "seq,hex_data\n"
        "1,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    with pytest.raises(ValueError, match="not found"):
        parse_csv_file(str(f), timestamp_column="no_such_column")


def test_explicit_ts_unit_override():
    """User specifies --ts-column and --ts-unit for a column without unit in header."""
    packets = parse_csv_file(
        os.path.join(FIXTURES, "bpftrace_28gbps.csv"),
        timestamp_column="rx_eda_ts",
        timestamp_unit="ns",
    )
    assert len(packets) == 263
    # rx_eda_ts first value: 2430854071100 ns = 2430.854071100 seconds
    assert packets[0].timestamp == pytest.approx(2430.8540711, rel=1e-6)


def test_ts_unit_overrides_header_unit(tmp_path):
    """--ts-unit overrides the unit detected from the column header."""
    f = tmp_path / "override.csv"
    f.write_text(
        "capture_ns,hex_data\n"
        "1000000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    # Header says ns, but user says us
    packets = parse_csv_file(str(f), timestamp_unit="us")
    assert len(packets) == 1
    # 1000000 us = 1.0 seconds (not 0.001 seconds as ns would give)
    assert packets[0].timestamp == pytest.approx(1.0)


def test_ts_unit_without_ts_column(tmp_path):
    """--ts-unit works with auto-detected timestamp column too."""
    f = tmp_path / "auto_unit.csv"
    f.write_text(
        "capture_ns,hex_data\n"
        "1000000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    # Auto-detects capture_ns, but user overrides unit to ms
    packets = parse_csv_file(str(f), timestamp_unit="ms")
    assert len(packets) == 1
    # 1000000 ms = 1000.0 seconds
    assert packets[0].timestamp == pytest.approx(1000.0)


def test_invalid_ts_unit(tmp_path):
    """Unknown time unit raises ValueError."""
    f = tmp_path / "bad_unit.csv"
    f.write_text(
        "ts,hex_data\n"
        "1000,ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    with pytest.raises(ValueError, match="Unknown time unit"):
        parse_csv_file(str(f), timestamp_column="ts", timestamp_unit="fortnight")

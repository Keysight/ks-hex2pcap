"""Tests for hex dump parser."""

import os
from datetime import datetime

import pytest

from hex2pcap.parser import parse_hex_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_plain_hex():
    packets = parse_hex_file(os.path.join(FIXTURES, "plain_hex.txt"))
    assert len(packets) == 2
    # First packet is ARP (42 bytes)
    assert len(packets[0].data) == 42
    # Dst MAC is broadcast
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"
    # EtherType 0x0806 = ARP
    assert packets[0].data[12:14] == b"\x08\x06"
    # No timestamps in this file
    assert packets[0].timestamp is None
    assert packets[1].timestamp is None


def test_space_separated():
    packets = parse_hex_file(os.path.join(FIXTURES, "space_separated.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"


def test_wireshark_style():
    packets = parse_hex_file(os.path.join(FIXTURES, "wireshark_style.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"


def test_all_formats_produce_same_data():
    plain = parse_hex_file(os.path.join(FIXTURES, "plain_hex.txt"))
    spaced = parse_hex_file(os.path.join(FIXTURES, "space_separated.txt"))
    wireshark = parse_hex_file(os.path.join(FIXTURES, "wireshark_style.txt"))
    plain_data = [p.data for p in plain]
    spaced_data = [p.data for p in spaced]
    wireshark_data = [p.data for p in wireshark]
    assert plain_data == spaced_data == wireshark_data


def test_too_short_packet(tmp_path):
    f = tmp_path / "short.txt"
    f.write_text("ffffffffffff0011\n")
    with pytest.raises(ValueError, match="minimum Ethernet"):
        parse_hex_file(str(f))


def test_skip_invalid(tmp_path):
    f = tmp_path / "mixed.txt"
    # First packet too short, second is valid ARP
    f.write_text(
        "ffffffffffff0011\n"
        "\n"
        "ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    packets = parse_hex_file(str(f), skip_invalid=True)
    assert len(packets) == 1
    assert len(packets[0].data) == 42


def test_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("")
    packets = parse_hex_file(str(f))
    assert packets == []


def test_comments_only(tmp_path):
    f = tmp_path / "comments.txt"
    f.write_text("# just a comment\n# another\n")
    packets = parse_hex_file(str(f))
    assert packets == []


def test_wireshark_with_text():
    packets = parse_hex_file(os.path.join(FIXTURES, "wireshark_with_text.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"
    assert packets[0].data[12:14] == b"\x08\x06"


def test_wireshark_with_text_matches_plain():
    with_text = parse_hex_file(os.path.join(FIXTURES, "wireshark_with_text.txt"))
    without_text = parse_hex_file(os.path.join(FIXTURES, "wireshark_style.txt"))
    assert [p.data for p in with_text] == [p.data for p in without_text]


def test_text_lines_ignored(tmp_path):
    f = tmp_path / "with_text.txt"
    # Text lines mixed in with a valid ARP packet
    f.write_text(
        "This is a description of the packet\n"
        "ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
        "End of packet\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"


def test_text_only_lines(tmp_path):
    f = tmp_path / "text_only.txt"
    f.write_text("Just some random text\nNo hex here\n")
    packets = parse_hex_file(str(f))
    assert packets == []


# --- Timestamp tests ---

def _expected_ts(dt_str):
    """Helper to get expected Unix timestamp from a datetime string."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(dt_str, fmt).timestamp()
        except ValueError:
            continue


def test_comment_timestamp_parsed():
    packets = parse_hex_file(os.path.join(FIXTURES, "comment_timestamps.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert len(packets[1].data) == 42
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00.123456"))
    assert packets[1].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:01.654321"))


def test_inline_timestamp_parsed():
    packets = parse_hex_file(os.path.join(FIXTURES, "inline_timestamps.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert len(packets[1].data) == 42
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00.123456"))
    assert packets[1].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:01.654321"))


def test_comment_and_inline_produce_same_data():
    comment = parse_hex_file(os.path.join(FIXTURES, "comment_timestamps.txt"))
    inline = parse_hex_file(os.path.join(FIXTURES, "inline_timestamps.txt"))
    assert [p.data for p in comment] == [p.data for p in inline]
    assert [p.timestamp for p in comment] == [p.timestamp for p in inline]


def test_timestamp_without_microseconds(tmp_path):
    f = tmp_path / "no_usec.txt"
    f.write_text(
        "# 2024-01-15 10:30:00\n"
        "ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00"))


def test_comment_without_timestamp_no_ts(tmp_path):
    f = tmp_path / "plain_comment.txt"
    f.write_text(
        "# ARP request packet\n"
        "ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert packets[0].timestamp is None


def test_inline_timestamp_overrides_comment(tmp_path):
    f = tmp_path / "both.txt"
    f.write_text(
        "# 2024-01-15 10:30:00.000000\n"
        "2024-01-15 11:00:00.000000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01\n"
        "08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01\n"
        "00 00 00 00 00 00 c0 a8 00 02\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    # Inline timestamp should override the comment timestamp
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 11:00:00.000000"))


# --- Backslash-x hex format tests ---

def test_backslash_x_hex():
    packets = parse_hex_file(os.path.join(FIXTURES, "backslash_x_hex.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"
    assert packets[0].data[12:14] == b"\x08\x06"


def test_backslash_x_matches_plain():
    bx = parse_hex_file(os.path.join(FIXTURES, "backslash_x_hex.txt"))
    plain = parse_hex_file(os.path.join(FIXTURES, "plain_hex.txt"))
    assert [p.data for p in bx] == [p.data for p in plain]


def test_backslash_x_space_separated(tmp_path):
    """\\x-prefixed bytes with spaces between them."""
    f = tmp_path / "bx_spaced.txt"
    f.write_text(
        "\\xff \\xff \\xff \\xff \\xff \\xff \\x00 \\x11 \\x22 \\x33 \\x44 \\x55 "
        "\\x08 \\x06 \\x00 \\x01 \\x08 \\x00 \\x06 \\x04 \\x00 \\x01 "
        "\\x00 \\x11 \\x22 \\x33 \\x44 \\x55 \\xc0 \\xa8 \\x00 \\x01 "
        "\\x00 \\x00 \\x00 \\x00 \\x00 \\x00 \\xc0 \\xa8 \\x00 \\x02\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42
    assert packets[0].data[:6] == b"\xff\xff\xff\xff\xff\xff"


def test_backslash_x_with_timestamp(tmp_path):
    f = tmp_path / "bx_ts.txt"
    f.write_text(
        "# 2024-01-15 10:30:00.123456\n"
        "\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x11\\x22\\x33\\x44\\x55"
        "\\x08\\x06\\x00\\x01\\x08\\x00\\x06\\x04\\x00\\x01"
        "\\x00\\x11\\x22\\x33\\x44\\x55\\xc0\\xa8\\x00\\x01"
        "\\x00\\x00\\x00\\x00\\x00\\x00\\xc0\\xa8\\x00\\x02\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00.123456"))


def test_per_line_timestamps():
    """Every hex line has a timestamp prefix — first line's ts is used."""
    packets = parse_hex_file(os.path.join(FIXTURES, "per_line_timestamps.txt"))
    assert len(packets) == 2
    assert len(packets[0].data) == 42
    assert len(packets[1].data) == 42
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00.123456"))
    assert packets[1].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:01.654321"))


def test_per_line_timestamps_same_data():
    """Per-line timestamps produce the same packet data as other formats."""
    per_line = parse_hex_file(os.path.join(FIXTURES, "per_line_timestamps.txt"))
    plain = parse_hex_file(os.path.join(FIXTURES, "wireshark_style.txt"))
    assert [p.data for p in per_line] == [p.data for p in plain]


def test_text_line_with_timestamp_before_packet(tmp_path):
    """A non-comment text line with a timestamp before a packet is used."""
    f = tmp_path / "text_ts.txt"
    f.write_text(
        "Captured at 2024-01-15 10:30:00.123456 on eth0\n"
        "ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01\n"
        "08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01\n"
        "00 00 00 00 00 00 c0 a8 00 02\n"
    )
    packets = parse_hex_file(str(f))
    assert len(packets) == 1
    assert len(packets[0].data) == 42
    assert packets[0].timestamp == pytest.approx(_expected_ts("2024-01-15 10:30:00.123456"))

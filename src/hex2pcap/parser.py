"""Parse hex dump text files into raw packet bytes."""

import re
from dataclasses import dataclass
from datetime import datetime

MIN_ETHERNET_LEN = 14  # 6 dst + 6 src + 2 ethertype

# Matches offset prefixes like "0000  ", "0010: ", "00a0   "
_OFFSET_RE = re.compile(r"^[0-9a-fA-F]{4,}[\s:]")

# Matches trailing ASCII column (2+ spaces then printable chars to end of line)
_ASCII_TAIL_RE = re.compile(r"\s{2,}[!-~. ]{8,}$")

# A line is valid hex if it contains only hex digits and whitespace
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F\s]+$")

# Matches timestamps like: 2024-01-15 10:30:00.123456
_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
)


@dataclass
class ParsedPacket:
    data: bytes
    timestamp: float = None


def _parse_timestamp(text: str):
    """Try to extract a timestamp from a string. Returns Unix time or None."""
    m = _TIMESTAMP_RE.search(text)
    if not m:
        return None
    ts_str = m.group(1).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def _strip_timestamp(line: str):
    """Strip a leading timestamp from a line.

    Returns (remaining_line, timestamp_or_none).
    """
    m = _TIMESTAMP_RE.search(line)
    if not m:
        return line, None
    # Only strip if the timestamp is at or near the start (within a prefix)
    # i.e. everything before the timestamp match is non-hex text
    prefix = line[:m.start()]
    if prefix.strip() and _HEX_ONLY_RE.match(prefix.strip()):
        # The part before the "timestamp" looks like hex data — not a real prefix
        return line, None
    ts = _parse_timestamp(line)
    if ts is not None:
        remaining = line[m.end():].strip()
        return remaining, ts
    return line, None


def _strip_offset(line: str) -> str:
    """Remove leading hex offset prefix if present."""
    m = _OFFSET_RE.match(line)
    if m:
        line = line[m.end():]
    return line


def _strip_ascii_tail(line: str) -> str:
    """Remove trailing ASCII representation column."""
    return _ASCII_TAIL_RE.sub("", line)


def _parse_hex_line(line: str):
    """Parse a single line of hex content into bytes.

    Returns (parsed_bytes, timestamp_or_none).
    """
    line = line.strip()
    if not line:
        return b"", None

    # Try to strip a timestamp prefix
    line, ts = _strip_timestamp(line)
    line = line.strip()

    if not line:
        return b"", ts

    line = _strip_offset(line)
    line = _strip_ascii_tail(line)

    # Strip \x prefixes (e.g. \xff\xff or \xff \xff)
    if "\\x" in line:
        line = line.replace("\\x", " ")

    line = line.strip()

    if not line:
        return b"", ts

    # Skip lines that aren't valid hex content (e.g. descriptive text)
    if not _HEX_ONLY_RE.match(line):
        return b"", ts

    # Check if space-separated or continuous hex
    tokens = line.split()
    if all(len(t) <= 2 for t in tokens):
        # Space-separated hex bytes
        return bytes.fromhex("".join(tokens)), ts
    else:
        # Continuous hex string — strip any remaining whitespace
        return bytes.fromhex(line.replace(" ", "")), ts


def _parse_packet_lines(lines: list):
    """Parse a group of lines into a single packet's bytes.

    Returns (raw_bytes, timestamp_or_none). The timestamp comes from the
    first line that has one.
    """
    raw = b""
    first_ts = None
    for line in lines:
        data, ts = _parse_hex_line(line)
        raw += data
        if first_ts is None and ts is not None:
            first_ts = ts
    return raw, first_ts


def parse_hex_file(filepath: str, skip_invalid: bool = False) -> list:
    """Parse a hex dump file into a list of ParsedPacket objects.

    Packets are separated by blank lines. Supports:
    - Plain continuous hex strings
    - Space-separated hex bytes
    - Wireshark/xxd style with offset prefixes and ASCII columns
    - Timestamps in comment lines (# 2024-01-15 10:30:00.123456)
    - Timestamps as prefix on any hex line
    - Timestamps on non-hex text lines preceding a packet

    Timestamp priority: first hex line prefix > previous text/comment line.

    Args:
        filepath: Path to the input text file.
        skip_invalid: If True, skip packets shorter than 14 bytes instead of raising.

    Returns:
        List of ParsedPacket objects, one per packet.
    """
    with open(filepath, "r") as f:
        lines = f.readlines()

    packets = []
    current_group = []
    pending_timestamp = None

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("#"):
            # Check for timestamp in comment line
            ts = _parse_timestamp(stripped)
            if ts is not None:
                pending_timestamp = ts
            continue

        if stripped == "":
            # Blank line ends a packet group
            if current_group:
                packets.append((current_group, pending_timestamp))
                current_group = []
                pending_timestamp = None
            continue

        current_group.append(stripped)

    # Don't forget the last group if file doesn't end with blank line
    if current_group:
        packets.append((current_group, pending_timestamp))

    result = []
    for i, (group, comment_ts) in enumerate(packets):
        try:
            pkt, line_ts = _parse_packet_lines(group)
        except ValueError as e:
            if skip_invalid:
                print(f"Warning: skipping packet {i + 1}: {e}")
                continue
            raise ValueError(f"Packet {i + 1}: {e}") from e

        if len(pkt) == 0:
            continue

        if len(pkt) < MIN_ETHERNET_LEN:
            msg = (
                f"Packet {i + 1} is {len(pkt)} bytes, "
                f"minimum Ethernet frame is {MIN_ETHERNET_LEN} bytes"
            )
            if skip_invalid:
                print(f"Warning: skipping — {msg}")
                continue
            raise ValueError(msg)

        # Timestamp from hex line prefix takes priority over comment timestamp
        ts = line_ts if line_ts is not None else comment_ts
        result.append(ParsedPacket(data=pkt, timestamp=ts))

    return result

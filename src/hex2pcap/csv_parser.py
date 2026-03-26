"""Parse CSV files containing hex dump columns into raw packet bytes."""

import csv
import re

from .parser import ParsedPacket

# Time unit patterns for detecting timestamp columns
_TIME_UNIT_RE = re.compile(
    r"(?:^|[_\s(])"
    r"(ps|psecs?|ns|nsecs?|us|usecs?|ms|msecs?|sec|secs|"
    r"picoseconds?|nanoseconds?|microseconds?|milliseconds?|seconds?)"
    r"(?:$|[_\s)])",
    re.IGNORECASE,
)

# Multipliers to convert time units to seconds
_UNIT_TO_SECONDS = {
    "ps": 1e-12,
    "psec": 1e-12,
    "psecs": 1e-12,
    "picosecond": 1e-12,
    "picoseconds": 1e-12,
    "ns": 1e-9,
    "nsec": 1e-9,
    "nsecs": 1e-9,
    "nanosecond": 1e-9,
    "nanoseconds": 1e-9,
    "us": 1e-6,
    "usec": 1e-6,
    "usecs": 1e-6,
    "microsecond": 1e-6,
    "microseconds": 1e-6,
    "ms": 1e-3,
    "msec": 1e-3,
    "msecs": 1e-3,
    "millisecond": 1e-3,
    "milliseconds": 1e-3,
    "sec": 1.0,
    "secs": 1.0,
    "second": 1.0,
    "seconds": 1.0,
}

# Matches hex dump content: hex digits with optional \x or 0x prefixes, spaces
_HEX_CELL_RE = re.compile(r"^[\s]*(?:(?:0x|\\x)?[0-9a-fA-F]{2}[\s:]*)+$")


def _parse_hex_cell(text: str) -> bytes:
    """Parse a single CSV cell of hex content into bytes.

    Unlike _parse_hex_line from parser.py, this does NOT strip offsets or
    timestamps since CSV cells contain only hex data.
    """
    text = text.strip()
    if not text:
        return b""

    # Strip \x and 0x prefixes
    if "\\x" in text or "0x" in text:
        text = text.replace("\\x", " ").replace("0x", " ")

    # Remove colons (e.g. "ff:ff:ff")
    text = text.replace(":", " ")
    text = text.strip()

    if not text:
        return b""

    tokens = text.split()
    return bytes.fromhex("".join(tokens))


def _is_hex_column(values):
    """Check if a column contains hex dump data (by sampling non-empty values)."""
    samples = [v for v in values if v.strip()]
    if not samples:
        return False
    hex_count = sum(1 for v in samples if _HEX_CELL_RE.match(v))
    return hex_count > len(samples) * 0.5


def _is_numeric_column(values):
    """Check if a column contains numeric (integer/float) values."""
    samples = [v for v in values if v.strip()]
    if not samples:
        return False
    num_count = 0
    for v in samples:
        try:
            float(v)
            num_count += 1
        except ValueError:
            pass
    return num_count > len(samples) * 0.5


def _find_timestamp_column(headers, numeric_cols, hex_start):
    """Find the first timestamp column before the hex columns.

    Looks for column headers containing time unit keywords.
    Returns (column_index, unit_multiplier) or (None, None).
    """
    for col_idx in numeric_cols:
        if col_idx >= hex_start:
            continue
        header = headers[col_idx]
        m = _TIME_UNIT_RE.search(header)
        if m:
            unit = m.group(1).lower()
            multiplier = _UNIT_TO_SECONDS.get(unit)
            if multiplier is not None:
                return col_idx, multiplier
    return None, None


def _find_hex_groups(headers, rows):
    """Find groups of consecutive hex columns.

    Returns list of (start_index, end_index) tuples for each group.
    """
    num_cols = len(headers)
    col_values = [[] for _ in range(num_cols)]
    for row in rows:
        for i in range(min(len(row), num_cols)):
            col_values[i].append(row[i])

    # A column that is both numeric and hex-looking is treated as numeric
    is_hex = [
        _is_hex_column(col_values[i]) and not _is_numeric_column(col_values[i])
        for i in range(num_cols)
    ]

    groups = []
    i = 0
    while i < num_cols:
        if is_hex[i]:
            start = i
            while i < num_cols and is_hex[i]:
                i += 1
            groups.append((start, i))
        else:
            i += 1

    return groups, col_values


def parse_csv_file(filepath: str, skip_invalid: bool = False,
                    timestamp_column: str = None,
                    timestamp_unit: str = None) -> list:
    """Parse a CSV file containing hex dump columns into ParsedPacket objects.

    Consecutive hex dump columns are merged into a single packet per row.
    If a numeric column before the hex columns has a time-unit keyword in
    its header (e.g. "timestamp_ns", "time (ms)"), it is used as the
    per-packet timestamp.

    Args:
        filepath: Path to the CSV file.
        skip_invalid: If True, skip invalid rows instead of aborting.
        timestamp_column: Optional column name to use as the timestamp.
            If provided, overrides auto-detection. The column header must
            contain a recognized time unit for unit conversion, otherwise
            values are treated as seconds.
        timestamp_unit: Optional time unit (e.g. "ns", "us", "ms", "sec").
            If provided, overrides unit detection from the column header.

    Returns:
        List of ParsedPacket objects, one per row.
    """
    with open(filepath, "r", newline="") as f:
        reader = csv.reader(f)
        headers = next(reader)
        rows = list(reader)

    if not rows:
        return []

    num_cols = len(headers)
    hex_groups, col_values = _find_hex_groups(headers, rows)

    if not hex_groups:
        return []

    # Identify numeric columns
    numeric_cols = [
        i for i in range(num_cols)
        if _is_numeric_column(col_values[i])
    ]

    hex_start = hex_groups[0][0]
    ts_col = None
    ts_multiplier = None

    # Resolve explicit unit override
    unit_override = None
    if timestamp_unit is not None:
        unit_override = _UNIT_TO_SECONDS.get(timestamp_unit.lower())
        if unit_override is None:
            raise ValueError(
                f"Unknown time unit '{timestamp_unit}'. "
                f"Recognized units: {', '.join(sorted(_UNIT_TO_SECONDS.keys()))}"
            )

    if timestamp_column is not None:
        # User-specified timestamp column
        for i, h in enumerate(headers):
            if h.strip() == timestamp_column.strip():
                ts_col = i
                if unit_override is not None:
                    ts_multiplier = unit_override
                else:
                    # Try to detect time unit from the header
                    m = _TIME_UNIT_RE.search(h)
                    if m:
                        ts_multiplier = _UNIT_TO_SECONDS.get(m.group(1).lower(), 1.0)
                    else:
                        ts_multiplier = 1.0  # assume seconds
                break
        if ts_col is None:
            raise ValueError(
                f"Timestamp column '{timestamp_column}' not found. "
                f"Available columns: {', '.join(headers)}"
            )
    else:
        # Auto-detect: first numeric column with time unit in header,
        # before the first hex group
        ts_col, ts_multiplier = _find_timestamp_column(
            headers, numeric_cols, hex_start
        )
        if unit_override is not None and ts_col is not None:
            ts_multiplier = unit_override

    result = []
    for row_idx, row in enumerate(rows):
        # Merge hex cells from all hex groups
        hex_parts = []
        for group_start, group_end in hex_groups:
            for col_idx in range(group_start, group_end):
                if col_idx < len(row) and row[col_idx].strip():
                    hex_parts.append(row[col_idx].strip())

        if not hex_parts:
            continue

        # Parse each cell separately and concatenate
        try:
            pkt_data = b""
            for part in hex_parts:
                pkt_data += _parse_hex_cell(part)
        except ValueError as e:
            if skip_invalid:
                print(f"Warning: skipping row {row_idx + 2}: {e}")
                continue
            raise ValueError(f"Row {row_idx + 2}: {e}") from e

        if len(pkt_data) == 0:
            continue

        # Extract timestamp
        timestamp = None
        if ts_col is not None and ts_col < len(row) and row[ts_col].strip():
            try:
                raw_value = float(row[ts_col])
                timestamp = raw_value * ts_multiplier
            except ValueError:
                pass

        result.append(ParsedPacket(data=pkt_data, timestamp=timestamp))

    return result

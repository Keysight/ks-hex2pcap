# hex2pcap

Convert hex dumps of Ethernet packets into pcap files that can be opened in Wireshark and other packet analysis tools.

## Installation

```bash
pip install .
```

Or for development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

## Usage

```bash
hex2pcap input.txt                  # writes input.pcap
hex2pcap input.txt -o output.pcap   # specify output file
hex2pcap input.txt -v               # verbose: print per-packet details
hex2pcap input.txt --skip-invalid   # skip bad packets instead of aborting
hex2pcap input.txt -t 1705314600    # set base Unix timestamp
hex2pcap capture.csv --ts-column rx_eda_ts  # specify CSV timestamp column
```

## Supported input formats

Packets are separated by blank lines. Lines starting with `#` are treated as comments. Non-hex text lines are automatically ignored.

### Plain continuous hex

```
ffffffffffff00112233445508060001080006040001001122334455c0a80001000000000000c0a80002
```

### Space-separated hex bytes

```
ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01
08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01
00 00 00 00 00 00 c0 a8 00 02
```

### Wireshark/xxd style (with byte offsets and ASCII column)

```
0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01  ........"3DU....
0010  08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01  ........"3DU....
0020  00 00 00 00 00 00 c0 a8 00 02                    ..........
```

### Backslash-x prefixed hex

```
\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x06\x00\x01
```

Also works space-separated (`\xff \xff \xff ...`) or with longer sequences (`\xffffffffffff`).

### Mixed formats with descriptive text

Non-hex text lines are automatically skipped:

```
Packet 1: ARP request from 192.168.0.1
0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01  ........"3DU....
0010  08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01  ........"3DU....
0020  00 00 00 00 00 00 c0 a8 00 02                    ..........
```

## Timestamps

Timestamps in the format `YYYY-MM-DD HH:MM:SS[.ffffff]` are automatically extracted and written as per-packet timestamps in the pcap. Packets without timestamps fall back to the base timestamp (from `-t` or current time), incrementing by 1 microsecond per packet.

### In comment lines

```
# 2024-01-15 10:30:00.123456
0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01  ........"3DU....
```

### As inline prefix on hex lines

Works with or without byte offsets:

```
2024-01-15 10:30:00.123456  0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01  ........"3DU....
0010  08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01  ........"3DU....
```

### On every line (e.g. from a logging tool)

```
2024-01-15 10:30:00.123456  0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01  ........"3DU....
2024-01-15 10:30:00.123456  0010  08 00 06 04 00 01 00 11 22 33 44 55 c0 a8 00 01  ........"3DU....
2024-01-15 10:30:00.123456  0020  00 00 00 00 00 00 c0 a8 00 02                    ..........
```

### In preceding text lines

```
Captured at 2024-01-15 10:30:00.123456 on eth0
ff ff ff ff ff ff 00 11 22 33 44 55 08 06 00 01
```

When both a comment/text line and an inline prefix contain timestamps, the inline prefix takes priority.

## CSV input

CSV files (`.csv` extension) are automatically detected. Each row becomes one packet.

```bash
hex2pcap capture.csv -o capture.pcap
hex2pcap capture.csv -v
hex2pcap capture.csv --ts-column rx_eda_ts             # specify timestamp column
hex2pcap capture.csv --ts-column rx_eda_ts --ts-unit ns  # specify column and unit
```

### Hex dump columns

Columns containing hex data are auto-detected. Consecutive hex columns are merged into a single packet per row. Supported cell formats include plain hex, space-separated, `\x`-prefixed, `0x`-prefixed, and colon-separated.

```csv
id,col1,col2,col3
1,ffffffffffff001122334455,080600010800,06040001001122334455c0a80001000000000000c0a80002
```

### Timestamp columns

Numeric columns before the hex columns are scanned for time-unit keywords in their headers. The first matching column is used as the per-packet timestamp, converted to seconds.

You can override auto-detection with `--ts-column` and optionally `--ts-unit`:

```bash
hex2pcap capture.csv --ts-column capture_ns              # unit from header
hex2pcap capture.csv --ts-column rx_eda_ts --ts-unit ns  # explicit unit
```

If `--ts-unit` is provided, it overrides unit detection from the column header. Without `--ts-unit`, the unit is inferred from the header; if the header has no recognized unit, values are treated as seconds. Available units: `ps`, `ns`, `us`, `ms`, `sec`.

Recognized time units:

| Unit | Header examples |
|------|----------------|
| Picoseconds | `ps`, `psec`, `psecs`, `picosecond`, `picoseconds` |
| Nanoseconds | `ns`, `nsec`, `nsecs`, `nanosecond`, `nanoseconds` |
| Microseconds | `us`, `usec`, `usecs`, `microsecond`, `microseconds` |
| Milliseconds | `ms`, `msec`, `msecs`, `millisecond`, `milliseconds` |
| Seconds | `sec`, `secs`, `second`, `seconds` |

Units can appear anywhere in the header with common separators: `sys_nsecs`, `capture_ns`, `time (ms)`, `elapsed_usec`, etc.

Example with nanosecond timestamps (from bpftrace):

```csv
sys_nsecs,sys_nsec_delta,rx_eda_ts,rx_eda_ts_delta,buf
10175982028632,10175982028632,2430854071100,2430854071100,\x52\x54\x00\x00\x00\x00\x8a\x41\xb5\x7d\x42\xcc\x86\xdd...
10176003340675,21312043,2430857130700,3059600,\x52\x54\x00\x00\x00\x00\x8a\x41\xb5\x7d\x42\xcc\x86\xdd...
```

When multiple columns match (e.g. `sys_nsecs` and `rx_eda_ts`), the first one is used.

## Metadata extraction

When packet buffers contain a vendor-specific metadata header before the Ethernet frame, use `--eth-offset` to specify where the Ethernet header starts. Everything before that offset is treated as metadata, which is parsed and written to a separate Markdown file.

```bash
hex2pcap capture.csv --eth-offset 48 --vendor edav2 -o capture.pcap
# Creates capture.pcap (Ethernet frames only) + capture_metadata.md
```

- `--eth-offset N` — byte offset where the Ethernet header starts
- `--vendor NAME` — vendor plugin for parsing metadata (requires `--eth-offset`)

Without `--vendor`, metadata is dumped as raw hex.

### Supported vendors

#### EDA v2 (`--vendor edav2`)

Parses the EDA v2 EDA metadata header (48 bytes). Supported metadata types:

| Type | Fields |
|------|--------|
| `EDA_RX_PKT` | flags, emulator_time, latency |
| `EDA_TX_PKT` | flags, ifg |
| `EDA_ET_HEARTBEAT` | flags, emulator_time |
| `EDA_REGISTER_PORT` | event, port_id, cap_tlv_count, cap_tlvs |
| `EDA_NOP` | raw hex |
| `EDA_PORT_DISABLED` | raw hex |

Example output (`capture_metadata.md`):

```markdown
## Packet 1

| Field | Value |
|-------|-------|
| mrg_num_buffers | 1 |
| metadata_type | EDA_RX_PKT |
| flags | 0x00000002 |
| emulator_time | 14683052179900 |
| latency | 0 |
```

### Writing a vendor plugin

Implement the `MetadataPlugin` interface and register with the `@register_vendor` decorator:

```python
from hex2pcap.metadata import MetadataPlugin, MetadataResult
from hex2pcap.vendors import register_vendor

@register_vendor
class MyVendorPlugin(MetadataPlugin):
    name = "myvendor"

    def parse(self, raw: bytes, packet_id: int) -> MetadataResult:
        # Parse raw metadata bytes, return MetadataResult with fields dict
        ...
```

Then add an import in `src/hex2pcap/vendors/__init__.py`.

## Python API

```python
from hex2pcap import parse_hex_file, parse_csv_file, write_pcap

# Text hex dump files
parsed = parse_hex_file("input.txt")

# CSV files (auto-detect timestamp column)
parsed = parse_csv_file("capture.csv")

# CSV files (explicit timestamp column)
parsed = parse_csv_file("capture.csv", timestamp_column="rx_eda_ts")

# CSV files (explicit column and unit)
parsed = parse_csv_file("capture.csv", timestamp_column="rx_eda_ts", timestamp_unit="ns")

# Common output
for p in parsed:
    print(f"{len(p.data)} bytes, timestamp={p.timestamp}")

packets = [p.data for p in parsed]
timestamps = [p.timestamp for p in parsed]
write_pcap("output.pcap", packets, timestamps=timestamps)

# Metadata extraction
from hex2pcap import extract_metadata, write_metadata_md
from hex2pcap.vendors import get_vendor

plugin = get_vendor("edav2")
trimmed, metadata = extract_metadata(parsed, eth_offset=48, plugin=plugin)
write_metadata_md("output_metadata.md", metadata, plugin.name)

packets = [p.data for p in trimmed]
write_pcap("output.pcap", packets)
```

## Running tests

```bash
python -m pytest tests/ -v
```

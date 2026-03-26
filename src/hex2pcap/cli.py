"""Command-line interface for hex2pcap."""

import argparse
import os
import sys

from .csv_parser import parse_csv_file
from .parser import parse_hex_file
from .pcap_writer import write_pcap


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hex2pcap",
        description="Convert hex dumps of Ethernet packets to pcap files",
    )
    parser.add_argument("input", help="Input hex dump text file or CSV file")
    parser.add_argument(
        "-o", "--output",
        help="Output pcap file (default: <input>.pcap)",
    )
    parser.add_argument(
        "-t", "--timestamp",
        type=float,
        default=None,
        help="Base Unix timestamp for first packet (default: current time)",
    )
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="Skip invalid packets instead of aborting",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print per-packet details",
    )
    parser.add_argument(
        "--ts-column",
        default=None,
        help="CSV column name to use as timestamp (overrides auto-detection)",
    )
    parser.add_argument(
        "--ts-unit",
        default=None,
        choices=["ps", "ns", "us", "ms", "sec"],
        help="Time unit for --ts-column values (overrides unit from header)",
    )
    parser.add_argument(
        "--eth-offset",
        type=int,
        default=None,
        help="Byte offset where Ethernet header starts. "
             "Bytes before this are treated as metadata.",
    )
    parser.add_argument(
        "--vendor",
        default=None,
        help="Vendor plugin for metadata formatting (e.g. 'edav2'). "
             "Requires --eth-offset.",
    )

    args = parser.parse_args(argv)

    if args.vendor and args.eth_offset is None:
        print("Error: --vendor requires --eth-offset", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    output = args.output
    if output is None:
        base, _ = os.path.splitext(args.input)
        output = base + ".pcap"

    is_csv = args.input.lower().endswith(".csv")

    try:
        if is_csv:
            parsed = parse_csv_file(
                args.input,
                skip_invalid=args.skip_invalid,
                timestamp_column=args.ts_column,
                timestamp_unit=args.ts_unit,
            )
        else:
            parsed = parse_hex_file(args.input, skip_invalid=args.skip_invalid)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not parsed:
        print("No valid packets found.", file=sys.stderr)
        sys.exit(1)

    # Extract metadata if eth-offset is specified
    if args.eth_offset is not None:
        from .metadata import extract_metadata
        from .md_writer import write_metadata_md
        from .vendors import get_vendor

        try:
            plugin = get_vendor(args.vendor) if args.vendor else None
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        if plugin is None:
            from .metadata import MetadataPlugin, MetadataResult

            class RawPlugin(MetadataPlugin):
                name = "raw"

                def parse(self, raw, packet_id):
                    return MetadataResult(
                        packet_id=packet_id,
                        raw_bytes=raw,
                        metadata_type="RAW",
                        fields={"raw_hex": raw.hex()},
                    )

            plugin = RawPlugin()

        parsed, metadata_results = extract_metadata(
            parsed, args.eth_offset, plugin
        )

        if not parsed:
            print("No valid packets after metadata extraction.", file=sys.stderr)
            sys.exit(1)

        md_path = os.path.splitext(output)[0] + "_metadata.md"
        write_metadata_md(md_path, metadata_results, plugin.name)
        print(f"Wrote metadata for {len(metadata_results)} packet(s) to {md_path}")

    packets = [p.data for p in parsed]
    timestamps = [p.timestamp for p in parsed]
    has_per_packet_ts = any(t is not None for t in timestamps)

    if args.verbose:
        for i, p in enumerate(parsed):
            ts_info = f", ts={p.timestamp}" if p.timestamp else ""
            print(f"Packet {i + 1}: {len(p.data)} bytes{ts_info}")

    write_pcap(
        output,
        packets,
        base_timestamp=args.timestamp,
        timestamps=timestamps if has_per_packet_ts else None,
    )
    print(f"Wrote {len(parsed)} packet(s) to {output}")

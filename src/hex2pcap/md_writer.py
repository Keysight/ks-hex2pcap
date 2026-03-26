"""Write packet metadata to a Markdown file."""


def write_metadata_md(filepath: str, results: list, vendor_name: str) -> None:
    """Write metadata results to a Markdown file.

    Each packet gets a section with its ID (matching the pcap) and a
    table of parsed fields.

    Args:
        filepath: Output .md file path.
        results: List of MetadataResult objects.
        vendor_name: Name of the vendor plugin used.
    """
    with open(filepath, "w") as f:
        f.write(f"# Packet Metadata (vendor: {vendor_name})\n\n")

        for result in results:
            f.write(f"## Packet {result.packet_id}\n\n")
            f.write("| Field | Value |\n")
            f.write("|-------|-------|\n")

            for key, value in result.fields.items():
                if key == "cap_tlvs" and isinstance(value, list):
                    for j, tlv in enumerate(value):
                        f.write(
                            f"| cap_tlv[{j}] | "
                            f"type={tlv['type']}, len={tlv['length']}, "
                            f"value={tlv['value']} |\n"
                        )
                else:
                    f.write(f"| {key} | {value} |\n")

            f.write("\n")

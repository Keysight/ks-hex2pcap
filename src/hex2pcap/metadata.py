"""Metadata extraction and vendor plugin interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .parser import ParsedPacket


@dataclass
class MetadataResult:
    """Parsed metadata for one packet."""
    packet_id: int
    raw_bytes: bytes
    metadata_type: str
    fields: dict = field(default_factory=dict)


class MetadataPlugin(ABC):
    """Base class for vendor-specific metadata formatters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name matching --vendor argument."""

    @abstractmethod
    def parse(self, raw: bytes, packet_id: int) -> MetadataResult:
        """Parse raw metadata bytes into a MetadataResult."""


def extract_metadata(
    packets: list,
    eth_offset: int,
    plugin: MetadataPlugin,
) -> tuple:
    """Split each packet at eth_offset into metadata + Ethernet frame.

    Returns (trimmed_packets, metadata_results).
    Packets shorter than eth_offset are skipped with a warning.
    """
    trimmed = []
    metadata = []

    for i, pkt in enumerate(packets):
        packet_id = i + 1

        if len(pkt.data) < eth_offset:
            print(
                f"Warning: packet {packet_id} is {len(pkt.data)} bytes, "
                f"shorter than eth_offset={eth_offset}, skipping"
            )
            continue

        meta_bytes = pkt.data[:eth_offset]
        eth_data = pkt.data[eth_offset:]

        result = plugin.parse(meta_bytes, packet_id)
        metadata.append(result)

        if len(eth_data) > 0:
            trimmed.append(ParsedPacket(data=eth_data, timestamp=pkt.timestamp))

    return trimmed, metadata

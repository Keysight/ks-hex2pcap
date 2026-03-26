"""EDA v2 metadata plugin."""

import struct

from ..metadata import MetadataPlugin, MetadataResult
from . import register_vendor

# metadata_type values
_TYPE_NAMES = {
    0: "EDA_NOP",
    1: "EDA_REGISTER_PORT",
    2: "EDA_TX_PKT",
    3: "EDA_RX_PKT",
    4: "EDA_ET_HEARTBEAT",
    5: "EDA_PORT_DISABLED",
}


@register_vendor
class Edav2Plugin(MetadataPlugin):
    """EDA v2 metadata parser."""

    name = "edav2"

    def parse(self, raw: bytes, packet_id: int) -> MetadataResult:
        if len(raw) < 4:
            return MetadataResult(
                packet_id=packet_id,
                raw_bytes=raw,
                metadata_type="UNKNOWN",
                fields={"raw_hex": raw.hex()},
            )

        mrg_num_buffers, metadata_type = struct.unpack_from("<HH", raw, 0)
        type_name = _TYPE_NAMES.get(metadata_type, f"UNKNOWN({metadata_type})")

        fields = {
            "mrg_num_buffers": mrg_num_buffers,
            "metadata_type": type_name,
        }

        payload = raw[4:]

        if metadata_type == 2 and len(payload) >= 12:
            # EDA_TX_PKT
            flags, ifg = struct.unpack_from("<IQ", payload, 0)
            fields["flags"] = f"0x{flags:08x}"
            fields["ifg"] = ifg

        elif metadata_type == 3 and len(payload) >= 20:
            # EDA_RX_PKT
            flags, emulator_time, latency = struct.unpack_from("<IQQ", payload, 0)
            fields["flags"] = f"0x{flags:08x}"
            fields["emulator_time"] = emulator_time
            fields["latency"] = latency

        elif metadata_type == 4 and len(payload) >= 12:
            # EDA_ET_HEARTBEAT
            flags, emulator_time = struct.unpack_from("<IQ", payload, 0)
            fields["flags"] = f"0x{flags:08x}"
            fields["emulator_time"] = emulator_time

        elif metadata_type == 1 and len(payload) >= 13:
            # EDA_REGISTER_PORT
            event, port_id, cap_tlv_count = struct.unpack_from("<IQB", payload, 0)
            fields["event"] = event
            fields["port_id"] = port_id
            fields["cap_tlv_count"] = cap_tlv_count
            if cap_tlv_count > 0:
                cap_data = payload[13:]
                fields["cap_tlvs"] = _parse_cap_tlvs(cap_data, cap_tlv_count)

        fields["raw_hex"] = raw.hex()

        return MetadataResult(
            packet_id=packet_id,
            raw_bytes=raw,
            metadata_type=type_name,
            fields=fields,
        )


def _parse_cap_tlvs(data: bytes, count: int) -> list:
    """Parse capability TLV entries."""
    tlvs = []
    offset = 0
    for _ in range(count):
        if offset + 2 > len(data):
            break
        tlv_type = data[offset]
        tlv_length = data[offset + 1]
        offset += 2
        if offset + tlv_length > len(data):
            break
        tlv_value = data[offset:offset + tlv_length].hex()
        tlvs.append({"type": tlv_type, "length": tlv_length, "value": tlv_value})
        offset += tlv_length
    return tlvs

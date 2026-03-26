"""Write raw packets to pcap format."""

import struct
import time

# PCAP global header: magic, version 2.4, GMT, no sigfigs, snaplen 65535, Ethernet
_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic number (little-endian)
    2,            # version major
    4,            # version minor
    0,            # thiszone
    0,            # sigfigs
    65535,        # snaplen
    1,            # LINKTYPE_ETHERNET
)


def write_pcap(filepath: str, packets: list, base_timestamp: float = None,
               timestamps: list = None) -> None:
    """Write packets to a pcap file.

    Args:
        filepath: Output pcap file path.
        packets: List of raw packet bytes.
        base_timestamp: Unix timestamp for the first packet.
            If None, uses current time. Used as fallback for packets
            without per-packet timestamps.
        timestamps: Optional list of per-packet Unix timestamps (parallel
            to packets). None entries fall back to base_timestamp + increment.
    """
    if base_timestamp is None:
        base_timestamp = time.time()

    # Use integer microseconds to avoid floating-point drift
    base_sec = int(base_timestamp)
    base_usec = int(round((base_timestamp - base_sec) * 1_000_000))

    fallback_index = 0

    with open(filepath, "wb") as f:
        f.write(_GLOBAL_HEADER)

        for i, pkt in enumerate(packets):
            per_pkt_ts = timestamps[i] if timestamps and i < len(timestamps) else None

            if per_pkt_ts is not None:
                ts_sec = int(per_pkt_ts)
                ts_usec = int(round((per_pkt_ts - ts_sec) * 1_000_000))
            else:
                total_usec = base_usec + fallback_index
                ts_sec = base_sec + total_usec // 1_000_000
                ts_usec = total_usec % 1_000_000
                fallback_index += 1

            _MAX_UINT32 = 4294967295
            if ts_sec < 0 or ts_sec > _MAX_UINT32:
                raise ValueError(
                    f"Packet {i + 1} timestamp {ts_sec}s overflows pcap "
                    f"32-bit field (max {_MAX_UINT32}). Check your "
                    f"timestamp unit — you may need --ts-unit."
                )

            pkt_len = len(pkt)

            # Packet record header
            f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            f.write(pkt)

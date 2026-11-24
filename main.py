"""
Assignment: Checksums Part 2
Course: CSCI 351 Data Communications and Networks

Team members:
    - Jonathan Schultz (jss5874@rit.edu)
    - Jay Stebbins (jks1805@rit.edu)
    - Caden Seaman (cjs6589@rit.edu)
    - Ryan Leifer (rjl8327@rit.edu)

Sources:
    - RFC 791, Internet Protocol
    - RFC 826, Address Resolution Protocol
    - RFC 894, IPv4 over Ethernet
    - RFC 2464, IPv6 over Ethernet
    - RFC 8200, Internet Protocol, Version 6
    - RFC 9293, Transmission Control Protocol
    - RFC 1071, Computing the Internet Checksum
    - IEEE 802.3 Standard
    - Wireshark
"""

import sys
from dataclasses import dataclass, field
import matplotlib.pyplot as plt


def print_mac(mac: bytes) -> str:
    """Format a MAC address from raw bytes to hexadecimal representation."""
    return ":".join(f"{b:02x}" for b in mac)


def format_ip(ip: bytes) -> str:
    """Format an IP address from raw bytes to dotted decimal representation."""
    return ".".join(str(b) for b in ip)


ETH_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8100: "VLAN",
    0x86DD: "IPv6",
}

VLAN_ETH_TYPES = {
    0x8100,  # 802.1Q
    0x88A8,  # 802.1ad
    0x9100  # QinQ
}
IPV6_EXT_HEADERS = {0, 43, 44, 51, 60, 135}


@dataclass
class FrameII:
    """Ethernet II frame: header fields plus payload."""

    dest_mac: bytes = bytes(6)       # 6 bytes
    source_mac: bytes = bytes(6)     # 6 bytes
    eth_type: bytes = bytes(2)       # 2 bytes
    data: bytes = b""                # 46-1500 bytes

    def __str__(self) -> str:
        """Return a string representation of the Ethernet II frame."""
        eth_type = int.from_bytes(self.eth_type, "big")
        return (
            f"Ethernet II: Dst: {print_mac(self.dest_mac)}, "
            f"Src: {print_mac(self.source_mac)}, "
            f"Type: {ETH_TYPES.get(eth_type, 'Unknown')} (0x{eth_type:04x})"
        )


@dataclass
class FrameIEEE:
    """IEEE 802.3 frame: header fields, LLC header, and payload."""

    dest_mac: bytes = bytes(6)       # 6 bytes
    source_mac: bytes = bytes(6)     # 6 bytes
    length: int = 0                  # 2 bytes
    llc_header: bytes = bytes(3)     # 3 bytes
    data: bytes = b""                # 46-1500 bytes

    def __str__(self) -> str:
        """Return a string representation of the IEEE 802.3 frame."""
        return (
            f"IEEE 802.3: Dst: {print_mac(self.dest_mac)}, "
            f"Src: {print_mac(self.source_mac)}, "
            f"Length: {self.length} bytes"
        )


@dataclass
class Packet:
    """IPv4 packet header fields (RFC 791) plus payload."""

    version: int = 0                    # 4 bits
    ihl: int = 0                        # 4 bits
    tos: int = 0                        # 8 bits
    total_length: int = 0               # 16 bits
    identification: int = 0             # 16 bits
    flags: int = 0                      # 3 bits
    fragment_offset: int = 0            # 13 bits
    ttl: int = 0                        # 8 bits
    protocol: int = 0                   # 8 bits
    header_checksum: bytes = bytes(2)   # 2 bytes
    source_ip: bytes = bytes(4)         # 4 bytes
    dest_ip: bytes = bytes(4)           # 4 bytes
    options: bytes = b""                # 0-40 bytes
    data: bytes = b""                   # variable length

    def __str__(self) -> str:
        """Return a string representation of the IPv4 packet."""
        flag_names = [
            name for bit, name in ((0x4, "Reserved"), (0x2, "DF"), (0x1, "MF"))
            if self.flags & bit
        ]
        return (
            f"IPv4:\n"
            f"\t\tVersion: {self.version}\n"
            f"\t\tHeader Length: {self.ihl * 4} bytes ({self.ihl})\n"
            f"\t\tType of Service: 0x{self.tos:02x}\n"
            f"\t\tTotal Length: {self.total_length}\n"
            f"\t\tIdentification: 0x{self.identification:04x} "
            f"({self.identification})\n"
            f"\t\tFlags: 0b{self.flags:03b} ({', '.join(flag_names) or 'None'})\n"
            f"\t\tFragment Offset: {self.fragment_offset}\n"
            f"\t\tTime to Live: {self.ttl}\n"
            f"\t\tProtocol: {self.protocol}\n"
            f"\t\tSource Address: {format_ip(self.source_ip)}\n"
            f"\t\tDestination Address: {format_ip(self.dest_ip)}\n"
            f"\t\tOptions: {len(self.options)} bytes"
        )


@dataclass
class Segment:
    """TCP segment header fields (RFC 9293) plus payload."""

    source_port: int = 0         # 16 bits
    dest_port: int = 0           # 16 bits
    sequence_number: int = 0     # 32 bits
    ack_number: int = 0          # 32 bits
    data_offset: int = 0         # 4 bits
    reserved: int = 0            # 4 bits
    flags: int = 0               # 8 bits
    window_size: int = 0         # 16 bits
    checksum: bytes = bytes(2)   # 2 bytes
    urgent_pointer: int = 0      # 16 bits
    optional_data: bytes = b""   # 0-40 bytes
    data: bytes = b""            # variable length

    def __str__(self) -> str:
        """Return a string representation of the TCP segment."""

        flag_names = [
            name for bit, name in (
                (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
                (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN"),
            )
            if self.flags & bit
        ]
        return (
            f"TCP:\n"
            f"\t\tSource Port: {self.source_port}\n"
            f"\t\tDestination Port: {self.dest_port}\n"
            f"\t\tSequence Number: {self.sequence_number}\n"
            f"\t\tAcknowledgment Number: {self.ack_number}\n"
            f"\t\tHeader Length: {self.data_offset * 4} bytes "
            f"({self.data_offset})\n"
            f"\t\tReserved: {self.reserved}\n"
            f"\t\tFlags: 0x{self.flags:02x} ({', '.join(flag_names) or 'None'})\n"
            f"\t\tWindow: {self.window_size}\n"
            f"\t\tUrgent Pointer: {self.urgent_pointer}\n"
            f"\t\tOptions: {len(self.optional_data)} bytes\n"
            f"\t\tPayload: {len(self.data)} bytes"
        )


@dataclass
class PacketStatistics:
    """Store Part 2 protocol counts, L3 sizes, and capture rates."""

    # Layer 2
    ethernet_ii: int = 0
    ieee_802_3: int = 0

    # Layer 3
    ipv4: int = 0
    ipv6: int = 0
    arp: int = 0
    other_l3: int = 0

    # Layer 4
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    icmpv6: int = 0
    igmp: int = 0
    other_l4: int = 0

    # Keys are the lower bounds of 250-byte L3 packet-size bins
    # ie. 0 represents 0-249 bytes, 250 represents 250-499.
    # Values are the number of frames in that bin
    packet_sizes: dict[int, int] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return a string representation of the packet statistics."""
        total = self.ethernet_ii + self.ieee_802_3

        def row(label: str, count: int) -> str:
            """Format one protocol count with its percentage of all frames."""
            percent = (100 * count / total) if total else 0
            return f"\t\t{label}: {count} ({percent:.1f}%)"

        if self.packet_sizes:
            size_lines = "\n".join(
                f"\t\t{lower}-{lower + 249} bytes: {count}"
                for lower, count in sorted(self.packet_sizes.items())
            )
        else:
            size_lines = "\t\tNo packet-size data"

        return (
            f"Packet Statistics ({total} frames):\n"
            f"\tLayer 2:\n"
            f"{row('Ethernet II', self.ethernet_ii)}\n"
            f"{row('IEEE 802.3', self.ieee_802_3)}\n"
            f"\tLayer 3:\n"
            f"{row('IPv4', self.ipv4)}\n"
            f"{row('IPv6', self.ipv6)}\n"
            f"{row('ARP', self.arp)}\n"
            f"{row('Other', self.other_l3)}\n"
            f"\tLayer 4:\n"
            f"{row('TCP', self.tcp)}\n"
            f"{row('UDP', self.udp)}\n"
            f"{row('ICMP', self.icmp)}\n"
            f"{row('ICMPv6', self.icmpv6)}\n"
            f"{row('IGMP', self.igmp)}\n"
            f"{row('Other', self.other_l4)}\n"
            f"\tL3 Packet Sizes (250-byte bins):\n"
            f"{size_lines}"
        )


@dataclass
class PacketRateStatistics:
    """Store packets-per-second data for the first 10 seconds."""
    bin_edges: list[float]
    rates: list[int]

    def __str__(self) -> str:
        """Return a string representation of the packets-per-second statistics."""
        return "Packets Per Second (first 10 seconds):\n" + "\n".join(
            f"\t{self.bin_edges[i]}-{self.bin_edges[i + 1]} sec: {self.rates[i]}"
            for i in range(len(self.rates))
        )


def parse(filename: str) -> list[tuple[float, bytes]]:
    """Read a text file containing hex-encoded Ethernet frames."""

    try:
        with open(filename) as file:
            frames = []
            while (line := file.readline()) != "":
                if line[:1].isdigit():
                    # Capture timestamp and convert to seconds after midnight
                    timestamp = line.split()[0]
                    hours, minutes, seconds, millis, micros = map(
                        int, timestamp.replace(",", ":").split(":")
                    )
                    result = hours * 3600 + minutes * 60 + seconds + (millis * 1000 + micros) / 1_000_000

                    # Read the next line containing the frame data
                    line = file.readline()
                    hex_values = (
                        int(c.strip(), 16)
                        for c in line.strip().split("|")[2:]
                        if c.strip()
                    )

                    frames.append((result, bytes(hex_values)))
            return frames
    except OSError:
        print(f"Could not open file: {filename}")
        sys.exit(1)
    except ValueError:
        print(f"Could not parse file: {filename}")
        sys.exit(1)


def ethernet_decapsulation(frame: bytes) -> FrameII | FrameIEEE:
    """Process a raw Ethernet frame and extract the header and data."""

    if len(frame) < 14:
        raise ValueError("Frame is too short to hold an Ethernet header.")

    # Determine whether we have an Ethernet II frame or an IEEE 802.3 frame
    eth_type = int.from_bytes(frame[12:14], "big")
    if eth_type < 0x0600:
        return FrameIEEE(
            dest_mac=frame[0:6],
            source_mac=frame[6:12],
            length=eth_type,
            llc_header=frame[14:17],
            data=frame[17:]
        )

    return FrameII(
        dest_mac=frame[0:6],
        source_mac=frame[6:12],
        eth_type=frame[12:14],
        data=frame[14:]
    )


def packet_decapsulation(data: bytes) -> Packet:
    """Process the payload of a frame and extract the IPv4 packet header and data."""

    # RFC 791: the minimum IPv4 header is 20 bytes
    if len(data) < 20:
        raise ValueError("Data is too short to hold an IPv4 header.")

    version = data[0] >> 4
    ihl = data[0] & 0x0F
    if version != 4:
        raise ValueError(f"Not an IPv4 packet (version {version}).")

    # IHL counts 32-bit words, so the header is ihl * 4 bytes long
    header_length = ihl * 4
    if header_length < 20 or len(data) < header_length:
        raise ValueError("Invalid IPv4 header length.")

    total_length = int.from_bytes(data[2:4], "big")
    if total_length < header_length:
        raise ValueError("IPv4 total length is smaller than the header length.")

    flags_and_offset = int.from_bytes(data[6:8], "big")

    return Packet(
        version=version,
        ihl=ihl,
        tos=data[1],
        total_length=total_length,
        identification=int.from_bytes(data[4:6], "big"),
        flags=flags_and_offset >> 13,             # top 3 bits
        fragment_offset=flags_and_offset & 0x1FFF,  # low 13 bits
        ttl=data[8],
        protocol=data[9],
        header_checksum=data[10:12],
        source_ip=data[12:16],
        dest_ip=data[16:20],
        options=data[20:header_length],
        # total_length marks where the packet ends, so Ethernet padding
        # after it isn't treated as payload
        data=data[header_length:total_length],
    )


def segment_decapsulation(packet: Packet) -> Segment:
    """Process an IPv4 packet and extract the TCP segment header and data.
    TCP header layout follows RFC 9293 Section 3.1. """

    if packet.fragment_offset != 0:
        raise ValueError("Cannot parse TCP header from a non-initial IPv4 fragment.")

    data = packet.data

    # RFC 9293 Section 3.1: The minimum TCP header is 20 bytes
    if len(data) < 20:
        raise ValueError("Packet is too short to hold a TCP header.")

    # RFC 9293 Section 3.1:
    # Byte 12 contains two 4-bit fields: upper 4 bits = Data Offset lower 4 bits = Reserved
    # Shifting right by 4 removes the Reserved bits and leaves Data Offset.
    data_offset = data[12] >> 4
    # RFC 9293 defines Data Offset as the number of 32-bit words in the TCP header, One 32-bit word = 4 bytes
    header_length = data_offset * 4

    # RFC 9293's minimum TCP header is 5 32-bit words
    if data_offset < 5:
        raise ValueError("Invalid TCP data offset.")

    if header_length > len(data):
        raise ValueError(
            "TCP header length exceeds available packet data."
        )

    return Segment(
        # RFC 9293 Section 3.1: Source Port and Destination Port are each 16-bit fields.
        # TCP uses network byte order, so multi-byte values are read big-endian.
        source_port=int.from_bytes(data[0:2], "big"),
        dest_port=int.from_bytes(data[2:4], "big"),
        # RFC 9293: Sequence Number and Acknowledgment Number are each 32 bits.
        sequence_number=int.from_bytes(data[4:8], "big"),
        ack_number=int.from_bytes(data[8:12], "big"),
        data_offset=data_offset,
        reserved=data[12] & 0x0F,  # 0x0F = binary 00001111 ANDing with 0x0F preserves only the lower 4 Reserved bits.
        # RFC 9293: The next 8 bits are the TCP control bits (flags), Keeping the whole byte preserves all eight flags.
        flags=data[13],
        # RFC 9293: Window, checksum, and urgent pointer all 16-bit fields.
        window_size=int.from_bytes(data[14:16], "big"),
        checksum=data[16:18],
        urgent_pointer=int.from_bytes(data[18:20], "big"),
        # RFC 9293: Options begin after the fixed 20-byte header and continue
        # until the location specified by Data Offset.
        # Gives the option size as: (Data Offset - 5) * 32 bits
        optional_data=data[20:header_length],
        data=data[header_length:]
    )


def ones_complement_sum(data: bytes) -> int:
    """Return the 16-bit one's complement sum of data (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for index in range(0, len(data), 2):
        total += int.from_bytes(data[index:index + 2], "big")

    # Add any carry bits back into the low 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return total


def calculate_ip_checksum(packet: Packet) -> int:
    """Return the IPv4 header checksum (RFC 791)."""

    # Rebuild the header with the checksum field zeroed
    flags_and_offset = (packet.flags << 13) | packet.fragment_offset
    header = (
        bytes([(packet.version << 4) | packet.ihl, packet.tos])
        + packet.total_length.to_bytes(2, "big")
        + packet.identification.to_bytes(2, "big")
        + flags_and_offset.to_bytes(2, "big")
        + bytes([packet.ttl, packet.protocol, 0, 0])
        + packet.source_ip
        + packet.dest_ip
        + packet.options
    )
    return ~ones_complement_sum(header) & 0xFFFF


def calculate_tcp_checksum(packet: Packet, segment: Segment) -> int:
    """Return the TCP checksum over the pseudo-header and segment (RFC 9293)."""
    # Rebuild the TCP header with the checksum field zeroed
    offset_and_reserved = (segment.data_offset << 4) | segment.reserved
    tcp_header = (
        segment.source_port.to_bytes(2, "big")
        + segment.dest_port.to_bytes(2, "big")
        + segment.sequence_number.to_bytes(4, "big")
        + segment.ack_number.to_bytes(4, "big")
        + bytes([offset_and_reserved, segment.flags])
        + segment.window_size.to_bytes(2, "big")
        + b"\x00\x00"
        + segment.urgent_pointer.to_bytes(2, "big")
        + segment.optional_data
    )
    segment_bytes = tcp_header + segment.data

    pseudo_header = (
        packet.source_ip
        + packet.dest_ip
        + bytes([0, packet.protocol])
        + len(segment_bytes).to_bytes(2, "big")
    )
    return ~ones_complement_sum(pseudo_header + segment_bytes) & 0xFFFF


def strip_vlan(eth_type: int, data: bytes) -> tuple[int, bytes]:
    """Skip any VLAN tags and return the inner EtherType and payload."""
    while eth_type in VLAN_ETH_TYPES and len(data) >= 4:
        eth_type = int.from_bytes(data[2:4], "big")
        data = data[4:]
    return eth_type, data


def count_l4_protocol(stats: PacketStatistics, protocol: int) -> None:
    """Increment the Layer 4 counter for an IP protocol number."""
    if protocol == 6:
        stats.tcp += 1
    elif protocol == 17:
        stats.udp += 1
    elif protocol == 1:
        stats.icmp += 1
    elif protocol == 58:
        stats.icmpv6 += 1
    elif protocol == 2:
        stats.igmp += 1
    else:
        stats.other_l4 += 1


def ipv6_packet_size(data: bytes) -> int | None:
    """Return the IPv6 packet length (40-byte header plus payload length)."""
    if len(data) < 6 or data[0] >> 4 != 6:
        return len(data) if data else None
    return 40 + int.from_bytes(data[4:6], "big")


def ipv6_upper_protocol(data: bytes) -> int | None:
    """Skip IPv6 extension headers and return the upper-layer protocol (RFC 8200)."""
    if len(data) < 40 or data[0] >> 4 != 6:
        return None

    packet_end = min(len(data), 40 + int.from_bytes(data[4:6], "big"))
    next_header = data[6]
    offset = 40

    while next_header in IPV6_EXT_HEADERS:
        if packet_end < offset + 8:
            return None

        # Fragment headers are always 8 bytes, AH counts 4-byte words, the rest count 8-byte words
        if next_header == 44:
            header_length = 8
        elif next_header == 51:
            header_length = (data[offset + 1] + 2) * 4
        else:
            header_length = (data[offset + 1] + 1) * 8

        if packet_end < offset + header_length:
            return None
        next_header = data[offset]
        offset += header_length

    # 59 means there is no upper-layer header
    return None if next_header == 59 else next_header


def arp_packet_size(data: bytes) -> int:
    """Return the ARP message length without Ethernet padding."""
    if len(data) < 8:
        return len(data)
    return 8 + 2 * (data[4] + data[5])


def bin_packet_sizes(sizes: list[int]) -> dict[int, int]:
    """Count packet sizes in 250-byte bins, using each bin's lower bound as the key."""
    bins = {}
    for size in sizes:
        lower = size - size % 250
        bins[lower] = bins.get(lower, 0) + 1
    return bins


def calculate_packet_statistics(frames: list[tuple[float, bytes]]) -> PacketStatistics:
    """Count frames per protocol and bin the L3 packet sizes."""
    stats = PacketStatistics()
    sizes: list[int] = []

    for _, raw in frames:
        try:
            frame = ethernet_decapsulation(raw)
        except ValueError:
            continue

        # IEEE 802.3 frames are only counted at Layer 2
        if isinstance(frame, FrameIEEE):
            stats.ieee_802_3 += 1
            continue

        stats.ethernet_ii += 1
        eth_type = int.from_bytes(frame.eth_type, "big")
        eth_type, payload = strip_vlan(eth_type, frame.data)

        if eth_type == 0x0800:
            stats.ipv4 += 1
            try:
                packet = packet_decapsulation(payload)
            except ValueError:
                if payload:
                    sizes.append(len(payload))
                continue
            sizes.append(packet.total_length)
            count_l4_protocol(stats, packet.protocol)
        elif eth_type == 0x86DD:
            stats.ipv6 += 1
            size = ipv6_packet_size(payload)
            if size is not None:
                sizes.append(size)
            protocol = ipv6_upper_protocol(payload)
            if protocol is not None:
                count_l4_protocol(stats, protocol)
        elif eth_type == 0x0806:
            stats.arp += 1
            sizes.append(arp_packet_size(payload))
        else:
            stats.other_l3 += 1
            if payload:
                sizes.append(len(payload))

    stats.packet_sizes = bin_packet_sizes(sizes)
    return stats


def calculate_packets_per_second(frames: list[tuple[float, bytes]]) -> PacketRateStatistics | None:
    """Count and return the number of packets received in each second of the first 10 seconds."""

    bins = [0] * 10

    if not frames:
        return None

    first_timestamp = frames[0][0]
    for (timestamp, _) in frames:
        seconds_since_start = timestamp - first_timestamp
        if 0 <= seconds_since_start < 10:
            bins[int(seconds_since_start)] += 1

    return PacketRateStatistics(
        bin_edges=list(range(11)),
        rates=bins,
    )


def graph_packet_statistics(statistics: PacketStatistics):
    """Display the protocol and packet-size statistics as bar graphs."""
    fig, axes = plt.subplots(2, 2, figsize=(11, 8))

    def _bar(ax, items: list[tuple[str, int]], title: str, xlabel: str):
        """Draw a bar chart of the non-zero items on the given axes."""
        items = [(label, count) for label, count in items if count > 0]
        if not items:
            ax.set_title(f"{title} (no data)")
            return
        labels, values = zip(*items)
        ax.bar(labels, values, color="steelblue", edgecolor="black")
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Packet count")
        ax.tick_params(axis="x", rotation=45)
        ax.grid(True, axis="y", linestyle=":", alpha=0.6)

    l2_items = [
        ("Ethernet II", statistics.ethernet_ii),
        ("IEEE 802.3", statistics.ieee_802_3),
    ]
    l3_items = [
        ("IPv4", statistics.ipv4),
        ("IPv6", statistics.ipv6),
        ("ARP", statistics.arp),
        ("Other", statistics.other_l3),
    ]
    l4_items = [
        ("TCP", statistics.tcp),
        ("UDP", statistics.udp),
        ("ICMP", statistics.icmp),
        ("ICMPv6", statistics.icmpv6),
        ("IGMP", statistics.igmp),
        ("Other", statistics.other_l4),
    ]
    size_items = [
        (f"{lower}-{lower + 249}", count)
        for lower, count in sorted(statistics.packet_sizes.items())
    ]

    _bar(axes[0, 0], l2_items, "L2 Protocol Distribution", "L2 type")
    _bar(axes[0, 1], l3_items, "L3 Protocol Distribution", "L3 protocol")
    _bar(axes[1, 0], l4_items, "L4 Protocol Distribution", "L4 protocol")
    _bar(axes[1, 1], size_items, "L3 Packet Size Distribution", "Size range (bytes)")

    fig.tight_layout()
    return fig


def graph_packets_per_second(statistics: PacketRateStatistics):
    """Plot packets per second over the capture's first ten seconds."""
    x = statistics.bin_edges[:-1]
    y = statistics.rates
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(x, y, color="black", linewidth=0.7)
    ax.set_title("Packets/sec — First 10 Seconds of Capture")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packets/1 sec")
    ax.grid(True, linestyle=":", linewidth=0.5, color="gray", alpha=0.6)
    ax.set_xlim(min(x), max(x))
    ax.set_ylim(bottom=0)
    fig.tight_layout()

    return fig


def number_converter():
    """Repeatedly convert unsigned 16-bit binary, hexadecimal, or decimal input."""
    print("\nNumber Converter (0 to 65535 / Max 16 bits)")
    print("Choose b for binary, h for hexadecimal, d for decimal, or q to quit.")

    bases = {"b": (2, "Binary"), "h": (16, "Hexadecimal"),
             "d": (10, "Decimal")}

    while True:
        try:
            choice = input("\nInput base (b/h/d/q): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting number converter.")
            break
        if choice.lower() == "q":
            print("Exiting number converter.")
            break
        if choice not in bases:
            print("Invalid choice. Enter b, h, d, or q.")
            continue

        base, name = bases[choice]
        try:
            number_text = input("\nEnter number (q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting number converter.")
            break

        try:
            number = int(number_text, base)
        except ValueError:
            print(f"Invalid {name.lower()} number. Try again.")
            continue

        if not 0 <= number <= 0xFFFF:
            print("Number out of range. Enter a value from 0 to 65535 (16 bits).")
            continue

        if choice != "b":
            print(f"Binary: {number:016b}")
        if choice != "h":
            print(f"Hexadecimal: 0x{number:X}")
        if choice != "d":
            print(f"Decimal: {number}")


def main(filename: str):
    """Parse the capture, print each frame's headers and checksums, then show statistics."""
    if filename.lower() == "convert":
        number_converter()
        return

    frames = parse(filename)
    if not frames:
        print("No packets found.")
        return

    # Process each frame and print the extracted information
    for index, (_, raw) in enumerate(frames):
        prefix = "" if index == 0 else "\n"
        print(f"{prefix}Packet {index + 1}")

        # Decapsulate the Ethernet frame
        try:
            frame = ethernet_decapsulation(raw)
            print(f"\t{frame}")
        except ValueError as e:
            print(f"\t{e}")
            continue

        # Only process IPv4 packets
        if isinstance(frame, FrameIEEE) or frame.eth_type != b"\x08\x00":
            continue

        # Decapsulate the IPv4 packet
        try:
            packet = packet_decapsulation(frame.data)
            print(f"\t{packet}")
        except ValueError as e:
            print(f"\t{e}")
            continue

        # Verify the IPv4 header checksum
        received_ip = int.from_bytes(packet.header_checksum, "big")
        calculated_ip = calculate_ip_checksum(packet)
        ip_result = "valid" if received_ip == calculated_ip else "invalid"
        print(
            f"\tIP Checksum: received 0x{received_ip:04x}, "
            f"calculated 0x{calculated_ip:04x} ({ip_result})"
        )

        # Only process TCP segments
        if packet.protocol != 6:
            continue

        # Decapsulate the TCP segment
        try:
            segment = segment_decapsulation(packet)
            print(f"\t{segment}")
        except ValueError as e:
            print(f"\t{e}")
            continue

        # Verify the TCP checksum
        received_tcp = int.from_bytes(segment.checksum, "big")
        calculated_tcp = calculate_tcp_checksum(packet, segment)
        tcp_result = "valid" if received_tcp == calculated_tcp else "invalid"
        print(
            f"\tTCP Checksum: received 0x{received_tcp:04x}, "
            f"calculated 0x{calculated_tcp:04x} ({tcp_result})"
        )

    statistics = calculate_packet_statistics(frames)
    print(f"\n{statistics}")
    graph_packet_statistics(statistics)

    first_10_sec_data = calculate_packets_per_second(frames)
    if first_10_sec_data is not None:
        print(f"\n{first_10_sec_data}")
        graph_packets_per_second(first_10_sec_data)

    plt.show()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <input_filename>")
        print("       python main.py convert   (16-bit number converter)")
        sys.exit(1)

    main(sys.argv[1])

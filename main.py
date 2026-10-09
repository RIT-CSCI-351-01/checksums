"""
Assignment: Checksums Part 1
Course: CSCI 351 Data Communications and Networks

Team members:
    - Jonathan Schultz (jss5874@rit.edu)

Sources:
    - RFC 791, Internet Protocol
    - RFC 9293, Transmission Control Protocol
    - RFC 1071, Computing the Internet Checksum
    - IEEE 802.3 Standard
    - Wireshark
"""

import sys
from dataclasses import dataclass


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

@dataclass
class FrameII:
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
            #f"Type: {ETH_TYPES.get(eth_type, "Unknown")} (0x{eth_type:04x})"
        )

@dataclass
class FrameIEEE:
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
    version: int = 0            # 4 bits
    ihl: int = 0                 # 4 bits
    tos: int = 0                 # 8 bits
    total_length: int = 0        # 16 bits
    identification: int = 0      # 16 bits
    flags: int = 0               # 3 bits
    fragment_offset: int = 0     # 13 bits
    ttl: int = 0                 # 8 bits
    protocol: int = 0            # 8 bits
    header_checksum: bytes = bytes(2)  # 2 bytes
    source_ip: bytes = bytes(4)        # 4 bytes
    dest_ip: bytes = bytes(4)          # 4 bytes
    options: bytes = b""               # 0-40 bytes
    data: bytes = b""                  # variable length

    def __str__(self) -> str:
        """Return a string representation of the IPv4 packet."""
        return ( 
            f"IPv4: Src: {format_ip(self.source_ip)}, "
            f"Dst: {format_ip(self.dest_ip)}, "
            f"Protocol: {self.protocol}"
        )


@dataclass
class Segment:
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
        return (
            f"TCP: Src Port: {self.source_port}, "
            f"Dst Port: {self.dest_port}, "
            f"Seq: {self.sequence_number}, "
            f"Ack: {self.ack_number}"
        )


def parse(filename: str) -> list[bytes]:
    try:
        with open(filename) as file:
            frames = []
            while (line := file.readline()) != "":
                # Ignore non-data lines and seperators
                if line.startswith("|"):
                    # Convert the hex values in the line to bytes and append to frames
                    hex_values = (
                        int(c.strip(), 16)
                        for c in line.strip().split("|")[2:]
                        if c.strip()
                    )
                    frames.append(bytes(hex_values))
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
    """Process an IPv4 packet and extract the TCP segment header and data."""

    return Segment() # TODO (RFC 9293)


def ones_complement_sum(data: bytes) -> int:
    return 0  # TODO (RFC 1071)


def calculate_ip_checksum(packet: Packet) -> int:
    return 0  # TODO


def calculate_tcp_checksum(packet: Packet, segment: Segment) -> int:
    return 0  # TODO


def main(filename: str):
    frames = parse(filename)
    if not frames:
        print("No packets found.")
        return

    # Process each frame and print the extracted information
    for index, raw in enumerate(frames):
        #print(f"{"" if index == 0 else "\n"}Packet {index + 1}")
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <input_filename>")
        sys.exit(1)

    main(sys.argv[1])

"""
Assignment: Checksums Part 1
Course: CSCI 351 Data Communications and Networks

Team members:
    - Jonathan Schultz (jss5874@rit.edu)

Sources:
    - RFC 791, Internet Protocol
    - RFC 9293, Transmission Control Protocol
    - RFC 1071, Computing the Internet Checksum
    - Wireshark
"""

import sys
from dataclasses import dataclass


def print_mac(mac: str) -> str:
    return ":".join(f"{int(mac[i:i+8], 2):02x}" for i in range(0, len(mac), 8))


def format_ip(ip: str) -> str:
    return ".".join(str(int(ip[i:i + 8], 2)) for i in range(0, 32, 8))


@dataclass
class Frame:
    dest_mac: str = ""          # 6 bytes
    source_mac: str = ""        # 6 bytes
    eth_type: str = ""          # 2 bytes
    data: str = ""              # 46-1500 bytes (may or may not be padded)

    def __str__(self) -> str:
        return (
            f"Ethernet II: Dst: {print_mac(self.dest_mac)}, "
            f"Src: {print_mac(self.source_mac)}, "
            f"Type: 0x{int(self.eth_type, 2):04x}"
        )


@dataclass
class Packet:
    version: str = ""           # 4 bits
    ihl: str = ""               # 4 bits
    tos: str = ""               # 8 bits
    total_length: str = ""      # 16 bits
    identification: str = ""    # 16 bits
    flags: str = ""             # 3 bits
    fragment_offset: str = ""   # 13 bits
    ttl: str = ""               # 8 bits
    protocol: str = ""          # 8 bits
    header_checksum: str = ""   # 16 bits
    source_ip: str = ""         # 32 bits
    dest_ip: str = ""           # 32 bits
    options: str = ""           # 0-40 bytes
    data: str = ""              # variable length

    def __str__(self) -> str:
        return (
            f"IPv4: Src: {format_ip(self.source_ip)}, "
            f"Dst: {format_ip(self.dest_ip)}, "
            f"Protocol: {int(self.protocol, 2)}"
        )


@dataclass
class Segment:
    source_port: str = ""       # 16 bits
    dest_port: str = ""         # 16 bits
    sequence_number: str = ""   # 32 bits
    ack_number: str = ""        # 32 bits
    data_offset: str = ""       # 4 bits
    reserved: str = ""          # 3 bits
    flags: str = ""             # 9 bits
    window_size: str = ""       # 16 bits
    checksum: str = ""          # 16 bits
    urgent_pointer: str = ""    # 16 bits
    optional_data: str = ""     # 0-40 bytes
    data: str = ""              # variable length

    def __str__(self) -> str:
        return (
            f"TCP: Src Port: {int(self.source_port, 2)}, "
            f"Dst Port: {int(self.dest_port, 2)}, "
            f"Seq: {int(self.sequence_number, 2)}, "
            f"Ack: {int(self.ack_number, 2)}"
        )


def parse(filename: str) -> list[str]:
    try:
        with open(filename) as file:
            frames = []
            while (line := file.readline()) != "":
                if line.startswith("|"):
                    frames.append("".join(
                        f"{int(c.strip(), 16):08b}" for c in line.strip().split("|")[2:] if c.strip()
                    ))
            return frames
    except OSError:
        print(f"Could not open file: {filename}")
        sys.exit(1)
    except ValueError:
        print(f"Could not parse file: {filename}")
        sys.exit(1)


def ethernet_decapsulation(frame: str) -> Frame:
    if len(frame) < 14 * 8: 
        raise ValueError("Frame is too short to hold an Ethernet header.")

    dest_mac = frame[0:48]
    source_mac = frame[48:96]
    eth_type = frame[96:112]
    data = frame[112:]
    
    if eth_type != f"{int('0800', 16):016b}":
        raise ValueError("Frame type is not IPv4.")

    return Frame(
        dest_mac=dest_mac,
        source_mac=source_mac,
        eth_type=eth_type,
        data=data
    )


def packet_decapsulation(frame: Frame) -> Packet:
    return Packet() # TODO create packet and trim data to total length


def segment_decapsulation(packet: Packet) -> Segment:
    return Segment() # TODO create segment


def main(filename: str):
    frames = parse(filename)
    if not frames:
        print("No packets found.")
        return

    for index, raw in enumerate(frames):
        print(f"Packet {index + 1}")
        try:
            frame = ethernet_decapsulation(raw)
            packet = packet_decapsulation(frame)
            segment = segment_decapsulation(packet)
            print(f"\n\t{frame}\n\t{packet}\n\t{segment}")
        except ValueError as e:
            print(f"\t{e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <input_filename>")
        sys.exit(1)

    main(sys.argv[1])
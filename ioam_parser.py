from scapy.all import AsyncSniffer, rdpcap
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6TimeExceeded,
    IPv6ExtHdrHopByHop,
    ICMPv6DestUnreach,
)
from datetime import datetime
from enum import Enum

import subprocess, sys, argparse, threading, ipaddress, copy

tab4 = "    "
parser_prefix = "[IOAM parser]"


class TraceFieldEnum(Enum):
    HOP_LIM_NODE_ID_SHORT = (0, "Hop_Lim and Node ID (short)", 4)
    INGRESS_EGRESS_IF_ID_SHORT = (1, "ingress_egress_if_id_short", 4)
    TIMESTAMP_SECS = (2, "Timestamp Seconds", 4)
    TIMESTAMP_FRAC = (3, "Timestamp Fraction", 4)
    TRANSIT_DELAY = (4, "Transit Delay", 4)
    NAMESPACE_SPECIFIC_SHORT = (5, "Namespace Data (short)", 4)
    QUEUE_DEPTH = (6, "queue_depth", 4)
    CHECKSUM_COMPLEMENT = (7, "checksum_complement", 4)
    HOP_LIM_NODE_ID_WIDE = (8, "Hop_Lim and Node ID (wide)", 8)
    INGRESS_EGRESS_IF_ID_WIDE = (9, "ingress_egress_if_id_wide", 8)
    NAMESPACE_SPECIFIC_WIDE = (10, "namespace_specific_wide", 8)
    BUFFER_OCCUPANCY = (11, "buffer_occupancy", 4)

    def __init__(self, bitnum: int, field_name: str, size: int):
        self.bitnum = bitnum
        self.field_name = field_name
        self.size = size

    def field_str(self, value: bytes) -> str:
        # TODO: add specific formats for relevant fields
        s = f"{self.field_name}: "
        match self:
            case TraceFieldEnum.HOP_LIM_NODE_ID_SHORT:
                ID = "".join(f"{b:02x}" for b in value[1:5])
                s += f"Hop_Lim: {value[0]} ID: 0x{ID}\n"
            case TraceFieldEnum.TIMESTAMP_SECS:  # timestamp sec
                s += f"{datetime.fromtimestamp(int.from_bytes(value))}\n"
            case TraceFieldEnum.TIMESTAMP_FRAC:  # timestamp frac
                s += f"{int.from_bytes(value) / 2**32:.12f}s\n"
            case _:
                s += f"0x{"".join(f"{b:02x}" for b in value)}\n"
        return s


class IOAMHeader:
    def __init__(
        self,
        ns_id: int,
        node_len: int,
        trace_type: bytes,
        node_array: bytes,
        trace_fields: list[TraceFieldEnum],
    ):
        self.namespace_id = ns_id
        self.node_length = node_len
        self.trace_type = trace_type
        self.node_array = node_array
        self.trace_fields = trace_fields

    def __repr__(self) -> str:
        s = f"{tab4}Namespace ID: {self.namespace_id}\n"
        s += f"{tab4}Node Length: {self.node_length}\n"
        s += f"{tab4}Trace Type: 0x" + (
            "".join(f"{b:02x}" for b in self.trace_type) + "\n"
        )
        s += f"{tab4}Node Array:\n"

        node_num = int(len(self.node_array) / self.node_length)
        # print nodes in reverse order
        for i in range(node_num - 1, -1, -1):
            s += f"{2 * tab4}Node {node_num - i}:\n"
            node_start = i * self.node_length
            node = self.node_array[node_start : node_start + self.node_length]
            s += node_str(self.trace_fields, node)
        s += "\n"
        return s


class IOAMPacketInfo:
    def __init__(self, icmp_type: str, src_ip: str, ioam_header: IOAMHeader):
        self.icmp_type = icmp_type
        self.src_ip = src_ip
        self.ioam_header = ioam_header

    def __repr__(self) -> str:
        s = self.icmp_type + " from " + self.src_ip + "\n"
        s += str(self.ioam_header)
        return s


def print_bytes_hexa(bytes):
    for i in range(0, len(bytes), 16):
        chunk = bytes[i : i + 16]
        hex_line = chunk.hex()
        spaced_hex = " ".join(hex_line[j : j + 2] for j in range(0, len(hex_line), 2))
        print(f"{i:04x}: {spaced_hex}")


def node_str(trace_fields: list[TraceFieldEnum], node_data: bytes) -> str:
    s = ""
    offset = 0
    for tf in trace_fields:
        if offset + tf.size > len(node_data):
            print(f"[!] Not enough data left to parse field {tf.name}. Skipping.")
            break
        value = node_data[offset : offset + tf.size]
        s += f"{3 * tab4}" + tf.field_str(value)
        offset += tf.size

    if offset < len(node_data):
        remaining = node_data[offset:]
        print(f"[!] Warning: {len(remaining)} extra bytes at end of node data")
    return s


def decode_trace_type(trace_type) -> list[TraceFieldEnum]:
    trace_fields = []
    trace_type_int = int.from_bytes(trace_type)

    for tf in TraceFieldEnum:
        if trace_type_int & (1 << (23 - tf.bitnum)):  # MSB is bit 0
            trace_fields.append(copy.copy(tf))

    return trace_fields


def parse_ioam_option(opt) -> IOAMHeader | None:
    data = opt.optdata

    option_type = data[1]
    if option_type != 0:
        print("[!] Non Pre-Allocated Trace-Option detected")
        return

    namespace_id = int.from_bytes(data[2:4])
    # node length is first 5 bits of 5th byte, scale of 4
    node_length = 4 * ((data[4] & 0b11111000) >> 3)
    # remaining length is 7 bottom bits of 6th byte, scale of 4
    remaining_length = 4 * (data[5] & 0b01111111)

    trace_type = data[6:9]
    trace_fields = decode_trace_type(trace_type)

    # skip free space
    trace_data = data[10:]
    node_array = trace_data[remaining_length:]

    header = IOAMHeader(namespace_id, node_length, trace_type, node_array, trace_fields)
    return header


def parse_packet(pkt) -> IOAMPacketInfo | None:
    if ICMPv6TimeExceeded in pkt:
        icmp_payload = bytes(pkt[ICMPv6TimeExceeded].payload)
        icmp_type = "ICMPv6TimeExceeded"
    elif ICMPv6DestUnreach in pkt:
        icmp_payload = bytes(pkt[ICMPv6DestUnreach].payload)
        icmp_type = "ICMPv6DestUnreach"
    else:
        return

    try:
        inner_ipv6 = IPv6(icmp_payload)
        if IPv6ExtHdrHopByHop in inner_ipv6:
            hopopts = inner_ipv6[IPv6ExtHdrHopByHop]
            for opt in hopopts.options:
                if opt.otype == 0x31:  # IOAM Trace Option
                    print(
                        f"[+] IOAM Option found, icmp type = {icmp_type}, length = {opt.optlen}"
                    )
                    ioam_header = parse_ioam_option(opt)
                    if ioam_header:
                        return IOAMPacketInfo(icmp_type, pkt[IPv6].src, ioam_header)
    except Exception as e:
        print(f"[-] Failed to extract IOAM: {e}")


def run_tracepath(destination):
    print(f"{parser_prefix} Running Tracepath:")
    try:
        result = subprocess.run(
            ["tracepath", "-6", "-n", "-m 20", "-l 256", "-p 33434", destination],
            capture_output=True,
            text=True,
            check=True,
        )
        print(tab4 + result.stdout.replace("\n", "\n" + tab4))
    except subprocess.CalledProcessError as e:
        print(f"{parser_prefix} Tracepath Error: {e.stderr}")


def parse_args():
    parser = argparse.ArgumentParser(description="IOAM Tracepath Sniffer & Parser")
    parser.add_argument("-i", "--interface", help="Interface to sniff on")
    parser.add_argument("input", help="IPv6 address to tracepath")
    return parser.parse_args()


def capture_tracepath_packets(args):
    ready = threading.Event()
    sniffer = AsyncSniffer(
        iface=args.interface,
        timeout=30,
        store=True,
        started_callback=lambda: ready.set(),
    )
    print(f"{parser_prefix} Starting Scapy sniffer")
    sniffer.start()
    ready.wait()

    run_tracepath(args.input)

    sniffer.stop()
    sniffer.join()
    packets = sniffer.results
    print(f"{parser_prefix} Scapy sniffer closed, {len(packets)} packets found")
    return packets


def get_packets(args):
    try:
        ipaddress.ip_address(args.input)
        packets = capture_tracepath_packets(args)
    except ValueError:
        packets = rdpcap(args.input)
    return packets


def parse_packets(packets) -> list[IOAMPacketInfo]:
    print(f"{parser_prefix} Parsing {len(packets)} packets for IOAM data...")

    ioam_info_array = []
    for i, pkt in enumerate(packets):
        ioam_info = parse_packet(pkt)
        if ioam_info:
            ioam_info_array.append(ioam_info)

    print(f"{parser_prefix} found IOAM data in {len(ioam_info_array)} packets")
    return ioam_info_array


def print_ioam_info(info_array):
    with open("ioam_data.txt", "w") as f:
        original_stdout = sys.stdout
        sys.stdout = f

        for pkt in info_array:
            print(pkt)
        sys.stdout = original_stdout

    print(f"{parser_prefix} Finished")


def main():
    args = parse_args()
    packets = get_packets(args)
    ioam_info_array = parse_packets(packets)
    print_ioam_info(ioam_info_array)


if __name__ == "__main__":
    main()

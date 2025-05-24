from scapy.all import AsyncSniffer, rdpcap, conf
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, IPv6ExtHdrHopByHop, ICMPv6DestUnreach

import subprocess, sys, argparse, threading, ipaddress

tab4 = "    "
parser_prefix = "[IOAM parser]"

IOAM_TRACE_FIELDS = [
    (0,  "hop_lim_node_id_short",       4),
    (1,  "ingress_egress_if_id_short",  4),
    (2,  "timestamp_secs",              4),
    (3,  "timestamp_frac",              4),
    (4,  "transit_delay",               4),
    (5,  "namespace_specific_short",    4),
    (6,  "queue_depth",                 4),
    (7,  "checksum_complement",         4),
    (8,  "hop_lim_node_id_wide",        8),
    (9,  "ingress_egress_if_id_wide",   8),
    (10, "namespace_specific_wide",     8),
    (11, "buffer_occupancy",            4),
    # bits 12–21: reserved, 4 bytes each if set
    # bit 22: opaque snapshot, variable-length — skip
]

class IOAMHeader:
    namespace_id: int
    node_length: int  # in bytes
    trace_type: bytes # 3 bytes
    node_array: bytes
    trace_fields = []

class IOAMPacketInfo:
    icmp_type = ""
    src_ip = ""
    ioam_header: IOAMHeader | None
    

def print_bytes_hexa(bytes):
    for i in range(0, len(bytes), 16):
        chunk = bytes[i:i+16]
        hex_line = chunk.hex()
        spaced_hex = ' '.join(hex_line[j:j+2] for j in range(0, len(hex_line), 2))
        print(f"{i:04x}: {spaced_hex}")


def print_node_fields(node_fields, node_data: bytes):
    offset = 0
    for name, size in node_fields:
        if offset + size > len(node_data):
            print(f"[!] Not enough data left to parse field {name}. Skipping.")
            break
        value = node_data[offset:offset+size]
        print(f"{3 * tab4}{name}: " + ''.join(f'{b:02x}' for b in value))
        offset += size

    if offset < len(node_data):
        remaining = node_data[offset:]
        print(f"[!] Warning: {len(remaining)} extra bytes at end of node data")


def print_ioam_data(ioamh: IOAMHeader):
    print(f"{tab4}Namespace ID: {ioamh.namespace_id}")
    print(f"{tab4}Node Length: {ioamh.node_length}")
    print(f"{tab4}Trace Type: 0x" + ''.join(f'{b:02x}' for b in ioamh.trace_type))
    print(f"{tab4}Node Array:")

    trace_fields = ioamh.trace_fields
    for i in range(0, int(len(ioamh.node_array) / ioamh.node_length)):
        print(f"{2 * tab4}Node {i + 1}:")
        node_start = i * ioamh.node_length
        node = ioamh.node_array[node_start:node_start + ioamh.node_length]
        print_node_fields(trace_fields, node)

    print("")

def decode_trace_type(trace_type):
    trace_fields = []
    trace_type_int = int.from_bytes(trace_type)

    for bit_index, name, size in IOAM_TRACE_FIELDS:
        if trace_type_int & (1 << (23 - bit_index)):  # MSB is bit 0
            trace_fields.append((name, size))

    return trace_fields


def parse_ioam_option(opt):
    # print_bytes_hexa(opt.optdata)
    data = opt.optdata
    header = IOAMHeader()
    # should be 0 for pre allocated trace
    option_type = int.from_bytes([data[1]])
    if option_type != 0:
        print("[!] Non Pre-Allocated Trace-Option detected")
        return

    header.namespace_id = int.from_bytes(data[2:4])
    # node length is first 5 bits of 5th byte
    header.node_length = 4 * ((int.from_bytes(data[4:5]) & 0b11111000) >> 3)
    # remaining length is 7 bottom bits of 6th byte
    remaining_length = 4 * ((int.from_bytes(data[5:6]) & 0b01111111))
    header.trace_type = data[6:9]
    header.trace_fields = decode_trace_type(header.trace_type)
    trace_data = data[10:] 
    # skip free space
    header.node_array = trace_data[remaining_length:] 

    return header
    

def parse_packet(pkt):
    if ICMPv6TimeExceeded in pkt:
        icmp_payload = bytes(pkt[ICMPv6TimeExceeded].payload)    
        icmp_type = "ICMPv6TimeExceeded"
    elif ICMPv6DestUnreach in pkt:
        icmp_payload = bytes(pkt[ICMPv6DestUnreach].payload)
        icmp_type = "ICMPv6DestUnreach"
    else:
        return
    
    packet_info = IOAMPacketInfo()
    packet_info.src_ip = pkt[IPv6].src
    packet_info.icmp_type = icmp_type

    try:
        inner_ipv6 = IPv6(icmp_payload)
        if IPv6ExtHdrHopByHop in inner_ipv6:
            hopopts = inner_ipv6[IPv6ExtHdrHopByHop]
            for opt in hopopts.options:
                if opt.otype == 0x31:  # IOAM Trace Option
                    print(f"[+] IOAM Option found, icmp type = {icmp_type}, length = {opt.optlen}") 
                    packet_info.ioam_header = parse_ioam_option(opt)
                    if packet_info.ioam_header:
                        return packet_info
    except Exception as e:
        print(f"[-] Failed to extract IOAM: {e}")


def run_tracepath(destination):
    print(f"{parser_prefix} Running Tracepath:")
    try:
        result = subprocess.run(
            ["tracepath", "-6", "-n", "-m 20", "-l 1000", "-p 33434", destination],
            capture_output=True,
            text=True,
            check=True
        )
        print(tab4 + result.stdout.replace("\n", "\n" + tab4))
    except subprocess.CalledProcessError as e:
        print(f"{parser_prefix} Tracepath Error: {e.stderr}")


def parse_args():
    default_iface = conf.iface
    parser = argparse.ArgumentParser(description="IOAM Tracepath Sniffer & Parser")
    parser.add_argument("-i", "--interface", help="Interface to sniff on")
    parser.add_argument("input", help="IPv6 address to tracepath")
    return parser.parse_args()


def capture_packets():
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=args.interface, timeout=30, 
                           store=True, started_callback=lambda: ready.set())
    print(f"{parser_prefix} Starting Scapy sniffer")
    sniffer.start()
    ready.wait()

    run_tracepath(args.input)

    sniffer.stop()
    sniffer.join()
    packets = sniffer.results
    print(f"{parser_prefix} Scapy sniffer closed, {len(packets)} packets found")
    return packets


def get_packets():
    input_is_ip = False
    try:
        ipaddress.ip_address(args.input)
        input_is_ip = True
    except ValueError:
        pass
    
    if input_is_ip:
        packets = capture_packets()
    else:
        packets = rdpcap(args.input)
    
    return packets


if __name__ == "__main__":
    args = parse_args()
    packets = get_packets()

    print(f"{parser_prefix} Parsing {len(packets)} packets for IOAM data...")
    ioam_packets_array = []
    for i, pkt in enumerate(packets):
        ioam_data = parse_packet(pkt)
        if ioam_data:
            ioam_packets_array.append(ioam_data)
    print(f"{parser_prefix} found IOAM data in {len(ioam_packets_array)} packets")
        
    with open("ioam_data.txt", "w") as f:
        original_stdout = sys.stdout
        sys.stdout = f

        for pkt in ioam_packets_array:
            print(pkt.icmp_type, "from", pkt.src_ip)
            print_ioam_data(pkt.ioam_header)
        sys.stdout = original_stdout

    print(f"{parser_prefix} Finished")
    
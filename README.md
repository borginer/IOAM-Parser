# IPv6 IOAM Network Emulator

This project emulates an IPv6 IOAM (In-situ Operations, Administration, and Maintenance) network using Linux network namespaces, Scapy, and custom tracepath probes. It allows you to simulate packet flows, inject IOAM headers, and parse trace information from live network traffic or `.pcap` files.

## Features

- Emulates a multi-node IPv6 network using `ip netns`
- Configures IOAM namespaces, schemas, and trace types
- Runs tracepath to generate hop-by-hop IOAM data
- Uses Scapy to capture and parse packets
- Outputs IOAM data in structured JSON format

## Dependencies and Setup

To run this project, install the following dependencies:

### 1. Python 3.13

Ensure you're using **Python 3.13**. You can check your version using:
python3 –version
If not installed, download it from https://www.python.org/downloads/, or use your package manager:

Example for Ubuntu (adjust for actual 3.13 availability or use deadsnakes PPA)

sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.13 python3.13-venv python3.13-dev

### 2. Scapy 2.5

Install Scapy version 2.5:
pip install scapy==2.5.0
Verify installation:
python -c “import scapy; print(scapy.version)”

### 3. tracepath

The `tracepath` tool is required to generate IOAM traffic.

Install with:
sudo apt install iputils-tracepath

Verify it’s available:
tracepath –version

## Usage

### Running the Emulation
sudo ./run_emulation.sh

creates alpha.pcap which you can parse again using the next option

### Running the Parser Alone
1. Reading from pcap file:
sudo python3 ioam_parser.py file.pcap

2. Running the parser to target (IPv6):
sudo python3 ioam_parser.py -i interface_name IPv6_address

## License

MIT License

## Acknowledgements

This project uses:
- Linux network namespaces
- Scapy
- iproute2 tracepath
# IPv6 IOAM Parser & Network Emulator

This project emulates an IPv6 IOAM (In-situ Operations, Administration, and Maintenance) network using Linux network namespaces to simulate packet flows and inject IOAM headers. Then parse trace information from live network traffic or `.pcap` files using Scapy.

## Features

- Emulates a multi-node IPv6 network using `ip netns`
- Configures IOAM namespaces, schemas, and trace types
- Uses `tracepath` to generate hop-by-hop IOAM data
- Captures and parses packets using Scapy
- Outputs IOAM data in a structured format

## Dependencies and Setup

To run this project, ensure the following dependencies are installed:

### 1. IOAM kernel flag

Ensure your kernel has the `CONFIG_IPV6_IOAM6_LWTUNNEL=y` configuration

Can check this by running:

```bash
grep CONFIG_IPV6_IOAM6_LWTUNNEL /boot/config-$(uname -r)
```

### 2. Python 3.13

Ensure you are using **Python 3.13** or higher.

Check version:

```bash
python3 --version
```

If not installed, install it using the [official Python website](https://www.python.org/downloads/) or via your package manager.

Example for Ubuntu:

```bash
sudo apt install python3
```

### 3. Scapy 2.5

Install Scapy version 2.5 or higher:

```bash
sudo apt install python3-scapy
```

Verify installation:

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

### 4. iproute2

`iproute2` provides the tools needed for Linux network namespaces

Install on Ubuntu:

```bash
sudo apt update
sudo apt install iproute2
```

### 5. tracepath

The `tracepath` utility is required to generate traffic.

Install on Ubuntu:

```bash
sudo apt install iputils-tracepath
```

Verify installation:

```bash
tracepath --version
```

## Usage

### Run the IOAM Network Emulation

To simulate the IOAM network and within it run the parser:

```bash
sudo ./run_emulation.sh
```

This creates a `alpha.pcap` file, which can be parsed again using the parser script separately:

### Run the IOAM Parser

1. **Parse from `.pcap` file**:

```bash
sudo python3 ioam_parser.py file.pcap
```

2. **Live capture on a network interface (for IPv6 destination)**:

```bash
sudo python3 ioam_parser.py -i <interface_name> <IPv6_address>
```

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

This project utilizes the following technologies:

- Linux network namespaces
- Scapy
- iproute2 tracepath
- Python3

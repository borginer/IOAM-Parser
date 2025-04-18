#!/bin/bash

rm gamma.pcap
rm packets.json
rm filtered_ioam.json

./IOAM_net_emulation.sh

sleep 1

tshark -r gamma.pcap -Y "icmpv6.type == 128 || icmpv6.type == 129" \
       -T json > packets.json

jq -f filter.jq packets.json > filtered_ioam.json
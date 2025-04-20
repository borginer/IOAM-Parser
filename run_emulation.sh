#!/bin/bash

rm gamma.pcap
rm packets.json
rm filtered_ioam.json

./IOAM_net_emulation.sh

sleep 1

tshark -r gamma.pcap -T json > packets.json

jq -f filter.jq packets.json > filtered_ioam.json
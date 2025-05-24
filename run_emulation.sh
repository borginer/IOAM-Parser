#!/bin/bash

for file in "gamma.pcap" "alpha.pcap"; do
    [ -f "$file" ] && rm $file
done


./IOAM_net_emulation.sh

sleep 1



# tshark -r gamma.pcap -T json > packets.json

# jq -f filter.jq packets.json > filtered_ioam.json
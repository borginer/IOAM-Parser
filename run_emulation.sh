#!/bin/bash

for file in "gamma.pcap" "alpha.pcap"; do
    [ -f "$file" ] && rm $file
done

./netns_ioam_emulation.sh

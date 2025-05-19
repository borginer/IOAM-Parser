#!/bin/bash
#  +-------------------+                                                            +-------------------+
#  |                   |                                                            |                   |
#  |    Alpha netns    |                                                            |    Gamma netns    |
#  |     deadbee0      |                                                            |      deadbee4     |
#  |  +-------------+  |                                                            |  +-------------+  |
#  |  |    veth0    |  |                                                            |  |    veth0    |  |
#  |  |  db01::2/64 |  |                                                            |  |  db04::2/64 |  |
#  |  +-------------+  |                                                            |  +-------------+  |
#  |        .          |                                                            |         .         |
#  +-------------------+                                                            +-------------------+
#           .                                                                                 .
#           .                                                                                 .
#           .                                                                                 .
#  +------------------------------+   +------------------------------+   +------------------------------+
#  |        .  deadbee1           |   |           deadbee2   .       |   |           deadbee3 .         |
#  | +----------+    +----------+ |   | +----------+    +----------+ |   | +----------+    +----------+ |
#  | |   veth0  |    |   veth1  | |   | |  veth0   |    |  veth1   | |   | |  veth0   |    |  veth1   | |
#  | |db01::1/64| .. |db02::1/64|.| . |.|db02::2/64| .. |db03::1/64|.| . |.|db03::2/64| .. |db04::1/64| |
#  | +----------+    +----------+ |   | +----------+    +----------+ |   | +----------+    +----------+ |
#  |                              |   |                              |   |                              |
#  |           r1 netns           |   |           r2 netns           |   |           r3 netns           |
#  +------------------------------+   +------------------------------+   +------------------------------+

source lib.sh

ALPHA=(
	1					# ID
	11111111				# Wide ID
	0xffff					# Ingress ID
	0xffffffff				# Ingress Wide ID
	101					# Egress ID
	101101					# Egress Wide ID
	0xdeadbee0				# Namespace Data
	0xcafec0caf11dc0de			# Namespace Wide Data
	555   					# Schema ID (0xffffff = None)
	"something that will be 4n-aligned"	# Schema Data
)

ROUTER1=(
	2
	22222222
	201
	201201
	202
	202202
	0xdeadbee1
	0xcafec0caf22dc0de
	666
	"Hello there -Obi"
)

ROUTER2=(
	4
	44444444
	401
	401401
	404
	404404
	0xdeadbee2
	0xcafec0caf44dc0de
	777
	"Hello there -Obi"
)

ROUTER3=(
	5
	55555555
	501
	501501
	505
	505505
	0xdeadbee3
	0xcafec0caf55dc0de
	888
	"Leshy there -Obi"
)

GAMMA=(
	3
	33333333
	301
	301301
	0xffff
	0xffffffff
	0xdeadbee4
	0xcafec0caf33dc0de
	999
	"World there -Obi"
)

check_kernel_compatibility()
{
  setup_ns ioam_tmp_node
  ip link add name veth0 netns $ioam_tmp_node type veth \
         peer name veth1 netns $ioam_tmp_node

  ip -netns $ioam_tmp_node link set veth0 up
  ip -netns $ioam_tmp_node link set veth1 up

  ip -netns $ioam_tmp_node ioam namespace add 0
  ns_ad=$?

  ip -netns $ioam_tmp_node ioam namespace show | grep -q "namespace 0"
  ns_sh=$?

  if [[ $ns_ad != 0 || $ns_sh != 0 ]]
  then
    echo "SKIP: kernel version probably too old, missing ioam support"
    ip link del veth0 2>/dev/null || true
    cleanup_ns $ioam_tmp_node || true
    exit $ksft_skip
  fi

  ip -netns $ioam_tmp_node route add db02::/64 encap ioam6 mode inline \
         trace prealloc type 0x800000 ns 0 size 4 dev veth0
  tr_ad=$?

  ip -netns $ioam_tmp_node -6 route | grep -q "encap ioam6"
  tr_sh=$?

  if [[ $tr_ad != 0 || $tr_sh != 0 ]]
  then
    echo "SKIP: cannot attach an ioam trace to a route, did you compile" \
         "without CONFIG_IPV6_IOAM6_LWTUNNEL?"
    ip link del veth0 2>/dev/null || true
    cleanup_ns $ioam_tmp_node || true
    exit $ksft_skip
  fi

  ip link del veth0 2>/dev/null || true
  cleanup_ns $ioam_tmp_node || true

  lsmod | grep -q "ip6_tunnel"
  ip6tnl_loaded=$?

  if [ $ip6tnl_loaded = 0 ]
  then
    encap_tests=0
  else
    modprobe ip6_tunnel &>/dev/null
    lsmod | grep -q "ip6_tunnel"
    encap_tests=$?

    if [ $encap_tests != 0 ]
    then
      ip a | grep -q "ip6tnl0"
      encap_tests=$?

      if [ $encap_tests != 0 ]
      then
        echo "Note: ip6_tunnel not found neither as a module nor inside the" \
             "kernel, tests that require it (encap mode) will be omitted"
      fi
    fi
  fi

  echo "IOAM Compatibility Check SUCCESS"
}

cleanup()
{
  ip link del ioam-veth-alpha 2>/dev/null || true
  ip link del ioam-veth-gamma 2>/dev/null || true

  cleanup_ns $ioam_node_alpha $ioam_node_r1 $ioam_node_r2 $ioam_node_r3 $ioam_node_gamma || true

  if [ $ip6tnl_loaded != 0 ]
  then
    modprobe -r ip6_tunnel 2>/dev/null || true
  fi
}

setup()
{
  echo "Setup Start"
  setup_ns ioam_node_alpha ioam_node_r1 ioam_node_r2 ioam_node_r3 ioam_node_gamma

  # connect namespaces
  ip link add name ioam-veth-alpha netns $ioam_node_alpha type veth \
         peer name ioam-veth-r1_L netns $ioam_node_r1

  ip link add name ioam-veth-r1_R netns $ioam_node_r1 type veth \
         peer name ioam-veth-r2_L netns $ioam_node_r2

  ip link add name ioam-veth-r2_R netns $ioam_node_r2 type veth \
       peer name ioam-veth-r3_L netns $ioam_node_r3

  ip link add name ioam-veth-r3_R netns $ioam_node_r3 type veth \
         peer name ioam-veth-gamma netns $ioam_node_gamma

  # rename interfaces
  ip -netns $ioam_node_alpha link set ioam-veth-alpha name veth0
  ip -netns $ioam_node_r1 link set ioam-veth-r1_L name veth0
  ip -netns $ioam_node_r1 link set ioam-veth-r1_R name veth1
  ip -netns $ioam_node_r2 link set ioam-veth-r2_L name veth0
  ip -netns $ioam_node_r2 link set ioam-veth-r2_R name veth1
  ip -netns $ioam_node_r3 link set ioam-veth-r3_L name veth0
  ip -netns $ioam_node_r3 link set ioam-veth-r3_R name veth1
  ip -netns $ioam_node_gamma link set ioam-veth-gamma name veth0

  # addressing
  ip -netns $ioam_node_alpha addr add db01::2/64 dev veth0
  ip -netns $ioam_node_r1 addr add db01::1/64 dev veth0
  ip -netns $ioam_node_r1 addr add db02::1/64 dev veth1
  ip -netns $ioam_node_r2 addr add db02::2/64 dev veth0
  ip -netns $ioam_node_r2 addr add db03::1/64 dev veth1
  ip -netns $ioam_node_r3 addr add db03::2/64 dev veth0
  ip -netns $ioam_node_r3 addr add db04::1/64 dev veth1
  ip -netns $ioam_node_gamma addr add db04::2/64 dev veth0

  # up all links
  ip -netns $ioam_node_alpha link set lo up
  ip -netns $ioam_node_alpha link set veth0 up

  ip -netns $ioam_node_r1 link set lo up
  ip -netns $ioam_node_r1 link set veth0 up
  ip -netns $ioam_node_r1 link set veth1 up

  ip -netns $ioam_node_r2 link set lo up
  ip -netns $ioam_node_r2 link set veth0 up
  ip -netns $ioam_node_r2 link set veth1 up

  ip -netns $ioam_node_r3 link set lo up
  ip -netns $ioam_node_r3 link set veth0 up
  ip -netns $ioam_node_r3 link set veth1 up

  ip -netns $ioam_node_gamma link set lo up
  ip -netns $ioam_node_gamma link set veth0 up

  # alpha -> gamma via r1
  ip -netns $ioam_node_alpha route add db04::/64 via db01::1 dev veth0
  # r1 -> gamma via r2
  ip -netns $ioam_node_r1 route add db04::/64 via db02::2 dev veth1
  # r2 -> alpha via r1
  ip -netns $ioam_node_r2 route add db01::/64 via db02::1 dev veth0
  # r2 -> gamma via r3
  ip -netns $ioam_node_r2 route add db04::/64 via db03::2 dev veth1
  # r3 -> alpha via r2
  ip -netns $ioam_node_r3 route add db01::/64 via db03::1 dev veth0
  # gamma -> alpha via r3
  ip -netns $ioam_node_gamma route add db01::/64 via db04::1 dev veth0

  # IOAM Config - ALPHA
  ip netns exec $ioam_node_alpha sysctl -wq net.ipv6.ioam6_id=${ALPHA[0]}
  ip netns exec $ioam_node_alpha sysctl -wq net.ipv6.ioam6_id_wide=${ALPHA[1]}
  ip netns exec $ioam_node_alpha sysctl -wq net.ipv6.conf.all.disable_ipv6=0
  ip netns exec $ioam_node_alpha sysctl -wq net.ipv6.conf.veth0.ioam6_id=${ALPHA[4]}
  ip netns exec $ioam_node_alpha sysctl -wq net.ipv6.conf.veth0.ioam6_id_wide=${ALPHA[5]}
  ip -netns $ioam_node_alpha ioam namespace add 123 data ${ALPHA[6]} wide ${ALPHA[7]}
  ip -netns $ioam_node_alpha ioam schema add ${ALPHA[8]} "${ALPHA[9]}"
  ip -netns $ioam_node_alpha ioam namespace set 123 schema ${ALPHA[8]}

  # IOAM Config - R1
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.all.forwarding=1
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.ioam6_id=${ROUTER1[0]}
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.ioam6_id_wide=${ROUTER1[1]}
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.veth0.ioam6_enabled=1
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.veth0.ioam6_id=${ROUTER1[2]}
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.veth0.ioam6_id_wide=${ROUTER1[3]}
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.veth1.ioam6_id=${ROUTER1[4]}
  ip netns exec $ioam_node_r1 sysctl -wq net.ipv6.conf.veth1.ioam6_id_wide=${ROUTER1[5]}
  ip -netns $ioam_node_r1 ioam namespace add 123 data ${ROUTER1[6]} wide ${ROUTER1[7]}
  ip -netns $ioam_node_r1 ioam schema add ${ROUTER1[8]} "${ROUTER1[9]}"
  ip -netns $ioam_node_r1 ioam namespace set 123 schema ${ROUTER1[8]}

  # IOAM Config - R2
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.all.forwarding=1
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.ioam6_id=${ROUTER2[0]}
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.ioam6_id_wide=${ROUTER2[1]}
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.veth0.ioam6_enabled=1
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.veth0.ioam6_id=${ROUTER2[2]}
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.veth0.ioam6_id_wide=${ROUTER2[3]}
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.veth1.ioam6_id=${ROUTER2[4]}
  ip netns exec $ioam_node_r2 sysctl -wq net.ipv6.conf.veth1.ioam6_id_wide=${ROUTER2[5]}
  ip -netns $ioam_node_r2 ioam namespace add 123 data ${ROUTER2[6]} wide ${ROUTER2[7]}
  ip -netns $ioam_node_r2 ioam schema add ${ROUTER2[8]} "${ROUTER2[9]}"
  ip -netns $ioam_node_r2 ioam namespace set 123 schema ${ROUTER2[8]}

  # IOAM Config - R3
  ip netns exec $ioam_node_r3 sysctl -wq net.ipv6.conf.all.forwarding=1

  # IOAM Config - GAMMA
  ip netns exec $ioam_node_gamma sysctl -wq net.ipv6.ioam6_id=${GAMMA[0]}
  ip netns exec $ioam_node_gamma sysctl -wq net.ipv6.ioam6_id_wide=${GAMMA[1]}
  ip netns exec $ioam_node_gamma sysctl -wq net.ipv6.conf.veth0.ioam6_enabled=0
  ip netns exec $ioam_node_gamma sysctl -wq net.ipv6.conf.veth0.ioam6_id=${GAMMA[2]}
  ip netns exec $ioam_node_gamma sysctl -wq net.ipv6.conf.veth0.ioam6_id_wide=${GAMMA[3]}
  ip -netns $ioam_node_gamma ioam namespace add 123 data ${GAMMA[6]} wide ${GAMMA[7]}
  ip -netns $ioam_node_gamma ioam schema add ${GAMMA[8]} "${GAMMA[9]}"
  ip -netns $ioam_node_gamma ioam namespace set 123 schema ${GAMMA[8]}

  sleep 0.5

  ip netns exec $ioam_node_alpha ping6 -c 5 -W 1 db04::2 &>/dev/null 
  if [ $? != 0 ]
  then
    echo "Setup FAILED"
    cleanup &>/dev/null
    exit 0
  fi


  ip -netns $ioam_node_alpha route del db04::/64
  ip -netns $ioam_node_alpha route add db04::/64 via db01::1 encap ioam6 mode inline \
         trace prealloc type 0xBC8000 ns 123 size 156 dev veth0

  echo "Setup SUCCESS"
}

check_kernel_compatibility
setup

echo ""
ip netns exec $ioam_node_alpha tcpdump -i veth0 'ip6' -w alpha.pcap &
# ip netns exec $ioam_node_alpha sudo python3 ./ioam_parser.py &
PID_ALPHA=$!

sleep 0.1
ip netns exec $ioam_node_gamma tcpdump -i veth0 'ip6' -w gamma.pcap &
PID_GAMMA=$!

sleep 0.5

# ip netns exec $ioam_node_alpha ping -6 -c 5 -W 1 db04::2
# ip netns exec $ioam_node_alpha ./iputils/builddir/tracepath -6 -n -m 10 -l 256 -p 33434 db04::2
ip netns exec $ioam_node_alpha sudo python3 ./ioam_parser.py -i veth0 db04::2

sleep 1
kill "$PID_ALPHA" "$PID_GAMMA"
cleanup &>/dev/null
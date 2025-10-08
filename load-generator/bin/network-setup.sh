#!/bin/bash

set -x

prefix="nfm-perf-test"

function name {
	echo "${prefix}-$1"
}

ip link del i1
ip link del i2
ip link del i3
ip link del i4

ip netns del $(name client)
ip netns del $(name tcp-tester)
ip netns del $(name server)

ip netns add $(name client)
ip netns add $(name tcp-tester)
ip netns add $(name server)

ip netns exec $(name client) sysctl -w net.ipv4.ip_forward=1
ip netns exec $(name tcp-tester) sysctl -w net.ipv4.ip_forward=1
ip netns exec $(name server) sysctl -w net.ipv4.ip_forward=1

ip netns exec $(name client) ip link set lo up
ip netns exec $(name tcp-tester) ip link set lo up
ip netns exec $(name server) ip link set lo up

ip link add i1 type veth peer i2
ip link add i3 type veth peer i4

# TODO: set the mtu to look realistic

ip link set i1 netns $(name client)
ip link set i2 netns $(name tcp-tester)
ip link set i3 netns $(name tcp-tester)
ip link set i4 netns $(name server)

ip netns exec $(name client) ip link set i1 up
ip netns exec $(name tcp-tester) ip link set i2 up
ip netns exec $(name tcp-tester) ip link set i3 up
ip netns exec $(name server) ip link set i4 up

# links
ip netns exec $(name client) ip addr add 10.0.0.1/24 dev i1
ip netns exec $(name tcp-tester) ip addr add 10.0.0.2/24 dev i2

ip netns exec $(name tcp-tester) ip addr add 20.0.0.1/24 dev i3
ip netns exec $(name server) ip addr add 20.0.0.2/24 dev i4

# loopbacks
ip netns exec $(name client) ip addr add 1.1.1.1 dev lo
ip netns exec $(name server) ip addr add 2.2.2.2 dev lo

# loopback a
ip netns exec $(name client) ip route add 2.2.2.2 via 10.0.0.2 src 1.1.1.1
ip netns exec $(name tcp-tester) ip route add 2.2.2.2 via 20.0.0.2


ip netns exec $(name server) ip route add 1.1.1.1 via 20.0.0.1 src 2.2.2.2
ip netns exec $(name tcp-tester) ip route add 1.1.1.1 via 10.0.0.1

# We need to disable segmentation offload because otherwise the segments don't
# correspond to packets.
ip netns exec $(name client) ethtool -K i1 tx-tcp-segmentation off
ip netns exec $(name server) ethtool -K i4 tx-tcp-segmentation off


ip netns exec $(name client) sysctl -w net.ipv4.tcp_sack=1
ip netns exec $(name server) sysctl -w net.ipv4.tcp_sack=1
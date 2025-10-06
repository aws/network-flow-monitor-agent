#!/bin/bash

enable="false"
loss_percent="0"
delay=0ms
jitter=0ms
interface=''
ip_addr=''
port=''
namespace=''

while [[ $# -gt 0 ]]; do
   case "$1" in
        --enable) enable="true" ;;
        --disable) enable="false" ;;
        --loss_percent=*) loss_percent="${1#*=}" ;;
        --loss_percent) loss_percent="$2"; shift ;;
        --interface=*) interface="${1#*=}" ;;
        --interface) interface="$2"; shift ;;
        --ip_addr=*) ip_addr="${1#*=}" ;;
        --ip_addr) ip_addr="$2"; shift ;;
        --port=*) port="${1#*=}" ;;
        --port) port="$2"; shift ;;
        --delay=*) delay="${1#*=}" ;;
        --delay) delay="$2"; shift ;;
        --jitter=*) jitter="${1#*=}" ;;
        --jitter) jitter="$2"; shift ;;
   esac
   shift
done

# Validate loss_percent is between 0 and 50
if [[ $loss_percent -lt 0 || $loss_percent -gt 99 ]]; then
    echo "Error: loss_percent must be between 0 and 99, got: $loss_percent"
    exit 1
fi

ns_prefix=''
if [[ -n "$namespace" ]]; then
    ns_prefix="ip netns exec $namespace"
fi

port_filter=''
if [[ -n "$port" ]]; then
    port_filter="match ip dport $port 0xffff"
fi

if [[ $enable == "true" ]]; then
    echo "Enabling synthetic network loss for interface $interface (loss: ${loss_percent}%, delay: ${delay}, jitter: ${jitter})"

    $ns_prefix tc qdisc add dev $interface root handle 1: prio 2>/dev/null || true
    $ns_prefix tc qdisc add dev $interface parent 1:2 handle 20: netem loss $loss_percent% delay $delay $jitter 2>/dev/null || true
    if [[ -n "$ip_addr" ]]; then
        $ns_prefix tc filter add dev $interface parent 1:0 protocol ip u32 match ip dst $ip_addr $port_filter flowid 1:2 2>/dev/null || true
        $ns_prefix tc filter add dev $interface parent 1:0 protocol ip u32 match ip src $ip_addr $port_filter flowid 1:2 2>/dev/null || true
    fi
else
    echo "Disabling synthetic network loss for interface $interface"

    $ns_prefix tc qdisc del dev $interface root 2>/dev/null || true
fi
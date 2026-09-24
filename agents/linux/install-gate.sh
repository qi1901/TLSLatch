#!/usr/bin/env bash

set -euo pipefail
ip=${1:?server IPv4}
port=${2:?port}
queue=${3:?queue}
table=${4:-tcpra_nfqset_$port}
pending=${5:-pending_flows}
[[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $port =~ ^[0-9]{1,5}$ &&
    $queue =~ ^[0-9]{1,5}$ && $table =~ ^[a-zA-Z_][a-zA-Z_0-9]{0,62}$ &&
    $pending =~ ^[a-zA-Z_][a-zA-Z_0-9]{0,62}$ ]] || exit 2
IFS=. read -r a b c d <<<"$ip"
for octet in "$a" "$b" "$c" "$d"; do ((10#$octet <= 255)) || exit 2; done
((10#$port > 0 && 10#$port < 65536 && 10#$queue < 65536)) || exit 2
port=$((10#$port))
queue=$((10#$queue))
if nft list table inet "$table" >/dev/null 2>&1; then
    echo "Refusing to overwrite existing gate. Keep it across agent restart; explicit maintenance requires stopped business." >&2
    exit 1
fi
nft -f - <<NFT
add table inet $table
add set inet $table $pending { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags dynamic; size 8192; }
add chain inet $table gate_out { type filter hook output priority -10; policy accept; }
add chain inet $table gate_in { type filter hook input priority -10; policy accept; }
add chain inet $table commit_verified { type filter hook output priority -9; policy accept; }
add rule inet $table gate_out ip daddr $ip tcp dport $port ct mark 0x544c0001 accept
add rule inet $table gate_out ip daddr $ip tcp dport $port tcp flags & (syn|ack) == syn add @$pending { ip saddr . tcp sport . ip daddr . tcp dport }
add rule inet $table gate_out ip saddr . tcp sport . ip daddr . tcp dport @$pending queue num $queue
add rule inet $table gate_out ip daddr $ip tcp dport $port queue num $queue
add rule inet $table gate_in ip saddr $ip tcp sport $port ct mark 0x544c0001 accept
add rule inet $table gate_in ip saddr $ip tcp sport $port queue num $queue
add rule inet $table commit_verified ip daddr $ip tcp dport $port meta mark 0x544c0001 ct mark set 0x544c0001 meta mark set 0
NFT

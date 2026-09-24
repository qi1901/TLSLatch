#!/usr/bin/env bash

set -euo pipefail
action=${1:-}
endpoint=${2:-}
port=${3:-}
table=tlslatch_quarantine
if [[ ! $endpoint =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ||
    ! $port =~ ^[0-9]{1,5}$ ]] || ((10#$port < 1 || 10#$port > 65535)); then
    echo "usage: $0 install|block|status|recover IPv4 PORT" >&2
    exit 2
fi
IFS=. read -r a b c d <<<"$endpoint"
for octet in "$a" "$b" "$c" "$d"; do
    ((10#$octet <= 255)) || exit 2
done
port=$((10#$port))
element="{ $endpoint . $port }"
case "$action" in
    install)

        if nft list table inet "$table" >/dev/null 2>&1; then
            nft list set inet "$table" blocked4 >/dev/null
            nft list chain inet "$table" quarantine_output >/dev/null
            nft list chain inet "$table" quarantine_input >/dev/null
            exit 0
        fi
        nft -f - <<NFT
add table inet $table
add set inet $table blocked4 { type ipv4_addr . inet_service; }
add chain inet $table quarantine_output { type filter hook output priority -320; policy accept; }
add chain inet $table quarantine_input { type filter hook input priority -320; policy accept; }
add rule inet $table quarantine_output ip daddr . tcp dport @blocked4 counter drop
add rule inet $table quarantine_output ip saddr . tcp sport @blocked4 counter drop
add rule inet $table quarantine_input ip saddr . tcp sport @blocked4 counter drop
add rule inet $table quarantine_input ip daddr . tcp dport @blocked4 counter drop
NFT
        ;;
    block)

        nft add element inet "$table" blocked4 "$element"
        nft get element inet "$table" blocked4 "$element"
        ;;
    status)
        nft get element inet "$table" blocked4 "$element"
        ;;
    recover)

        nft delete element inet "$table" blocked4 "$element"
        ;;
    *)
        echo "unknown action" >&2
        exit 2
        ;;
esac

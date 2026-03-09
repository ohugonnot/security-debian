#!/bin/bash
set -euo pipefail
if iptables -nL "$2" | grep -qF "$1"; then
    iptables -D "$2" -s "$1" -j REJECT
fi

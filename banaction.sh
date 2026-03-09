#!/bin/bash
set -euo pipefail
if ! iptables -nL "$2" | grep -qF "$1"; then
    iptables -I "$2" 1 -s "$1" -j REJECT
fi

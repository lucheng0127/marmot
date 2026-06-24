#!/bin/bash
# marmot policy routing setup
# Sets up routing rules for TProxy (fwmark=1 → table 100)

set -e

BRIDGE="${1:-br0}"

echo "=== Setting up policy routing for marmot ==="

# Create TProxy routing table
ip route show table 100 >/dev/null 2>&1 || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

# Add fwmark=1 → table 100 rule
ip rule add fwmark 1 lookup 100 priority 1000 2>/dev/null || true

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null

# Disable rp_filter for TProxy
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf."${BRIDGE}".rp_filter=0 2>/dev/null || true

echo "=== Policy routing rules ==="
ip rule show | head -5
echo ""
echo "=== Route table 100 ==="
ip route show table 100

echo ""
echo "=== Done ==="
echo "Traffic with fwmark=1 will be routed to TProxy via table 100"

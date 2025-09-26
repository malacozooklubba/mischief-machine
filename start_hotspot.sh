#!/bin/bash

# Start the configured hotspot connection
echo "Starting hotspot connection..."

# Activate the hotspot connection
nmcli connection up Hotspot

echo "=== Hotspot started === $(date)"
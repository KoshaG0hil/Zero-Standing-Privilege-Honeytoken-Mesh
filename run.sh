#!/usr/bin/env bash
set -e
echo "=========================================================="
echo "  Zero-Standing-Privilege Dynamic Access & Honeytoken Mesh"
echo "  AWS Ephemeral STS Broker · Canary Tripwire Containment"
echo "=========================================================="
python3 -m src.cli simulate

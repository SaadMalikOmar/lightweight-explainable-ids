#!/bin/bash
set -ex

# Setup Attacker VM
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y hydra nmap sshpass

echo "Attacker tools installed."

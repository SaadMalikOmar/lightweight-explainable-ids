#!/bin/bash
set -ex

# Setup Host VM with eBPF tools
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y bpfcc-tools linux-headers-$(uname -r)

echo "eBPF tools installed. You can test them by running 'sudo execsnoop-bpfcc'."

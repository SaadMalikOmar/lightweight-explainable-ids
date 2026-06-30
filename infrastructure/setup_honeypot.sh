#!/bin/bash
set -ex

# Setup Honeypot VM with Cowrie
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3-venv python3-pip libssl-dev libffi-dev build-essential \
  libpython3-dev python3-minimal authbind iptables

adduser --disabled-password --gecos "" cowrie || true

sudo -u cowrie bash <<'EOF'
cd /home/cowrie
if [ ! -d "cowrie" ]; then
  git clone https://github.com/cowrie/cowrie
fi
cd /home/cowrie/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
pip install -e .

# Configure cowrie to listen on 2222
cp -n etc/cowrie.cfg.dist etc/cowrie.cfg
sed -i 's/#listen_endpoints = tcp:2222:interface=0.0.0.0/listen_endpoints = tcp:2222:interface=0.0.0.0/' etc/cowrie.cfg

# Start cowrie (handle both old and new versions)
if [ -f "bin/cowrie" ]; then
  bin/cowrie start
else
  cowrie-env/bin/cowrie start
fi
EOF

echo "Cowrie honeypot installed and started on port 2222."

#!/bin/bash
# Start eBPF monitoring tools
sudo pkill -f execsnoop-bpfcc || true
sudo pkill -f tcpconnect-bpfcc || true
sleep 1

# Clear old logs
echo "" > /tmp/execsnoop.log
echo "" > /tmp/tcp.log

# Start monitors
sudo nohup execsnoop-bpfcc -T > /tmp/execsnoop.log 2>&1 &
echo "execsnoop PID: $!"

sudo nohup tcpconnect-bpfcc > /tmp/tcp.log 2>&1 &
echo "tcpconnect PID: $!"

sleep 3
echo "Monitors started"
ps aux | grep -E "(execsnoop|tcpconnect)" | grep -v grep

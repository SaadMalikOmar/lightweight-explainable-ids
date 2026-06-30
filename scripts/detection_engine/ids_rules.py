import json
import os
import argparse
from datetime import datetime

# Rule 1: Failed login spike (Cowrie logs)
# Rule 2: Suspicious command execution (Cowrie logs)

def parse_cowrie_logs(log_path):
    alerts = []
    failed_logins = {}
    
    suspicious_commands = ["wget", "curl", "chmod +x", "nc ", "nmap", "cat /etc/passwd", "cat /etc/shadow"]

    try:
        with open(log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    event_id = event.get('eventid', '')
                    timestamp = event.get('timestamp', '')
                    
                    # failed login check
                    if event_id == 'cowrie.login.failed':
                        src_ip = event.get('src_ip', 'unknown')
                        failed_logins.setdefault(src_ip, []).append(timestamp)
                        if len(failed_logins[src_ip]) > 5:
                            alerts.append({
                                'timestamp': timestamp,
                                'rule': 'Brute Force SSH Attack Detected',
                                'evidence': f"5+ failed logins from IP {src_ip}",
                                'explanation': f"The IP {src_ip} attempted to log in repeatedly and failed. In an IoT/edge environment, this strongly indicates an automated brute-force attack attempting to gain access to the device."
                            })
                            failed_logins[src_ip] = [] # Reset after alert
                    
                    # command execution check
                    if event_id == 'cowrie.command.input':
                        cmd = event.get('input', '')
                        for s_cmd in suspicious_commands:
                            if s_cmd in cmd:
                                alerts.append({
                                    'timestamp': timestamp,
                                    'rule': 'Suspicious Command Execution',
                                    'evidence': f"Command executed: {cmd}",
                                    'explanation': f"An attacker executed '{cmd}' which is commonly used to download payloads or read sensitive files. This behavior is highly suspicious for a standard IoT device."
                                })
                                break
                                
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[-] Cowrie log file not found: {log_path}")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Explainable IDS Prototype Detection Engine")
    parser.add_argument('--cowrie-log', default='../logs/cowrie/cowrie.json', help='Path to cowrie json log')
    args = parser.parse_args()

    print("[*] Starting Explainable IDS Detection Engine...")
    alerts = parse_cowrie_logs(args.cowrie_log)
    
    if alerts:
        print(f"\n[!] Detected {len(alerts)} suspicious activities:\n" + "="*50)
        for idx, alert in enumerate(alerts, 1):
            print(f"Alert #{idx}")
            print(f"Timestamp   : {alert['timestamp']}")
            print(f"Rule Name   : {alert['rule']}")
            print(f"Evidence    : {alert['evidence']}")
            print(f"Explanation : {alert['explanation']}")
            print("-" * 50)
    else:
        print("[+] No suspicious activities detected.")

if __name__ == '__main__':
    main()

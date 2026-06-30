#!/usr/bin/env python3
"""
ids_rules_v2.py -- Enhanced Explainable IDS Detection Engine with Metrics
CI6600 Final Year Project | Malik Omar | K2335386

Enhancements over v1:
- Precision/Recall/F1 calculation against ground truth
- Configurable thresholds for sensitivity analysis
- JSON output for dashboard integration
- eBPF correlation support

Rules: (1) Brute-force SSH auth ATT&CK T1110
       (2) Suspicious post-auth command ATT&CK T1059
"""

import json
import sys
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Configuration
BRUTE_FORCE_THRESHOLD = 5
SUSPICIOUS_SUBSTRINGS = [
    "wget", "curl", "chmod +x", "nc ", "nmap",
    "cat /etc/passwd", "cat /etc/shadow", "/bin/sh", "python", "bash -i",
]

# Ground truth labels for evaluation (attacker IPs in controlled lab)
KNOWN_ATTACKER_IPS = {"192.168.56.30"}  # Add all attacker IPs from your simulation
KNOWN_BENIGN_IPS = {"192.168.56.10", "192.168.56.20"}  # Legitimate lab IPs

SEP = "=" * 70


class DetectionMetrics:
    #Track detection performance metrics.
    
    def __init__(self):
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self.alerts = []
    
    def record_alert(self, src_ip: str, alert_type: str, is_attack: bool):
        #Record an alert and update metrics.
        if src_ip in KNOWN_ATTACKER_IPS:
            if is_attack:
                self.true_positives += 1
            else:
                self.false_negatives += 1
        elif src_ip in KNOWN_BENIGN_IPS:
            if is_attack:
                self.false_positives += 1
            else:
                self.true_negatives += 1
        # Unknown IPs treated as potential attacks in honeypot context
        else:
            if is_attack:
                self.true_positives += 1
    """
    Calculate precision: TP / (TP + FP)
    Calculate recall: TP / (TP + FN)
    Calculate F1 score: 2 * (P * R) / (P + R)"""
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0
    
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0
    
    def f1_score(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    
    def summary(self) -> str:
        #Return formatted metrics summary.
        return (
            f"\n{SEP}\n"
            f"DETECTION METRICS SUMMARY\n"
            f"{SEP}\n"
            f"  True Positives:  {self.true_positives}\n"
            f"  False Positives: {self.false_positives}\n"
            f"  True Negatives:  {self.true_negatives}\n"
            f"  False Negatives: {self.false_negatives}\n"
            f"  {'-' * 30}\n"
            f"  Precision:       {self.precision():.4f}\n"
            f"  Recall:          {self.recall():.4f}\n"
            f"  F1 Score:        {self.f1_score():.4f}\n"
            f"{SEP}\n"
        )


def fmt_brute(src_ip: str, timestamps: List[str], metrics: DetectionMetrics) -> str:
    #Format brute force alert with evidence.
    count = len(timestamps)
    metrics.record_alert(src_ip, "brute_force", True)
    
    alert_data = {
        "alert_type": "BRUTE_FORCE",
        "rule": "ATT&CK T1110",
        "src_ip": src_ip,
        "count": count,
        "threshold": BRUTE_FORCE_THRESHOLD,
        "first_seen": timestamps[0],
        "last_seen": timestamps[-1],
        "severity": "HIGH",
        "timestamp": datetime.now().isoformat()
    }
    metrics.alerts.append(alert_data)
    
    return (
        f"\n{SEP}\n[ALERT] BRUTE FORCE AUTHENTICATION DETECTED\n"
        f"  Rule      : Repeated Failed SSH Login (ATT&CK T1110)\n"
        f"  Source IP : {src_ip}\n"
        f"  Count     : {count} attempts (threshold: {BRUTE_FORCE_THRESHOLD})\n"
        f"  First     : {timestamps[0]}\n"
        f"  Last      : {timestamps[-1]}\n"
        f"  Evidence  : {count} cowrie.login.failed events from same source\n"
        f"  Explain   : Automated credential guessing against edge SSH service\n"
        f"  Severity  : HIGH\n"
        f"  Action    : Block {src_ip}; check for subsequent successful auth\n{SEP}"
    )


def fmt_cmd(src_ip: str, ts: str, cmd: str, matched: List[str], 
            metrics: DetectionMetrics) -> str:
    #Format suspicious command alert with evidence.
    metrics.record_alert(src_ip, "suspicious_command", True)
    
    alert_data = {
        "alert_type": "SUSPICIOUS_COMMAND",
        "rule": "ATT&CK T1059",
        "src_ip": src_ip,
        "command": cmd,
        "matched_patterns": matched,
        "severity": "HIGH",
        "timestamp": ts
    }
    metrics.alerts.append(alert_data)
    
    return (
        f"\n{SEP}\n[ALERT] SUSPICIOUS COMMAND EXECUTION\n"
        f"  Rule      : Post-Auth Command Match (ATT&CK T1059)\n"
        f"  Source IP : {src_ip}\n"
        f"  Time      : {ts}\n"
        f"  Command   : {cmd}\n"
        f"  Matched   : {', '.join(matched)}\n"
        f"  Evidence  : cowrie.command.input event from authenticated session\n"
        f"  Explain   : Command indicates payload retrieval or credential access\n"
        f"  Severity  : HIGH\n"
        f"  Action    : Isolate source IP; preserve Cowrie session logs\n{SEP}"
    )


def detect(log_path: str, output_json: Optional[str] = None) -> Tuple[List[str], DetectionMetrics]:

    #Run detection on Cowrie JSON log file.
    
    #Returns: Tuple of (alert strings, metrics object)

    failed = defaultdict(list)
    alerted = set()
    alerts = []
    metrics = DetectionMetrics()
    
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}")
        return alerts, metrics
    
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            
            eid = ev.get("eventid", "")
            ts = ev.get("timestamp", "")
            ip = ev.get("src_ip", "unknown")
            
            if eid == "cowrie.login.failed":
                failed[ip].append(ts)
                if len(failed[ip]) > BRUTE_FORCE_THRESHOLD and ip not in alerted:
                    a = fmt_brute(ip, failed[ip], metrics)
                    alerts.append(a)
                    alerted.add(ip)
                    print(a)
            
            elif eid == "cowrie.command.input":
                cmd = ev.get("input", "")
                m = [s for s in SUSPICIOUS_SUBSTRINGS if s in cmd]
                if m:
                    a = fmt_cmd(ip, ts, cmd, m, metrics)
                    alerts.append(a)
                    print(a)
    
    # Post-detection: evaluate non-alerted sessions for TN/FN
    # This fixes the architectural gap where only alert-generating code
    # paths called record_alert, meaning TN and FN could never increment.
    all_sessions = defaultdict(list)
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            sid = ev.get("session", "_none_")
            all_sessions[sid].append(ev)

    for sid, evs in all_sessions.items():
        ip = next((e.get("src_ip") for e in evs if e.get("src_ip")), "unknown")
        # Check if this specific session generated any alerts
        session_had_alert = False
        for ev in evs:
            eid = ev.get("eventid", "")
            cmd = ev.get("input", "")
            if eid == "cowrie.login.failed" and ip in alerted:
                session_had_alert = True
            elif eid == "cowrie.command.input":
                if any(s in cmd for s in SUSPICIOUS_SUBSTRINGS):
                    session_had_alert = True

        if not session_had_alert:
            if ip in KNOWN_ATTACKER_IPS:
                metrics.false_negatives += 1
            elif ip in KNOWN_BENIGN_IPS:
                metrics.true_negatives += 1

    # Print metrics summary
    print(metrics.summary())
    
    # Optionally write alerts to JSON for dashboard
    if output_json:
        with open(output_json, "w") as f:
            json.dump(metrics.alerts, f, indent=2)
        print(f"[+] Alerts written to {output_json}")
    
    print(f"\nComplete -- {len(alerts)} alert(s) generated.")
    return alerts, metrics


def sensitivity_analysis(log_path: str, thresholds: List[int] = [3, 5, 7, 10]) -> None:
    """
    Run detection across multiple thresholds to analyze sensitivity.
    Useful for tuning and demonstrating threshold impact.
    """
    global BRUTE_FORCE_THRESHOLD
    
    print(f"\n{'='*70}")
    print("SENSITIVITY ANALYSIS: Brute Force Threshold Impact")
    print(f"{'='*70}")
    print(f"{'Threshold':<12} {'Alerts':<10} {'Precision':<12} {'Recall':<12} {'F1':<10}")
    print("-" * 56)
    
    for thresh in thresholds:
        BRUTE_FORCE_THRESHOLD = thresh
        _, metrics = detect(log_path)
        print(f"{thresh:<12} {len(metrics.alerts):<10} {metrics.precision():<12.4f} "
              f"{metrics.recall():<12.4f} {metrics.f1_score():<10.4f}")


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    
    output_json = sys.argv[2] if len(sys.argv) > 2 else "alerts.json"
    
    alerts, metrics = detect(log_path, output_json)
    
    # sensitivity_analysis(log_path)

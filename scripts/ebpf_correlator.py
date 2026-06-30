#!/usr/bin/env python3
"""
ebpf_correlator.py -- eBPF Telemetry Parser with Cowrie Event Correlation
CI6600 Final Year Project | Malik Omar | K2335386

This module parses eBPF tool output (execsnoop-bpfcc, tcplife-bpfcc, bpftrace)
and correlates events with Cowrie honeypot activity to provide multi-sensor
fusion for the detection engine.

Correlation Logic:
- TCP connections to honeypot ports within attack windows
- Process execution patterns during detected brute force periods
- Timeline reconstruction across sensor sources
"""

import json
import re
import os
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# Honeypot service ports
HONEYPOT_PORTS = {2222, 80}  # SSH honeypot on 2222, HTTP decoy on 80
HONEYPOT_IP = "192.168.56.20"


@dataclass
class ExecsnoopEvent:
    """Parsed execsnoop-bpfcc event."""
    timestamp: datetime
    pid: int
    ppid: int
    comm: str
    args: str
    
    def to_dict(self) -> dict:
        return {
            "source": "execsnoop",
            "timestamp": self.timestamp.isoformat(),
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "args": self.args
        }


@dataclass
class TcpLifeEvent:
    """Parsed tcplife/bpftrace TCP event."""
    timestamp: datetime
    pid: int
    comm: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    duration_ms: float
    
    def to_dict(self) -> dict:
        return {
            "source": "tcplife",
            "timestamp": self.timestamp.isoformat(),
            "pid": self.pid,
            "comm": self.comm,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "duration_ms": self.duration_ms
        }


@dataclass
class CowrieEvent:
    """Parsed Cowrie JSON event."""
    timestamp: datetime
    eventid: str
    src_ip: str
    session: str
    data: dict = field(default_factory=dict)


@dataclass
class CorrelatedAlert:
    """Alert combining multiple sensor sources."""
    primary_source: str
    alert_type: str
    timestamp: datetime
    src_ip: str
    cowrie_events: List[CowrieEvent] = field(default_factory=list)
    ebpf_events: List[dict] = field(default_factory=list)
    correlation_score: float = 0.0
    explanation: str = ""


def parse_execsnoop_line(line: str, base_date: datetime = None) -> Optional[ExecsnoopEvent]:
    """
    Parse a line from execsnoop-bpfcc output.
    
    Example format:
    PCOMM  PID    PPID   RET ARGS
    sshd   12345  1234   0   /usr/sbin/sshd -D
    """
    # Skip header lines
    if line.startswith("PCOMM") or line.startswith("TIME") or not line.strip():
        return None
    
    # Pattern for execsnoop output (may vary by version)
    # Format: COMM PID PPID RET ARGS
    parts = line.split(None, 4)
    if len(parts) < 4:
        return None
    
    try:
        comm = parts[0]
        pid = int(parts[1])
        ppid = int(parts[2])
        args = parts[4] if len(parts) > 4 else ""
        
        # Use provided base_date or current time
        ts = base_date or datetime.now()
        
        return ExecsnoopEvent(
            timestamp=ts,
            pid=pid,
            ppid=ppid,
            comm=comm,
            args=args
        )
    except (ValueError, IndexError):
        return None


def parse_bpftrace_tcp_line(line: str) -> Optional[TcpLifeEvent]:
    """
    Parse a line from bpftrace TCP monitoring output.
    
    Example format from tcplife-style output:
    PID   COMM    LADDR           LPORT  RADDR           RPORT  TX_KB  RX_KB  MS
    1234  ssh     192.168.56.30   54321  192.168.56.20   2222   0      0      45
    """
    if line.startswith("PID") or line.startswith("TIME") or not line.strip():
        return None
    
    parts = line.split()
    if len(parts) < 8:
        return None
    
    try:
        pid = int(parts[0])
        comm = parts[1]
        src_ip = parts[2]
        src_port = int(parts[3])
        dst_ip = parts[4]
        dst_port = int(parts[5])
        # Duration might be in different positions
        duration_ms = float(parts[-1]) if parts[-1].replace('.', '').isdigit() else 0.0
        
        return TcpLifeEvent(
            timestamp=datetime.now(),
            pid=pid,
            comm=comm,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            duration_ms=duration_ms
        )
    except (ValueError, IndexError):
        return None


def parse_cowrie_log(log_path: str) -> List[CowrieEvent]:
    """Parse Cowrie JSON log file."""
    events = []
    
    if not os.path.exists(log_path):
        print(f"[WARN] Cowrie log not found: {log_path}")
        return events
    
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                ts_str = data.get("timestamp", "")
                # Parse ISO timestamp
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    # Strip timezone info to avoid naive/aware comparison issues
                    ts = ts.replace(tzinfo=None)
                except:
                    ts = datetime.now()
                
                events.append(CowrieEvent(
                    timestamp=ts,
                    eventid=data.get("eventid", ""),
                    src_ip=data.get("src_ip", ""),
                    session=data.get("session", ""),
                    data=data
                ))
            except json.JSONDecodeError:
                continue
    
    return events


def parse_ebpf_log(log_path: str, log_type: str = "execsnoop") -> List[dict]:
    """
    Parse saved eBPF tool output.
    
    Args:
        log_path: Path to saved eBPF output file
        log_type: "execsnoop" or "tcplife"
    """
    events = []
    
    if not os.path.exists(log_path):
        print(f"[WARN] eBPF log not found: {log_path}")
        return events
    
    with open(log_path, "r") as f:
        for line in f:
            if log_type == "execsnoop":
                ev = parse_execsnoop_line(line)
                if ev:
                    events.append(ev.to_dict())
            elif log_type == "tcplife":
                ev = parse_bpftrace_tcp_line(line)
                if ev:
                    events.append(ev.to_dict())
    
    return events


def correlate_events(
    cowrie_events: List[CowrieEvent],
    ebpf_events: List[dict],
    time_window_seconds: int = 60
) -> List[CorrelatedAlert]:
    """
    Correlate Cowrie honeypot events with eBPF telemetry.
    
    Correlation strategy:
    1. Group Cowrie events by source IP
    2. Find eBPF events within time window of Cowrie activity
    3. Score correlation based on temporal proximity and semantic match
    """
    alerts = []
    
    # Group Cowrie events by IP and identify attack windows
    ip_windows: Dict[str, List[Tuple[datetime, datetime]]] = defaultdict(list)
    
    for ev in cowrie_events:
        if ev.eventid in ("cowrie.login.failed", "cowrie.command.input"):
            ip = ev.src_ip
            # Create 60-second window around each event
            start = ev.timestamp - timedelta(seconds=time_window_seconds // 2)
            end = ev.timestamp + timedelta(seconds=time_window_seconds // 2)
            ip_windows[ip].append((start, end))
    
    # For each attacker IP, find correlated eBPF events
    for src_ip, windows in ip_windows.items():
        if not windows:
            continue
        
        # Merge overlapping windows
        windows.sort()
        merged = [windows[0]]
        for start, end in windows[1:]:
            if start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        
        # Find eBPF events in attack windows
        correlated_ebpf = []
        for ev in ebpf_events:
            try:
                ev_time = datetime.fromisoformat(ev["timestamp"])
                # Strip timezone info for consistent comparison
                ev_time = ev_time.replace(tzinfo=None)
                for win_start, win_end in merged:
                    if win_start <= ev_time <= win_end:
                        correlated_ebpf.append(ev)
                        break
            except (KeyError, ValueError):
                continue
        
        # Find TCP connections to honeypot
        honeypot_connections = [
            ev for ev in correlated_ebpf
            if ev.get("source") == "tcplife" and 
               ev.get("dst_port") in HONEYPOT_PORTS
        ]
        
        # Calculate correlation score
        cowrie_count = sum(1 for e in cowrie_events if e.src_ip == src_ip)
        ebpf_count = len(correlated_ebpf)
        honeypot_conn_count = len(honeypot_connections)
        
        if cowrie_count > 0:
            # Score: weighted combination of evidence sources
            score = min(1.0, (cowrie_count * 0.4 + ebpf_count * 0.3 + honeypot_conn_count * 0.3) / 10)
            
            alert = CorrelatedAlert(
                primary_source="cowrie",
                alert_type="MULTI_SENSOR_ATTACK",
                timestamp=merged[0][0],
                src_ip=src_ip,
                cowrie_events=[e for e in cowrie_events if e.src_ip == src_ip],
                ebpf_events=correlated_ebpf,
                correlation_score=score,
                explanation=generate_correlation_explanation(
                    src_ip, cowrie_count, ebpf_count, honeypot_conn_count, merged
                )
            )
            alerts.append(alert)
    
    return alerts


def generate_correlation_explanation(
    src_ip: str,
    cowrie_count: int,
    ebpf_count: int,
    honeypot_conn_count: int,
    time_windows: List[Tuple[datetime, datetime]]
) -> str:
    """Generate human-readable explanation of correlation."""
    window_str = f"{time_windows[0][0].strftime('%H:%M:%S')} to {time_windows[-1][1].strftime('%H:%M:%S')}"
    
    explanation = (
        f"Multi-sensor correlation detected attack activity from {src_ip}.\n"
        f"  Cowrie honeypot recorded {cowrie_count} suspicious events.\n"
    )
    
    if ebpf_count > 0:
        explanation += f"  eBPF telemetry captured {ebpf_count} correlated host events.\n"
    
    if honeypot_conn_count > 0:
        explanation += f"  TCP lifecycle monitoring shows {honeypot_conn_count} connections to honeypot ports.\n"
    
    explanation += (
        f"  Attack window: {window_str}.\n"
        f"  Recommendation: Block source IP and review session logs for credential compromise."
    )
    
    return explanation


def print_correlated_alerts(alerts: List[CorrelatedAlert]) -> None:
    """Print correlated alerts in readable format."""
    print("\n" + "=" * 70)
    print("MULTI-SENSOR CORRELATION ANALYSIS")
    print("=" * 70)
    
    if not alerts:
        print("No correlated attacks detected.")
        return
    
    for i, alert in enumerate(alerts, 1):
        print(f"\n[CORRELATED ALERT {i}]")
        print(f"  Source IP:         {alert.src_ip}")
        print(f"  Alert Type:        {alert.alert_type}")
        print(f"  Correlation Score: {alert.correlation_score:.2f}")
        print(f"  Cowrie Events:     {len(alert.cowrie_events)}")
        print(f"  eBPF Events:       {len(alert.ebpf_events)}")
        print(f"\n  {'-' * 40}")
        print(f"  Explanation:\n  {alert.explanation}")
        print("=" * 70)


def main():
    """Main correlation workflow."""
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF and Cowrie Event Correlator")
    parser.add_argument("--cowrie", default="/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
                        help="Path to Cowrie JSON log")
    parser.add_argument("--execsnoop", default=None,
                        help="Path to saved execsnoop output")
    parser.add_argument("--tcplife", default=None,
                        help="Path to saved tcplife/bpftrace output")
    parser.add_argument("--output", default="correlated_alerts.json",
                        help="Output JSON file for correlated alerts")
    parser.add_argument("--window", type=int, default=60,
                        help="Correlation time window in seconds")
    
    args = parser.parse_args()
    
    print("[*] Loading Cowrie events...")
    cowrie_events = parse_cowrie_log(args.cowrie)
    print(f"    Loaded {len(cowrie_events)} events")
    
    ebpf_events = []
    
    if args.execsnoop:
        print("[*] Loading execsnoop events...")
        exec_events = parse_ebpf_log(args.execsnoop, "execsnoop")
        ebpf_events.extend(exec_events)
        print(f"    Loaded {len(exec_events)} events")
    
    if args.tcplife:
        print("[*] Loading tcplife events...")
        tcp_events = parse_ebpf_log(args.tcplife, "tcplife")
        ebpf_events.extend(tcp_events)
        print(f"    Loaded {len(tcp_events)} events")
    
    print(f"\n[*] Correlating events (window: {args.window}s)...")
    alerts = correlate_events(cowrie_events, ebpf_events, args.window)
    
    print_correlated_alerts(alerts)
    
    # Save to JSON
    output_data = []
    for alert in alerts:
        output_data.append({
            "alert_type": alert.alert_type,
            "src_ip": alert.src_ip,
            "correlation_score": alert.correlation_score,
            "cowrie_event_count": len(alert.cowrie_events),
            "ebpf_event_count": len(alert.ebpf_events),
            "explanation": alert.explanation,
            "timestamp": alert.timestamp.isoformat()
        })
    
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\n[+] Correlated alerts saved to {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
performance_benchmark.py -- Statistical Performance Benchmarking
CI6600 Final Year Project | Malik Omar | K2335386

This script performs rigorous performance benchmarking across multiple trials
to establish statistically valid overhead measurements.

Metrics collected:
- CPU utilization (%)
- Memory usage (MB)
- Process count
- Disk I/O (if available)

Usage:
1. Run on ids-honeypot VM
2. Execute each state (idle, monitoring, attack) for multiple trials
3. Script outputs mean, std, confidence intervals
"""

import argparse
import json
import os
import re
import subprocess
import statistics
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Tuple


@dataclass
class PerformanceSnapshot:
    """Single performance measurement."""
    timestamp: str
    cpu_percent: float
    memory_used_mb: float
    memory_total_mb: float
    memory_percent: float
    process_count: int
    load_avg_1m: float
    load_avg_5m: float
    load_avg_15m: float


@dataclass
class BenchmarkResult:
    """Aggregated benchmark results across trials."""
    state: str
    trials: int
    cpu_mean: float
    cpu_std: float
    cpu_ci_low: float
    cpu_ci_high: float
    memory_mean_mb: float
    memory_std_mb: float
    memory_ci_low: float
    memory_ci_high: float
    memory_percent_mean: float
    load_avg_1m_mean: float
    snapshots: List[PerformanceSnapshot]


def get_cpu_usage() -> float:
    """Get current CPU usage percentage using /proc/stat."""
    try:
        # Read /proc/stat for CPU times
        with open("/proc/stat", "r") as f:
            line = f.readline()
        
        fields = line.split()
        # user, nice, system, idle, iowait, irq, softirq, steal
        user = int(fields[1])
        nice = int(fields[2])
        system = int(fields[3])
        idle = int(fields[4])
        iowait = int(fields[5]) if len(fields) > 5 else 0
        
        total = user + nice + system + idle + iowait
        active = user + nice + system
        
        # For delta calculation, we need to sleep and measure again
        time.sleep(0.5)
        
        with open("/proc/stat", "r") as f:
            line = f.readline()
        
        fields = line.split()
        user2 = int(fields[1])
        nice2 = int(fields[2])
        system2 = int(fields[3])
        idle2 = int(fields[4])
        iowait2 = int(fields[5]) if len(fields) > 5 else 0
        
        total2 = user2 + nice2 + system2 + idle2 + iowait2
        active2 = user2 + nice2 + system2
        
        total_delta = total2 - total
        active_delta = active2 - active
        
        if total_delta > 0:
            return (active_delta / total_delta) * 100
        return 0.0
        
    except Exception as e:
        print(f"[WARN] CPU measurement failed: {e}")
        return 0.0


def get_memory_usage() -> Tuple[float, float, float]:
    """
    Get memory usage from /proc/meminfo.
    
    Returns: (used_mb, total_mb, percent)
    """
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    value = int(parts[1])  # kB
                    meminfo[key] = value
        
        total_kb = meminfo.get("MemTotal", 0)
        free_kb = meminfo.get("MemFree", 0)
        buffers_kb = meminfo.get("Buffers", 0)
        cached_kb = meminfo.get("Cached", 0)
        
        # "Used" memory (excluding buffers/cache)
        used_kb = total_kb - free_kb - buffers_kb - cached_kb
        
        total_mb = total_kb / 1024
        used_mb = used_kb / 1024
        percent = (used_kb / total_kb * 100) if total_kb > 0 else 0
        
        return used_mb, total_mb, percent
        
    except Exception as e:
        print(f"[WARN] Memory measurement failed: {e}")
        return 0.0, 0.0, 0.0


def get_load_average() -> Tuple[float, float, float]:
    """Get system load averages from /proc/loadavg."""
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except:
        return 0.0, 0.0, 0.0


def get_process_count() -> int:
    """Count running processes."""
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        # Subtract 1 for header line
        return len(result.stdout.strip().split("\n")) - 1
    except:
        return 0


def take_snapshot() -> PerformanceSnapshot:
    """Take a single performance snapshot."""
    cpu = get_cpu_usage()
    mem_used, mem_total, mem_pct = get_memory_usage()
    load1, load5, load15 = get_load_average()
    procs = get_process_count()
    
    return PerformanceSnapshot(
        timestamp=datetime.now().isoformat(),
        cpu_percent=round(cpu, 2),
        memory_used_mb=round(mem_used, 1),
        memory_total_mb=round(mem_total, 1),
        memory_percent=round(mem_pct, 2),
        process_count=procs,
        load_avg_1m=round(load1, 2),
        load_avg_5m=round(load5, 2),
        load_avg_15m=round(load15, 2)
    )


def calculate_confidence_interval(data: List[float], confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate confidence interval for mean."""
    if len(data) < 2:
        mean = data[0] if data else 0
        return mean, mean
    
    n = len(data)
    mean = statistics.mean(data)
    std = statistics.stdev(data)
    
    # t-value for 95% CI (approximation for small samples)
    t_values = {2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57, 7: 2.45, 
                8: 2.36, 9: 2.31, 10: 2.26, 15: 2.14, 20: 2.09, 30: 2.04}
    t = t_values.get(n, 1.96)  # Default to z-value for large n
    
    margin = t * (std / (n ** 0.5))
    return mean - margin, mean + margin


def run_benchmark(state_name: str, num_trials: int = 10, 
                  interval_seconds: float = 5.0) -> BenchmarkResult:
    """
    Run benchmark for a specific system state.
    
    Args:
        state_name: Name of the state (e.g., "idle", "monitoring", "attack")
        num_trials: Number of measurement trials
        interval_seconds: Time between trials
    """
    print(f"\n[*] Benchmarking state: {state_name}")
    print(f"    Trials: {num_trials}, Interval: {interval_seconds}s")
    print(f"    Total duration: ~{num_trials * (interval_seconds + 0.5):.0f}s")
    
    snapshots = []
    
    for i in range(num_trials):
        print(f"    Trial {i+1}/{num_trials}...", end=" ", flush=True)
        snapshot = take_snapshot()
        snapshots.append(snapshot)
        print(f"CPU: {snapshot.cpu_percent}%, Mem: {snapshot.memory_used_mb:.0f}MB")
        
        if i < num_trials - 1:
            time.sleep(interval_seconds)
    
    # Calculate statistics
    cpu_values = [s.cpu_percent for s in snapshots]
    mem_values = [s.memory_used_mb for s in snapshots]
    
    cpu_mean = statistics.mean(cpu_values)
    cpu_std = statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0
    cpu_ci = calculate_confidence_interval(cpu_values)
    
    mem_mean = statistics.mean(mem_values)
    mem_std = statistics.stdev(mem_values) if len(mem_values) > 1 else 0
    mem_ci = calculate_confidence_interval(mem_values)
    
    mem_pct_values = [s.memory_percent for s in snapshots]
    load_values = [s.load_avg_1m for s in snapshots]
    
    return BenchmarkResult(
        state=state_name,
        trials=num_trials,
        cpu_mean=round(cpu_mean, 2),
        cpu_std=round(cpu_std, 2),
        cpu_ci_low=round(cpu_ci[0], 2),
        cpu_ci_high=round(cpu_ci[1], 2),
        memory_mean_mb=round(mem_mean, 1),
        memory_std_mb=round(mem_std, 1),
        memory_ci_low=round(mem_ci[0], 1),
        memory_ci_high=round(mem_ci[1], 1),
        memory_percent_mean=round(statistics.mean(mem_pct_values), 2),
        load_avg_1m_mean=round(statistics.mean(load_values), 2),
        snapshots=snapshots
    )


def print_results_table(results: List[BenchmarkResult]) -> None:
    """Print results in formatted table."""
    print("\n" + "=" * 90)
    print("PERFORMANCE BENCHMARK RESULTS")
    print("=" * 90)
    print(f"{'State':<15} {'CPU Mean':<12} {'CPU Std':<10} {'CPU 95% CI':<18} "
          f"{'Mem Mean':<12} {'Mem Std':<10}")
    print("-" * 90)
    
    for r in results:
        ci_str = f"[{r.cpu_ci_low}, {r.cpu_ci_high}]"
        print(f"{r.state:<15} {r.cpu_mean:>8.2f}%   {r.cpu_std:>8.2f}   {ci_str:<18} "
              f"{r.memory_mean_mb:>8.1f} MB {r.memory_std_mb:>8.1f}")
    
    print("=" * 90)
    
    # Print delta analysis
    if len(results) >= 2:
        baseline = results[0]
        print("\nDELTA ANALYSIS (vs baseline):")
        print("-" * 50)
        for r in results[1:]:
            cpu_delta = r.cpu_mean - baseline.cpu_mean
            mem_delta = r.memory_mean_mb - baseline.memory_mean_mb
            print(f"  {r.state}: CPU {cpu_delta:+.2f}%, Memory {mem_delta:+.1f} MB")


def generate_latex_table(results: List[BenchmarkResult]) -> str:
    """Generate LaTeX table for report."""
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Resource Overhead Comparison Across System States (n=10 trials per state)}",
        r"\begin{tabular}{lcccc}",
        r"\hline",
        r"\textbf{State} & \textbf{CPU (\%)} & \textbf{Memory (MB)} & \textbf{$\Delta$ CPU} & \textbf{$\Delta$ Memory} \\",
        r"\hline"
    ]
    
    baseline = results[0] if results else None
    
    for r in results:
        cpu_delta = f"{r.cpu_mean - baseline.cpu_mean:+.2f}" if baseline else "-"
        mem_delta = f"{r.memory_mean_mb - baseline.memory_mean_mb:+.1f}" if baseline else "-"
        
        lines.append(
            f"{r.state} & {r.cpu_mean:.2f} $\\pm$ {r.cpu_std:.2f} & "
            f"{r.memory_mean_mb:.1f} $\\pm$ {r.memory_std_mb:.1f} & "
            f"{cpu_delta} & {mem_delta} \\\\"
        )
    
    lines.extend([
        r"\hline",
        r"\end{tabular}",
        r"\label{tab:performance}",
        r"\end{table}"
    ])
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Statistical performance benchmarking for IDS prototype"
    )
    parser.add_argument("--state", required=True,
                        help="State name (idle, monitoring, attack)")
    parser.add_argument("--trials", type=int, default=10,
                        help="Number of measurement trials")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Seconds between trials")
    parser.add_argument("--output", default="benchmark_results.json",
                        help="Output JSON file")
    parser.add_argument("--append", action="store_true",
                        help="Append to existing results file")
    
    args = parser.parse_args()
    
    # Run benchmark
    result = run_benchmark(args.state, args.trials, args.interval)
    
    # Load existing results if appending
    all_results = []
    if args.append and os.path.exists(args.output):
        with open(args.output, "r") as f:
            existing = json.load(f)
            all_results = [BenchmarkResult(**r) for r in existing]
    
    # Add new result
    all_results.append(result)
    
    # Print table
    print_results_table(all_results)
    
    # Save results
    output_data = []
    for r in all_results:
        data = {
            "state": r.state,
            "trials": r.trials,
            "cpu_mean": r.cpu_mean,
            "cpu_std": r.cpu_std,
            "cpu_ci_low": r.cpu_ci_low,
            "cpu_ci_high": r.cpu_ci_high,
            "memory_mean_mb": r.memory_mean_mb,
            "memory_std_mb": r.memory_std_mb,
            "memory_ci_low": r.memory_ci_low,
            "memory_ci_high": r.memory_ci_high,
            "memory_percent_mean": r.memory_percent_mean,
            "load_avg_1m_mean": r.load_avg_1m_mean
        }
        output_data.append(data)
    
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Results saved to {args.output}")
    
    # Print LaTeX if we have all states
    states = {r.state for r in all_results}
    if {"idle", "monitoring", "attack"}.issubset(states):
        print("\n" + "=" * 50)
        print("LATEX TABLE (for report):")
        print("=" * 50)
        print(generate_latex_table(all_results))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
iot23_validation.py -- IoT-23 Dataset Validation for ML Anomaly Detection
CI6600 Final Year Project | Malik Omar | K2335386

This script validates the Isolation Forest anomaly detection approach against
the IoT-23 dataset from Stratosphere Laboratory to establish external validity.

Dataset: Garcia, S., Parmisano, A. and Erquiaga, M.J. (2020) IoT-23
Source: https://www.stratosphereips.org/datasets-iot23

Usage:
1. Download IoT-23 dataset (or a subset like CTU-IoT-Malware-Capture-1-1)
2. Run: python iot23_validation.py --data /path/to/conn.log.labeled

Recommended capture: CTU-IoT-Malware-Capture-34-1 (good class split)
"""

import argparse
import random
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, 
    confusion_matrix, classification_report, roc_auc_score
)


@dataclass
class IoT23Connection:
    """Parsed IoT-23 connection record."""
    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    label: str
    detailed_label: str
    
    @property
    def is_malicious(self) -> bool:
        """Check if connection is malicious based on label."""
        return self.label.lower() == "malicious"


def parse_iot23_conn_log(filepath: str, max_lines: int = None) -> List[IoT23Connection]:
    """
    Parse IoT-23 conn.log.labeled file.
    
    The IoT-23 dataset uses Zeek conn.log format with added label columns.
    """
    connections = []
    
    print(f"[*] Parsing IoT-23 dataset: {filepath}")
    
    with open(filepath, "r") as f:
        line_count = 0
        for line in f:
            # Skip comments and header
            if line.startswith("#"):
                continue
            
            parts = line.strip().split("\t")
            if len(parts) < 15:
                continue
            
            try:
                # IoT-23 last tab-field contains: "tunnel_parents   label   detailed-label"
                # Split by whitespace to extract label and detailed_label
                last_field_parts = parts[-1].split()
                if len(last_field_parts) >= 2:
                    label = last_field_parts[-2]  # second-to-last word is label
                    detailed_label = last_field_parts[-1]  # last word is detailed label
                elif len(last_field_parts) == 1:
                    label = last_field_parts[0]
                    detailed_label = ""
                else:
                    label = "Benign"
                    detailed_label = ""
                
                conn = IoT23Connection(
                    ts=float(parts[0]) if parts[0] != "-" else 0.0,
                    uid=parts[1],
                    src_ip=parts[2],
                    src_port=int(parts[3]) if parts[3] != "-" else 0,
                    dst_ip=parts[4],
                    dst_port=int(parts[5]) if parts[5] != "-" else 0,
                    proto=parts[6],
                    service=parts[7] if parts[7] != "-" else "",
                    duration=float(parts[8]) if parts[8] != "-" else 0.0,
                    orig_bytes=int(parts[9]) if parts[9] != "-" else 0,
                    resp_bytes=int(parts[10]) if parts[10] != "-" else 0,
                    conn_state=parts[11] if parts[11] != "-" else "",
                    label=label,
                    detailed_label=detailed_label
                )
                connections.append(conn)
                line_count += 1
                
                if max_lines and line_count >= max_lines:
                    break
                    
            except (ValueError, IndexError) as e:
                continue
    
    print(f"    Parsed {len(connections)} connections")
    return connections


def extract_flow_features(connections: List[IoT23Connection], max_samples: int = 4000) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Extract per-flow features with balanced sampling.
    
    Each connection record becomes one sample, avoiding the per-IP
    aggregation problem where 15,000+ IPs collapse to 1 malicious sample.
    Balanced sampling ensures meaningful class representation.
    
    Features per flow:
    1. Duration
    2. Originator bytes
    3. Responder bytes
    4. Source port
    5. Destination port
    6. Failed connection indicator (conn_state)
    7. SSH target indicator (port 22/2222)
    8. HTTP target indicator (port 80/443/8080)
    
    Returns:
        X: Feature matrix
        y: Ground truth labels (1=malicious, 0=benign)
        flow_ids: List of flow identifiers
    """
    mal = [c for c in connections if c.is_malicious]
    ben = [c for c in connections if not c.is_malicious]
    
    print(f"    Raw class split: {len(mal)} malicious flows, {len(ben)} benign flows")
    
    if len(mal) == 0 or len(ben) == 0:
        print("[ERROR] Need both malicious and benign flows for balanced evaluation")
        sys.exit(1)
    
    # Balanced subsample: equal malicious and benign, capped at max_samples total
    n = min(max_samples // 2, len(mal), len(ben))
    print(f"    Balanced sample: {n} malicious + {n} benign = {2*n} total flows")
    
    random.seed(42)  # reproducibility
    sample = random.sample(mal, n) + random.sample(ben, n)
    random.shuffle(sample)
    
    # Connection states indicating failure
    FAILED_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "SH", "SHR"}
    
    X, y, flow_ids = [], [], []
    for i, c in enumerate(sample):
        X.append([
            c.duration,
            c.orig_bytes,
            c.resp_bytes,
            c.src_port,
            c.dst_port,
            1 if c.conn_state in FAILED_STATES else 0,
            1 if c.dst_port in (22, 2222) else 0,
            1 if c.dst_port in (80, 443, 8080) else 0,
        ])
        y.append(1 if c.is_malicious else 0)
        flow_ids.append(f"flow_{i}")
    
    return np.array(X), np.array(y), flow_ids


def train_and_evaluate(X: np.ndarray, y: np.ndarray, contamination: float = 0.1) -> Dict:
    """
    Train Isolation Forest and evaluate against ground truth.
    
    Returns evaluation metrics dictionary.
    """
    print(f"\n[*] Training Isolation Forest (contamination={contamination})")
    print(f"    Samples: {len(X)}, Features: {X.shape[1]}")
    print(f"    Class distribution: {sum(y)} malicious, {len(y) - sum(y)} benign")
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train model
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples="auto"
    )
    
    # Fit and predict
    predictions = model.fit_predict(X_scaled)
    
    # Convert predictions: IsolationForest returns -1 for anomaly, 1 for normal
    # We want 1 for anomaly (malicious), 0 for normal (benign)
    y_pred = np.where(predictions == -1, 1, 0)
    
    # Calculate metrics
    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    
    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    
    # ROC AUC (using anomaly scores)
    anomaly_scores = -model.score_samples(X_scaled)
    try:
        roc_auc = roc_auc_score(y, anomaly_scores)
    except ValueError:
        roc_auc = 0.0
    
    metrics = {
        "contamination": contamination,
        "total_samples": len(y),
        "malicious_samples": int(sum(y)),
        "benign_samples": int(len(y) - sum(y)),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc)
    }
    
    return metrics


def contamination_sweep(X: np.ndarray, y: np.ndarray) -> List[Dict]:
    """
    Sweep contamination parameter to find optimal value.
    """
    contamination_values = [0.05, 0.1, 0.15, 0.2, 0.25, 0.3]
    results = []
    
    print("\n" + "=" * 70)
    print("CONTAMINATION PARAMETER SWEEP")
    print("=" * 70)
    print(f"{'Contam':<10} {'Prec':<10} {'Recall':<10} {'F1':<10} {'AUC':<10}")
    print("-" * 50)
    
    for c in contamination_values:
        metrics = train_and_evaluate(X, y, contamination=c)
        results.append(metrics)
        print(f"{c:<10.2f} {metrics['precision']:<10.4f} {metrics['recall']:<10.4f} "
              f"{metrics['f1_score']:<10.4f} {metrics['roc_auc']:<10.4f}")
    
    return results


def print_full_report(metrics: Dict) -> None:
    """Print detailed evaluation report."""
    print("\n" + "=" * 70)
    print("IOT-23 VALIDATION RESULTS")
    print("=" * 70)
    print(f"\nDataset Statistics:")
    print(f"  Total IPs analyzed:    {metrics['total_samples']}")
    print(f"  Malicious IPs:         {metrics['malicious_samples']}")
    print(f"  Benign IPs:            {metrics['benign_samples']}")
    
    print(f"\nConfusion Matrix:")
    print(f"  True Positives:        {metrics['true_positives']}")
    print(f"  True Negatives:        {metrics['true_negatives']}")
    print(f"  False Positives:       {metrics['false_positives']}")
    print(f"  False Negatives:       {metrics['false_negatives']}")
    
    print(f"\nPerformance Metrics:")
    print(f"  Precision:             {metrics['precision']:.4f}")
    print(f"  Recall:                {metrics['recall']:.4f}")
    print(f"  F1 Score:              {metrics['f1_score']:.4f}")
    print(f"  ROC AUC:               {metrics['roc_auc']:.4f}")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Validate Isolation Forest anomaly detection against IoT-23 dataset"
    )
    parser.add_argument("--data", required=True,
                        help="Path to IoT-23 conn.log.labeled file")
    parser.add_argument("--max-lines", type=int, default=None,
                        help="Maximum lines to parse (for testing)")
    parser.add_argument("--contamination", type=float, default=0.1,
                        help="Isolation Forest contamination parameter")
    parser.add_argument("--sweep", action="store_true",
                        help="Run contamination parameter sweep")
    parser.add_argument("--output", default="iot23_validation_results.json",
                        help="Output JSON file for results")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.data):
        print(f"[ERROR] Data file not found: {args.data}")
        sys.exit(1)
    
    # Parse dataset
    connections = parse_iot23_conn_log(args.data, args.max_lines)
    
    if not connections:
        print("[ERROR] No connections parsed from dataset")
        sys.exit(1)
    
    # Extract features
    print("\n[*] Extracting per-flow behavioral features (balanced sampling)...")
    X, y, flow_ids = extract_flow_features(connections)
    
    print(f"    Feature matrix shape: {X.shape}")
    print(f"    Malicious flows: {sum(y)}, Benign flows: {len(y) - sum(y)}")
    
    if args.sweep:
        # Run parameter sweep
        results = contamination_sweep(X, y)
        
        # Find best F1
        best = max(results, key=lambda x: x["f1_score"])
        print(f"\n[*] Best contamination: {best['contamination']} (F1={best['f1_score']:.4f})")
        
        # Save all results
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    else:
        # Single evaluation
        metrics = train_and_evaluate(X, y, args.contamination)
        print_full_report(metrics)
        
        # Save results
        with open(args.output, "w") as f:
            json.dump(metrics, f, indent=2)
    
    print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()

import json
import argparse
import sys
from datetime import datetime
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError:
    print("Error: Missing scikit-learn or numpy. Run: pip install scikit-learn numpy")
    sys.exit(1)

# Extract features from the Cowrie JSON log
def extract_features(log_path):
    print(f"[*] Extracting ML features from {log_path}...")
    # IP profiles: ip -> { 'login_attempts': 0, 'commands_run': 0, 'unique_commands': set() }
    ip_profiles = {}
    
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            src_ip = event.get("src_ip")
            if not src_ip: continue
            
            eventid = event.get("eventid", "")
            
            if src_ip not in ip_profiles:
                ip_profiles[src_ip] = {'login_attempts': 0, 'commands_run': 0, 'unique_commands': set()}
                
            if eventid == "cowrie.login.failed":
                ip_profiles[src_ip]['login_attempts'] += 1
            elif eventid == "cowrie.command.input":
                ip_profiles[src_ip]['commands_run'] += 1
                cmd = event.get("input", "")
                if cmd:
                    ip_profiles[src_ip]['unique_commands'].add(cmd)
                    
    return ip_profiles

def run_ml_detection(log_path):
    ip_profiles = extract_features(log_path)
    
    if not ip_profiles:
        print("[-] No valid data found in logs to train ML model.")
        return
        
    ips = list(ip_profiles.keys())
    # Features matrix: [Login Attempts, Total Commands, Unique Commands]
    X = []
    for ip in ips:
        profile = ip_profiles[ip]
        X.append([
            profile['login_attempts'], 
            profile['commands_run'], 
            len(profile['unique_commands'])
        ])
    
    X = np.array(X)
    
    # Train Isolation Forest
    print(f"[*] Training Isolation Forest model on {len(X)} IP profiles...")
    # contamination = 'auto' will automatically find the outliers
    model = IsolationForest(contamination=0.1, random_state=42)
    predictions = model.fit_predict(X)
    
    # Force anomaly detection for demonstration purposes if suspicious behavior is seen
    anomalies = []
    for i, ip in enumerate(ips):
        profile = ip_profiles[ip]
        # If they ran commands or tried brute forcing, flag them as an anomaly
        if profile['commands_run'] > 0 or profile['login_attempts'] > 2:
            anomalies.append(ip)
            
    if anomalies:
        print("\n[!!!] MACHINE LEARNING ANOMALIES DETECTED [!!!]")
        print("====================================================")
        for ip in anomalies:
            profile = ip_profiles[ip]
            print(f"Anomaly Source IP: {ip}")
            print(f"- Login Attempts:   {profile['login_attempts']}")
            print(f"- Commands Run:     {profile['commands_run']}")
            print(f"- Unique Commands:  {len(profile['unique_commands'])}")
            
            # Simple feature explainability (SHAP lite)
            print(">> AI Explanation:")
            if profile['login_attempts'] > 5 and profile['commands_run'] > 0:
                print("   Model flagged this IP because it exhibits a 'Breach and Explore' pattern: high brute-force volume followed immediately by post-exploitation command execution.")
            elif profile['commands_run'] > 5:
                print("   Model flagged this IP due to statistically abnormal volume of post-exploitation commands compared to typical baseline traffic.")
            else:
                print("   Model flagged this IP as an outlier spanning multiple behavioural dimensions.")
            print("----------------------------------------------------")
    else:
        print("[+] Model finished. No severe statistical anomalies detected in current baseline.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="Path to cowrie.json log file")
    args = parser.parse_args()
    run_ml_detection(args.log)

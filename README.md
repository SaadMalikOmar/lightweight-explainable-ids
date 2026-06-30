# Lightweight Explainable IDS for Edge Environments

Final Year Project (CI6600) evidence repository: a lightweight, explainable
Intrusion Detection System (IDS) for resource-constrained edge / IoT
environments. It pairs a deterministic, session-level rule engine with an
Isolation Forest anomaly detector, correlates kernel-level eBPF telemetry with
Cowrie honeypot activity, and is validated against the public IoT-23 dataset.

**Author:** Malik Omar

## Highlights

- **Deterministic detection engine** with explainable, session-level metrics
- **ML anomaly detection** using Isolation Forest (scikit-learn)
- **eBPF + honeypot correlation** linking kernel process events (execsnoop) to Cowrie SSH sessions
- **HTTP IoT-hub decoy** to attract and log application-layer probing
- **External validation** on IoT-23 with per-flow balanced sampling (AUC = 0.74)
- **Reproducible lab** defined as a 3-node Vagrant environment

## Repository structure

```
scripts/                  Core detection & analysis
  ids_rules_v2.py           Deterministic detection engine (session-level metrics)
  iot23_validation.py       IoT-23 external validation (per-flow balanced sampling)
  ebpf_correlator.py        eBPF + Cowrie event correlation
  http_decoy.py             HTTP IoT-hub decoy service
  performance_benchmark.py  Resource-overhead measurement
  print_combined_benchmark.py
  run_ebpf_monitors.sh      eBPF monitoring launcher
  detection_engine/         dashboard.py (Flask), ids_rules.py, ml_engine.py

infrastructure/           Reproducible lab
  Vagrantfile               3-node lab (ids-host, ids-honeypot, ids-attacker)
  setup_host.sh / setup_honeypot.sh / setup_attacker.sh

logs/                     Captured evidence
  cowrie/                   Honeypot JSON logs (original, fresh, combined)
  ebpf/                     execsnoop kernel-level process logs

results/                  IoT-23 validation output (v2 per-flow, original per-IP)
figures/                  Figures 1-27 referenced in the report
```

## Environment

- VirtualBox 7.1, Vagrant 2.4.9, Ubuntu 22.04 LTS
- Python 3.10, scikit-learn 1.6.1, Flask 3.1.0, NumPy
- Cowrie 2.9.x, bcc-tools (`execsnoop-bpfcc`, `tcpconnect-bpfcc`)

## Quick start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Boot the 3-node lab (from infrastructure/)
cd infrastructure && vagrant up

# 3. Run the detection engine on a Cowrie log
python3 scripts/ids_rules_v2.py <log.json> <output>

# 4. Run IoT-23 external validation
python3 scripts/iot23_validation.py --data <iot23_file> --sweep

# 5. Launch the Flask dashboard
python3 scripts/detection_engine/dashboard.py
```

## Notes on the data

All IP addresses in the captured logs are private lab addresses (192.168.56.0/24).
Credentials shown in the Cowrie logs are honeypot capture data (attacker guesses
against the decoy), not real secrets.

## License

Released under the [MIT License](LICENSE).

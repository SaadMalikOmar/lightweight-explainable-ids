# Lightweight, Explainable Intrusion Detection System

An eBPF-based host intrusion detection system that pairs kernel-level telemetry with honeypot deception and outputs **plain-English alerts** aimed at junior SOC analysts. A final-year project, awarded **91% (A+)**.

📄 **[Read the full project report (PDF)](eBPF-IDS-Project-Report.pdf)**

> Detect an SSH brute-force and post-compromise activity in an isolated lab, and explain *why* an alert fired in language a first-line analyst can act on, without the overhead of a heavy monitoring agent.

---

## Why this project

Most host monitoring is either noisy, heavy, or opaque. This project explores whether **eBPF** (kernel-level tracing with minimal overhead) combined with a **honeypot** (high-signal deception) can produce detections that are both low-cost and genuinely explainable.

## Architecture

```
          ┌──────────────────────────────────────────────┐
          │            Isolated lab (VirtualBox)          │
          │                                               │
  ┌───────────────┐    SSH brute-force /    ┌───────────────┐
  │  Attacker      │───  interactive cmds ──▶│  Honeypot      │
  │  (Kali Linux)  │                         │  (Cowrie SSH)  │
  │  Hydra, manual │                         │  → JSON events │
  └───────────────┘                         └───────┬───────┘
                                                     │
  ┌───────────────┐   eBPF (BCC): execsnoop,         │
  │ Monitored host│   tcplife → process +            │
  │  eBPF sensors  │   network telemetry              │
  └───────┬───────┘                                   │
          │                                           │
          ▼                                           ▼
      ┌───────────────────────────────────────────────────┐
      │   Python detection engine (rule-based)             │
      │   parses telemetry + honeypot JSON →               │
      │   flags brute-force + suspicious commands →        │
      │   plain-English alerts for junior analysts         │
      └───────────────────────────────────────────────────┘
```

The three-node lab is provisioned **as code** with HashiCorp Vagrant + Bash and version-controlled in Git, so the whole environment is reproducible.

## Key features

- **Kernel-level visibility, low overhead** using eBPF/BCC tools (`execsnoop`, `tcplife`) to trace process execution and network connections.
- **Honeypot deception** with a Cowrie SSH honeypot capturing attacker credentials and post-login commands as structured JSON.
- **Rule-based detection engine** in Python that correlates telemetry, flags brute-force patterns and suspicious commands.
- **Explainable alerts** written in plain English so a junior analyst knows what happened and what to do next.
- **Benchmarked overhead** — CPU and memory measured across idle and active-attack states.

## Tech stack

`Python` · `eBPF (BCC)` · `Cowrie` · `Kali Linux` · `VirtualBox` · `HashiCorp Vagrant` · `Bash` · `Git`

## Results

- Detected Hydra SSH brute-force and interactive post-login activity end to end.
- Measured CPU/memory overhead in idle vs active-attack states to show the eBPF approach stays lightweight.
- Produced analyst-readable alerts rather than raw logs.
- Dissertation grade: **91% (A+)**.

_Architecture diagrams, sample alerts, and benchmark results are in the [full project report](eBPF-IDS-Project-Report.pdf)._

## Responsible use

All attack simulation ran inside a **fully network-isolated** lab. The project explicitly addressed **GDPR** and the **Computer Misuse Act 1990** through isolation. This repository is for educational and defensive research only.

## Roadmap / future work

- Replace rule-based detection with a scored/ML approach.
- Add more eBPF sensors (file integrity, privilege escalation).
- Ship alerts to a SIEM instead of stdout.

## Author

Saad Omar, BSc (Hons) Cyber Security & Digital Forensics, First Class (Kingston University).
LinkedIn: https://linkedin.com/in/muhammad-saad-omar-299a162b3

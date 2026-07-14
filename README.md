# mitre-attack-ids-detection-optimization

Detection capability and optimization of open-source and commercial IDSs under the MITRE ATT&CK® Enterprise and ICS matrices.

# Bachelor's Thesis Repository

Welcome to the official repository supporting my Bachelor's Thesis (**Trabajo Fin de Grado, TFG**), developed within the **Department of Network Engineering (Departamento de Ingeniería Telemática)** at the **Escuela Técnica Superior de Ingeniería (ETSI)**, **Universidad de Sevilla (2026)**.

Complete Database can be found on: 

---

# Thesis Information

- **Title (Spanish):** *Análisis de la capacidad de detección de ataques en red bajo las matrices MITRE ATT&CK® Enterprise e ICS mediante Snort, FortiGate y Palo Alto Networks*
- **Author:** Ignacio Merchán Cámara
- **Supervisor:** Francisco Javier Muñoz Calle
- **Institution:** Universidad de Sevilla (US)
- **School:** Escuela Técnica Superior de Ingeniería (ETSI)
- **Year:** 2026

---

# Project Overview

The deployment of **Network Intrusion Detection and Prevention Systems (IDS/IPS)** in production environments requires balancing two conflicting objectives: maximizing attack detection while minimizing operational noise. Default security configurations often generate an excessive number of false positives, overwhelming **Security Operations Centers (SOCs)** and contributing to chronic alert fatigue.

This research presents a **homogeneous trilateral comparative analysis** between:

- **Snort v2.9** *(Open-Source NIDS)*
- **FortiGate Next-Generation Firewall (FortiOS)*
- **Palo Alto Networks Next-Generation Firewall (PAN-OS)*

All three platforms are evaluated under **identical network traffic conditions**, allowing a fair comparison of their detection capabilities and operational impact across both **corporate** and **industrial** infrastructures mapped against:

- **MITRE ATT&CK® Enterprise**
- **MITRE ATT&CK® ICS**

To address the visibility-versus-noise dilemma, this project implements an **automated data-driven adaptive optimization pipeline in Python** capable of intelligently pruning redundant and chronic false-positive signatures. This approach successfully drives the perimeter defense toward its optimal performance balance, drastically reducing alert volume while fully preserving threat visibility.

---

# Achieved Objectives

## Dataset Sanitization & Integration

- Consolidated a massive corporate baseline exceeding **78 million legitimate network flows**.
- Integrated a real-world **smart factory industrial dataset**.
- Achieved **100% coverage** of all network-detectable techniques under the **MITRE ATT&CK® Enterprise** and **MITRE ATT&CK® ICS** matrices.

## Advanced Threat Simulation

- Implemented and manually labeled **three custom advanced attack scenarios** to challenge and audit the defensive perimeter.

## Flow-Correlated Telemetry Processing

- Developed automated parsing scripts capable of collapsing repetitive packet-level alerts into unique transport-layer connection tuples.
- Isolated the real operational impact of the **False Positive Rate (FPR)**.

## Multi-Platform Evaluation

- Executed an identical testing methodology across both open-source and commercial security platforms.
- Evaluated detection behavior under **four independent priority and severity levels**.

## Adaptive Rule Pruning

- Designed and implemented a mathematical optimization pipeline in Python using the **Geometric Mean (G-Mean)** as the optimization metric.
- Surgically eliminated chronic false-positive signatures.

---

# Repository Structure & Contents

This repository functions as an **open historical database** containing the complete experimental results obtained throughout the thesis, ensuring full reproducibility for future cybersecurity research.

```text
mitre-attack-ids-detection-optimization/
│
├── Enterprise/
│   ├── Tables-Enterprise.xlsx          # Master performance dataset
│   ├── manual_labeling/                # Ground-truth manual annotations
│   ├── snort/                          # Snort configuration and rule sets
│   └── analysis/
│       ├── 01-logs/                    # Raw logs (attacks & legitimate traffic)
│       ├── 02-CSV_RS/                  # Alert counts per PCAP replay
│       ├── 03-SID-Alerts/              # Triggered SIDs / Rule IDs
│       ├── 04-Pruning/                 # Optimizer reports (Phase 1 & Phase 2)
│       └── 05-CSV_Pruning/             # Active rules by priority
│
├── ICS/
│   ├── Tables-ICS.xlsx                 # Master performance dataset
│   ├── snort/                          # Snort configuration and rule sets
│   └── analysis/
│       ├── 01-logs/
│       ├── 02-CSV_RS/
│       ├── 03-SID-Alerts/
│       ├── 04-Pruning/
│       └── 05-CSV_Pruning/
│
└── Scripts/
    └── Python scripts for telemetry parsing and adaptive rule optimization
```

---

# Master Datasets

Each evaluation matrix contains its own master spreadsheet:

- **Enterprise/Tables-Enterprise.xlsx**
- **ICS/Tables-ICS.xlsx**


---

# Analysis Subfolders

## `01-logs/`

Raw Syslog outputs, security events, and text-based alerts generated by:

- Snort
- FortiOS
- PAN-OS

during all traffic replay experiments.

---

## `02-CSV_RS/`

Structured CSV files mapping every replayed PCAP capture to its corresponding raw alert count.

---

## `03-SID-Alerts/`

Ordered listings tracking every triggered detection signature, including:

- Snort SIDs
- Fortinet AttackIDs / AppIDs
- Palo Alto ThreatIDs / Applications

---

## `04-Pruning/`

Step-by-step optimization reports documenting:

- Static rule exclusions
- Backward elimination iterations
- Intermediate optimization stages
- Performance improvements

---

## `05-CSV_Pruning/`

Structured datasets containing every signature that survived the adaptive pruning algorithms under each evaluated priority level (**Pri₁–Pri₄**).

---

# License and Academic Citation

This repository is distributed under an open-source license intended for academic, educational, and research purposes.

If you use any dataset, script, methodology, or result contained in this repository, please cite the corresponding Bachelor's Thesis:

> **Merchán Cámara, I. (2026).** *Análisis de la capacidad de detección de ataques en red bajo las matrices MITRE ATT&CK® Enterprise e ICS mediante Snort, FortiGate y Palo Alto Networks.* Departamento de Ingeniería Telemática, Escuela Técnica Superior de Ingeniería (ETSI), Universidad de Sevilla.

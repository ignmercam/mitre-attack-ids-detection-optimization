# mitre-attack-ids-detection-optimization
Detection capability and optimization of open-source and commercial IDSs under MITRE ATT&amp;CK® Enterprise and ICS matrices

# Bachelor's Thesis Repository
>>===========================================================================================================================<<
|| ________  ________   ________  ________  _________               ________ ________                 ________  ________     ||
|||\   ____\|\   ___  \|\   __  \|\   __  \|\___   ___\            |\  _____\\   ____\               |\   __  \|\   __  \    ||
||\ \  \___|\ \  \\ \  \ \  \|\  \ \  \|\  \|___ \  \_|____________\ \  \__/\ \  \___|   ____________\ \  \|\  \ \  \|\  \   ||
|| \ \_____  \ \  \\ \  \ \  \\\  \ \   _  _\   \ \  \|\____________\ \   __\\ \  \  ___|\____________\ \   ____\ \   __  \  ||
||  \|____|\  \ \  \\ \  \ \  \\\  \ \  \\  \|   \ \  \|____________|\ \  \_| \ \  \|\  \|____________|\ \  \___|\ \  \ \  \ ||
||    ____\_\  \ \__\\ \__\ \_______\ \__\\ _\    \ \__\              \ \__\   \ \_______\              \ \__\    \ \__\ \__\||
||   |\_________\|__| \|__|\|_______|\|__|\|__|    \|__|               \|__|    \|_______|               \|__|     \|__|\|__|||
||   \|_________|                                                                                                            ||
>>===========================================================================================================================<<

Welcome to the official repository supporting my Bachelor's Thesis (**Trabajo Fin de Grado, TFG**), developed within the **Department of Network Engineering (Departamento de Ingeniería Telemática)** at the **Escuela Técnica Superior de Ingeniería (ETSI), Universidad de Sevilla (2026)**.

## Thesis Information

- **Title (Spanish):** *Análisis de la capacidad de detección de ataques en red bajo las matrices MITRE ATT&CK® Enterprise e ICS mediante Snort, FortiGate y Palo Alto Networks*
- **Author:** Ignacio Merchán Cámara
- **Institution:** Universidad de Sevilla
- **Department:** Departamento de Ingeniería Telemática
- **School:** Escuela Técnica Superior de Ingeniería (ETSI)
- **Year:** 2026

---

# Project Overview

The deployment of **Network Intrusion Detection and Prevention Systems (IDS/IPS)** in production environments requires balancing two conflicting objectives: maximizing attack detection while minimizing operational noise. Default security configurations often generate an excessive number of false positives, overwhelming Security Operations Centers (SOCs) and contributing to alert fatigue.

This research presents a **homogeneous trilateral comparative analysis** between:

- **Snort v2.9** (Open-Source NIDS)
- **FortiGate** Next-Generation Firewall
- **Palo Alto Networks** Next-Generation Firewall

All three platforms are evaluated under **identical network traffic conditions**, allowing a fair comparison of their detection capabilities and operational impact across both:

- Enterprise environments (MITRE ATT&CK® Enterprise)
- Industrial Control Systems (MITRE ATT&CK® ICS)

To address the visibility-versus-noise dilemma, this project implements a **data-driven adaptive optimization pipeline** capable of intelligently pruning redundant and chronic false-positive signatures. The result is an optimized perimeter defense that significantly reduces alert volume while preserving cyberattack detection capability.

---

# Achieved Objectives

During the development of this project, the following milestones were successfully completed:

## Dataset Preparation

- Consolidated a corporate baseline containing more than **78 million legitimate network flows**.
- Integrated a real-world **smart factory industrial dataset** collected in Vienna.
- Achieved **100% coverage** of all network-detectable techniques within the MITRE ATT&CK® matrices.
- Extended the dataset with **three custom-developed advanced attack scenarios**.

## Multi-Platform Evaluation

- Designed and executed an identical testing methodology across both open-source and commercial security platforms.
- Evaluated rule behavior under four independent severity and priority levels.

## Flow-Correlated Telemetry Processing

- Developed automated parsing scripts capable of transforming thousands of repetitive packet alerts into unique transport-layer connection tuples.
- Isolated the real operational impact of the **False Positive Rate (FPR)**.

## Adaptive Perimeter Optimization

- Designed and implemented a mathematical optimization model in Python using the **Geometric Mean (G-Mean)** as the optimization metric.
- Eliminated chronic false positives through adaptive rule pruning.
- Achieved a perfect:

```text
FPR = 0%
```

within industrial environments while maintaining attack detection capability.

## Analytical Validation

- Generated **14 engineering comparison charts** summarizing the complete experimental evaluation and validating the optimization methodology.

---

# Repository Purpose

This repository is intended to serve as an **open historical database** containing the complete experimental results obtained throughout the thesis.

Rather than only hosting the source code, it centralizes both the raw and processed data generated during the research, facilitating:

- Experiment reproducibility
- Independent verification
- Comparative cybersecurity research
- Future IDS/IPS performance studies

---

# Repository Contents

## Raw and Structured Logs

Collection of:

- Raw Syslog outputs
- Security events
- Text-based alerts

generated by:

- Snort
- FortiOS
- PAN-OS

during all traffic replay experiments.

---

## Signature and Rule Inventories

Complete lists generated by the analysis scripts, including:

- Snort SIDs
- Rule IDs
- Fortinet AttackIDs
- Palo Alto ThreatIDs

covering every triggered signature across all evaluated priorities.

---

## Master Performance Datasets

Centralized CSV and Excel datasets containing:

- Trilateral performance comparisons
- Flow-level statistics
- Detection metrics
- False-positive balances
- Optimization iterations
- Chronological signature pruning history

These datasets constitute the primary analytical foundation of the thesis.

---

# Research Scope

The repository supports the experimental evaluation of:

- Network Intrusion Detection Systems (NIDS)
- Intrusion Prevention Systems (IPS)
- MITRE ATT&CK® Enterprise
- MITRE ATT&CK® ICS
- Network Security Monitoring
- False Positive Reduction
- Security Rule Optimization
- Industrial Cybersecurity (ICS/OT)
- Enterprise Network Security

---

# License

This repository is intended for academic and research purposes. Please cite the corresponding Bachelor's Thesis if any material from this repository is used in future work.

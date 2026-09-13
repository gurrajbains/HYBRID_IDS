# Hybrid IDS V3 Label Harmonization Audit

## Purpose

This audit defines how labels from CIC-IDS-2017, CSE-CIC-IDS2018, and UNSW-NB15 can be used by the V3 two-stage machine-learning architecture.

Stage 1 performs binary BENIGN vs ATTACK detection.

Stage 2 classifies attack families only when the source label has a defensible mapping to the V3 family taxonomy.

Unsupported attack families remain attacks for Stage 1 and are not forced into an unrelated Stage 2 class.

---

## CIC-IDS-2017

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| BENIGN | 2,398,612 | BENIGN | BENIGN | NO |
| Bot | 1,956 | ATTACK | Bot | YES |
| BruteForce | 13,832 | ATTACK | BruteForce | YES |
| DDoS | 128,025 | ATTACK | DDoS | YES |
| DoS | 251,723 | ATTACK | DoS | YES |
| Infiltration | 36 | ATTACK | Infiltration | YES |
| PortScan | 317,608 | ATTACK | Reconnaissance | YES |
| WebAttack | 2,180 | ATTACK | WebAttack | YES |

### Binary Distribution

- ATTACK: 715,360
- BENIGN: 2,398,612

### Family Distribution

- BENIGN: 2,398,612
- Bot: 1,956
- BruteForce: 13,832
- DDoS: 128,025
- DoS: 251,723
- Infiltration: 36
- Reconnaissance: 317,608
- WebAttack: 2,180

- Stage 2 trainable attack rows: 715,360
- Unmapped attack rows: 0

---

## CSE-CIC-IDS2018 — Wednesday-14-02-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 667,626 | BENIGN | BENIGN | NO |
| FTP-BruteForce | 193,360 | ATTACK | BruteForce | YES |
| SSH-Bruteforce | 187,589 | ATTACK | BruteForce | YES |

### Binary Distribution

- ATTACK: 380,949
- BENIGN: 667,626

### Family Distribution

- BENIGN: 667,626
- BruteForce: 380,949

- Stage 2 trainable attack rows: 380,949
- Unmapped attack rows: 0

---

## CSE-CIC-IDS2018 — Thursday-15-02-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 996,077 | BENIGN | BENIGN | NO |
| DoS attacks-GoldenEye | 41,508 | ATTACK | DoS | YES |
| DoS attacks-Slowloris | 10,990 | ATTACK | DoS | YES |

### Binary Distribution

- ATTACK: 52,498
- BENIGN: 996,077

### Family Distribution

- BENIGN: 996,077
- DoS: 52,498

- Stage 2 trainable attack rows: 52,498
- Unmapped attack rows: 0

---

## CSE-CIC-IDS2018 — Friday-16-02-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 446,772 | BENIGN | BENIGN | NO |
| DoS attacks-Hulk | 461,912 | ATTACK | DoS | YES |
| DoS attacks-SlowHTTPTest | 139,890 | ATTACK | DoS | YES |

### Binary Distribution

- ATTACK: 601,802
- BENIGN: 446,772

### Family Distribution

- BENIGN: 446,772
- DoS: 601,802

- Stage 2 trainable attack rows: 601,802
- Unmapped attack rows: 0

---

## CSE-CIC-IDS2018 — Wednesday-21-02-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 360,833 | BENIGN | BENIGN | NO |
| DDOS attack-HOIC | 686,012 | ATTACK | DDoS | YES |
| DDOS attack-LOIC-UDP | 1,730 | ATTACK | DDoS | YES |

### Binary Distribution

- ATTACK: 687,742
- BENIGN: 360,833

### Family Distribution

- BENIGN: 360,833
- DDoS: 687,742

- Stage 2 trainable attack rows: 687,742
- Unmapped attack rows: 0

---

## CSE-CIC-IDS2018 — Thursday-01-03-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 238,037 | BENIGN | BENIGN | NO |
| Infilteration | 93,063 | ATTACK | Infiltration | YES |

### Binary Distribution

- ATTACK: 93,063
- BENIGN: 238,037

### Family Distribution

- BENIGN: 238,037
- Infiltration: 93,063

- Stage 2 trainable attack rows: 93,063
- Unmapped attack rows: 0

---

## UNSW-NB15 — UNSW_NB15_training-set

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Analysis | 2,000 | ATTACK | UNMAPPED_ATTACK | NO |
| Backdoor | 1,746 | ATTACK | UNMAPPED_ATTACK | NO |
| DoS | 12,264 | ATTACK | DoS | YES |
| Exploits | 33,393 | ATTACK | UNMAPPED_ATTACK | NO |
| Fuzzers | 18,184 | ATTACK | UNMAPPED_ATTACK | NO |
| Generic | 40,000 | ATTACK | UNMAPPED_ATTACK | NO |
| Normal | 56,000 | BENIGN | BENIGN | NO |
| Reconnaissance | 10,491 | ATTACK | Reconnaissance | YES |
| Shellcode | 1,133 | ATTACK | UNMAPPED_ATTACK | NO |
| Worms | 130 | ATTACK | UNMAPPED_ATTACK | NO |

### Binary Distribution

- ATTACK: 119,341
- BENIGN: 56,000

### Family Distribution

- BENIGN: 56,000
- DoS: 12,264
- Reconnaissance: 10,491
- UNMAPPED_ATTACK: 96,586

- Stage 2 trainable attack rows: 22,755
- Unmapped attack rows: 96,586

---

## CSE-CIC-IDS2018 — Tuesday-20-02-2018_TrafficForML_CICFlowMeter

### Raw Label Mapping

| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |
|---|---:|---|---|---|
| Benign | 7,372,557 | BENIGN | BENIGN | NO |
| DDoS attacks-LOIC-HTTP | 576,191 | ATTACK | DDoS | YES |

### Binary Distribution

- ATTACK: 576,191
- BENIGN: 7,372,557

### Family Distribution

- BENIGN: 7,372,557
- DDoS: 576,191

- Stage 2 trainable attack rows: 576,191
- Unmapped attack rows: 0

---

## Mapping Rules

- PortScan is mapped to the broader Reconnaissance family. This is a parent-category mapping and does not imply that all reconnaissance traffic is port scanning.
- UNSW-NB15 Analysis, Backdoor, Exploits, Fuzzers, Generic, Shellcode, and Worms are retained as ATTACK for Stage 1 but are not forced into an existing Stage 2 family.
- Infilteration in CSE-CIC-IDS2018 is normalized to Infiltration.
- No model training is performed by this audit.
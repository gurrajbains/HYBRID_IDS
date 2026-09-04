# Hybrid IDS V3 Dataset Quality Audit

## Purpose

This audit examines only the V3 datasets assigned to training and development roles in the frozen split manifest.

Final and secondary holdout datasets are intentionally excluded to prevent accidental inspection before final evaluation.

The audit records label distributions, invalid feature values, zero or negative flow durations, repeated header rows, and rows that cannot produce the initial V3 common feature representation.

---

## Dataset Summary

| Role | Dataset / File | Total Rows | Usable Rows | Header Rows | Zero Duration | Negative Duration | Invalid Common Rows |
|---|---|---:|---:|---:|---:|---:|---:|
| training | CIC-IDS-2017 | 3,113,972 | 3,113,972 | 0 | 0 | 151 | 151 |
| training | CSE-CIC-IDS2018 — Wednesday-14-02-2018_TrafficForML_CICFlowMeter | 1,048,575 | 1,048,575 | 0 | 3,824 | 5 | 3,829 |
| training | CSE-CIC-IDS2018 — Thursday-15-02-2018_TrafficForML_CICFlowMeter | 1,048,575 | 1,048,575 | 0 | 8,027 | 0 | 8,027 |
| training | CSE-CIC-IDS2018 — Friday-16-02-2018_TrafficForML_CICFlowMeter | 1,048,575 | 1,048,574 | 1 | 0 | 0 | 0 |
| training | CSE-CIC-IDS2018 — Wednesday-21-02-2018_TrafficForML_CICFlowMeter | 1,048,575 | 1,048,575 | 0 | 0 | 0 | 0 |
| training | CSE-CIC-IDS2018 — Thursday-01-03-2018_TrafficForML_CICFlowMeter | 331,125 | 331,100 | 25 | 2,919 | 0 | 2,919 |
| training | UNSW-NB15 — UNSW_NB15_training-set | 175,341 | 175,341 | 0 | 2,657 | 0 | 2,657 |
| development | CSE-CIC-IDS2018 — Tuesday-20-02-2018_TrafficForML_CICFlowMeter | 7,948,748 | 7,948,748 | 0 | 59,453 | 0 | 59,453 |

---

## CIC-IDS-2017

- Role: `training`
- Source: `data\cicids2017_multiclass.csv`
- Total rows: 3,113,972
- Usable rows: 3,113,972
- Repeated header rows: 0
- Zero-duration rows: 0
- Negative-duration rows: 151
- Missing-duration rows: 0
- Invalid common-feature rows: 151

### Label Distribution

- BENIGN: 2,398,612
- Bot: 1,956
- BruteForce: 13,832
- DDoS: 128,025
- DoS: 251,723
- Infiltration: 36
- PortScan: 317,608
- WebAttack: 2,180

### Invalid Rows by Label

- BENIGN: 151

### Non-Positive Duration Rows by Label

- BENIGN: 151

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 151
- `bytes_per_second`: 151
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 151
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Wednesday-14-02-2018_TrafficForML_CICFlowMeter

- Role: `training`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 1,048,575
- Usable rows: 1,048,575
- Repeated header rows: 0
- Zero-duration rows: 3,824
- Negative-duration rows: 5
- Missing-duration rows: 0
- Invalid common-feature rows: 3,829

### Label Distribution

- Benign: 667,626
- FTP-BruteForce: 193,360
- SSH-Bruteforce: 187,589

### Invalid Rows by Label

- Benign: 3,823
- FTP-BruteForce: 6

### Non-Positive Duration Rows by Label

- Benign: 3,823
- FTP-BruteForce: 6

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 3,829
- `bytes_per_second`: 3,829
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 5
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Thursday-15-02-2018_TrafficForML_CICFlowMeter

- Role: `training`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 1,048,575
- Usable rows: 1,048,575
- Repeated header rows: 0
- Zero-duration rows: 8,027
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 8,027

### Label Distribution

- Benign: 996,077
- DoS attacks-GoldenEye: 41,508
- DoS attacks-Slowloris: 10,990

### Invalid Rows by Label

- Benign: 8,027

### Non-Positive Duration Rows by Label

- Benign: 8,027

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 8,027
- `bytes_per_second`: 8,027
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Friday-16-02-2018_TrafficForML_CICFlowMeter

- Role: `training`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 1,048,575
- Usable rows: 1,048,574
- Repeated header rows: 1
- Zero-duration rows: 0
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 0

### Label Distribution

- Benign: 446,772
- DoS attacks-Hulk: 461,912
- DoS attacks-SlowHTTPTest: 139,890

### Invalid Rows by Label

- None

### Non-Positive Duration Rows by Label

- None

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Wednesday-21-02-2018_TrafficForML_CICFlowMeter

- Role: `training`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 1,048,575
- Usable rows: 1,048,575
- Repeated header rows: 0
- Zero-duration rows: 0
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 0

### Label Distribution

- Benign: 360,833
- DDOS attack-HOIC: 686,012
- DDOS attack-LOIC-UDP: 1,730

### Invalid Rows by Label

- None

### Non-Positive Duration Rows by Label

- None

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Thursday-01-03-2018_TrafficForML_CICFlowMeter

- Role: `training`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 331,125
- Usable rows: 331,100
- Repeated header rows: 25
- Zero-duration rows: 2,919
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 2,919

### Label Distribution

- Benign: 238,037
- Infilteration: 93,063

### Invalid Rows by Label

- Benign: 2,259
- Infilteration: 660

### Non-Positive Duration Rows by Label

- Benign: 2,259
- Infilteration: 660

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 2,919
- `bytes_per_second`: 2,919
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## UNSW-NB15 — UNSW_NB15_training-set

- Role: `training`
- Source: `evaluation\datasets\UNSW-NB15\UNSW_NB15_training-set.csv`
- Total rows: 175,341
- Usable rows: 175,341
- Repeated header rows: 0
- Zero-duration rows: 2,657
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 2,657

### Label Distribution

- Analysis: 2,000
- Backdoor: 1,746
- DoS: 12,264
- Exploits: 33,393
- Fuzzers: 18,184
- Generic: 40,000
- Normal: 56,000
- Reconnaissance: 10,491
- Shellcode: 1,133
- Worms: 130

### Invalid Rows by Label

- Analysis: 1
- Backdoor: 1
- DoS: 8
- Exploits: 8
- Fuzzers: 6
- Normal: 2,630
- Reconnaissance: 3

### Non-Positive Duration Rows by Label

- Analysis: 1
- Backdoor: 1
- DoS: 8
- Exploits: 8
- Fuzzers: 6
- Normal: 2,630
- Reconnaissance: 3

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 2,657
- `bytes_per_second`: 2,657
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## CSE-CIC-IDS2018 — Tuesday-20-02-2018_TrafficForML_CICFlowMeter

- Role: `development`
- Source: `evaluation\datasets\CSE-CIC-IDS2018\Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`
- Total rows: 7,948,748
- Usable rows: 7,948,748
- Repeated header rows: 0
- Zero-duration rows: 59,453
- Negative-duration rows: 0
- Missing-duration rows: 0
- Invalid common-feature rows: 59,453

### Label Distribution

- Benign: 7,372,557
- DDoS attacks-LOIC-HTTP: 576,191

### Invalid Rows by Label

- Benign: 59,453

### Non-Positive Duration Rows by Label

- Benign: 59,453

### Missing Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 59,453
- `bytes_per_second`: 59,453
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

### Negative Values by Common Feature

- `flow_duration`: 0
- `fwd_packets`: 0
- `bwd_packets`: 0
- `fwd_bytes`: 0
- `bwd_bytes`: 0
- `total_packets`: 0
- `total_bytes`: 0
- `packets_per_second`: 0
- `bytes_per_second`: 0
- `fwd_mean_packet_bytes`: 0
- `bwd_mean_packet_bytes`: 0

---

## Methodology

- Dataset files are selected from `evaluation/v3_split_manifest.json`.
- Only training and development roles are audited.
- Final and secondary holdouts are excluded from this audit.
- Files are processed in chunks to avoid loading complete datasets into memory at once.
- Missing or undefined rate features are recorded rather than replaced with fabricated values.
- Repeated CSV header rows are counted separately and excluded from usable data.
- No model training or model selection is performed during this audit.
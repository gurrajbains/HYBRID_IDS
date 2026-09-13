# Hybrid IDS Baseline V1

## Overview

Hybrid IDS Baseline V1 combines:

- Custom behavioral detectors
- Suricata signature detection
- Random Forest flow classification
- Unified alert logging
- IDS metrics tracking

This baseline represents the original system before model tuning, expanded training, feature redesign, or algorithm changes that future versions may have modified.

---

## Machine Learning Model

### Model Configuration

Model:

- Random Forest

Training dataset:

- CIC-IDS-2017

Source files:

- `Monday-WorkingHours.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

Features:

- 41 live-compatible CICFlowMeter features

Classes:

- BENIGN
- Bot
- BruteForce
- DDoS
- DoS
- PortScan
- WebAttack

Infiltration was not included as a V1 prediction class because only 36 Infiltration records were available in the prepared CIC-IDS-2017 dataset, and obtaining enough additional compatible data from the full raw dataset was not practical for this version.
### Internal CIC-IDS-2017 Evaluation

- Accuracy: 99.76%
- Macro F1: 96.80%
- Weighted F1: 99.76%

These results represent in-distribution evaluation and are not indicative of cross-dataset generalization.

---

# External Evaluation

## CSE-CIC-IDS2018

The V1 model was frozen before external evaluation and no retraining or model tuning was performed after external results were observed.

### Infiltration

- Detected as any non-BENIGN class: 0.50%
- Attack recall: 0.50%
- Attack F1: 0.97%
- Benign recall: 99.21%

The model showed extremely limited detection of Infiltration traffic in part as Infiltration was not included as a training class in V1, and differences between CIC-IDS-2017 and CSE-CIC-IDS2018 may have also affected the result.

### FTP-BruteForce

- Predicted as BruteForce: 6.84%
- Detected as any non-BENIGN class: 6.84%

### SSH-Bruteforce

- Predicted as BruteForce: 2.10%
- Detected as any non-BENIGN class: 2.10%

### Brute-Force Day Overall

- Attack recall: 4.50%
- Attack F1: 8.06%
- BruteForce precision: 99.92%
- BruteForce recall: 4.50%

The model's BruteForce predictions were highly precise when produced, but most brute-force traffic was classified as BENIGN thus missing most of the brute force traffic .

### DoS GoldenEye

- Predicted as DoS: 30.83%
- Detected as any non-BENIGN class: 30.95%

### DoS Slowloris

- Predicted as DoS: 98.43%
- Detected as any non-BENIGN class: 98.43%

### GoldenEye / Slowloris Day Overall

- Attack recall: 45.07%
- Attack F1: 40.95%
- DoS recall: 44.98%
- DoS F1: 40.96%
- Benign recall: 96.01%

### DoS Hulk

- Predicted as DoS: 13.59%
- Detected as any non-BENIGN class: 13.80%

### DoS SlowHTTPTest

- Predicted as DoS: 0.00%
- Detected as any non-BENIGN class: 9.83%

 Detected SlowHTTPTest traffic was falsely classified as BruteForce instead of DoS.

### Hulk / SlowHTTPTest Day Overall

- Attack recall: 12.88%
- Attack F1: 22.82%
- DoS recall: 10.43%
- DoS F1: 18.89%
- Benign recall: 99.99%

---

# UNSW-NB15 Compatibility

Testing records:

- Total: 82,332
- Normal: 37,000
- Attack: 45,332

Attack families:

- Generic
- Exploits
- Fuzzers
- DoS
- Reconnaissance
- Analysis
- Backdoor
- Shellcode
- Worms

UNSW-NB15 is not directly compatible with the 41 CICFlowMeter features required by V1.

Several required V1 feature groups do not have direct UNSW-NB15 equivalents, including:

- Packet-length distribution statistics
- Several flow IAT statistics
- Directional IAT statistics
- CIC-style TCP flag counts

Because of this, V1 was not tested by filling unavailable features with fake zeros or estimated values. UNSW-NB15 will instead be used later with models that use a compatible feature representation.

---

# Controlled Hybrid IDS Evaluation

PCAP:

- `pcaps/synthetic_attacks.pcap`

Traffic:

- Total packets: 144
- TCP packets: 84
- ICMP packets: 60
- Flows analyzed: 84
- Flows classified: 84

## Controlled Attack Scenarios

Port Scan:

- 12 TCP SYN packets across multiple destination ports

SYN Flood:

- 60 TCP SYN packets

SSH Connection Attempts:

- 12 TCP SYN packets to destination port 22

ICMP Flood:

- 60 ICMP Echo Request packets

## Behavioral Detector Results

| Detector | Expected Alerts | Observed Alerts | Result |
|---|---:|---:|---|
| Port Scan | 1 | 1 | PASS |
| SYN Flood | 1 | 1 | PASS |
| SSH Connection Attempts | 1 | 1 | PASS |
| ICMP Flood | 1 | 1 | PASS |

- Scenarios detected: 4 of 4
- Controlled scenario coverage: 100%

This measures controlled functional coverage and is not real-world detection accuracy.

---

# Suricata Baseline

Suricata version:

- 8.0.6

Rules:

- ET Open

Synthetic PCAP alerts:

- 0

The synthetic traffic was designed around the custom behavioral thresholds rather than known ET Open signatures.

---

# Training and Evaluation Limitations

- V1 was trained only on CIC-IDS-2017. This means the model mainly learned the traffic patterns and feature distributions found in that dataset, which likely contributed to weaker performance on CSE-CIC-IDS2018.

- The CIC-IDS-2017 training data was highly imbalanced. Some attack classes had hundreds of thousands of available records while other classes had only a few thousand.

- Infiltration was excluded from the V1 prediction classes because only 36 Infiltration records were available in the prepared CIC-IDS-2017 dataset. This was not enough to reliably train and evaluate the class as mentioned above.

- Several related attacks were grouped into broader prediction classes. FTP and SSH brute-force traffic were grouped into `BruteForce`, while multiple DoS attack types were grouped into `DoS`.

- The internal CIC-IDS-2017 evaluation uses the same dataset family that was used during training. Because of this, the 99.76% internal accuracy represents in-distribution performance rather than cross-dataset performance.

- The live V1 model uses 41 CICFlowMeter-compatible features because these are the features currently available from the live flow tracker. The original CICFlowMeter dataset contains additional features that are not used by the live model.

- UNSW-NB15 could not be directly evaluated with V1 because its feature structure is different from CICFlowMeter. Missing values were not filled with zeros or estimated values because this would make the evaluation unfair.

- The controlled synthetic PCAP was specifically created to trigger the behavioral detectors. The 100% controlled scenario coverage shows that these detectors work under the controlled conditions, but it does not represent real-world detection accuracy.

- The controlled PCAP also does not provide a meaningful measurement of ML accuracy. The synthetic one-packet flows are very different from the CIC-IDS-2017 flow distributions used to train the model.

- The current Suricata test mainly verifies that Suricata is correctly integrated into the Hybrid IDS pipeline. The synthetic PCAP was not designed around known ET Open signatures, so the result of 0 Suricata alerts does not represent Suricata's overall detection ability.

- V1 does not include a dedicated unknown or zero-day attack class. Traffic that does not match the patterns learned during training may therefore be classified as BENIGN or incorrectly mapped to another known attack class.

---

# V1 Key Findings


- Cross-dataset performance on CSE-CIC-IDS2018 was much lower for several attack families.

- Detection performance changed significantly depending on the specific attack type.

- Slowloris had the strongest cross-dataset result with 98.43% detection.

- Infiltration, FTP brute force, SSH brute force, Hulk,and SlowHTTPTest had much weaker detection.

- High performance on CIC-IDS-2017 did not automatically lead to strong performance on another dataset.


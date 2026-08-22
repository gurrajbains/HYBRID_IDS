# CSE-CIC-IDS2018 External Evaluation
## Wednesday-14-02-2018

Model: Frozen CIC-IDS-2017 41-feature Random Forest

Rows evaluated: 1,044,751

Ground Truth:
- Benign: 663,808
- BruteForce: 380,943

Binary Confusion Matrix:
[[636187, 27621],
 [363787, 17156]]

Binary Metrics:
- Accuracy: 0.6254
- Benign Precision: 0.6362
- Benign Recall: 0.9584
- Benign F1: 0.7647
- Attack Precision: 0.3831
- Attack Recall: 0.0450
- Attack F1: 0.0806

Mapped BruteForce Metrics:
- BruteForce Precision: 0.9992
- BruteForce Recall: 0.0450
- BruteForce F1: 0.0862

Per-Attack Detection:
- FTP-BruteForce detected as BruteForce: 6.8377%
- SSH-Bruteforce detected as BruteForce: 2.0977%

Raw Model Predictions:
- BENIGN: 999,974
- DoS: 27,523
- BruteForce: 17,170
- WebAttack: 75
- PortScan: 9

Interpretation:
The frozen CIC-IDS-2017 model maintained high benign recall but had very low recall for CSE-CIC-IDS2018 brute-force traffic. BruteForce predictions were highly precise when produced, but the model failed to detect most brute-force flows. The result is retained without retraining or tuning.
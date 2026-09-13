# CSE-CIC-IDS2018 External Evaluation
## Thursday-15-02-2018

Model: Frozen CIC-IDS-2017 41-feature Random Forest

Rows evaluated: 1,040,548

Ground Truth:
- Benign: 988,050
- DoS: 52,498

Binary Metrics:
- Accuracy: 0.9344
- Benign Precision: 0.9705
- Benign Recall: 0.9601
- Benign F1: 0.9653
- Attack Precision: 0.3752
- Attack Recall: 0.4507
- Attack F1: 0.4095

Mapped DoS Metrics:
- DoS Precision: 0.3759
- DoS Recall: 0.4498
- DoS F1: 0.4096

Per-Attack Detection:
- GoldenEye predicted specifically as DoS: 30.8326%
- GoldenEye detected as any non-BENIGN: 30.9483%
- Slowloris predicted specifically as DoS: 98.4258%
- Slowloris detected as any non-BENIGN: 98.4258%

Interpretation:
The frozen CIC-IDS-2017 model showed mixed cross-dataset generalization on CSE-CIC-IDS2018 DoS traffic. Slowloris transferred extremely well, while GoldenEye transferred poorly. The result is retained without retraining or tuning.
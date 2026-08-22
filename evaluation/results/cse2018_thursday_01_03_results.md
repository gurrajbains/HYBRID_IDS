# CSE-CIC-IDS2018 External Evaluation
## Thursday-01-03-2018

Model: Frozen CIC-IDS-2017 41-feature Random Forest

Rows after repeated-header removal: 331,100
Invalid rows removed: 2,919
Rows evaluated: 328,181

Ground Truth:
- Benign: 235,778
- Attack: 92,403

Confusion Matrix:
[[233920, 1858],
 [91944, 459]]

Binary Metrics:
- Accuracy: 0.7142
- Benign Precision: 0.7178
- Benign Recall: 0.9921
- Benign F1: 0.8330
- Attack Precision: 0.1981
- Attack Recall: 0.0050
- Attack F1: 0.0097
- Macro F1: 0.4213
- Weighted F1: 0.6012

Infilteration Detection Rate:
- 0.4967%

Raw Predictions:
- BENIGN: 325,864
- DoS: 1,668
- BruteForce: 559
- PortScan: 72
- WebAttack: 18

Interpretation:
The frozen CIC-IDS-2017 model generalized poorly to unseen CSE-CIC-IDS2018 Infilteration traffic while maintaining high recall on benign traffic. This result is retained without retraining or model modification as part of the cross-dataset evaluation.
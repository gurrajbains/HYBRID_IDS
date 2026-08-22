# CSE-CIC-IDS2018 External Evaluation
## Friday-16-02-2018

Model: Frozen CIC-IDS-2017 41-feature Random Forest

Rows evaluated: 1,048,574

Ground Truth:
- Benign: 446,772
- Hulk: 461,912
- SlowHTTPTest: 139,890

Binary Metrics:
- Accuracy: 0.5000
- Benign Precision: 0.4601
- Benign Recall: 0.9999
- Benign F1: 0.6302
- Attack Precision: 0.9996
- Attack Recall: 0.1288
- Attack F1: 0.2282

Mapped DoS Metrics:
- DoS Precision: 0.9999
- DoS Recall: 0.1043
- DoS F1: 0.1889

Per-Attack Detection:
- Hulk predicted specifically as DoS: 13.5903%
- Hulk detected as any non-BENIGN: 13.8009%
- SlowHTTPTest predicted specifically as DoS: 0.0000%
- SlowHTTPTest detected as any non-BENIGN: 9.8327%

SlowHTTPTest Predictions:
- BENIGN: 126,135
- BruteForce: 13,755

Interpretation:
The frozen CIC-IDS-2017 model showed poor transfer to CSE-CIC-IDS2018 Hulk and SlowHTTPTest traffic. Hulk was occasionally recognized as DoS, while SlowHTTPTest was never classified as DoS and was instead sometimes confused with BruteForce. Benign traffic remained almost entirely classified as benign. No retraining or tuning was performed.
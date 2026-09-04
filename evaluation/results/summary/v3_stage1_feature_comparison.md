# Hybrid IDS V3 Stage 1 Feature Comparison

## Methodology

Feature Sets A, B, and C were compared using the same Random Forest configuration.

- Random Forest trees: 200
- Class weighting: balanced_subsample
- Random state: 42
- Training data: V3 Stage 1 sampled cross-dataset training data
- Development data: CSE-CIC-IDS2018 Tuesday-20-02-2018
- Final and secondary holdouts were not used

## Results

| Feature Set | Features | Training Rows | Dev Rows | Removed | Accuracy | Balanced Accuracy | Attack Precision | Attack Recall | Attack F1 | Benign Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 5 | 556,000 | 7,948,748 | 0 | 0.745550 | 0.590918 | 0.123130 | 0.410067 | 0.189392 | 0.771769 | 0.228231 |
| B | 9 | 556,000 | 7,948,748 | 0 | 0.736756 | 0.586165 | 0.118796 | 0.410039 | 0.184220 | 0.762290 | 0.237710 |
| C | 11 | 552,196 | 7,889,295 | 59,453 | 0.749511 | 0.592994 | 0.126096 | 0.409704 | 0.192841 | 0.776284 | 0.223716 |

## Feature Set A

- Features: 5
- Training rows: 556,000
- Training time: 23.95 seconds
- Development rows evaluated: 7,948,748
- Invalid development rows removed: 0
- Accuracy: 0.745550
- Balanced accuracy: 0.590918
- Attack precision: 0.123130
- Attack recall: 0.410067
- Attack F1: 0.189392
- Benign recall: 0.771769
- False-positive rate: 0.228231
- False-negative rate: 0.589933

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 5,689,912
- FP: 1,682,645
- FN: 339,914
- TP: 236,277

## Feature Set B

- Features: 9
- Training rows: 556,000
- Training time: 24.98 seconds
- Development rows evaluated: 7,948,748
- Invalid development rows removed: 0
- Accuracy: 0.736756
- Balanced accuracy: 0.586165
- Attack precision: 0.118796
- Attack recall: 0.410039
- Attack F1: 0.184220
- Benign recall: 0.762290
- False-positive rate: 0.237710
- False-negative rate: 0.589961

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 5,620,027
- FP: 1,752,530
- FN: 339,930
- TP: 236,261

## Feature Set C

- Features: 11
- Training rows: 552,196
- Training time: 35.22 seconds
- Development rows evaluated: 7,889,295
- Invalid development rows removed: 59,453
- Accuracy: 0.749511
- Balanced accuracy: 0.592994
- Attack precision: 0.126096
- Attack recall: 0.409704
- Attack F1: 0.192841
- Benign recall: 0.776284
- False-positive rate: 0.223716
- False-negative rate: 0.590296

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 5,677,044
- FP: 1,636,060
- FN: 340,123
- TP: 236,068

## Selection Note

No feature set should be selected from accuracy alone. Attack recall, attack precision, attack F1, benign recall, false-positive rate, and balanced accuracy must be considered together.
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
| A | 5 | 556,000 | 7,948,748 | 0 | 0.891890 | 0.650691 | 0.300010 | 0.368595 | 0.330785 | 0.932787 | 0.067213 |
| B | 9 | 556,000 | 7,948,748 | 0 | 0.884170 | 0.646475 | 0.276040 | 0.368477 | 0.315630 | 0.924473 | 0.075527 |
| C | 11 | 552,746 | 7,889,295 | 59,453 | 0.894205 | 0.652242 | 0.310947 | 0.368892 | 0.337450 | 0.935593 | 0.064407 |

## Feature Set A

- Features: 5
- Training rows: 556,000
- Training time: 25.45 seconds
- Development rows evaluated: 7,948,748
- Invalid development rows removed: 0
- Accuracy: 0.891890
- Balanced accuracy: 0.650691
- Attack precision: 0.300010
- Attack recall: 0.368595
- Attack F1: 0.330785
- Benign recall: 0.932787
- False-positive rate: 0.067213
- False-negative rate: 0.631405

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,877,025
- FP: 495,532
- FN: 363,810
- TP: 212,381

## Feature Set B

- Features: 9
- Training rows: 556,000
- Training time: 29.89 seconds
- Development rows evaluated: 7,948,748
- Invalid development rows removed: 0
- Accuracy: 0.884170
- Balanced accuracy: 0.646475
- Attack precision: 0.276040
- Attack recall: 0.368477
- Attack F1: 0.315630
- Benign recall: 0.924473
- False-positive rate: 0.075527
- False-negative rate: 0.631523

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,815,732
- FP: 556,825
- FN: 363,878
- TP: 212,313

## Feature Set C

- Features: 11
- Training rows: 552,746
- Training time: 30.24 seconds
- Development rows evaluated: 7,889,295
- Invalid development rows removed: 59,453
- Accuracy: 0.894205
- Balanced accuracy: 0.652242
- Attack precision: 0.310947
- Attack recall: 0.368892
- Attack F1: 0.337450
- Benign recall: 0.935593
- False-positive rate: 0.064407
- False-negative rate: 0.631108

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,842,092
- FP: 471,012
- FN: 363,639
- TP: 212,552

## Selection Note

No feature set should be selected from accuracy alone. Attack recall, attack precision, attack F1, benign recall, false-positive rate, and balanced accuracy must be considered together.
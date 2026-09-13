# Hybrid IDS V3 Stage 1 Algorithm Comparison

## Methodology

Three classifiers were compared using the same V3 Feature Set C training data and the same Tuesday development rows.

- Feature representation: Set C
- Features: 11
- Training rows: 552,746
- Development dataset: CSE-CIC-IDS2018 Tuesday-20-02-2018
- Final and secondary holdout datasets were not used
- Default classifier decision thresholds were used

## Development Coverage

- Evaluated rows: 7,889,295
- Excluded rows: 59,453
- Coverage: 99.2520%

## Results

| Model | Accuracy | Balanced Accuracy | Attack Precision | Attack Recall | Attack F1 | Benign Recall | FPR | ROC AUC | Avg Precision | Train Sec | Rows/Sec |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| random_forest | 0.894205 | 0.652242 | 0.310947 | 0.368892 | 0.337450 | 0.935593 | 0.064407 | 0.893759 | 0.455156 | 36.20 | 159660.22 |
| extra_trees | 0.882623 | 0.645158 | 0.273671 | 0.367073 | 0.313564 | 0.923242 | 0.076758 | 0.855946 | 0.343115 | 28.39 | 94497.88 |
| hist_gradient_boosting | 0.930373 | 0.729161 | 0.524808 | 0.493531 | 0.508689 | 0.964792 | 0.035208 | 0.970540 | 0.616453 | 6.94 | 139123.56 |

## random_forest

- Accuracy: 0.894205
- Balanced accuracy: 0.652242
- Attack precision: 0.310947
- Attack recall: 0.368892
- Attack F1: 0.337450
- Benign recall: 0.935593
- False-positive rate: 0.064407
- ROC AUC: 0.893759
- Average precision: 0.455156
- Training time: 36.20 seconds
- Development inference time: 49.41 seconds
- Development throughput: 159,660.22 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,842,092
- FP: 471,012
- FN: 363,639
- TP: 212,552

## extra_trees

- Accuracy: 0.882623
- Balanced accuracy: 0.645158
- Attack precision: 0.273671
- Attack recall: 0.367073
- Attack F1: 0.313564
- Benign recall: 0.923242
- False-positive rate: 0.076758
- ROC AUC: 0.855946
- Average precision: 0.343115
- Training time: 28.39 seconds
- Development inference time: 83.49 seconds
- Development throughput: 94,497.88 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,751,768
- FP: 561,336
- FN: 364,687
- TP: 211,504

## hist_gradient_boosting

- Accuracy: 0.930373
- Balanced accuracy: 0.729161
- Attack precision: 0.524808
- Attack recall: 0.493531
- Attack F1: 0.508689
- Benign recall: 0.964792
- False-positive rate: 0.035208
- ROC AUC: 0.970540
- Average precision: 0.616453
- Training time: 6.94 seconds
- Development inference time: 56.71 seconds
- Development throughput: 139,123.56 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 7,055,621
- FP: 257,483
- FN: 291,823
- TP: 284,368

## Selection Rule

The selected algorithm should not be chosen from accuracy alone. Attack recall, attack precision, attack F1, benign false-positive behavior, ranking metrics, and inference performance must be considered together.
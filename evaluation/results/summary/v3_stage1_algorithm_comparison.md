# Hybrid IDS V3 Stage 1 Algorithm Comparison

## Methodology

Three classifiers were compared using the same V3 Feature Set C training data and the same Tuesday development rows.

- Feature representation: Set C
- Features: 11
- Training rows: 552,196
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
| random_forest | 0.749511 | 0.592994 | 0.126096 | 0.409704 | 0.192841 | 0.776284 | 0.223716 | 0.727728 | 0.284801 | 32.73 | 81118.18 |
| extra_trees | 0.736735 | 0.585833 | 0.119524 | 0.409118 | 0.185000 | 0.762547 | 0.237453 | 0.748093 | 0.190170 | 26.81 | 57058.59 |
| hist_gradient_boosting | 0.935529 | 0.963033 | 0.531296 | 0.995241 | 0.692768 | 0.930824 | 0.069176 | 0.969850 | 0.638463 | 6.58 | 150376.31 |

## random_forest

- Accuracy: 0.749511
- Balanced accuracy: 0.592994
- Attack precision: 0.126096
- Attack recall: 0.409704
- Attack F1: 0.192841
- Benign recall: 0.776284
- False-positive rate: 0.223716
- ROC AUC: 0.727728
- Average precision: 0.284801
- Training time: 32.73 seconds
- Development inference time: 97.26 seconds
- Development throughput: 81,118.18 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 5,677,044
- FP: 1,636,060
- FN: 340,123
- TP: 236,068

## extra_trees

- Accuracy: 0.736735
- Balanced accuracy: 0.585833
- Attack precision: 0.119524
- Attack recall: 0.409118
- Attack F1: 0.185000
- Benign recall: 0.762547
- False-positive rate: 0.237453
- ROC AUC: 0.748093
- Average precision: 0.190170
- Training time: 26.81 seconds
- Development inference time: 138.27 seconds
- Development throughput: 57,058.59 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 5,576,588
- FP: 1,736,516
- FN: 340,461
- TP: 235,730

## hist_gradient_boosting

- Accuracy: 0.935529
- Balanced accuracy: 0.963033
- Attack precision: 0.531296
- Attack recall: 0.995241
- Attack F1: 0.692768
- Benign recall: 0.930824
- False-positive rate: 0.069176
- ROC AUC: 0.969850
- Average precision: 0.638463
- Training time: 6.58 seconds
- Development inference time: 52.46 seconds
- Development throughput: 150,376.31 rows/sec

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,807,214
- FP: 505,890
- FN: 2,742
- TP: 573,449

## Selection Rule

The selected algorithm should not be chosen from accuracy alone. Attack recall, attack precision, attack F1, benign false-positive behavior, ranking metrics, and inference performance must be considered together.
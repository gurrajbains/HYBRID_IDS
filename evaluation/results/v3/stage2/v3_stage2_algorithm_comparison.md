# Hybrid IDS V3 Stage 2 Algorithm Comparison

This experiment compares candidate classifiers for the V3 Stage 2 attack-family classifier.

Only the four core families with meaningful multi-dataset training support are used.

Exact duplicate Feature Set C vectors are grouped so the same feature signature cannot appear in both the training and internal test partitions.

This remains an internal model-selection experiment and must not be interpreted as final cross-dataset generalization.

## Core families

- BruteForce: 113,832
- DDoS: 200,000
- DoS: 212,256
- Reconnaissance: 110,488

## Split

- Method: StratifiedGroupKFold first fold
- Training rows: 509,127
- Internal test rows: 127,449
- Unique feature signatures: 294,436
- Duplicate rows by feature signature: 342,140
- Train/test signature overlap: 0

## Model comparison

| Model | Accuracy | Balanced Accuracy | Macro F1 | Weighted F1 | Train Time (s) | Inference rows/s |
|---|---:|---:|---:|---:|---:|---:|
| RandomForest | 84.9893% | 88.5589% | 86.1581% | 84.4776% | 26.45 | 223,242 |
| ExtraTrees | 74.4792% | 69.1700% | 64.2581% | 68.0309% | 14.66 | 160,516 |
| HistGradientBoosting | 75.1430% | 69.7105% | 64.6578% | 68.5034% | 12.67 | 101,132 |

## Per-family recall

| Model | BruteForce | DDoS | DoS | Reconnaissance |
|---|---:|---:|---:|---:|
| RandomForest | 99.9956% | 91.7375% | 62.9596% | 99.5429% |
| ExtraTrees | 0.0000% | 92.3700% | 84.7401% | 99.5701% |
| HistGradientBoosting | 0.0000% | 96.0475% | 83.3149% | 99.4796% |

## Internal selection

Selection rule: highest macro F1, then highest balanced accuracy, then lower training time.

Selected candidate: **RandomForest**

This selection applies only to the internal grouped holdout. External development and final holdout results are evaluated separately.

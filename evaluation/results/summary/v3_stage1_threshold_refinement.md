# Hybrid IDS V3 Stage 1 Threshold Selection

## Methodology

The selected HistGradientBoosting Stage 1 classifier was trained once using Feature Set C.

Its attack probabilities were evaluated using a pre-defined threshold grid on the Tuesday development dataset.

Final and secondary holdouts were not used.

## Selection Rule

Choose the threshold with the lowest false-positive rate while preserving at least 95% attack recall.

If multiple thresholds have the same false-positive rate, prefer the one with the highest attack F1.

## Coverage

- Development rows evaluated: 7,889,295
- Rows excluded for undefined Set C features: 59,453
- Attack rows: 576,191
- Benign rows: 7,313,104

## Threshold Results

| Threshold | Accuracy | Balanced Accuracy | Attack Precision | Attack Recall | Attack F1 | Benign Recall | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.650000 | 0.950591 | 0.962260 | 0.599328 | 0.975925 | 0.742610 | 0.948595 | 0.051405 |
| 0.655000 | 0.958705 | 0.962295 | 0.645014 | 0.966499 | 0.773690 | 0.958091 | 0.041909 |
| 0.660000 | 0.958829 | 0.962362 | 0.645746 | 0.966499 | 0.774216 | 0.958225 | 0.041775 |
| 0.665000 | 0.956926 | 0.948131 | 0.639963 | 0.937833 | 0.760781 | 0.958430 | 0.041570 |
| 0.670000 | 0.956340 | 0.943279 | 0.638332 | 0.927984 | 0.756376 | 0.958574 | 0.041426 |
| 0.675000 | 0.956433 | 0.942658 | 0.639171 | 0.926526 | 0.756479 | 0.958790 | 0.041210 |
| 0.680000 | 0.925527 | 0.730220 | 0.490369 | 0.501506 | 0.495875 | 0.958935 | 0.041065 |
| 0.685000 | 0.924211 | 0.720539 | 0.481178 | 0.482028 | 0.481603 | 0.959050 | 0.040950 |
| 0.690000 | 0.925209 | 0.721043 | 0.487830 | 0.481953 | 0.484874 | 0.960133 | 0.039867 |
| 0.695000 | 0.924892 | 0.710289 | 0.484998 | 0.458978 | 0.471629 | 0.961600 | 0.038400 |
| 0.700000 | 0.925036 | 0.710350 | 0.486013 | 0.458940 | 0.472088 | 0.961759 | 0.038241 |

## Selected Threshold

- Threshold: 0.660
- Attack recall: 96.6499%
- Attack precision: 64.5746%
- Attack F1: 77.4216%
- Benign recall: 95.8225%
- False-positive rate: 4.1775%
- Balanced accuracy: 96.2362%

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 7,007,597
- FP: 305,507
- FN: 19,303
- TP: 556,888
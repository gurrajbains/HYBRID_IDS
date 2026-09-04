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
| 0.05 | 0.083371 | 0.505570 | 0.073797 | 0.999990 | 0.137450 | 0.011151 | 0.988849 |
| 0.10 | 0.126566 | 0.528053 | 0.077049 | 0.998218 | 0.143056 | 0.057889 | 0.942111 |
| 0.15 | 0.180104 | 0.556594 | 0.081620 | 0.997485 | 0.150893 | 0.115703 | 0.884297 |
| 0.20 | 0.296746 | 0.619510 | 0.093889 | 0.997485 | 0.171625 | 0.241535 | 0.758465 |
| 0.25 | 0.446824 | 0.700461 | 0.116404 | 0.997485 | 0.208479 | 0.403438 | 0.596562 |
| 0.30 | 0.715502 | 0.845385 | 0.203970 | 0.997485 | 0.338684 | 0.693285 | 0.306715 |
| 0.35 | 0.834353 | 0.909081 | 0.305587 | 0.996591 | 0.467747 | 0.821571 | 0.178429 |
| 0.40 | 0.901984 | 0.945559 | 0.426764 | 0.996588 | 0.597614 | 0.894531 | 0.105469 |
| 0.45 | 0.929260 | 0.959825 | 0.508014 | 0.995618 | 0.672755 | 0.924031 | 0.075969 |
| 0.50 | 0.935529 | 0.963033 | 0.531296 | 0.995241 | 0.692768 | 0.930824 | 0.069176 |
| 0.55 | 0.943335 | 0.961870 | 0.564293 | 0.983575 | 0.717147 | 0.940164 | 0.059836 |
| 0.60 | 0.947303 | 0.961294 | 0.583032 | 0.977678 | 0.730459 | 0.944910 | 0.055090 |
| 0.65 | 0.950591 | 0.962260 | 0.599328 | 0.975925 | 0.742610 | 0.948595 | 0.051405 |
| 0.70 | 0.925036 | 0.710350 | 0.486013 | 0.458940 | 0.472088 | 0.961759 | 0.038241 |
| 0.75 | 0.925564 | 0.694046 | 0.488910 | 0.422926 | 0.453530 | 0.965167 | 0.034833 |
| 0.80 | 0.927019 | 0.685260 | 0.500457 | 0.402146 | 0.445948 | 0.968373 | 0.031627 |
| 0.85 | 0.947386 | 0.684551 | 0.794981 | 0.376757 | 0.511232 | 0.992345 | 0.007655 |
| 0.90 | 0.945886 | 0.665939 | 0.810509 | 0.338107 | 0.477163 | 0.993772 | 0.006228 |
| 0.95 | 0.921999 | 0.497858 | 0.016558 | 0.001165 | 0.002176 | 0.994550 | 0.005450 |

## Selected Threshold

- Threshold: 0.65
- Attack recall: 97.5925%
- Attack precision: 59.9328%
- Attack F1: 74.2610%
- Benign recall: 94.8595%
- False-positive rate: 5.1405%
- Balanced accuracy: 96.2260%

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,937,174
- FP: 375,930
- FN: 13,872
- TP: 562,319
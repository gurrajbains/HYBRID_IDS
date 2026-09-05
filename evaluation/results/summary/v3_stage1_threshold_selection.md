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
| 0.050000 | 0.545514 | 0.754195 | 0.138306 | 0.998572 | 0.242960 | 0.509818 | 0.490182 |
| 0.100000 | 0.851738 | 0.916100 | 0.329068 | 0.991470 | 0.494134 | 0.840729 | 0.159271 |
| 0.150000 | 0.912006 | 0.943976 | 0.452754 | 0.981414 | 0.619647 | 0.906537 | 0.093463 |
| 0.200000 | 0.928695 | 0.943697 | 0.506234 | 0.961266 | 0.663203 | 0.926128 | 0.073872 |
| 0.250000 | 0.940254 | 0.945760 | 0.552817 | 0.952209 | 0.699519 | 0.939312 | 0.060688 |
| 0.300000 | 0.945847 | 0.937843 | 0.580872 | 0.928470 | 0.714645 | 0.947216 | 0.052784 |
| 0.350000 | 0.950011 | 0.939450 | 0.602542 | 0.927083 | 0.730384 | 0.951818 | 0.048182 |
| 0.400000 | 0.952919 | 0.934258 | 0.620915 | 0.912404 | 0.738953 | 0.956111 | 0.043889 |
| 0.450000 | 0.942122 | 0.814307 | 0.592499 | 0.664629 | 0.626495 | 0.963985 | 0.036015 |
| 0.500000 | 0.930373 | 0.729161 | 0.524808 | 0.493531 | 0.508689 | 0.964792 | 0.035208 |
| 0.550000 | 0.930102 | 0.715249 | 0.524280 | 0.463645 | 0.492102 | 0.966853 | 0.033147 |
| 0.600000 | 0.929479 | 0.696644 | 0.521152 | 0.423981 | 0.467571 | 0.969307 | 0.030693 |
| 0.650000 | 0.943991 | 0.703331 | 0.691114 | 0.421504 | 0.523643 | 0.985157 | 0.014843 |
| 0.700000 | 0.944877 | 0.693793 | 0.721240 | 0.399760 | 0.514403 | 0.987827 | 0.012173 |
| 0.750000 | 0.946111 | 0.691310 | 0.750272 | 0.392924 | 0.515746 | 0.989696 | 0.010304 |
| 0.800000 | 0.946776 | 0.691616 | 0.763676 | 0.392809 | 0.518777 | 0.990423 | 0.009577 |
| 0.850000 | 0.927456 | 0.555611 | 0.514384 | 0.120160 | 0.194812 | 0.991062 | 0.008938 |
| 0.900000 | 0.919993 | 0.499538 | 0.065235 | 0.007163 | 0.012908 | 0.991914 | 0.008086 |
| 0.950000 | 0.921753 | 0.498424 | 0.034947 | 0.002681 | 0.004981 | 0.994166 | 0.005834 |

## Selected Threshold

- Threshold: 0.250
- Attack recall: 95.2209%
- Attack precision: 55.2817%
- Attack F1: 69.9519%
- Benign recall: 93.9312%
- False-positive rate: 6.0688%
- Balanced accuracy: 94.5760%

Confusion matrix [[TN, FP], [FN, TP]]:

- TN: 6,869,289
- FP: 443,815
- FN: 27,537
- TP: 548,654
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
| 0.250000 | 0.940254 | 0.945760 | 0.552817 | 0.952209 | 0.699519 | 0.939312 | 0.060688 |
| 0.255000 | 0.939763 | 0.938344 | 0.551591 | 0.936682 | 0.694316 | 0.940005 | 0.059995 |
| 0.260000 | 0.939679 | 0.936335 | 0.551478 | 0.932420 | 0.693052 | 0.940251 | 0.059749 |
| 0.265000 | 0.940358 | 0.936702 | 0.554526 | 0.932420 | 0.695454 | 0.940983 | 0.059017 |
| 0.270000 | 0.941036 | 0.937068 | 0.557608 | 0.932420 | 0.697873 | 0.941715 | 0.058285 |
| 0.275000 | 0.941288 | 0.935385 | 0.559039 | 0.928472 | 0.697880 | 0.942298 | 0.057702 |
| 0.280000 | 0.941420 | 0.935456 | 0.559649 | 0.928472 | 0.698355 | 0.942441 | 0.057559 |
| 0.285000 | 0.945015 | 0.937395 | 0.576759 | 0.928472 | 0.711524 | 0.946318 | 0.053682 |
| 0.290000 | 0.945390 | 0.937597 | 0.578606 | 0.928472 | 0.712929 | 0.946723 | 0.053277 |
| 0.295000 | 0.945512 | 0.937662 | 0.579210 | 0.928470 | 0.713386 | 0.946855 | 0.053145 |
| 0.300000 | 0.945847 | 0.937843 | 0.580872 | 0.928470 | 0.714645 | 0.947216 | 0.052784 |

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
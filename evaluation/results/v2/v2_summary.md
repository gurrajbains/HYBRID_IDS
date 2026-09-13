# Hybrid IDS V2 Candidate Comparison

## Purpose

V2 focused on improving the Random Forest model while keeping the same CIC-IDS-2017 training dataset and the same 41 live-compatible features used in V1.

No new training datasets were added during V2. This was intentional so that changes in performance could be attributed mainly to changes in the Random Forest configuration rather than changes in the dataset.

Five different V2 candidates were tested:

- V2-A
- V2-B
- V2-C
- V2-D
- V2-E

Each candidate used the same overall training setup but different Random Forest parameters.

The main goal was to compare internal CIC-IDS-2017 performance with external CSE-CIC-IDS2018 performance and determine whether Random Forest tuning alone could improve cross-dataset generalization.

---

# V1 Baseline

V1 used the original Random Forest configuration and served as the baseline for all V2 comparisons.

## V1 Parameters

- Trees: 100
- Class Weight: balanced_subsample
- Random State: 42
- n_jobs: -1
- Max Depth: default/unlimited
- Minimum Samples Split: default
- Minimum Samples Leaf: default
- Max Features: default

## Internal Results on CIC-IDS-2017

- Accuracy: 99.7600%
- Macro F1: 96.7980%
- Weighted F1: 99.7613%
- Bot Recall: 84.40%
- WebAttack Recall: 97.25%

V1 performed extremely well internally, with an accuracy of 99.7600% and a Macro F1 score of 96.7980%.

However, external testing showed that this performance did not transfer equally well to CSE-CIC-IDS2018 traffic.

External V1 results included:

- Brute-force Attack Recall: 4.50%
- FTP-BruteForce Detection: 6.84%
- SSH-Bruteforce Detection: 2.10%
- GoldenEye Detection: 30.95%
- Slowloris Detection: 98.43%
- Hulk Detection: 13.80%
- SlowHTTPTest Detection: 9.83%

This showed that strong same-dataset performance did not automatically result in strong cross-dataset generalization.

---

# V2-A

## Parameters

- Trees: 300
- Max Depth: 30
- Minimum Samples Split: 4
- Minimum Samples Leaf: 1
- Max Features: sqrt
- Class Weight: balanced_subsample
- Bootstrap: True
- Random State: 42
- n_jobs: -1

## Internal Results

- Accuracy: 99.7461%
- Macro F1: 96.7309%
- Weighted F1: 99.7498%
- Bot Recall: 89.0026%
- Bot F1: 81.4035%
- WebAttack Recall: 97.0183%

Compared with V1:

- Accuracy decreased from 99.7600% to 99.7461%.
- This was a decrease of 0.0139 percentage points.
- Macro F1 decreased from 96.7980% to 96.7309%.
- Bot Recall increased from 84.40% to 89.0026%.
- Bot Recall improved by approximately 4.60 percentage points.

## External Results on CSE-CIC-IDS2018

- Brute-force Attack Recall: 4.29%
- FTP-BruteForce Detection: 6.4079%
- SSH-Bruteforce Detection: 2.1003%
- GoldenEye Detection: 31.1627%
- Slowloris Detection: 98.4895%
- Hulk Detection: 13.9358%
- SlowHTTPTest Detection: 10.0908%

Compared with V1:

- Brute-force Recall decreased from 4.50% to 4.29%.
- FTP-BruteForce Detection decreased from 6.84% to 6.4079%.
- SSH-Bruteforce Detection remained almost unchanged at approximately 2.10%.
- GoldenEye Detection increased from 30.95% to 31.1627%.
- Slowloris Detection increased from 98.43% to 98.4895%.
- Hulk Detection increased from 13.80% to 13.9358%.
- SlowHTTPTest Detection increased from 9.83% to 10.0908%.

## Observation

V2-A improved Bot recall substantially while leaving overall internal performance almost unchanged.

Bot Recall increased from 84.40% in V1 to 89.0026% in V2-A.

The model also produced small improvements on several DoS-related attacks during external evaluation.

However, brute-force generalization did not improve. Brute-force Attack Recall decreased from 4.50% to 4.29%, and FTP-BruteForce Detection decreased from 6.84% to 6.4079%.

V2-A showed that regularizing the Random Forest could improve minority-class sensitivity without causing a major decrease in overall internal accuracy.

---

# V2-B

## Parameters

- Trees: 400
- Max Depth: 35
- Minimum Samples Split: 3
- Minimum Samples Leaf: 1
- Max Features: sqrt
- Class Weight: balanced_subsample
- Bootstrap: True
- Random State: 42
- n_jobs: -1

## Internal Results

- Accuracy: 99.7511%
- Macro F1: 96.7730%
- Weighted F1: 99.7535%
- Bot Recall: 86.7008%
- Bot F1: 81.6867%
- WebAttack Recall: 97.0183%

Compared with V1:

- Accuracy decreased from 99.7600% to 99.7511%.
- Macro F1 decreased from 96.7980% to 96.7730%.
- Bot Recall increased from 84.40% to 86.7008%.
- Bot Recall improved by approximately 2.30 percentage points.

Compared with V2-A:

- Accuracy increased from 99.7461% to 99.7511%.
- Macro F1 increased from 96.7309% to 96.7730%.
- Bot Recall decreased from 89.0026% to 86.7008%.

## External Results on CSE-CIC-IDS2018

- Brute-force Attack Recall: 2.06%
- FTP-BruteForce Detection: 1.9813%
- SSH-Bruteforce Detection: 2.1345%
- GoldenEye Detection: 31.1482%
- Slowloris Detection: 98.4804%
- Hulk Detection: 13.6422%
- SlowHTTPTest Detection: 7.8812%

Compared with V1:

- Brute-force Recall dropped from 4.50% to 2.06%.
- FTP-BruteForce Detection dropped from 6.84% to 1.9813%.
- SSH-Bruteforce Detection remained close to the V1 result at 2.1345%.
- GoldenEye Detection increased slightly from 30.95% to 31.1482%.
- Slowloris Detection remained similar at 98.4804%.
- Hulk Detection decreased from 13.80% to 13.6422%.
- SlowHTTPTest Detection dropped from 9.83% to 7.8812%.

## Observation

V2-B had slightly stronger internal results than V2-A.

Accuracy increased from 99.7461% in V2-A to 99.7511% in V2-B, while Macro F1 increased from 96.7309% to 96.7730%.

However, external generalization became worse.

Brute-force Recall fell to 2.06%, compared with 4.50% in V1 and 4.29% in V2-A.

FTP-BruteForce Detection fell to 1.9813%, compared with 6.84% in V1.

SlowHTTPTest Detection also fell to 7.8812%, compared with 9.83% in V1.

This candidate demonstrated that slightly stronger internal metrics did not necessarily translate into stronger cross-dataset performance.

---

# V2-C

## Parameters

- Trees: 350
- Max Depth: 20
- Minimum Samples Split: 6
- Minimum Samples Leaf: 2
- Max Features: sqrt
- Class Weight: balanced_subsample
- Bootstrap: True
- Random State: 42
- n_jobs: -1

## Internal Results

- Accuracy: 99.5117%
- Macro F1: 93.0480%
- Weighted F1: 99.5817%
- Bot Recall: 98.2097%
- Bot Precision: 39.38%
- Bot F1: 56.2225%
- WebAttack Recall: 97.7064%

Compared with V1:

- Accuracy decreased from 99.7600% to 99.5117%.
- Macro F1 decreased from 96.7980% to 93.0480%.
- Bot Recall increased from 84.40% to 98.2097%.
- Bot Recall improved by approximately 13.81 percentage points.
- Bot Precision was only 39.38%.
- Bot F1 fell to 56.2225%.

The internal confusion matrix showed:

- 591 BENIGN samples were incorrectly classified as Bot.
- 7 Bot samples were classified as BENIGN.
- 384 of 391 Bot samples were correctly detected.

## External Results on CSE-CIC-IDS2018

- Brute-force Attack Recall: 7.25%
- FTP-BruteForce Detection: 10.6571%
- SSH-Bruteforce Detection: 3.7476%
- GoldenEye Detection: 33.0442%
- Slowloris Detection: 98.3894%
- Hulk Detection: 13.9864%
- SlowHTTPTest Detection: 10.9350%

Compared with V1:

- Brute-force Recall increased from 4.50% to 7.25%.
- FTP-BruteForce Detection increased from 6.84% to 10.6571%.
- SSH-Bruteforce Detection increased from 2.10% to 3.7476%.
- GoldenEye Detection increased from 30.95% to 33.0442%.
- Slowloris Detection changed slightly from 98.43% to 98.3894%.
- Hulk Detection increased from 13.80% to 13.9864%.
- SlowHTTPTest Detection increased from 9.83% to 10.9350%.

## Observation

V2-C produced a major increase in minority-class sensitivity.

Bot Recall reached 98.2097%, compared with 84.40% in V1.

However, Bot Precision dropped to 39.38%.

The model detected 384 of the 391 Bot samples, but it also incorrectly classified 591 BENIGN samples as Bot.

Because of this, Bot F1 dropped to 56.2225% and overall Macro F1 dropped from 96.7980% in V1 to 93.0480%.

Despite weaker internal balance, V2-C generalized better than V2-A and V2-B across several external attack types.

For example:

- Brute-force Recall increased to 7.25%.
- FTP-BruteForce Detection increased to 10.6571%.
- SSH-Bruteforce Detection increased to 3.7476%.
- GoldenEye Detection increased to 33.0442%.

This showed that lower internal performance could still correspond to stronger external attack detection.

---

# V2-D

## Parameters

- Trees: 400
- Max Depth: 24
- Minimum Samples Split: 5
- Minimum Samples Leaf: 1
- Max Features: sqrt
- Class Weight: balanced_subsample
- Bootstrap: True
- Random State: 42
- n_jobs: -1

## Internal Results

- Accuracy: 99.7288%
- Macro F1: 96.4132%
- Weighted F1: 99.7371%
- Bot Recall: 94.1176%
- Bot Precision: 68.40%
- Bot F1: 79.2250%
- WebAttack Recall: 97.0183%

Compared with V2-C:

- Accuracy increased from 99.5117% to 99.7288%.
- Macro F1 increased from 93.0480% to 96.4132%.
- Bot Recall decreased from 98.2097% to 94.1176%.
- Bot Precision increased from 39.38% to 68.40%.
- Bot F1 increased from 56.2225% to 79.2250%.

Compared with V1:

- Bot Recall increased from 84.40% to 94.1176%.
- This was an increase of approximately 9.72 percentage points.

## External Results on CSE-CIC-IDS2018

- Brute-force Attack Recall: 6.45%
- FTP-BruteForce Detection: 10.6571%
- SSH-Bruteforce Detection: 2.1094%
- GoldenEye Detection: 31.5530%
- Slowloris Detection: 98.3894%
- Hulk Detection: 13.7704%
- SlowHTTPTest Detection: 10.9350%

Compared with V1:

- Brute-force Recall improved from 4.50% to 6.45%.
- FTP-BruteForce Detection improved from 6.84% to 10.6571%.
- SSH-Bruteforce Detection remained close to V1 at 2.1094%.
- GoldenEye Detection improved from 30.95% to 31.5530%.
- SlowHTTPTest Detection improved from 9.83% to 10.9350%.

## Observation

V2-D was designed as a middle ground between the more conservative V2-A configuration and the more aggressive V2-C configuration.

It retained a high Bot Recall of 94.1176% while improving Bot Precision to 68.40%.

This was a major improvement over V2-C, where Bot Precision was only 39.38%.

Bot F1 also improved from 56.2225% in V2-C to 79.2250% in V2-D.

External performance remained stronger than V1 in several areas, although V2-D did not match V2-C on every attack.

V2-D therefore represented a better internal balance while still maintaining some cross-dataset improvements.

---

# V2-E

## Parameters

- Trees: 500
- Max Depth: 22
- Minimum Samples Split: 5
- Minimum Samples Leaf: 1
- Max Features: 0.5
- Class Weight: balanced_subsample
- Bootstrap: True
- Random State: 42
- n_jobs: -1

The major parameter change in V2-E was:

`max_features = 0.5`

With 41 total live-compatible features, approximately half of the feature set could be considered at each split.

Using `sqrt` with 41 features allows approximately 6 features to be considered at each split.

V2-E therefore allowed each tree split to consider significantly more of the available feature information.

## Internal Results

- Accuracy: 99.7288%
- Macro F1: 96.5078%
- Weighted F1: 99.7381%
- Bot Recall: 96.4194%
- Bot Precision: 67.68%
- Bot F1: 79.5359%
- WebAttack Recall: 97.7064%

## Per-Class Recall

- BENIGN: 99.3100%
- Bot: 96.4194%
- BruteForce: 99.7832%
- DDoS: 99.9766%
- DoS: 99.8160%
- PortScan: 99.9740%
- WebAttack: 97.7064%

## Performance

- Training Time: 360.78 seconds
- Inference Time: 1.22 seconds
- Inference Samples: 179,199

Compared with V1:

- Accuracy decreased from 99.7600% to 99.7288%.
- This was a decrease of 0.0312 percentage points.
- Macro F1 decreased from 96.7980% to 96.5078%.
- Bot Recall increased from 84.40% to 96.4194%.
- Bot Recall improved by approximately 12.02 percentage points.
- WebAttack Recall increased from 97.25% to 97.7064%.

---

## External Brute-Force Evaluation

The CSE-CIC-IDS2018 brute-force evaluation contained:

- 663,808 valid BENIGN samples
- 380,943 valid attack samples
- 1,044,751 total evaluated samples

The attack traffic consisted of:

- FTP-BruteForce
- SSH-Bruteforce

### Binary Confusion Matrix

```text
[[631430  32378]
 [226497 154446]]
```

The confusion matrix represents:

- 631,430 benign samples correctly classified as BENIGN
- 32,378 benign samples classified as attacks
- 226,497 attack samples classified as BENIGN
- 154,446 attack samples detected as attacks

### Binary Results

- BENIGN Precision: 73.60%
- BENIGN Recall: 95.12%
- BENIGN F1: 82.99%
- ATTACK Precision: 82.67%
- ATTACK Recall: 40.54%
- ATTACK F1: 54.40%
- Accuracy: 75.22%
- Macro F1: 68.70%
- Weighted F1: 72.57%

### Mapped BruteForce Results

The external labels were mapped as:

- Benign -> BENIGN
- FTP-BruteForce -> BruteForce
- SSH-Bruteforce -> BruteForce

Mapped BruteForce results:

- BruteForce Precision: 99.96%
- BruteForce Recall: 40.54%
- BruteForce F1: 57.69%

### Per-Attack Detection

FTP-BruteForce:

- Total samples: 193,354
- Predicted as BENIGN: 170,204
- Predicted as BruteForce: 23,150
- Specific BruteForce Detection: 11.9729%
- Any-Attack Detection: 11.9729%

SSH-Bruteforce:

- Total samples: 187,589
- Predicted as BENIGN: 56,293
- Predicted as BruteForce: 131,296
- Specific BruteForce Detection: 69.9913%
- Any-Attack Detection: 69.9913%

### Compared with V1

- Brute-force Attack Recall increased from 4.50% to 40.54%.
- This was an improvement of approximately 36.04 percentage points.
- FTP-BruteForce Detection increased from 6.84% to 11.9729%.
- This was an improvement of approximately 5.13 percentage points.
- SSH-Bruteforce Detection increased from 2.10% to 69.9913%.
- This was an improvement of approximately 67.89 percentage points.

V2-E detected 154,446 of the 380,943 attack samples as attacks.

However, 32,378 of the 663,808 benign samples were also classified as attacks.

---

## External GoldenEye and Slowloris Evaluation

The evaluation contained:

- 988,050 valid BENIGN samples
- 52,498 valid attack samples
- 1,040,548 total evaluated samples

The attacks consisted of:

- DoS attacks-GoldenEye
- DoS attacks-Slowloris

### Binary Confusion Matrix

```text
[[941284  46766]
 [ 26002  26496]]
```

The confusion matrix represents:

- 941,284 benign samples correctly classified as BENIGN
- 46,766 benign samples classified as attacks
- 26,002 attack samples classified as BENIGN
- 26,496 attack samples detected as attacks

### Binary Results

- BENIGN Precision: 97.31%
- BENIGN Recall: 95.27%
- BENIGN F1: 96.28%
- ATTACK Precision: 36.17%
- ATTACK Recall: 50.47%
- ATTACK F1: 42.14%
- Accuracy: 93.01%
- Macro F1: 69.21%
- Weighted F1: 93.55%

### Mapped DoS Results

The external labels were mapped to DoS.

Mapped results:

- DoS Precision: 36.87%
- DoS Recall: 48.52%
- DoS F1: 41.90%

### GoldenEye

GoldenEye predictions:

- BENIGN: 25,896
- DoS: 14,588
- WebAttack: 1,024

Results:

- Specifically predicted as DoS: 35.1450%
- Detected as any non-BENIGN class: 37.6120%

Compared with V1:

- V1 GoldenEye Detection: 30.95%
- V2-E GoldenEye Detection: 37.6120%
- Improvement: approximately 6.66 percentage points

### Slowloris

Slowloris predictions:

- DoS: 10,884
- BENIGN: 106

Results:

- Specifically predicted as DoS: 99.0355%
- Detected as any non-BENIGN class: 99.0355%

Compared with V1:

- V1 Slowloris Detection: 98.43%
- V2-E Slowloris Detection: 99.0355%
- Improvement: approximately 0.61 percentage points

---

## External Hulk and SlowHTTPTest Evaluation

The evaluation contained:

- 446,772 BENIGN samples
- 601,802 attack samples
- 1,048,574 total evaluated samples

The attack traffic consisted of:

- DoS attacks-Hulk
- DoS attacks-SlowHTTPTest

### Binary Confusion Matrix

```text
[[446664    108]
 [519969  81833]]
```

The confusion matrix represents:

- 446,664 benign samples correctly classified as BENIGN
- 108 benign samples classified as attacks
- 519,969 attack samples classified as BENIGN
- 81,833 attack samples detected as attacks

### Binary Results

- BENIGN Precision: 46.21%
- BENIGN Recall: 99.98%
- BENIGN F1: 63.20%
- ATTACK Precision: 99.87%
- ATTACK Recall: 13.60%
- ATTACK F1: 23.94%
- Accuracy: 50.40%
- Macro F1: 43.57%
- Weighted F1: 40.67%

### Mapped DoS Results

The attack labels were mapped as:

- Hulk -> DoS
- SlowHTTPTest -> DoS

Mapped DoS results:

- DoS Precision: 100.00%
- DoS Recall: 10.54%
- DoS F1: 19.07%

### Hulk

Hulk predictions:

- BENIGN: 397,306
- DoS: 63,437
- WebAttack: 1,169

Results:

- Specifically predicted as DoS: 13.7336%
- Detected as any non-BENIGN class: 13.9866%

Compared with V1:

- V1 Hulk Detection: 13.80%
- V2-E Hulk Detection: 13.9866%
- Improvement: approximately 0.19 percentage points

### SlowHTTPTest

SlowHTTPTest predictions:

- BENIGN: 122,663
- BruteForce: 17,227

Results:

- Specifically predicted as DoS: 0.00%
- Detected as any non-BENIGN class: 12.3147%

Compared with V1:

- V1 SlowHTTPTest Detection: 9.83%
- V2-E SlowHTTPTest Detection: 12.3147%
- Improvement: approximately 2.48 percentage points

---

# V2-E Observation

V2-E produced the strongest overall external development performance of the five V2 candidates.

The largest improvement occurred on SSH-Bruteforce traffic.

SSH-Bruteforce Detection across versions was:

- V1: 2.10%
- V2-A: 2.1003%
- V2-B: 2.1345%
- V2-C: 3.7476%
- V2-D: 2.1094%
- V2-E: 69.9913%

Overall Brute-force Attack Recall increased:

- V1: 4.50%
- V2-E: 40.54%

This was an improvement of approximately 36.04 percentage points.

V2-E also increased:

- Bot Recall from 84.40% to 96.4194%
- FTP-BruteForce Detection from 6.84% to 11.9729%
- GoldenEye Detection from 30.95% to 37.6120%
- Slowloris Detection from 98.43% to 99.0355%
- Hulk Detection from 13.80% to 13.9866%
- SlowHTTPTest Detection from 9.83% to 12.3147%

The model did have tradeoffs.

Bot Precision was 67.68%, while Bot Recall was 96.4194%.

The external brute-force evaluation also produced 32,378 false-positive attack classifications among 663,808 benign samples.

Despite these tradeoffs, V2-E produced the strongest overall combination of internal performance and external development performance.

---

# Candidate Comparison

| Metric | V1 | V2-A | V2-B | V2-C | V2-D | V2-E |
|---|---:|---:|---:|---:|---:|---:|
| Accuracy | 99.7600% | 99.7461% | 99.7511% | 99.5117% | 99.7288% | 99.7288% |
| Macro F1 | 96.7980% | 96.7309% | 96.7730% | 93.0480% | 96.4132% | 96.5078% |
| Bot Recall | 84.40% | 89.00% | 86.70% | 98.21% | 94.12% | 96.42% |
| Brute-force External Recall | 4.50% | 4.29% | 2.06% | 7.25% | 6.45% | 40.54% |
| FTP-BruteForce Detection | 6.84% | 6.41% | 1.98% | 10.66% | 10.66% | 11.97% |
| SSH-Bruteforce Detection | 2.10% | 2.10% | 2.13% | 3.75% | 2.11% | 69.99% |
| GoldenEye Detection | 30.95% | 31.16% | 31.15% | 33.04% | 31.55% | 37.61% |
| Slowloris Detection | 98.43% | 98.49% | 98.48% | 98.39% | 98.39% | 99.04% |
| Hulk Detection | 13.80% | 13.94% | 13.64% | 13.99% | 13.77% | 13.99% |
| SlowHTTPTest Detection | 9.83% | 10.09% | 7.88% | 10.94% | 10.94% | 12.31% |

---

# Selected V2

V2-E was selected as the official V2 model.

## Selected Parameters

```python
{
    "n_estimators": 500,
    "max_depth": 22,
    "min_samples_split": 5,
    "min_samples_leaf": 1,
    "max_features": 0.5,
    "class_weight": "balanced_subsample",
    "bootstrap": True,
    "random_state": 42,
    "n_jobs": -1
}
```

## Selection Reason

V2-E was selected because it produced the strongest overall balance between internal CIC-IDS-2017 performance and external CSE-CIC-IDS2018 development performance.

It did not have the single highest internal accuracy.

Internal accuracy across the models was:

- V1: 99.7600%
- V2-A: 99.7461%
- V2-B: 99.7511%
- V2-C: 99.5117%
- V2-D: 99.7288%
- V2-E: 99.7288%

The internal accuracy differences were relatively small compared with the differences seen during external evaluation.

Brute-force Attack Recall was:

- V1: 4.50%
- V2-A: 4.29%
- V2-B: 2.06%
- V2-C: 7.25%
- V2-D: 6.45%
- V2-E: 40.54%

SSH-Bruteforce Detection was:

- V1: 2.10%
- V2-A: 2.10%
- V2-B: 2.13%
- V2-C: 3.75%
- V2-D: 2.11%
- V2-E: 69.99%

V2-E also maintained a Bot Recall of 96.4194%, compared with 84.40% in V1.

Because of this overall balance, V2-E was selected as the official V2 candidate.

The official V2 model files are:

- `models/random_forest_live_v2.joblib`
- `models/live_feature_names_v2.json`
- `models/live_model_metrics_v2.json`

The original V2-E candidate artifacts were also preserved separately.

---

# Development Evaluation Methodology

The CSE-CIC-IDS2018 datasets containing the following attacks were used repeatedly while comparing V2-A through V2-E:

- FTP-BruteForce
- SSH-Bruteforce
- GoldenEye
- Slowloris
- Hulk
- SlowHTTPTest

Because these results influenced candidate selection, they are considered external development or validation results.

They are not treated as untouched final external test results.

After V2-E was selected, the model was frozen.

A previously unused CSE-CIC-IDS2018 day was then selected for a fresh external evaluation.

No V2 parameters were changed after examining the fresh dataset.

---

# Fresh External Evaluation

The fresh external dataset was:

`Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`

This dataset had not been used during V2-A through V2-E candidate selection.

## Dataset Distribution

- DDOS attack-HOIC: 686,012
- DDOS attack-LOIC-UDP: 1,730
- Benign: 360,833
- Total Rows: 1,048,575
- Invalid Feature Rows: 0
- Rows Evaluated: 1,048,575

Total attack samples:

- 687,742

Total benign samples:

- 360,833

The frozen model used for this evaluation was:

`models/random_forest_live_v2.joblib`

No retraining was performed using this dataset.

---

# Fresh Binary External Results

Binary interpretation:

- BENIGN = benign traffic
- ATTACK = any non-BENIGN model prediction

## Confusion Matrix

```text
[[360776     57]
 [628660  59082]]
```

This represents:

- True Benign: 360,776
- False Attack Alerts on Benign Traffic: 57
- Missed Attacks: 628,660
- Detected Attacks: 59,082

## BENIGN Results

- Precision: 36.46%
- Recall: 99.98%
- F1: 53.44%
- Support: 360,833

## ATTACK Results

- Precision: 99.90%
- Recall: 8.59%
- F1: 15.82%
- Support: 687,742

## Overall Results

- Accuracy: 40.04%
- Macro F1: 34.63%

The model produced very few false-positive attack classifications against benign traffic.

Only 57 of 360,833 benign flows were predicted as an attack class.

However, the model had a major false-negative problem.

Out of 687,742 attacks:

- 59,082 were detected as some type of attack.
- 628,660 were incorrectly classified as BENIGN.

This resulted in an Attack Recall of only 8.59%.

---

# Fresh DDoS Classification Results

Both external attack labels were mapped to the V2 `DDoS` class:

- DDOS attack-HOIC -> DDoS
- DDOS attack-LOIC-UDP -> DDoS

## Mapped Confusion Matrix

```text
[[360776      0]
 [628660      0]]
```

## Specific DDoS Results

- DDoS Precision: 0.00%
- DDoS Recall: 0.00%
- DDoS F1: 0.00%

The frozen V2 model did not produce a single `DDoS` prediction on the fresh dataset.

Out of 687,742 actual DDoS attack flows:

- 0 were classified specifically as DDoS.

---

# Fresh Raw Prediction Distribution

The frozen V2 model produced:

- BENIGN: 989,436
- DoS: 58,983
- WebAttack: 100
- BruteForce: 42
- PortScan: 14
- DDoS: 0

The majority of traffic was classified as BENIGN.

The largest non-benign prediction class was DoS with 58,983 predictions.

The model produced 0 DDoS predictions.

This suggests that some of the fresh attack traffic had characteristics closer to patterns learned for the CIC-IDS-2017 DoS class than to the patterns learned for the CIC-IDS-2017 DDoS class.

However, most attack traffic was still classified as benign.

---

# HOIC Results

Total HOIC samples:

- 686,012

## Prediction Distribution

- BENIGN: 626,930
- DoS: 58,982
- WebAttack: 100
- DDoS: 0

## Detection Results

- Specific DDoS Detection: 0.00%
- Any-Attack Detection: 8.6124%

Out of 686,012 HOIC attack flows:

- 626,930 were classified as BENIGN.
- 58,982 were classified as DoS.
- 100 were classified as WebAttack.
- 0 were classified as DDoS.

A total of 59,082 HOIC flows were detected as some type of attack.

A total of 626,930 HOIC flows were missed.

---

# LOIC-UDP Results

Total LOIC-UDP samples:

- 1,730

## Prediction Distribution

- BENIGN: 1,730
- DDoS: 0

## Detection Results

- Specific DDoS Detection: 0.00%
- Any-Attack Detection: 0.00%

Every LOIC-UDP flow was classified as BENIGN.

The model therefore missed all 1,730 LOIC-UDP attack flows.

---

# V2 Main Findings

The V2 experiments showed that Random Forest tuning could significantly change cross-dataset behavior even when the training dataset remained unchanged.

V2-E produced major improvements over V1 on several development metrics.

## Bot Recall

- V1: 84.40%
- V2-E: 96.4194%
- Improvement: approximately 12.02 percentage points

## Brute-force External Recall

- V1: 4.50%
- V2-E: 40.54%
- Improvement: approximately 36.04 percentage points

## SSH-Bruteforce Detection

- V1: 2.10%
- V2-E: 69.9913%
- Improvement: approximately 67.89 percentage points

## FTP-BruteForce Detection

- V1: 6.84%
- V2-E: 11.9729%
- Improvement: approximately 5.13 percentage points

## GoldenEye Detection

- V1: 30.95%
- V2-E: 37.6120%
- Improvement: approximately 6.66 percentage points

## Slowloris Detection

- V1: 98.43%
- V2-E: 99.0355%
- Improvement: approximately 0.61 percentage points

## Hulk Detection

- V1: 13.80%
- V2-E: 13.9866%
- Improvement: approximately 0.19 percentage points

## SlowHTTPTest Detection

- V1: 9.83%
- V2-E: 12.3147%
- Improvement: approximately 2.48 percentage points

These development results showed that V2-E was more effective than V1 against several attack types.

However, the fresh external DDoS evaluation exposed a major limitation.

Fresh DDoS results were:

- Attack Precision: 99.90%
- Attack Recall: 8.59%
- Attack F1: 15.82%
- Specific DDoS Recall: 0.00%
- HOIC Any-Attack Detection: 8.6124%
- LOIC-UDP Any-Attack Detection: 0.00%

Out of 687,742 fresh attack flows:

- 59,082 were detected as some attack class.
- 628,660 were classified as BENIGN.
- 0 were classified specifically as DDoS.

This demonstrated that V2 had a major false-negative problem when exposed to DDoS traffic that differed from the patterns represented in its CIC-IDS-2017 training data.

---

# Training Data Used by V2

V2 used the same CIC-IDS-2017 training data as V1.

The training distribution after class sampling was:

- BENIGN: 250,000
- DoS: 250,000
- PortScan: 250,000
- DDoS: 128,025
- BruteForce: 13,832
- WebAttack: 2,180
- Bot: 1,956

Total samples:

- 895,993

Training samples:

- 716,794

Testing samples:

- 179,199

Number of live-compatible features:

- 41

The training setup remained unchanged across V2-A through V2-E so that the Random Forest parameter changes could be compared more directly.

---

# Infiltration Exclusion

Infiltration was excluded from the V2 model.

The prepared CIC-IDS-2017 dataset contained only 36 Infiltration records.

This was considered too few samples to train and evaluate a reliable Infiltration class.

V2 therefore used the following seven classes:

- BENIGN
- Bot
- BruteForce
- DDoS
- DoS
- PortScan
- WebAttack

---

# Methodology Note

The V2 development process intentionally kept the training dataset and 41-feature schema unchanged.

The variables changed between V2-A through V2-E were Random Forest hyperparameters.

The CSE-CIC-IDS2018 datasets containing BruteForce, GoldenEye, Slowloris, Hulk, and SlowHTTPTest traffic were examined repeatedly while comparing the candidates.

Because those results influenced candidate selection, they are treated as development or validation results rather than untouched final test results.

The `Wednesday-21-02-2018` HOIC and LOIC-UDP dataset was not examined until after V2-E had already been selected and frozen.

This dataset was therefore used as the fresh external evaluation.

The model was not retrained or modified after observing the fresh external results.

The poor DDoS results were kept as part of the official evaluation rather than being removed or excluded.

---

# V2 Limitations

## Single Training Dataset

V2 was trained only on CIC-IDS-2017.

This means its learned attack patterns are limited by the types of traffic and attacks represented in that dataset.

## Class Imbalance

The training distribution remained highly imbalanced.

Large classes included:

- BENIGN: 250,000
- DoS: 250,000
- PortScan: 250,000
- DDoS: 128,025

Much smaller classes included:

- BruteForce: 13,832
- WebAttack: 2,180
- Bot: 1,956

This imbalance continued to affect minority-class behavior.

For example, V2-E achieved:

- Bot Recall: 96.4194%
- Bot Precision: 67.68%
- Bot F1: 79.5359%

## Infiltration Exclusion

Infiltration was excluded because only 36 prepared CIC-IDS-2017 Infiltration records were available.

The model therefore cannot directly predict an Infiltration class.

## Same-Dataset Internal Evaluation

The internal train/test evaluation came from CIC-IDS-2017.

This likely contributed to the extremely high internal results:

- Accuracy: 99.7288%
- Macro F1: 96.5078%
- Weighted F1: 99.7381%

These internal numbers should not be interpreted as equivalent to cross-dataset or real-world performance.

The fresh external evaluation demonstrated this difference clearly.

Internal DDoS Recall was:

- 99.9766%

Fresh CSE-CIC-IDS2018 specific DDoS Recall was:

- 0.00%

This represents an extreme difference between internal and external performance.

## Feature Limit

V2 continued to use only the 41 features supported by the live Hybrid IDS flow extractor.

This maintains compatibility with the live IDS but limits the amount of information available compared with larger offline feature sets.

## Cross-Dataset Domain Shift

The fresh CSE-CIC-IDS2018 evaluation showed substantial differences between the patterns learned from CIC-IDS-2017 and the HOIC/LOIC-UDP attacks.

The clearest evidence was:

- 687,742 total DDoS attack flows
- 628,660 attacks predicted as BENIGN
- 59,082 detected as another attack class
- 0 predicted specifically as DDoS

## UNSW-NB15 Compatibility

UNSW-NB15 was not used for direct V2 inference because its feature schema differs from the 41 CICFlowMeter-compatible features used by V2.

Unavailable features were not replaced with fake zero values or fabricated approximations.

A later model version will require a common feature strategy or another compatible training approach before UNSW-NB15 can be incorporated correctly.

---

# V2 Conclusion

V2-E was selected as the official V2 Random Forest model because it produced the strongest overall balance among V2-A through V2-E.

Compared with V1, V2-E significantly improved several important development metrics.

Bot Recall increased:

- 84.40% -> 96.4194%

Brute-force External Recall increased:

- 4.50% -> 40.54%

SSH-Bruteforce Detection increased:

- 2.10% -> 69.9913%

FTP-BruteForce Detection increased:

- 6.84% -> 11.9729%

GoldenEye Detection increased:

- 30.95% -> 37.6120%

Slowloris Detection increased:

- 98.43% -> 99.0355%

Hulk Detection increased:

- 13.80% -> 13.9866%

SlowHTTPTest Detection increased:

- 9.83% -> 12.3147%

However, the fresh CSE-CIC-IDS2018 DDoS evaluation showed that Random Forest tuning alone did not solve cross-dataset generalization.

On 687,742 fresh DDoS attack flows:

- 59,082 were detected as any attack class.
- 628,660 were classified as BENIGN.
- 0 were classified specifically as DDoS.

Fresh Attack Precision was:

- 99.90%

Fresh Attack Recall was:

- 8.59%

Fresh Attack F1 was:

- 15.82%

HOIC Any-Attack Detection was:

- 8.6124%

LOIC-UDP Detection was:

- 0.00%

Specific DDoS Recall was:

- 0.00%

The contrast between internal and external DDoS performance was especially significant:

- CIC-IDS-2017 Internal DDoS Recall: 99.9766%
- Fresh CSE-CIC-IDS2018 Specific DDoS Recall: 0.00%

These results show that V2 improved the existing CIC-IDS-2017 model but still depends heavily on the characteristics of its training data.

The V2 tuning experiments were still valuable because they showed that model configuration alone could substantially change cross-dataset behavior, particularly with BruteForce and SSH-Bruteforce traffic.

However, the fresh DDoS results demonstrated that further tuning of a model trained only on CIC-IDS-2017 is unlikely to fully solve the generalization problem.

The next model version should therefore focus on increasing training diversity and improving cross-dataset generalization rather than continuing to optimize only CIC-IDS-2017 internal performance.
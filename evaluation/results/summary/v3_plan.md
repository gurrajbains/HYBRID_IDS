# Hybrid IDS V3 Plan

## Goal

V3 focuses on improving the overall Hybrid IDS instead of only tuning the machine-learning model.

V1 established the baseline system.

V2 improved the Random Forest model, but external testing showed that strong CIC-IDS-2017 performance did not always generalize well to other datasets.

V3 will focus on broader generalization using multiple datasets, common features, multiple ML algorithms, improved behavioral detection, stronger Suricata testing, and hybrid detector fusion.

## Main Research Question

Can machine learning, behavioral detection, and signature detection work together to detect unfamiliar network traffic better than any single detector alone?

## V3.1 Common Features

Create features that can be used consistently across:

- CIC-IDS-2017
- CSE-CIC-IDS2018
- UNSW-NB15
- Live Hybrid IDS traffic

Missing features will not be replaced with fake zero values.

## V3.2 Cross-Dataset Machine Learning

Stage 1:

- BENIGN
- ATTACK

Stage 2:

- Attack-family classification when labels can be mapped reliably

Attack types that cannot be mapped safely will remain classified as attacks instead of being forced into the wrong family.

## V3.3 Feature Comparison

Compare three common feature sets:

- Feature Set A: 5 base features
- Feature Set B: 9 structural features
- Feature Set C: 11 structural and rate features

The best feature set will be chosen using development data.

## V3.4 Algorithm Comparison

After selecting the feature set, compare models such as:

- Random Forest
- Extra Trees
- Gradient-based tree model

## V3.5 Behavioral Detection

Improve and evaluate behavioral detectors using:

- Threshold testing
- Benign traffic
- Attack detection rates
- False positives
- Mixed benign and attack traffic
- Additional attack scenarios

## V3.6 Suricata Evaluation

Test Suricata with traffic designed to trigger meaningful IDS signatures instead of relying only on the original synthetic behavioral PCAP.

## V3.7 Hybrid Fusion

Combine evidence from:

- Machine learning
- Behavioral detectors
- Suricata

Measure whether combining detectors improves detection and reduces weaknesses from individual components.

## Dataset Roles

### Training

- CIC-IDS-2017
- Selected CSE-CIC-IDS2018 days
- UNSW-NB15 training set

### Development

- CSE-CIC-IDS2018 Tuesday-20-02-2018

Used for comparing models and feature sets.

### Final Holdout

- Reserved CSE-CIC-IDS2018 days
- UNSW-NB15 testing set

These will not be used for training or tuning.

### Secondary Holdout

Additional reserved CSE-CIC-IDS2018 days for later generalization testing.

## Evaluation Rules

- Do not train on holdout data
- Do not tune using final results
- Include benign traffic
- Do not invent missing features
- Only map attack labels when justified
- Record false positives and false negatives
- Keep poor results instead of hiding them
- Use measured results only
- Freeze models before final evaluation

## Current Stage 1 Dataset

Maximum sampling:

- 100,000 rows per dataset and binary class

Current datasets:

- Feature Set A: 556,000 rows
- Feature Set B: 556,000 rows
- Feature Set C: 552,196 rows

Feature Set C lost 3,804 rows because rate features were undefined for some flows.

## V3 Success Criteria

V3 should aim for:

- Better cross-dataset generalization
- Better detection across different traffic sources
- Low benign false positives
- Better performance on unfamiliar traffic
- Proper train/development/holdout separation
- Features compatible with live traffic
- Evidence that combining detectors improves the Hybrid IDS
# Hybrid IDS Evaluation Plan

## Training Dataset
- CIC-IDS-2017 only

## External Evaluation Datasets
- CSE-CIC-IDS2018
- UNSW-NB15

## Controlled Evaluation
- Custom generated PCAPs

## Systems Compared
- Custom signature detectors only
- Suricata only
- Random Forest only
- Hybrid IDS combined

## Metrics
- Precision
- Recall
- F1-score
- False positive rate
- Detection rate
- Confusion matrix
- Per-attack detection coverage

## Evaluation Rules
- Do not retrain the Random Forest on external evaluation datasets.
- Do not cherry-pick only attacks the system detects well.
- Include benign traffic.
- Do not replace unavailable features with fake zero values.
- Keep dataset attack labels separate unless a mapping is explicitly justified.
- Record all failures and missed attacks.
- Use measured results only.
- Have Fun
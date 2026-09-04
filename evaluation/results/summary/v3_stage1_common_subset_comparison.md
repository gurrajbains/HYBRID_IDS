# Hybrid IDS V3 Stage 1 Common-Subset Comparison

## Purpose

Feature Sets A, B, and C are evaluated on the exact same Tuesday development rows.

The common evaluation subset contains only rows for which every Feature Set C feature is defined.

This prevents Feature Set C from receiving an unfair comparison advantage by excluding rows that Feature Sets A and B previously evaluated.

## Coverage

- Total development rows: 7,948,748
- Common valid rows: 7,889,295
- Excluded rows: 59,453
- Common-subset coverage: 99.2520%

## Results

| Set | Features | Train Rows | Accuracy | Balanced Accuracy | Attack Precision | Attack Recall | Attack F1 | Benign Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 5 | 556,000 | 0.743647 | 0.589998 | 0.123137 | 0.410067 | 0.189400 | 0.769929 | 0.230071 |
| B | 9 | 556,000 | 0.734792 | 0.585209 | 0.118806 | 0.410039 | 0.184232 | 0.760379 | 0.239621 |
| C | 11 | 552,196 | 0.749511 | 0.592994 | 0.126096 | 0.409704 | 0.192841 | 0.776284 | 0.223716 |

## Interpretation Rule

Feature selection should consider common-subset performance together with operational coverage. Feature Set C must justify its excluded rows with a meaningful improvement over simpler feature sets.
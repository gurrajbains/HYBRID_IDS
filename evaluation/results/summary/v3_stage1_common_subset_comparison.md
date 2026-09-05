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
| A | 5 | 556,000 | 0.891084 | 0.650422 | 0.300039 | 0.368595 | 0.330803 | 0.932250 | 0.067750 |
| B | 9 | 556,000 | 0.883311 | 0.646175 | 0.276079 | 0.368477 | 0.315655 | 0.923874 | 0.076126 |
| C | 11 | 552,746 | 0.894205 | 0.652242 | 0.310947 | 0.368892 | 0.337450 | 0.935593 | 0.064407 |

## Interpretation Rule

Feature selection should consider common-subset performance together with operational coverage. Feature Set C must justify its excluded rows with a meaningful improvement over simpler feature sets.
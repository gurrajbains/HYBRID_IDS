# Hybrid IDS V3 Common Feature Profile

## Purpose

This report profiles the initial V3 common feature representation across CIC-IDS-2017, CSE-CIC-IDS2018, and UNSW-NB15.

The goal is to identify invalid values, incompatible scales, and large distribution differences before building a combined training dataset.

---

## CIC-IDS-2017

- Source: `data\cicids2017_multiclass.csv`
- Rows sampled: 100,000
- Fully valid rows: 99,993

| Feature | Valid | Missing | Min | Median | Mean | P95 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|
| `flow_duration` | 100,000 | 0 | -1e-06 | 0.02366 | 10.1781 | 114.504 | 120 |
| `fwd_packets` | 100,000 | 0 | 1 | 2 | 5.82763 | 20 | 3119 |
| `bwd_packets` | 100,000 | 0 | 0 | 2 | 5.94682 | 18 | 3635 |
| `fwd_bytes` | 100,000 | 0 | 0 | 60 | 465.749 | 1798.05 | 232349 |
| `bwd_bytes` | 100,000 | 0 | 0 | 112 | 5367.95 | 6634 | 7.15082e+06 |
| `total_packets` | 100,000 | 0 | 2 | 4 | 11.7744 | 39 | 6325 |
| `total_bytes` | 100,000 | 0 | 0 | 184 | 5833.7 | 9368 | 7.17288e+06 |
| `packets_per_second` | 99,993 | 7 | 0.02039 | 168.209 | 54308.4 | 181818 | 3e+06 |
| `bytes_per_second` | 99,993 | 7 | 0 | 9318.42 | 2.00683e+06 | 2.37433e+06 | 2.071e+09 |
| `fwd_mean_packet_bytes` | 100,000 | 0 | 0 | 34 | 48.3156 | 139.5 | 3412.94 |
| `bwd_mean_packet_bytes` | 100,000 | 0 | 0 | 64 | 141.176 | 642.667 | 2442.52 |

---

## CSE-CIC-IDS2018

- Source: `evaluation\datasets\CSE-CIC-IDS2018\Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`
- Rows sampled: 100,000
- Fully valid rows: 100,000

| Feature | Valid | Missing | Min | Median | Mean | P95 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|
| `flow_duration` | 100,000 | 0 | 1e-06 | 3e-06 | 0.135725 | 0.001693 | 112.642 |
| `fwd_packets` | 100,000 | 0 | 1 | 1 | 1.14266 | 2 | 207 |
| `bwd_packets` | 100,000 | 0 | 0 | 1 | 1.102 | 1 | 889 |
| `fwd_bytes` | 100,000 | 0 | 0 | 0 | 15.9559 | 0 | 11888 |
| `bwd_bytes` | 100,000 | 0 | 0 | 0 | 58.1724 | 0 | 1.56627e+06 |
| `total_packets` | 100,000 | 0 | 2 | 2 | 2.24466 | 2 | 1096 |
| `total_bytes` | 100,000 | 0 | 0 | 0 | 74.1284 | 0 | 1.56803e+06 |
| `packets_per_second` | 100,000 | 0 | 0.0266331 | 666667 | 670882 | 1e+06 | 2e+06 |
| `bytes_per_second` | 100,000 | 0 | 0 | 0 | 3834.75 | 0 | 1.73014e+06 |
| `fwd_mean_packet_bytes` | 100,000 | 0 | 0 | 0 | 5.01355 | 0 | 697.6 |
| `bwd_mean_packet_bytes` | 100,000 | 0 | 0 | 0 | 10.0951 | 0 | 1955.96 |

---

## UNSW-NB15

- Source: `evaluation\datasets\UNSW-NB15\UNSW_NB15_testing-set.csv`
- Rows sampled: 82,332
- Fully valid rows: 81,382

| Feature | Valid | Missing | Min | Median | Mean | P95 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|
| `flow_duration` | 82,332 | 0 | 0 | 0.014138 | 1.00676 | 2.40379 | 60 |
| `fwd_packets` | 82,332 | 0 | 1 | 6 | 18.6665 | 60 | 10646 |
| `bwd_packets` | 82,332 | 0 | 0 | 2 | 17.5459 | 54 | 11018 |
| `fwd_bytes` | 82,332 | 0 | 24 | 534 | 7993.91 | 12472 | 1.43558e+07 |
| `bwd_bytes` | 82,332 | 0 | 0 | 178 | 13233.8 | 30622 | 1.46575e+07 |
| `total_packets` | 82,332 | 0 | 1 | 8 | 36.2124 | 108 | 12660 |
| `total_bytes` | 82,332 | 0 | 24 | 880 | 21227.7 | 52956 | 1.47282e+07 |
| `packets_per_second` | 81,382 | 950 | 0.0333333 | 3533.57 | 168111 | 666667 | 2e+06 |
| `bytes_per_second` | 81,382 | 950 | 1.53333 | 312697 | 1.65616e+07 | 6.66667e+07 | 1.317e+09 |
| `fwd_mean_packet_bytes` | 82,332 | 0 | 24 | 65 | 139.536 | 637.714 | 1504 |
| `bwd_mean_packet_bytes` | 82,332 | 0 | 0 | 44.25 | 116.256 | 683 | 1500 |

---

## Methodology Note

These statistics are exploratory development measurements. They are not model evaluation results.

Large differences between datasets will be documented rather than silently normalized away. Any scaling or transformation selected later must be fitted using training data only.
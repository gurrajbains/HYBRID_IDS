# Hybrid IDS V3 Feature Compatibility

## Purpose

This audit checks whether the first V3 common feature representation can be built consistently across CIC-IDS-2017, CSE-CIC-IDS2018, and UNSW-NB15.

No unavailable features are replaced with fake zero values or estimated equivalents.

---

## V3 Common Base Features

- `flow_duration`
- `fwd_packets`
- `bwd_packets`
- `fwd_bytes`
- `bwd_bytes`

## V3 Derived Features

- `total_packets`
- `total_bytes`
- `packets_per_second`
- `bytes_per_second`
- `fwd_mean_packet_bytes`
- `bwd_mean_packet_bytes`

Total candidate V3 common features: 11

---

## Compatibility Matrix

| Dataset | V3 Feature | Source Column | Available |
|---|---|---|---|
| CIC-IDS-2017 | `flow_duration` | `Flow Duration` | YES |
| CIC-IDS-2017 | `fwd_packets` | `Total Fwd Packets` | YES |
| CIC-IDS-2017 | `bwd_packets` | `Total Backward Packets` | YES |
| CIC-IDS-2017 | `fwd_bytes` | `Total Length of Fwd Packets` | YES |
| CIC-IDS-2017 | `bwd_bytes` | `Total Length of Bwd Packets` | YES |
| CSE-CIC-IDS2018 | `flow_duration` | `Flow Duration` | YES |
| CSE-CIC-IDS2018 | `fwd_packets` | `Tot Fwd Pkts` | YES |
| CSE-CIC-IDS2018 | `bwd_packets` | `Tot Bwd Pkts` | YES |
| CSE-CIC-IDS2018 | `fwd_bytes` | `TotLen Fwd Pkts` | YES |
| CSE-CIC-IDS2018 | `bwd_bytes` | `TotLen Bwd Pkts` | YES |
| UNSW-NB15 | `flow_duration` | `dur` | YES |
| UNSW-NB15 | `fwd_packets` | `spkts` | YES |
| UNSW-NB15 | `bwd_packets` | `dpkts` | YES |
| UNSW-NB15 | `fwd_bytes` | `sbytes` | YES |
| UNSW-NB15 | `bwd_bytes` | `dbytes` | YES |

---

## Duration Units

- CIC-IDS-2017: microseconds
- CSE-CIC-IDS2018: microseconds
- UNSW-NB15: seconds

V3 preprocessing must normalize flow duration to the same unit before derived rate features are calculated.

---

## Dataset Compatibility

- CIC-IDS-2017: PASS
- CSE-CIC-IDS2018: PASS
- UNSW-NB15: PASS

---

## Initial V3 Decision

Only features with defensible mappings across all selected datasets should enter the first common V3 model.

Features such as CICFlowMeter IAT statistics, TCP flag counts, and destination port are not automatically included because equivalent semantics are not currently established across all three datasets.

Additional features may be added later only after their definitions are verified.
# Hybrid IDS V3 Stage 2 Dataset Build

Stage 2 contains only mapped attack families from the frozen V3 training partition.

Development, final holdout, and secondary holdout datasets were not opened by this build.

## Configuration

- Feature set: C
- Feature count: 11
- Sampling method: deterministic_random_priority_top_k
- Maximum rows per dataset/family: 100,000
- Random state: 42

## Totals

- Raw training rows read: 7,814,738
- Attack rows: 2,650,755
- Mapped Stage 2 attack rows: 2,554,169
- Unmapped attack rows: 96,586
- Invalid Feature Set C rows: 677
- Valid mapped rows: 2,553,492
- Final sampled rows: 733,151

## Final sampled family counts

| Family | Rows |
|---|---:|
| Bot | 1,956 |
| BruteForce | 113,832 |
| DDoS | 200,000 |
| DoS | 212,256 |
| Infiltration | 92,439 |
| Reconnaissance | 110,488 |
| WebAttack | 2,180 |

## Dataset/family sampled counts

### cicids2017

| Family | Rows |
|---|---:|
| Bot | 1,956 |
| BruteForce | 13,832 |
| DDoS | 100,000 |
| DoS | 100,000 |
| Infiltration | 36 |
| Reconnaissance | 100,000 |
| WebAttack | 2,180 |

### cse_cic_ids2018

| Family | Rows |
|---|---:|
| BruteForce | 100,000 |
| DDoS | 100,000 |
| DoS | 100,000 |
| Infiltration | 92,403 |

### unsw_nb15

| Family | Rows |
|---|---:|
| DoS | 12,256 |
| Reconnaissance | 10,488 |

## Unmapped attack raw labels

| Dataset | Raw label | Rows |
|---|---|---:|
| unsw_nb15 | Analysis | 2,000 |
| unsw_nb15 | Backdoor | 1,746 |
| unsw_nb15 | Exploits | 33,393 |
| unsw_nb15 | Fuzzers | 18,184 |
| unsw_nb15 | Generic | 40,000 |
| unsw_nb15 | Shellcode | 1,133 |
| unsw_nb15 | Worms | 130 |

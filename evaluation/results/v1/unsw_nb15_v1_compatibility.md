# UNSW-NB15 V1 Compatibility Assessment

## Dataset

Official UNSW-NB15 testing partition.

Records: 82,332

Binary distribution:
- Attack: 45,332
- Normal: 37,000

Attack categories:
- Generic: 18,871
- Exploits: 11,132
- Fuzzers: 6,062
- DoS: 4,089
- Reconnaissance: 3,496
- Analysis: 677
- Backdoor: 583
- Shellcode: 378
- Worms: 44

## V1 Compatibility

The current V1 Random Forest was trained using 41 CICFlowMeter-style
features from CIC-IDS-2017.

UNSW-NB15 uses a different flow-feature schema derived from Argus,
Bro/Zeek, and dataset-specific feature-generation algorithms.

Some features have conceptual equivalents, including:
- Flow duration
- Forward packet count
- Backward packet count
- Forward bytes
- Backward bytes
- Directional mean packet size
- Packet/flow rate information

However, several required V1 features do not have direct UNSW-NB15
equivalents, including multiple packet-length distribution statistics,
CICFlowMeter IAT statistics, directional IAT statistics, and CIC-style
TCP flag counts.

## Decision

V1 will not be directly evaluated on UNSW-NB15 by filling unavailable
features with zeros or approximated values.

Doing so would introduce synthetic feature values and make the external
evaluation misleading.

UNSW-NB15 will instead be retained for evaluation of a later model built
using a legitimately compatible feature representation.

No V1 model tuning or retraining was performed as a result of inspecting
UNSW-NB15.
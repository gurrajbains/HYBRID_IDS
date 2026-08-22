# Hybrid IDS V1 Controlled Evaluation

## Test Traffic

- Synthetic PCAP: `pcaps/synthetic_attacks.pcap`
- Total packets: 144
- Port scan SYN packets: 12
- SYN flood packets: 60
- SSH connection-attempt SYN packets: 12
- ICMP echo-request packets: 60

## Expected Behavioral Alerts

- Port Scan: 1
- SYN Flood: 1
- SSH Brute Force: 1
- ICMP Flood: 1

## Observed Alerts

- ICMP Flood: 1
- Port Scan: 1
- SSH Brute Force: 1
- SYN Flood: 1

Total alerts recorded: 4

## Detector Verification

- Port Scan: PASS (expected 1, observed 1)
- SYN Flood: PASS (expected 1, observed 1)
- SSH Brute Force: PASS (expected 1, observed 1)
- ICMP Flood: PASS (expected 1, observed 1)

## Controlled Detection Coverage

- Behavioral attack scenarios detected: 4/4
- Scenario detection coverage: 100.00%

## Interpretation

This controlled evaluation verifies whether the Hybrid IDS V1 behavioral detectors produce the expected alerts for predefined synthetic attack scenarios. The test is functional and controlled; it should not be interpreted as a real-world attack-detection accuracy measurement.

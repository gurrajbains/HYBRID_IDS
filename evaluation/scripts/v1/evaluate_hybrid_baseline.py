import json
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PCAP_PATH = PROJECT_ROOT / "pcaps" / "synthetic_attacks.pcap"
ALERT_LOG = PROJECT_ROOT / "logs" / "alerts.jsonl"
RESULT_PATH = PROJECT_ROOT / "evaluation" / "results" / "hybrid_v1_controlled_results.md"


EXPECTED_ALERT_TYPES = {
    "Port Scan": 1,
    "SYN Flood": 1,
    "SSH Brute Force": 1,
    "ICMP Flood": 1
}


def clear_alert_log():
    if ALERT_LOG.exists():
        ALERT_LOG.unlink()


def run_hybrid_ids():
    print("Running Hybrid IDS V1 on controlled synthetic PCAP...")
    command = [
        str(PROJECT_ROOT / "venv" / "Scripts" / "python.exe"),
        "-m",
        "src.capture.packet_reader",
        "--pcap",
        str(PCAP_PATH)
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )

    print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"Hybrid IDS exited with code {result.returncode}")


def read_alerts():
    if not ALERT_LOG.exists():
        return []

    alerts = []

    with ALERT_LOG.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            alerts.append(json.loads(line))

    return alerts


def summarize_alerts(alerts):
    counts = {}

    for alert in alerts:
        alert_type = alert.get("type", "UNKNOWN")
        counts[alert_type] = counts.get(alert_type, 0) + 1

    return counts


def evaluate_expected_alerts(counts):
    results = {}

    for alert_type, expected_count in EXPECTED_ALERT_TYPES.items():
        actual_count = counts.get(alert_type, 0)

        results[alert_type] = {
            "expected": expected_count,
            "actual": actual_count,
            "passed": actual_count == expected_count
        }

    return results


def write_results(alerts, counts, evaluation):
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)

    passed = sum(1 for result in evaluation.values() if result["passed"])
    total = len(evaluation)

    with RESULT_PATH.open("w", encoding="utf-8") as file:
        file.write("# Hybrid IDS V1 Controlled Evaluation\n\n")

        file.write("## Test Traffic\n\n")
        file.write("- Synthetic PCAP: `pcaps/synthetic_attacks.pcap`\n")
        file.write("- Total packets: 144\n")
        file.write("- Port scan SYN packets: 12\n")
        file.write("- SYN flood packets: 60\n")
        file.write("- SSH connection-attempt SYN packets: 12\n")
        file.write("- ICMP echo-request packets: 60\n\n")

        file.write("## Expected Behavioral Alerts\n\n")
        file.write("- Port Scan: 1\n")
        file.write("- SYN Flood: 1\n")
        file.write("- SSH Brute Force: 1\n")
        file.write("- ICMP Flood: 1\n\n")

        file.write("## Observed Alerts\n\n")

        for alert_type, count in sorted(counts.items()):
            file.write(f"- {alert_type}: {count}\n")

        file.write(f"\nTotal alerts recorded: {len(alerts)}\n\n")

        file.write("## Detector Verification\n\n")

        for alert_type, result in evaluation.items():
            status = "PASS" if result["passed"] else "FAIL"

            file.write(
                f"- {alert_type}: {status} "
                f"(expected {result['expected']}, observed {result['actual']})\n"
            )

        file.write("\n## Controlled Detection Coverage\n\n")
        file.write(f"- Behavioral attack scenarios detected: {passed}/{total}\n")
        file.write(f"- Scenario detection coverage: {(passed / total) * 100:.2f}%\n\n")

        file.write("## Interpretation\n\n")
        file.write(
            "This controlled evaluation verifies whether the Hybrid IDS V1 "
            "behavioral detectors produce the expected alerts for predefined "
            "synthetic attack scenarios. The test is functional and controlled; "
            "it should not be interpreted as a real-world attack-detection "
            "accuracy measurement.\n"
        )


def main():
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"PCAP not found: {PCAP_PATH}")

    clear_alert_log()
    run_hybrid_ids()

    alerts = read_alerts()
    counts = summarize_alerts(alerts)
    evaluation = evaluate_expected_alerts(counts)

    print("\n--- Controlled Evaluation Summary ---")

    for alert_type, result in evaluation.items():
        status = "PASS" if result["passed"] else "FAIL"
        print(
            f"{alert_type}: {status} "
            f"(expected {result['expected']}, observed {result['actual']})"
        )

    passed = sum(1 for result in evaluation.values() if result["passed"])

    print(f"\nScenarios detected correctly: {passed}/{len(evaluation)}")
    print(f"Result file: {RESULT_PATH}")

    write_results(alerts, counts, evaluation)


if __name__ == "__main__":
    main()
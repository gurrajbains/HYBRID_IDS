import subprocess
from pathlib import Path

from src.suricata.eve_reader import read_suricata_alerts


SURICATA_EXE = Path(r"C:\Program Files\Suricata\suricata.exe")
SURICATA_CONFIG = Path(r"C:\Program Files\Suricata\suricata.yaml")
SURICATA_RULES = Path("rules/suricata.rules")
SURICATA_LOG_DIR = Path("logs/suricata")
EVE_PATH = SURICATA_LOG_DIR / "eve.json"


def clear_suricata_logs():
    SURICATA_LOG_DIR.mkdir(parents=True, exist_ok=True)

    if EVE_PATH.exists():
        EVE_PATH.unlink()


def run_suricata_pcap(pcap_path, rules_path=SURICATA_RULES):
    pcap_path = Path(pcap_path)
    rules_path = Path(rules_path)

    if not SURICATA_EXE.exists():
        raise FileNotFoundError(f"Suricata executable not found: {SURICATA_EXE}")

    if not SURICATA_CONFIG.exists():
        raise FileNotFoundError(f"Suricata config not found: {SURICATA_CONFIG}")

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if not rules_path.exists():
        raise FileNotFoundError(f"Suricata rules not found: {rules_path}")

    clear_suricata_logs()

    command = [
        str(SURICATA_EXE),
        "-r",
        str(pcap_path),
        "-c",
        str(SURICATA_CONFIG),
        "-S",
        str(rules_path),
        "-l",
        str(SURICATA_LOG_DIR)
    ]

    print("\n--- Suricata Analysis ---")
    print(f"PCAP: {pcap_path}")
    print(f"Rules: {rules_path}")

    result = subprocess.run(command, capture_output=True, text=True)

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"Suricata exited with code {result.returncode}")

    alerts = read_suricata_alerts(EVE_PATH)

    print(f"Suricata alerts detected: {len(alerts)}")

    return alerts


if __name__ == "__main__":
    alerts = run_suricata_pcap("pcaps/synthetic_attacks.pcap")

    for alert in alerts[:10]:
        print(
            f"{alert['alert_type']} | "
            f"{alert['src_ip']} -> {alert['dst_ip']} | "
            f"{alert['severity']}"
        )
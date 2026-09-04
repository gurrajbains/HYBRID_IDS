from pathlib import Path
import json

import pandas as pd

from src.ml.v3.feature_schema import DATASET_MAPPINGS, V3_COMMON_FEATURES


CIC17_PATH = Path("data/cicids2017_multiclass.csv")

CSE2018_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")

UNSW_PATH = Path("evaluation/datasets/UNSW-NB15/UNSW_NB15_testing-set.csv")

OUTPUT_JSON = Path("evaluation/results/summary/v3_feature_compatibility.json")
OUTPUT_MARKDOWN = Path("evaluation/results/summary/v3_feature_compatibility.md")


def normalize_columns(columns):
    return {str(column).strip(): str(column) for column in columns}


def read_columns(path):
    dataframe = pd.read_csv(path, nrows=0)
    return normalize_columns(dataframe.columns)


def audit_mapping(dataset_name, mapping, columns):
    results = []

    for common_name, source_name in mapping.columns.items():
        exists = source_name in columns

        results.append(
            {
                "common_feature": common_name,
                "source_column": source_name,
                "exists": exists,
            }
        )

    return {
        "dataset": dataset_name,
        "duration_unit": mapping.duration_unit,
        "base_features": results,
        "compatible": all(item["exists"] for item in results),
    }


def find_cse2018_file():
    files = sorted(CSE2018_DIRECTORY.glob("*.csv"))

    if not files:
        raise FileNotFoundError(f"No CSE-CIC-IDS2018 CSV files found in {CSE2018_DIRECTORY}")

    return files[0]


def build_markdown(results):
    lines = []

    lines.append("# Hybrid IDS V3 Feature Compatibility")
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append("This audit checks whether the first V3 common feature representation can be built consistently across CIC-IDS-2017, CSE-CIC-IDS2018, and UNSW-NB15.")
    lines.append("")
    lines.append("No unavailable features are replaced with fake zero values or estimated equivalents.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## V3 Common Base Features")
    lines.append("")

    for feature in [
        "flow_duration",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
    ]:
        lines.append(f"- `{feature}`")

    lines.append("")
    lines.append("## V3 Derived Features")
    lines.append("")

    for feature in [
        "total_packets",
        "total_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_mean_packet_bytes",
        "bwd_mean_packet_bytes",
    ]:
        lines.append(f"- `{feature}`")

    lines.append("")
    lines.append(f"Total candidate V3 common features: {len(V3_COMMON_FEATURES)}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Compatibility Matrix")
    lines.append("")
    lines.append("| Dataset | V3 Feature | Source Column | Available |")
    lines.append("|---|---|---|---|")

    for result in results:
        for feature in result["base_features"]:
            status = "YES" if feature["exists"] else "NO"
            lines.append(f"| {result['dataset']} | `{feature['common_feature']}` | `{feature['source_column']}` | {status} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Duration Units")
    lines.append("")

    for result in results:
        lines.append(f"- {result['dataset']}: {result['duration_unit']}")

    lines.append("")
    lines.append("V3 preprocessing must normalize flow duration to the same unit before derived rate features are calculated.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Dataset Compatibility")
    lines.append("")

    for result in results:
        status = "PASS" if result["compatible"] else "FAIL"
        lines.append(f"- {result['dataset']}: {status}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Initial V3 Decision")
    lines.append("")
    lines.append("Only features with defensible mappings across all selected datasets should enter the first common V3 model.")
    lines.append("")
    lines.append("Features such as CICFlowMeter IAT statistics, TCP flag counts, and destination port are not automatically included because equivalent semantics are not currently established across all three datasets.")
    lines.append("")
    lines.append("Additional features may be added later only after their definitions are verified.")

    return "\n".join(lines)


def main():
    print("Hybrid IDS V3 Feature Compatibility Audit")
    print("=" * 55)

    if not CIC17_PATH.exists():
        raise FileNotFoundError(f"Missing CIC-IDS-2017 dataset: {CIC17_PATH}")

    if not UNSW_PATH.exists():
        raise FileNotFoundError(f"Missing UNSW-NB15 dataset: {UNSW_PATH}")

    cse2018_path = find_cse2018_file()

    print(f"CIC-IDS-2017: {CIC17_PATH}")
    print(f"CSE-CIC-IDS2018: {cse2018_path}")
    print(f"UNSW-NB15: {UNSW_PATH}")
    print()

    cic_columns = read_columns(CIC17_PATH)
    cse_columns = read_columns(cse2018_path)
    unsw_columns = read_columns(UNSW_PATH)

    results = [
        audit_mapping("CIC-IDS-2017", DATASET_MAPPINGS["cicids2017"], cic_columns),
        audit_mapping("CSE-CIC-IDS2018", DATASET_MAPPINGS["cse_cic_ids2018"], cse_columns),
        audit_mapping("UNSW-NB15", DATASET_MAPPINGS["unsw_nb15"], unsw_columns),
    ]

    for result in results:
        print(result["dataset"])

        for feature in result["base_features"]:
            marker = "PASS" if feature["exists"] else "MISSING"
            print(f"  {marker:<7} {feature['common_feature']:<20} -> {feature['source_column']}")

        print(f"  Overall: {'PASS' if result['compatible'] else 'FAIL'}")
        print()

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "common_features": V3_COMMON_FEATURES,
                "datasets": results,
            },
            file,
            indent=4,
        )

    markdown = build_markdown(results)
    OUTPUT_MARKDOWN.write_text(markdown, encoding="utf-8")

    print(f"JSON report: {OUTPUT_JSON}")
    print(f"Markdown report: {OUTPUT_MARKDOWN}")


if __name__ == "__main__":
    main()
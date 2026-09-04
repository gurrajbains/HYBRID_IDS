from collections import Counter
from pathlib import Path
import json

from src.ml.v3.label_schema import BENIGN, UNMAPPED_ATTACK, get_binary_label, get_family_label, is_stage2_trainable


INPUT_PATH = Path("evaluation/results/summary/v3_dataset_quality.json")

OUTPUT_JSON = Path("evaluation/results/summary/v3_label_harmonization.json")
OUTPUT_MARKDOWN = Path("evaluation/results/summary/v3_label_harmonization.md")


def audit_dataset(dataset):
    dataset_name = dataset["dataset"]
    dataset_key = dataset["mapping"]

    binary_counts = Counter()
    family_counts = Counter()

    mappings = []

    stage2_trainable_rows = 0
    unmapped_attack_rows = 0

    for raw_label, count in dataset["label_counts"].items():
        binary_label = get_binary_label(dataset_key, raw_label)
        family_label = get_family_label(dataset_key, raw_label)
        stage2_trainable = is_stage2_trainable(dataset_key, raw_label)

        binary_counts[binary_label] += count
        family_counts[family_label] += count

        if stage2_trainable:
            stage2_trainable_rows += count

        if family_label == UNMAPPED_ATTACK:
            unmapped_attack_rows += count

        mappings.append(
            {
                "raw_label": raw_label,
                "count": count,
                "binary_label": binary_label,
                "family_label": family_label,
                "stage2_trainable": stage2_trainable,
            }
        )

    return {
        "dataset": dataset_name,
        "dataset_key": dataset_key,
        "binary_counts": dict(binary_counts),
        "family_counts": dict(family_counts),
        "stage2_trainable_rows": stage2_trainable_rows,
        "unmapped_attack_rows": unmapped_attack_rows,
        "mappings": mappings,
    }


def build_markdown(results):
    lines = []

    lines.append("# Hybrid IDS V3 Label Harmonization Audit")
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append(
        "This audit defines how labels from CIC-IDS-2017, "
        "CSE-CIC-IDS2018, and UNSW-NB15 can be used by the "
        "V3 two-stage machine-learning architecture."
    )
    lines.append("")
    lines.append("Stage 1 performs binary BENIGN vs ATTACK detection.")
    lines.append("")
    lines.append(
        "Stage 2 classifies attack families only when the source label "
        "has a defensible mapping to the V3 family taxonomy."
    )
    lines.append("")
    lines.append(
        "Unsupported attack families remain attacks for Stage 1 and are "
        "not forced into an unrelated Stage 2 class."
    )

    for result in results:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"## {result['dataset']}")
        lines.append("")

        lines.append("### Raw Label Mapping")
        lines.append("")
        lines.append("| Raw Label | Rows | Stage 1 | Stage 2 | Train Stage 2 |")
        lines.append("|---|---:|---|---|---|")

        for mapping in result["mappings"]:
            stage2 = "YES" if mapping["stage2_trainable"] else "NO"

            lines.append(
                f"| {mapping['raw_label']} "
                f"| {mapping['count']:,} "
                f"| {mapping['binary_label']} "
                f"| {mapping['family_label']} "
                f"| {stage2} |"
            )

        lines.append("")
        lines.append("### Binary Distribution")
        lines.append("")

        for label, count in sorted(result["binary_counts"].items()):
            lines.append(f"- {label}: {count:,}")

        lines.append("")
        lines.append("### Family Distribution")
        lines.append("")

        for label, count in sorted(result["family_counts"].items()):
            lines.append(f"- {label}: {count:,}")

        lines.append("")
        lines.append(f"- Stage 2 trainable attack rows: {result['stage2_trainable_rows']:,}")
        lines.append(f"- Unmapped attack rows: {result['unmapped_attack_rows']:,}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Mapping Rules")
    lines.append("")
    lines.append(
        "- PortScan is mapped to the broader Reconnaissance family. "
        "This is a parent-category mapping and does not imply that "
        "all reconnaissance traffic is port scanning."
    )
    lines.append(
        "- UNSW-NB15 Analysis, Backdoor, Exploits, Fuzzers, Generic, "
        "Shellcode, and Worms are retained as ATTACK for Stage 1 but "
        "are not forced into an existing Stage 2 family."
    )
    lines.append(
        "- Infilteration in CSE-CIC-IDS2018 is normalized to "
        "Infiltration."
    )
    lines.append(
        "- No model training is performed by this audit."
    )

    return "\n".join(lines)


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Missing V3 dataset quality report: {INPUT_PATH}"
        )

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        datasets = json.load(file)

    results = [
        audit_dataset(dataset)
        for dataset in datasets
    ]

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    OUTPUT_MARKDOWN.write_text(
        build_markdown(results),
        encoding="utf-8",
    )

    print("Hybrid IDS V3 Label Harmonization Audit")
    print("=" * 60)

    for result in results:
        print()
        print(result["dataset"])

        for mapping in result["mappings"]:
            print(
                f"  {mapping['raw_label']:<30} "
                f"-> {mapping['binary_label']:<7} "
                f"-> {mapping['family_label']}"
            )

        print(
            f"  Stage 2 trainable attack rows: "
            f"{result['stage2_trainable_rows']:,}"
        )

        print(
            f"  Unmapped attack rows: "
            f"{result['unmapped_attack_rows']:,}"
        )

    print()
    print(f"JSON report: {OUTPUT_JSON}")
    print(f"Markdown report: {OUTPUT_MARKDOWN}")


if __name__ == "__main__":
    main()
from collections import Counter
from pathlib import Path
import json

import numpy as np
import pandas as pd

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS


CHUNK_SIZE = 100_000

MANIFEST_PATH = Path("evaluation/v3_split_manifest.json")

CSE2018_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")
UNSW_DIRECTORY = Path("evaluation/datasets/UNSW-NB15")

OUTPUT_JSON = Path("evaluation/results/summary/v3_dataset_quality.json")
OUTPUT_MARKDOWN = Path("evaluation/results/summary/v3_dataset_quality.md")

AUDIT_ROLES = (
    "training",
    "development",
)


DATASET_DISPLAY_NAMES = {
    "cicids2017": "CIC-IDS-2017",
    "cse_cic_ids2018": "CSE-CIC-IDS2018",
    "unsw_nb15": "UNSW-NB15",
}


LABEL_COLUMNS = {
    "cicids2017": "Label",
    "cse_cic_ids2018": "Label",
    "unsw_nb15": "attack_cat",
}


def resolve_path(dataset_key: str, filename: str) -> Path:
    if dataset_key == "cicids2017":
        return Path(filename)

    if dataset_key == "cse_cic_ids2018":
        return CSE2018_DIRECTORY / filename

    if dataset_key == "unsw_nb15":
        return UNSW_DIRECTORY / filename

    raise KeyError(f"Unknown dataset key: {dataset_key}")


def update_counter(counter: Counter, values: pd.Series) -> None:
    counts = values.value_counts(dropna=False)

    for label, count in counts.items():
        counter[str(label)] += int(count)


def audit_file(
    name: str,
    path: Path,
    mapping_key: str,
    label_column: str,
    role: str,
) -> dict:
    print()
    print(name)
    print("=" * 70)
    print(f"Role: {role}")
    print(f"File: {path}")

    total_rows = 0
    usable_rows = 0
    repeated_header_rows = 0

    zero_duration_rows = 0
    negative_duration_rows = 0
    missing_duration_rows = 0
    invalid_common_rows = 0

    label_counts = Counter()
    invalid_by_label = Counter()
    nonpositive_duration_by_label = Counter()

    feature_missing = Counter()
    feature_negative = Counter()

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            path,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        chunk.columns = chunk.columns.str.strip()

        total_rows += len(chunk)

        if label_column not in chunk.columns:
            raise KeyError(
                f"{path} is missing label column '{label_column}'"
            )

        labels = chunk[label_column].astype("string").str.strip()

        header_mask = labels.eq(label_column)

        repeated_header_rows += int(header_mask.sum())

        chunk = chunk.loc[~header_mask].copy()
        labels = labels.loc[~header_mask]

        usable_rows += len(chunk)

        update_counter(
            label_counts,
            labels,
        )

        common = transform_common_features(
            chunk,
            DATASET_MAPPINGS[mapping_key],
        )

        common = common.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        duration = common["flow_duration"]

        zero_mask = duration.eq(0)
        negative_mask = duration.lt(0)
        missing_duration_mask = duration.isna()
        nonpositive_mask = duration.le(0)

        valid_row_mask = common.notna().all(axis=1)
        invalid_mask = ~valid_row_mask

        zero_duration_rows += int(zero_mask.sum())
        negative_duration_rows += int(negative_mask.sum())
        missing_duration_rows += int(missing_duration_mask.sum())
        invalid_common_rows += int(invalid_mask.sum())

        update_counter(
            invalid_by_label,
            labels.loc[invalid_mask],
        )

        update_counter(
            nonpositive_duration_by_label,
            labels.loc[nonpositive_mask],
        )

        for column in common.columns:
            feature_missing[column] += int(
                common[column].isna().sum()
            )

            feature_negative[column] += int(
                (common[column] < 0).sum()
            )

        print(
            f"Chunk {chunk_number}: "
            f"rows={len(chunk):,}, "
            f"invalid={int(invalid_mask.sum()):,}, "
            f"duration<=0={int(nonpositive_mask.sum()):,}"
        )

    print()
    print(f"Total rows: {total_rows:,}")
    print(f"Usable rows: {usable_rows:,}")
    print(f"Repeated header rows: {repeated_header_rows:,}")
    print(f"Zero duration: {zero_duration_rows:,}")
    print(f"Negative duration: {negative_duration_rows:,}")
    print(f"Missing duration: {missing_duration_rows:,}")
    print(f"Invalid common-feature rows: {invalid_common_rows:,}")

    return {
        "dataset": name,
        "role": role,
        "path": str(path),
        "mapping": mapping_key,
        "label_column": label_column,
        "total_rows": total_rows,
        "usable_rows": usable_rows,
        "repeated_header_rows": repeated_header_rows,
        "zero_duration_rows": zero_duration_rows,
        "negative_duration_rows": negative_duration_rows,
        "missing_duration_rows": missing_duration_rows,
        "invalid_common_rows": invalid_common_rows,
        "label_counts": dict(sorted(label_counts.items())),
        "invalid_by_label": dict(sorted(invalid_by_label.items())),
        "nonpositive_duration_by_label": dict(
            sorted(nonpositive_duration_by_label.items())
        ),
        "feature_missing": dict(feature_missing),
        "feature_negative": dict(feature_negative),
    }


def build_dataset_list() -> list:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Missing V3 split manifest: {MANIFEST_PATH}"
        )

    with MANIFEST_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        manifest = json.load(file)

    datasets = []

    for role in AUDIT_ROLES:
        if role not in manifest:
            raise KeyError(
                f"Split manifest is missing role '{role}'"
            )

        for dataset_key, filenames in manifest[role].items():
            if dataset_key not in DATASET_MAPPINGS:
                raise KeyError(
                    f"Unknown dataset key in manifest: {dataset_key}"
                )

            if dataset_key not in LABEL_COLUMNS:
                raise KeyError(
                    f"No label column configured for: {dataset_key}"
                )

            for filename in filenames:
                path = resolve_path(
                    dataset_key,
                    filename,
                )

                if not path.exists():
                    raise FileNotFoundError(
                        f"Manifest file is missing locally: {path}"
                    )

                display_name = DATASET_DISPLAY_NAMES[dataset_key]

                if dataset_key == "cicids2017":
                    name = display_name
                else:
                    name = (
                        f"{display_name} — {path.stem}"
                    )

                datasets.append(
                    (
                        name,
                        path,
                        dataset_key,
                        LABEL_COLUMNS[dataset_key],
                        role,
                    )
                )

    return datasets


def build_markdown(results: list) -> str:
    lines = []

    lines.append("# Hybrid IDS V3 Dataset Quality Audit")
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append(
        "This audit examines only the V3 datasets assigned to "
        "training and development roles in the frozen split manifest."
    )
    lines.append("")
    lines.append(
        "Final and secondary holdout datasets are intentionally excluded "
        "to prevent accidental inspection before final evaluation."
    )
    lines.append("")
    lines.append(
        "The audit records label distributions, invalid feature values, "
        "zero or negative flow durations, repeated header rows, and rows "
        "that cannot produce the initial V3 common feature representation."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Dataset Summary")
    lines.append("")
    lines.append(
        "| Role | Dataset / File | Total Rows | Usable Rows | Header Rows | "
        "Zero Duration | Negative Duration | Invalid Common Rows |"
    )
    lines.append(
        "|---|---|---:|---:|---:|---:|---:|---:|"
    )

    for result in results:
        lines.append(
            f"| {result['role']} "
            f"| {result['dataset']} "
            f"| {result['total_rows']:,} "
            f"| {result['usable_rows']:,} "
            f"| {result['repeated_header_rows']:,} "
            f"| {result['zero_duration_rows']:,} "
            f"| {result['negative_duration_rows']:,} "
            f"| {result['invalid_common_rows']:,} |"
        )

    for result in results:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"## {result['dataset']}")
        lines.append("")
        lines.append(f"- Role: `{result['role']}`")
        lines.append(f"- Source: `{result['path']}`")
        lines.append(f"- Total rows: {result['total_rows']:,}")
        lines.append(f"- Usable rows: {result['usable_rows']:,}")
        lines.append(
            f"- Repeated header rows: "
            f"{result['repeated_header_rows']:,}"
        )
        lines.append(
            f"- Zero-duration rows: "
            f"{result['zero_duration_rows']:,}"
        )
        lines.append(
            f"- Negative-duration rows: "
            f"{result['negative_duration_rows']:,}"
        )
        lines.append(
            f"- Missing-duration rows: "
            f"{result['missing_duration_rows']:,}"
        )
        lines.append(
            f"- Invalid common-feature rows: "
            f"{result['invalid_common_rows']:,}"
        )
        lines.append("")

        lines.append("### Label Distribution")
        lines.append("")

        for label, count in result["label_counts"].items():
            lines.append(
                f"- {label}: {count:,}"
            )

        lines.append("")
        lines.append("### Invalid Rows by Label")
        lines.append("")

        if result["invalid_by_label"]:
            for label, count in result["invalid_by_label"].items():
                lines.append(
                    f"- {label}: {count:,}"
                )
        else:
            lines.append("- None")

        lines.append("")
        lines.append(
            "### Non-Positive Duration Rows by Label"
        )
        lines.append("")

        if result["nonpositive_duration_by_label"]:
            for label, count in result[
                "nonpositive_duration_by_label"
            ].items():
                lines.append(
                    f"- {label}: {count:,}"
                )
        else:
            lines.append("- None")

        lines.append("")
        lines.append(
            "### Missing Values by Common Feature"
        )
        lines.append("")

        for feature, count in result["feature_missing"].items():
            lines.append(
                f"- `{feature}`: {count:,}"
            )

        lines.append("")
        lines.append(
            "### Negative Values by Common Feature"
        )
        lines.append("")

        for feature, count in result["feature_negative"].items():
            lines.append(
                f"- `{feature}`: {count:,}"
            )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "- Dataset files are selected from "
        "`evaluation/v3_split_manifest.json`."
    )
    lines.append(
        "- Only training and development roles are audited."
    )
    lines.append(
        "- Final and secondary holdouts are excluded from this audit."
    )
    lines.append(
        "- Files are processed in chunks to avoid loading complete "
        "datasets into memory at once."
    )
    lines.append(
        "- Missing or undefined rate features are recorded rather than "
        "replaced with fabricated values."
    )
    lines.append(
        "- Repeated CSV header rows are counted separately and excluded "
        "from usable data."
    )
    lines.append(
        "- No model training or model selection is performed during "
        "this audit."
    )

    return "\n".join(lines)


def main() -> None:
    datasets = build_dataset_list()

    if not datasets:
        raise FileNotFoundError(
            "No V3 training or development datasets were found."
        )

    print(
        "Hybrid IDS V3 Manifest-Controlled Dataset Quality Audit"
    )
    print("=" * 70)

    print(
        "Audited roles: "
        + ", ".join(AUDIT_ROLES)
    )

    print(
        "Final and secondary holdouts are excluded."
    )

    results = []

    for (
        name,
        path,
        mapping_key,
        label_column,
        role,
    ) in datasets:
        result = audit_file(
            name,
            path,
            mapping_key,
            label_column,
            role,
        )

        results.append(result)

    OUTPUT_JSON.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
        )

    OUTPUT_MARKDOWN.write_text(
        build_markdown(results),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("Audit complete.")
    print(f"JSON: {OUTPUT_JSON}")
    print(f"Markdown: {OUTPUT_MARKDOWN}")


if __name__ == "__main__":
    main()
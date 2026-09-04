from pathlib import Path

import numpy as np
import pandas as pd

from src.ml.v3.common_features import transform_common_features, validate_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS


CIC17_PATH = Path("data/cicids2017_multiclass.csv")
CSE2018_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")
UNSW_PATH = Path("evaluation/datasets/UNSW-NB15/UNSW_NB15_testing-set.csv")

OUTPUT_PATH = Path("evaluation/results/summary/v3_common_feature_profile.md")

SAMPLE_ROWS = 100_000


def load_sample(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, nrows=SAMPLE_ROWS, low_memory=False)


def summarize_features(features: pd.DataFrame) -> pd.DataFrame:
    clean = features.replace([np.inf, -np.inf], np.nan)

    rows = []

    for column in clean.columns:
        values = clean[column].dropna()

        if values.empty:
            rows.append(
                {
                    "feature": column,
                    "valid": 0,
                    "missing": int(clean[column].isna().sum()),
                    "min": np.nan,
                    "median": np.nan,
                    "mean": np.nan,
                    "p95": np.nan,
                    "max": np.nan,
                }
            )

            continue

        rows.append(
            {
                "feature": column,
                "valid": int(values.count()),
                "missing": int(clean[column].isna().sum()),
                "min": float(values.min()),
                "median": float(values.median()),
                "mean": float(values.mean()),
                "p95": float(values.quantile(0.95)),
                "max": float(values.max()),
            }
        )

    return pd.DataFrame(rows)


def profile_dataset(name: str, path: Path, mapping_key: str):
    print(f"\n{name}")
    print("-" * 60)
    print(f"File: {path}")

    raw = load_sample(path)

    raw.columns = raw.columns.str.strip()

    common = transform_common_features(
        raw,
        DATASET_MAPPINGS[mapping_key],
    )

    validation = validate_common_features(common)
    summary = summarize_features(common)

    print(f"Rows sampled: {validation['rows']:,}")
    print(f"Fully valid rows: {validation['fully_valid_rows']:,}")

    return {
        "dataset": name,
        "path": str(path),
        "validation": validation,
        "summary": summary,
    }


def write_report(results):
    lines = []

    lines.append("# Hybrid IDS V3 Common Feature Profile")
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append(
        "This report profiles the initial V3 common feature representation "
        "across CIC-IDS-2017, CSE-CIC-IDS2018, and UNSW-NB15."
    )
    lines.append("")
    lines.append(
        "The goal is to identify invalid values, incompatible scales, "
        "and large distribution differences before building a combined "
        "training dataset."
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    for result in results:
        validation = result["validation"]
        summary = result["summary"]

        lines.append(f"## {result['dataset']}")
        lines.append("")
        lines.append(f"- Source: `{result['path']}`")
        lines.append(f"- Rows sampled: {validation['rows']:,}")
        lines.append(f"- Fully valid rows: {validation['fully_valid_rows']:,}")
        lines.append("")

        lines.append("| Feature | Valid | Missing | Min | Median | Mean | P95 | Max |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")

        for _, row in summary.iterrows():
            lines.append(
                f"| `{row['feature']}` "
                f"| {int(row['valid']):,} "
                f"| {int(row['missing']):,} "
                f"| {row['min']:.6g} "
                f"| {row['median']:.6g} "
                f"| {row['mean']:.6g} "
                f"| {row['p95']:.6g} "
                f"| {row['max']:.6g} |"
            )

        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Methodology Note")
    lines.append("")
    lines.append(
        "These statistics are exploratory development measurements. "
        "They are not model evaluation results."
    )
    lines.append("")
    lines.append(
        "Large differences between datasets will be documented rather than "
        "silently normalized away. Any scaling or transformation selected "
        "later must be fitted using training data only."
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main():
    cse_files = sorted(CSE2018_DIRECTORY.glob("*.csv"))

    if not cse_files:
        raise FileNotFoundError(
            f"No CSE-CIC-IDS2018 files found in {CSE2018_DIRECTORY}"
        )

    results = [
        profile_dataset(
            "CIC-IDS-2017",
            CIC17_PATH,
            "cicids2017",
        ),
        profile_dataset(
            "CSE-CIC-IDS2018",
            cse_files[0],
            "cse_cic_ids2018",
        ),
        profile_dataset(
            "UNSW-NB15",
            UNSW_PATH,
            "unsw_nb15",
        ),
    ]

    write_report(results)

    print()
    print(f"Report saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
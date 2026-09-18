import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import V3_FEATURE_SET_C, get_mapping
from src.ml.v3.label_schema import (
    ATTACK,
    BENIGN,
    UNMAPPED_ATTACK,
    get_family_label,
)


MANIFEST_PATH = Path("evaluation/v3_split_manifest.json")

CSE_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")
UNSW_DIRECTORY = Path("evaluation/datasets/UNSW-NB15")

OUTPUT_DIRECTORY = Path("data/v3")
OUTPUT_DATASET_PATH = OUTPUT_DIRECTORY / "stage2_feature_set_c.csv"

RESULT_DIRECTORY = Path("evaluation/results/v3/stage2")
REPORT_JSON_PATH = RESULT_DIRECTORY / "v3_stage2_dataset_build.json"
REPORT_MARKDOWN_PATH = RESULT_DIRECTORY / "v3_stage2_dataset_build.md"

CHUNK_SIZE = 100_000
MAX_ROWS_PER_DATASET_FAMILY = 100_000
RANDOM_STATE = 42

SAMPLING_METHOD = "deterministic_random_priority_top_k"

FEATURE_SET = "C"
FEATURES = V3_FEATURE_SET_C


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def resolve_path(dataset_key: str, filename: str) -> Path:
    if dataset_key == "cicids2017":
        return Path(filename)

    if dataset_key == "cse_cic_ids2018":
        return CSE_DIRECTORY / filename

    if dataset_key == "unsw_nb15":
        return UNSW_DIRECTORY / filename

    raise KeyError(
        f"Unknown dataset key: {dataset_key}"
    )


def get_label_column(dataset_key: str) -> str:
    if dataset_key in {
        "cicids2017",
        "cse_cic_ids2018",
    }:
        return "Label"

    if dataset_key == "unsw_nb15":
        return "attack_cat"

    raise KeyError(
        f"Unknown dataset key: {dataset_key}"
    )


def get_sampling_seed(
    key: tuple[str, str],
) -> int:
    text = (
        f"{RANDOM_STATE}|"
        f"{key[0]}|"
        f"{key[1]}"
    )

    digest = hashlib.sha256(
        text.encode("utf-8")
    ).digest()

    return int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=False,
    )


def get_sampling_rng(
    rngs: dict,
    key: tuple[str, str],
) -> np.random.Generator:
    if key not in rngs:
        rngs[key] = np.random.default_rng(
            get_sampling_seed(key)
        )

    return rngs[key]


def uniform_priority_sample_add(
    samples: dict,
    rngs: dict,
    key: tuple[str, str],
    dataframe: pd.DataFrame,
) -> None:
    if dataframe.empty:
        return

    rng = get_sampling_rng(
        rngs,
        key,
    )

    candidate = dataframe.copy()

    candidate["_sample_priority"] = (
        rng.random(len(candidate))
    )

    if key in samples:
        candidate = pd.concat(
            [
                samples[key],
                candidate,
            ],
            ignore_index=True,
        )

    if (
        len(candidate)
        > MAX_ROWS_PER_DATASET_FAMILY
    ):
        candidate = candidate.nsmallest(
            MAX_ROWS_PER_DATASET_FAMILY,
            "_sample_priority",
            keep="first",
        )

    samples[key] = candidate.reset_index(
        drop=True
    )


def extract_raw_labels(
    dataset_key: str,
    dataframe: pd.DataFrame,
) -> pd.Series:
    label_column = get_label_column(
        dataset_key
    )

    if label_column not in dataframe.columns:
        raise KeyError(
            f"{dataset_key} is missing "
            f"label column '{label_column}'"
        )

    labels = (
        dataframe[label_column]
        .astype("string")
        .fillna("")
        .str.strip()
    )

    if dataset_key == "unsw_nb15":
        if "label" in dataframe.columns:
            binary = pd.to_numeric(
                dataframe["label"],
                errors="coerce",
            )

            normal_mask = (
                labels.eq("")
                & binary.eq(0)
            )

            attack_mask = (
                labels.eq("")
                & binary.eq(1)
            )

            labels = labels.mask(
                normal_mask,
                "Normal",
            )

            labels = labels.mask(
                attack_mask,
                "UNMAPPED_RAW_ATTACK",
            )

    return labels


def counter_to_dict(
    counter: Counter,
) -> dict:
    return {
        str(key): int(value)
        for key, value
        in sorted(
            counter.items(),
            key=lambda item: str(item[0]),
        )
    }


def tuple_counter_to_nested_dict(
    counter: Counter,
) -> dict:
    output = {}

    for (
        dataset_key,
        family,
    ), count in sorted(
        counter.items()
    ):
        output.setdefault(
            dataset_key,
            {},
        )

        output[dataset_key][family] = int(
            count
        )

    return output


def process_training_file(
    dataset_key: str,
    path: Path,
    samples: dict,
    rngs: dict,
    global_counts: dict,
    mapped_family_counts: Counter,
    valid_family_counts: Counter,
    sampled_input_counts: Counter,
    unmapped_raw_label_counts: Counter,
    dataset_family_counts: Counter,
) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Training file not found: {path}"
        )

    mapping = get_mapping(dataset_key)

    file_stats = {
        "dataset": dataset_key,
        "file": str(path),
        "raw_rows": 0,
        "rows_after_header_cleanup": 0,
        "attack_rows": 0,
        "mapped_attack_rows": 0,
        "unmapped_attack_rows": 0,
        "invalid_feature_rows": 0,
        "valid_mapped_attack_rows": 0,
    }

    print()
    print("=" * 70)
    print(
        f"Processing {dataset_key}: "
        f"{path.name}"
    )

    for dataframe in pd.read_csv(
        path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        file_stats["raw_rows"] += len(
            dataframe
        )

        global_counts["raw_rows"] += len(
            dataframe
        )

        raw_labels = extract_raw_labels(
            dataset_key,
            dataframe,
        )

        label_column = get_label_column(
            dataset_key
        )

        repeated_header_mask = (
            raw_labels.str.lower()
            == label_column.lower()
        )

        if repeated_header_mask.any():
            dataframe = dataframe.loc[
                ~repeated_header_mask
            ].copy()

            raw_labels = raw_labels.loc[
                ~repeated_header_mask
            ].copy()

        file_stats[
            "rows_after_header_cleanup"
        ] += len(dataframe)

        global_counts[
            "rows_after_header_cleanup"
        ] += len(dataframe)

        family_labels = pd.Series(
            [
                get_family_label(
                    dataset_key,
                    raw_label,
                )
                for raw_label
                in raw_labels
            ],
            index=dataframe.index,
            dtype="string",
        )

        attack_mask = (
            family_labels != BENIGN
        )

        mapped_mask = (
            attack_mask
            & (
                family_labels
                != UNMAPPED_ATTACK
            )
        )

        unmapped_mask = (
            family_labels
            == UNMAPPED_ATTACK
        )

        attack_count = int(
            attack_mask.sum()
        )

        mapped_count = int(
            mapped_mask.sum()
        )

        unmapped_count = int(
            unmapped_mask.sum()
        )

        file_stats[
            "attack_rows"
        ] += attack_count

        file_stats[
            "mapped_attack_rows"
        ] += mapped_count

        file_stats[
            "unmapped_attack_rows"
        ] += unmapped_count

        global_counts[
            "attack_rows"
        ] += attack_count

        global_counts[
            "mapped_attack_rows"
        ] += mapped_count

        global_counts[
            "unmapped_attack_rows"
        ] += unmapped_count

        mapped_labels = family_labels.loc[
            mapped_mask
        ]

        mapped_family_counts.update(
            mapped_labels.tolist()
        )

        for family in mapped_labels:
            dataset_family_counts[
                (
                    dataset_key,
                    str(family),
                )
            ] += 1

        if unmapped_count:
            unmapped_labels = raw_labels.loc[
                unmapped_mask
            ]

            for raw_label in unmapped_labels:
                unmapped_raw_label_counts[
                    (
                        dataset_key,
                        str(raw_label),
                    )
                ] += 1

        if not mapped_mask.any():
            continue

        mapped_dataframe = dataframe.loc[
            mapped_mask
        ].copy()

        mapped_raw_labels = raw_labels.loc[
            mapped_mask
        ].copy()

        mapped_family = family_labels.loc[
            mapped_mask
        ].copy()

        common_features = (
            transform_common_features(
                mapped_dataframe,
                mapping,
            )
        )

        common_features = (
            common_features[FEATURES]
            .replace(
                [np.inf, -np.inf],
                np.nan,
            )
        )

        valid_mask = (
            common_features
            .notna()
            .all(axis=1)
        )

        invalid_count = int(
            (~valid_mask).sum()
        )

        file_stats[
            "invalid_feature_rows"
        ] += invalid_count

        global_counts[
            "invalid_feature_rows"
        ] += invalid_count

        common_features = (
            common_features.loc[
                valid_mask
            ].copy()
        )

        valid_raw_labels = (
            mapped_raw_labels.loc[
                valid_mask
            ].copy()
        )

        valid_family = (
            mapped_family.loc[
                valid_mask
            ].copy()
        )

        valid_count = len(
            common_features
        )

        file_stats[
            "valid_mapped_attack_rows"
        ] += valid_count

        global_counts[
            "valid_mapped_attack_rows"
        ] += valid_count

        valid_family_counts.update(
            valid_family.tolist()
        )

        prepared = common_features.copy()

        prepared[
            "binary_label"
        ] = ATTACK

        prepared[
            "family_label"
        ] = valid_family.astype(str)

        prepared[
            "raw_label"
        ] = valid_raw_labels.astype(str)

        prepared[
            "source_dataset"
        ] = dataset_key

        prepared[
            "source_file"
        ] = path.name

        for family, group in prepared.groupby(
            "family_label",
            sort=True,
        ):
            key = (
                dataset_key,
                str(family),
            )

            sampled_input_counts[
                key
            ] += len(group)

            uniform_priority_sample_add(
                samples,
                rngs,
                key,
                group,
            )

    print(
        "Raw rows: "
        f"{file_stats['raw_rows']:,}"
    )

    print(
        "Attack rows: "
        f"{file_stats['attack_rows']:,}"
    )

    print(
        "Mapped Stage 2 rows: "
        f"{file_stats['mapped_attack_rows']:,}"
    )

    print(
        "Unmapped attack rows: "
        f"{file_stats['unmapped_attack_rows']:,}"
    )

    print(
        "Invalid Feature Set C rows: "
        f"{file_stats['invalid_feature_rows']:,}"
    )

    print(
        "Valid Stage 2 rows: "
        f"{file_stats['valid_mapped_attack_rows']:,}"
    )

    return file_stats


def build_markdown_report(
    report: dict,
) -> str:
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 2 Dataset Build"
    )
    lines.append("")
    lines.append(
        "Stage 2 contains only mapped attack "
        "families from the frozen V3 training "
        "partition."
    )
    lines.append("")
    lines.append(
        "Development, final holdout, and "
        "secondary holdout datasets were not "
        "opened by this build."
    )
    lines.append("")

    lines.append("## Configuration")
    lines.append("")
    lines.append(
        f"- Feature set: {report['feature_set']}"
    )
    lines.append(
        f"- Feature count: "
        f"{len(report['features'])}"
    )
    lines.append(
        f"- Sampling method: "
        f"{report['sampling']['method']}"
    )
    lines.append(
        f"- Maximum rows per dataset/family: "
        f"{report['sampling']['max_rows_per_dataset_family']:,}"
    )
    lines.append(
        f"- Random state: "
        f"{report['sampling']['random_state']}"
    )
    lines.append("")

    totals = report["totals"]

    lines.append("## Totals")
    lines.append("")
    lines.append(
        f"- Raw training rows read: "
        f"{totals['raw_rows']:,}"
    )
    lines.append(
        f"- Attack rows: "
        f"{totals['attack_rows']:,}"
    )
    lines.append(
        f"- Mapped Stage 2 attack rows: "
        f"{totals['mapped_attack_rows']:,}"
    )
    lines.append(
        f"- Unmapped attack rows: "
        f"{totals['unmapped_attack_rows']:,}"
    )
    lines.append(
        f"- Invalid Feature Set C rows: "
        f"{totals['invalid_feature_rows']:,}"
    )
    lines.append(
        f"- Valid mapped rows: "
        f"{totals['valid_mapped_attack_rows']:,}"
    )
    lines.append(
        f"- Final sampled rows: "
        f"{totals['sampled_rows']:,}"
    )
    lines.append("")

    lines.append(
        "## Final sampled family counts"
    )
    lines.append("")
    lines.append(
        "| Family | Rows |"
    )
    lines.append(
        "|---|---:|"
    )

    for family, count in report[
        "sampled_family_counts"
    ].items():
        lines.append(
            f"| {family} | {count:,} |"
        )

    lines.append("")

    lines.append(
        "## Dataset/family sampled counts"
    )
    lines.append("")

    for dataset_key, families in report[
        "sampled_dataset_family_counts"
    ].items():
        lines.append(
            f"### {dataset_key}"
        )
        lines.append("")
        lines.append(
            "| Family | Rows |"
        )
        lines.append(
            "|---|---:|"
        )

        for family, count in families.items():
            lines.append(
                f"| {family} | {count:,} |"
            )

        lines.append("")

    lines.append(
        "## Unmapped attack raw labels"
    )
    lines.append("")

    unmapped = report[
        "unmapped_attack_raw_labels"
    ]

    if not unmapped:
        lines.append(
            "No unmapped attack labels were observed."
        )
    else:
        lines.append(
            "| Dataset | Raw label | Rows |"
        )
        lines.append(
            "|---|---|---:|"
        )

        for dataset_key, labels in (
            unmapped.items()
        ):
            for raw_label, count in (
                labels.items()
            ):
                lines.append(
                    f"| {dataset_key} | "
                    f"{raw_label} | "
                    f"{count:,} |"
                )

    lines.append("")

    return "\n".join(lines)


def main():
    print(
        "Hybrid IDS V3 Stage 2 "
        "Dataset Builder"
    )

    print("=" * 70)

    with MANIFEST_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        manifest = json.load(file)

    training_manifest = manifest.get(
        "training"
    )

    if not training_manifest:
        raise ValueError(
            "Manifest does not contain "
            "a training partition."
        )

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    samples = {}
    rngs = {}

    global_counts = {
        "raw_rows": 0,
        "rows_after_header_cleanup": 0,
        "attack_rows": 0,
        "mapped_attack_rows": 0,
        "unmapped_attack_rows": 0,
        "invalid_feature_rows": 0,
        "valid_mapped_attack_rows": 0,
    }

    mapped_family_counts = Counter()
    valid_family_counts = Counter()
    sampled_input_counts = Counter()
    unmapped_raw_label_counts = Counter()
    dataset_family_counts = Counter()

    file_stats = []

    for (
        dataset_key,
        filenames,
    ) in training_manifest.items():
        for filename in filenames:
            path = resolve_path(
                dataset_key,
                filename,
            )

            stats = process_training_file(
                dataset_key,
                path,
                samples,
                rngs,
                global_counts,
                mapped_family_counts,
                valid_family_counts,
                sampled_input_counts,
                unmapped_raw_label_counts,
                dataset_family_counts,
            )

            file_stats.append(stats)

    sampled_frames = []

    sampled_dataset_family_counts = Counter()
    sampled_family_counts = Counter()

    for key in sorted(samples):
        dataframe = samples[key].copy()

        dataset_key, family = key

        sampled_dataset_family_counts[
            key
        ] = len(dataframe)

        sampled_family_counts[
            family
        ] += len(dataframe)

        dataframe = dataframe.sort_values(
            "_sample_priority",
            kind="stable",
        )

        sampled_frames.append(
            dataframe
        )

    if not sampled_frames:
        raise RuntimeError(
            "No Stage 2 training rows "
            "were produced."
        )

    output = pd.concat(
        sampled_frames,
        ignore_index=True,
    )

    output = output.drop(
        columns=["_sample_priority"]
    )

    output = output[
        FEATURES
        + [
            "binary_label",
            "family_label",
            "raw_label",
            "source_dataset",
            "source_file",
        ]
    ]

    output.to_csv(
        OUTPUT_DATASET_PATH,
        index=False,
    )

    global_counts[
        "sampled_rows"
    ] = len(output)

    unmapped_nested = {}

    for (
        dataset_key,
        raw_label,
    ), count in sorted(
        unmapped_raw_label_counts.items()
    ):
        unmapped_nested.setdefault(
            dataset_key,
            {},
        )

        unmapped_nested[
            dataset_key
        ][raw_label] = int(count)

    report = {
        "version": "V3",
        "stage": "Stage 2 attack-family dataset",
        "feature_set": FEATURE_SET,
        "features": FEATURES,
        "manifest": {
            "path": str(MANIFEST_PATH),
            "sha256": sha256_file(
                MANIFEST_PATH
            ),
            "partition_used": "training",
        },
        "sampling": {
            "method": SAMPLING_METHOD,
            "random_state": RANDOM_STATE,
            "max_rows_per_dataset_family":
                MAX_ROWS_PER_DATASET_FAMILY,
            "grouping":
                "source_dataset x family_label",
        },
        "policy": {
            "benign_rows_in_stage2_training":
                False,
            "unmapped_attack_rows_in_stage2_training":
                False,
            "development_data_used":
                False,
            "final_holdout_data_used":
                False,
            "secondary_holdout_data_used":
                False,
            "missing_features_fabricated":
                False,
        },
        "totals": {
            key: int(value)
            for key, value
            in global_counts.items()
        },
        "mapped_family_counts_before_feature_validation":
            counter_to_dict(
                mapped_family_counts
            ),
        "valid_family_counts":
            counter_to_dict(
                valid_family_counts
            ),
        "sampled_family_counts":
            counter_to_dict(
                sampled_family_counts
            ),
        "observed_dataset_family_counts":
            tuple_counter_to_nested_dict(
                dataset_family_counts
            ),
        "sampled_dataset_family_counts":
            tuple_counter_to_nested_dict(
                sampled_dataset_family_counts
            ),
        "unmapped_attack_raw_labels":
            unmapped_nested,
        "source_files": file_stats,
        "output": {
            "dataset": str(
                OUTPUT_DATASET_PATH
            ),
            "report_json": str(
                REPORT_JSON_PATH
            ),
            "report_markdown": str(
                REPORT_MARKDOWN_PATH
            ),
        },
    }

    with REPORT_JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    markdown = build_markdown_report(
        report
    )

    REPORT_MARKDOWN_PATH.write_text(
        markdown,
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print(
        "V3 Stage 2 dataset build complete."
    )

    print()
    print(
        "Final sampled family distribution:"
    )

    for family, count in sorted(
        sampled_family_counts.items()
    ):
        print(
            f"{family}: {count:,}"
        )

    print()
    print(
        f"Total Stage 2 rows: "
        f"{len(output):,}"
    )

    print(
        f"Dataset: "
        f"{OUTPUT_DATASET_PATH}"
    )

    print(
        f"Report: "
        f"{REPORT_JSON_PATH}"
    )

    print()
    print(
        "Development and holdout "
        "partitions were not opened."
    )


if __name__ == "__main__":
    main()
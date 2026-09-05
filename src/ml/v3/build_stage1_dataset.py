from collections import defaultdict
from pathlib import Path
import hashlib
import json

import numpy as np
import pandas as pd

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS, V3_FEATURE_SETS
from src.ml.v3.label_schema import get_binary_label


MANIFEST_PATH = Path("evaluation/v3_split_manifest.json")

CSE_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")
UNSW_DIRECTORY = Path("evaluation/datasets/UNSW-NB15")
OUTPUT_DIRECTORY = Path("data/v3")

CHUNK_SIZE = 100_000
MAX_ROWS_PER_DATASET_CLASS = 100_000
RANDOM_STATE = 42

SAMPLING_METHOD = "deterministic_random_priority_top_k"


def resolve_path(dataset_key: str, filename: str) -> Path:
    if dataset_key == "cicids2017":
        return Path(filename)

    if dataset_key == "cse_cic_ids2018":
        return CSE_DIRECTORY / filename

    if dataset_key == "unsw_nb15":
        return UNSW_DIRECTORY / filename

    raise KeyError(f"Unknown dataset key: {dataset_key}")


def get_label_column(dataset_key: str) -> str:
    if dataset_key in {
        "cicids2017",
        "cse_cic_ids2018",
    }:
        return "Label"

    if dataset_key == "unsw_nb15":
        return "attack_cat"

    raise KeyError(f"Unknown dataset key: {dataset_key}")


def get_sampling_seed(key: tuple[str, str]) -> int:
    dataset_key, binary_class = key

    seed_material = (
        f"{RANDOM_STATE}|"
        f"{dataset_key}|"
        f"{binary_class}"
    ).encode("utf-8")

    digest = hashlib.sha256(
        seed_material
    ).digest()

    return int.from_bytes(
        digest[:8],
        byteorder="little",
        signed=False,
    )


def get_sampling_rng(
    rngs: dict,
    key: tuple[str, str],
):
    if key not in rngs:
        rngs[key] = np.random.default_rng(
            get_sampling_seed(key)
        )

    return rngs[key]


def uniform_priority_sample_add(
    storage,
    key,
    dataframe,
    limit,
    rngs,
):
    if dataframe.empty:
        return

    candidate = dataframe.copy()

    rng = get_sampling_rng(
        rngs,
        key,
    )

    candidate["_sample_priority"] = rng.random(
        len(candidate)
    )

    existing = storage[key]

    if existing is None:
        combined = candidate
    else:
        combined = pd.concat(
            [
                existing,
                candidate,
            ],
            ignore_index=True,
        )

    if len(combined) > limit:
        combined = (
            combined
            .nsmallest(
                limit,
                "_sample_priority",
                keep="first",
            )
            .reset_index(drop=True)
        )

    storage[key] = combined


def process_training_file(
    dataset_key,
    filename,
    storage,
    statistics,
    rngs,
):
    path = resolve_path(
        dataset_key,
        filename,
    )

    label_column = get_label_column(
        dataset_key
    )

    mapping = DATASET_MAPPINGS[
        dataset_key
    ]

    print()
    print("=" * 70)
    print(f"Dataset: {dataset_key}")
    print(f"File: {path}")

    if not path.exists():
        raise FileNotFoundError(
            f"Missing training file: {path}"
        )

    total_rows = 0
    invalid_header_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            path,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        chunk.columns = (
            chunk.columns.str.strip()
        )

        if label_column not in chunk.columns:
            raise KeyError(
                f"{path} does not contain "
                f"label column '{label_column}'"
            )

        raw_labels = (
            chunk[label_column]
            .astype("string")
            .str.strip()
        )

        header_mask = raw_labels.eq(
            label_column
        )

        invalid_header_rows += int(
            header_mask.sum()
        )

        chunk = chunk.loc[
            ~header_mask
        ].copy()

        raw_labels = raw_labels.loc[
            ~header_mask
        ]

        total_rows += len(chunk)

        features = transform_common_features(
            chunk,
            mapping,
        )

        binary_labels = raw_labels.map(
            lambda value: get_binary_label(
                dataset_key,
                value,
            )
        )

        for binary_class in [
            "BENIGN",
            "ATTACK",
        ]:
            mask = binary_labels.eq(
                binary_class
            )

            class_features = features.loc[
                mask
            ].copy()

            class_features[
                "binary_label"
            ] = binary_class

            class_features[
                "source_dataset"
            ] = dataset_key

            class_features[
                "source_file"
            ] = filename

            storage_key = (
                dataset_key,
                binary_class,
            )

            uniform_priority_sample_add(
                storage,
                storage_key,
                class_features,
                MAX_ROWS_PER_DATASET_CLASS,
                rngs,
            )

            statistics[
                dataset_key
            ][binary_class][
                "observed"
            ] += int(mask.sum())

        print(
            f"Chunk {chunk_number}: "
            f"rows={len(chunk):,}"
        )

    statistics[
        dataset_key
    ]["metadata"]["rows"] += total_rows

    statistics[
        dataset_key
    ]["metadata"][
        "header_rows"
    ] += invalid_header_rows


def build_feature_set(
    dataframe,
    feature_set_name,
):
    selected_features = V3_FEATURE_SETS[
        feature_set_name
    ]

    output = dataframe[
        selected_features
        + [
            "binary_label",
            "source_dataset",
            "source_file",
        ]
    ].copy()

    feature_values = output[
        selected_features
    ].replace(
        [np.inf, -np.inf],
        np.nan,
    )

    valid_mask = (
        feature_values
        .notna()
        .all(axis=1)
    )

    valid = output.loc[
        valid_mask
    ].reset_index(drop=True)

    return (
        valid,
        int((~valid_mask).sum()),
    )


def main():
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Missing split manifest: "
            f"{MANIFEST_PATH}"
        )

    with MANIFEST_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        manifest = json.load(file)

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    storage = defaultdict(
        lambda: None
    )

    sampling_rngs = {}

    statistics = defaultdict(
        lambda: {
            "BENIGN": {
                "observed": 0,
                "sampled": 0,
            },
            "ATTACK": {
                "observed": 0,
                "sampled": 0,
            },
            "metadata": {
                "rows": 0,
                "header_rows": 0,
            },
        }
    )

    print(
        "Hybrid IDS V3 Stage 1 Dataset Builder"
    )
    print("=" * 70)

    print(
        f"Sampling method: "
        f"{SAMPLING_METHOD}"
    )

    print(
        f"Maximum rows per "
        f"dataset/class: "
        f"{MAX_ROWS_PER_DATASET_CLASS:,}"
    )

    print(
        "Only manifest training sources "
        "will be processed."
    )

    for dataset_key, filenames in (
        manifest["training"].items()
    ):
        for filename in filenames:
            process_training_file(
                dataset_key,
                filename,
                storage,
                statistics,
                sampling_rngs,
            )

    pieces = []

    print()
    print("=" * 70)
    print("Sampled training rows")
    print("=" * 70)

    for key in sorted(storage):
        dataset_key, binary_class = key

        dataframe = storage[key]

        if dataframe is None:
            sampled = 0
        else:
            sampled = len(dataframe)

            prepared_sample = (
                dataframe
                .drop(
                    columns=[
                        "_sample_priority"
                    ],
                    errors="ignore",
                )
                .reset_index(drop=True)
            )

            pieces.append(
                prepared_sample
            )

        statistics[
            dataset_key
        ][binary_class][
            "sampled"
        ] = sampled

        observed = statistics[
            dataset_key
        ][binary_class][
            "observed"
        ]

        print(
            f"{dataset_key:<20} "
            f"{binary_class:<8} "
            f"observed={observed:>10,} "
            f"sampled={sampled:>10,}"
        )

    if not pieces:
        raise RuntimeError(
            "No training rows were collected."
        )

    combined = pd.concat(
        pieces,
        ignore_index=True,
    )

    combined = combined.sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    report = {
        "random_state": RANDOM_STATE,
        "max_rows_per_dataset_class": (
            MAX_ROWS_PER_DATASET_CLASS
        ),
        "sampling": {
            "method": SAMPLING_METHOD,
            "scope": (
                "each dataset and binary class"
            ),
            "deterministic": True,
            "uniform_without_replacement_equivalent": True,
            "description": (
                "Each eligible row receives an "
                "independent deterministic pseudorandom "
                "priority. The rows with the smallest "
                "priorities are retained for each "
                "dataset/class group."
            ),
            "group_seeds": {},
        },
        "training_sources": (
            manifest["training"]
        ),
        "datasets": {},
        "feature_sets": {},
    }

    for key in sorted(storage):
        dataset_key, binary_class = key

        report["sampling"][
            "group_seeds"
        ][
            f"{dataset_key}|{binary_class}"
        ] = get_sampling_seed(key)

    for (
        dataset_key,
        dataset_stats,
    ) in statistics.items():
        report["datasets"][
            dataset_key
        ] = {
            "rows_observed": (
                dataset_stats[
                    "metadata"
                ]["rows"]
            ),
            "header_rows_removed": (
                dataset_stats[
                    "metadata"
                ]["header_rows"]
            ),
            "benign_observed": (
                dataset_stats[
                    "BENIGN"
                ]["observed"]
            ),
            "benign_sampled": (
                dataset_stats[
                    "BENIGN"
                ]["sampled"]
            ),
            "attack_observed": (
                dataset_stats[
                    "ATTACK"
                ]["observed"]
            ),
            "attack_sampled": (
                dataset_stats[
                    "ATTACK"
                ]["sampled"]
            ),
        }

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        prepared, invalid_rows = (
            build_feature_set(
                combined,
                feature_set_name,
            )
        )

        output_path = (
            OUTPUT_DIRECTORY
            / (
                "stage1_feature_set_"
                f"{feature_set_name.lower()}.csv"
            )
        )

        prepared.to_csv(
            output_path,
            index=False,
        )

        report["feature_sets"][
            feature_set_name
        ] = {
            "features": (
                V3_FEATURE_SETS[
                    feature_set_name
                ]
            ),
            "rows": len(prepared),
            "rows_removed_for_invalid_features": (
                invalid_rows
            ),
            "binary_distribution": {
                str(label): int(count)
                for label, count
                in prepared[
                    "binary_label"
                ].value_counts().items()
            },
            "source_distribution": {
                str(label): int(count)
                for label, count
                in prepared[
                    "source_dataset"
                ].value_counts().items()
            },
            "output": str(
                output_path
            ),
        }

        print()
        print(
            f"Feature Set "
            f"{feature_set_name}: "
            f"{len(prepared):,} rows"
        )

        print(
            f"Invalid rows removed: "
            f"{invalid_rows:,}"
        )

        print(
            prepared[
                "binary_label"
            ]
            .value_counts()
            .to_string()
        )

        print()
        print(
            "Source distribution:"
        )

        print(
            prepared[
                "source_dataset"
            ]
            .value_counts()
            .to_string()
        )

    report_path = (
        Path(
            "evaluation/results/summary"
        )
        / "v3_stage1_dataset_build.json"
    )

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with report_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    print()
    print("=" * 70)
    print("Stage 1 dataset build complete.")
    print(
        f"Sampling method: "
        f"{SAMPLING_METHOD}"
    )
    print(
        f"Report: {report_path}"
    )


if __name__ == "__main__":
    main()
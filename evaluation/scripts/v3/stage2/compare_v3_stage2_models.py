import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

from src.ml.v3.feature_schema import V3_FEATURE_SET_C


DATASET_PATH = Path("data/v3/stage2_feature_set_c.csv")

RESULT_DIRECTORY = Path("evaluation/results/v3/stage2")
RESULT_JSON_PATH = RESULT_DIRECTORY / "v3_stage2_algorithm_comparison.json"
RESULT_MARKDOWN_PATH = RESULT_DIRECTORY / "v3_stage2_algorithm_comparison.md"

RANDOM_STATE = 42
N_SPLITS = 5

CORE_FAMILIES = [
    "BruteForce",
    "DDoS",
    "DoS",
    "Reconnaissance",
]

FEATURES = V3_FEATURE_SET_C

CLASS_TO_ID = {
    family: index
    for index, family in enumerate(CORE_FAMILIES)
}

ID_TO_CLASS = {
    index: family
    for family, index in CLASS_TO_ID.items()
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def counts_dict(series: pd.Series) -> dict:
    counts = series.value_counts()

    return {
        str(key): int(value)
        for key, value in sorted(
            counts.items(),
            key=lambda item: str(item[0]),
        )
    }


def source_family_counts(dataframe: pd.DataFrame) -> dict:
    grouped = (
        dataframe.groupby(
            ["source_dataset", "family_label"]
        )
        .size()
    )

    output = {}

    for (
        source_dataset,
        family,
    ), count in grouped.items():
        output.setdefault(
            str(source_dataset),
            {},
        )

        output[
            str(source_dataset)
        ][str(family)] = int(count)

    return output


def make_feature_signature(
    dataframe: pd.DataFrame,
) -> pd.Series:
    return pd.util.hash_pandas_object(
        dataframe[FEATURES],
        index=False,
    ).astype("uint64")


def create_grouped_split(
    dataframe: pd.DataFrame,
):
    X = dataframe[FEATURES].copy()

    y = dataframe[
        "family_label"
    ].map(CLASS_TO_ID)

    if y.isna().any():
        unknown = sorted(
            dataframe.loc[
                y.isna(),
                "family_label",
            ]
            .astype(str)
            .unique()
            .tolist()
        )

        raise ValueError(
            "Unexpected Stage 2 family labels: "
            f"{unknown}"
        )

    y = y.astype(int)

    groups = make_feature_signature(
        dataframe
    )

    splitter = StratifiedGroupKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    train_indices, test_indices = next(
        splitter.split(
            X,
            y,
            groups=groups,
        )
    )

    train_groups = groups.iloc[
        train_indices
    ].unique()

    test_groups = groups.iloc[
        test_indices
    ].unique()

    overlap = np.intersect1d(
        train_groups,
        test_groups,
    )

    if len(overlap) != 0:
        raise RuntimeError(
            "Feature-signature leakage detected "
            "between train and test splits."
        )

    return (
        X,
        y,
        groups,
        train_indices,
        test_indices,
    )


def evaluate_predictions(
    y_true: pd.Series,
    y_pred: np.ndarray,
) -> dict:
    labels = list(
        range(len(CORE_FAMILIES))
    )

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    balanced_accuracy = (
        balanced_accuracy_score(
            y_true,
            y_pred,
        )
    )

    (
        precision,
        recall,
        f1,
        support,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average=None,
        zero_division=0,
    )

    (
        macro_precision,
        macro_recall,
        macro_f1,
        _,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="macro",
        zero_division=0,
    )

    (
        weighted_precision,
        weighted_recall,
        weighted_f1,
        _,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=labels,
    )

    per_class = {}

    for class_id in labels:
        family = ID_TO_CLASS[
            class_id
        ]

        per_class[family] = {
            "precision": float(
                precision[class_id]
            ),
            "recall": float(
                recall[class_id]
            ),
            "f1": float(
                f1[class_id]
            ),
            "support": int(
                support[class_id]
            ),
        }

    return {
        "accuracy": float(accuracy),
        "balanced_accuracy": float(
            balanced_accuracy
        ),
        "macro_precision": float(
            macro_precision
        ),
        "macro_recall": float(
            macro_recall
        ),
        "macro_f1": float(
            macro_f1
        ),
        "weighted_precision": float(
            weighted_precision
        ),
        "weighted_recall": float(
            weighted_recall
        ),
        "weighted_f1": float(
            weighted_f1
        ),
        "per_class": per_class,
        "confusion_matrix": {
            "labels": CORE_FAMILIES,
            "values": matrix.tolist(),
        },
    }


def build_models() -> dict:
    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "HistGradientBoosting":
            HistGradientBoostingClassifier(
                learning_rate=0.1,
                max_iter=200,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                random_state=RANDOM_STATE,
            ),
    }


def train_and_evaluate(
    model_name: str,
    model,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict:
    print()
    print("=" * 70)
    print(f"Training {model_name}")

    train_start = time.perf_counter()

    if model_name == "HistGradientBoosting":
        sample_weights = (
            compute_sample_weight(
                class_weight="balanced",
                y=y_train,
            )
        )

        model.fit(
            X_train,
            y_train,
            sample_weight=sample_weights,
        )

    else:
        model.fit(
            X_train,
            y_train,
        )

    train_seconds = (
        time.perf_counter()
        - train_start
    )

    inference_start = (
        time.perf_counter()
    )

    predictions = model.predict(
        X_test
    )

    inference_seconds = (
        time.perf_counter()
        - inference_start
    )

    metrics = evaluate_predictions(
        y_test,
        predictions,
    )

    throughput = (
        len(X_test) / inference_seconds
        if inference_seconds > 0
        else None
    )

    print(
        f"Accuracy: "
        f"{metrics['accuracy'] * 100:.4f}%"
    )

    print(
        f"Balanced accuracy: "
        f"{metrics['balanced_accuracy'] * 100:.4f}%"
    )

    print(
        f"Macro F1: "
        f"{metrics['macro_f1'] * 100:.4f}%"
    )

    print(
        f"Weighted F1: "
        f"{metrics['weighted_f1'] * 100:.4f}%"
    )

    print(
        f"Training time: "
        f"{train_seconds:.2f} seconds"
    )

    print(
        f"Inference throughput: "
        f"{throughput:,.0f} rows/sec"
    )

    print()
    print("Per-family recall:")

    for family in CORE_FAMILIES:
        recall = metrics[
            "per_class"
        ][family]["recall"]

        print(
            f"  {family}: "
            f"{recall * 100:.4f}%"
        )

    return {
        "model": model_name,
        "parameters": model.get_params(),
        "train_seconds": float(
            train_seconds
        ),
        "inference_seconds": float(
            inference_seconds
        ),
        "inference_rows_per_second":
            float(throughput),
        "metrics": metrics,
    }


def build_markdown_report(
    report: dict,
) -> str:
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 2 "
        "Algorithm Comparison"
    )
    lines.append("")

    lines.append(
        "This experiment compares candidate "
        "classifiers for the V3 Stage 2 "
        "attack-family classifier."
    )
    lines.append("")

    lines.append(
        "Only the four core families with "
        "meaningful multi-dataset training "
        "support are used."
    )
    lines.append("")

    lines.append(
        "Exact duplicate Feature Set C vectors "
        "are grouped so the same feature "
        "signature cannot appear in both the "
        "training and internal test partitions."
    )
    lines.append("")

    lines.append(
        "This remains an internal model-selection "
        "experiment and must not be interpreted "
        "as final cross-dataset generalization."
    )
    lines.append("")

    lines.append("## Core families")
    lines.append("")

    for family in CORE_FAMILIES:
        count = report[
            "dataset"
        ][
            "core_family_counts"
        ][family]

        lines.append(
            f"- {family}: {count:,}"
        )

    lines.append("")

    lines.append("## Split")
    lines.append("")

    split = report["split"]

    lines.append(
        f"- Method: "
        f"{split['method']}"
    )

    lines.append(
        f"- Training rows: "
        f"{split['train_rows']:,}"
    )

    lines.append(
        f"- Internal test rows: "
        f"{split['test_rows']:,}"
    )

    lines.append(
        f"- Unique feature signatures: "
        f"{split['unique_feature_signatures']:,}"
    )

    lines.append(
        f"- Duplicate rows by feature signature: "
        f"{split['duplicate_feature_rows']:,}"
    )

    lines.append(
        f"- Train/test signature overlap: "
        f"{split['train_test_signature_overlap']}"
    )

    lines.append("")

    lines.append("## Model comparison")
    lines.append("")

    lines.append(
        "| Model | Accuracy | Balanced Accuracy | "
        "Macro F1 | Weighted F1 | Train Time (s) | "
        "Inference rows/s |"
    )

    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|"
    )

    for result in report[
        "models"
    ]:
        metrics = result["metrics"]

        lines.append(
            f"| {result['model']} "
            f"| {metrics['accuracy'] * 100:.4f}% "
            f"| {metrics['balanced_accuracy'] * 100:.4f}% "
            f"| {metrics['macro_f1'] * 100:.4f}% "
            f"| {metrics['weighted_f1'] * 100:.4f}% "
            f"| {result['train_seconds']:.2f} "
            f"| {result['inference_rows_per_second']:,.0f} |"
        )

    lines.append("")

    lines.append("## Per-family recall")
    lines.append("")

    header = (
        "| Model | "
        + " | ".join(
            CORE_FAMILIES
        )
        + " |"
    )

    separator = (
        "|---|"
        + "---:|" * len(
            CORE_FAMILIES
        )
    )

    lines.append(header)
    lines.append(separator)

    for result in report[
        "models"
    ]:
        values = []

        for family in CORE_FAMILIES:
            recall = result[
                "metrics"
            ][
                "per_class"
            ][family]["recall"]

            values.append(
                f"{recall * 100:.4f}%"
            )

        lines.append(
            f"| {result['model']} | "
            + " | ".join(values)
            + " |"
        )

    lines.append("")

    selection = report[
        "selection"
    ]

    lines.append(
        "## Internal selection"
    )
    lines.append("")

    lines.append(
        "Selection rule: highest macro F1, "
        "then highest balanced accuracy, "
        "then lower training time."
    )
    lines.append("")

    lines.append(
        f"Selected candidate: "
        f"**{selection['selected_model']}**"
    )

    lines.append("")

    lines.append(
        "This selection applies only to the "
        "internal grouped holdout. External "
        "development and final holdout results "
        "are evaluated separately."
    )

    lines.append("")

    return "\n".join(lines)


def main():
    print(
        "Hybrid IDS V3 Stage 2 "
        "Algorithm Comparison"
    )

    print("=" * 70)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Stage 2 dataset not found: "
            f"{DATASET_PATH}"
        )

    dataframe = pd.read_csv(
        DATASET_PATH,
        low_memory=False,
    )

    print(
        f"Loaded Stage 2 rows: "
        f"{len(dataframe):,}"
    )

    required_columns = (
        FEATURES
        + [
            "family_label",
            "source_dataset",
            "source_file",
        ]
    )

    missing = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing:
        raise KeyError(
            "Stage 2 dataset is missing "
            f"required columns: {missing}"
        )

    all_family_counts = counts_dict(
        dataframe["family_label"]
    )

    core = dataframe[
        dataframe[
            "family_label"
        ].isin(CORE_FAMILIES)
    ].copy()

    non_core = dataframe[
        ~dataframe[
            "family_label"
        ].isin(CORE_FAMILIES)
    ].copy()

    print(
        f"Core-family rows: "
        f"{len(core):,}"
    )

    print(
        f"Non-core mapped rows held aside: "
        f"{len(non_core):,}"
    )

    numeric = core[
        FEATURES
    ].apply(
        pd.to_numeric,
        errors="coerce",
    )

    numeric = numeric.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    invalid_rows = (
        ~numeric.notna().all(axis=1)
    )

    if invalid_rows.any():
        raise ValueError(
            "Core Stage 2 dataset unexpectedly "
            f"contains {int(invalid_rows.sum()):,} "
            "invalid feature rows."
        )

    core.loc[
        :,
        FEATURES,
    ] = numeric

    (
        X,
        y,
        groups,
        train_indices,
        test_indices,
    ) = create_grouped_split(
        core
    )

    X_train = X.iloc[
        train_indices
    ].copy()

    X_test = X.iloc[
        test_indices
    ].copy()

    y_train = y.iloc[
        train_indices
    ].copy()

    y_test = y.iloc[
        test_indices
    ].copy()

    train_dataframe = core.iloc[
        train_indices
    ].copy()

    test_dataframe = core.iloc[
        test_indices
    ].copy()

    unique_signatures = int(
        groups.nunique()
    )

    duplicate_feature_rows = int(
        len(groups)
        - unique_signatures
    )

    train_signatures = np.unique(
        groups.iloc[
            train_indices
        ].to_numpy()
    )

    test_signatures = np.unique(
        groups.iloc[
            test_indices
        ].to_numpy()
    )

    overlap = int(
        np.intersect1d(
            train_signatures,
            test_signatures,
        ).size
    )

    signature_labels = pd.DataFrame(
        {
            "signature": groups.to_numpy(),
            "family_label":
                core[
                    "family_label"
                ].to_numpy(),
        }
    )

    labels_per_signature = (
        signature_labels.groupby(
            "signature"
        )["family_label"]
        .nunique()
    )

    conflicting_signatures = int(
        (
            labels_per_signature > 1
        ).sum()
    )

    print()
    print("Grouped internal split:")
    print(
        f"Training rows: "
        f"{len(X_train):,}"
    )
    print(
        f"Internal test rows: "
        f"{len(X_test):,}"
    )
    print(
        f"Unique feature signatures: "
        f"{unique_signatures:,}"
    )
    print(
        f"Duplicate rows: "
        f"{duplicate_feature_rows:,}"
    )
    print(
        f"Conflicting-label signatures: "
        f"{conflicting_signatures:,}"
    )
    print(
        f"Train/test signature overlap: "
        f"{overlap}"
    )

    models = build_models()

    model_results = []

    for model_name, model in (
        models.items()
    ):
        result = train_and_evaluate(
            model_name,
            model,
            X_train,
            y_train,
            X_test,
            y_test,
        )

        model_results.append(
            result
        )

    selected = max(
        model_results,
        key=lambda result: (
            result[
                "metrics"
            ]["macro_f1"],
            result[
                "metrics"
            ][
                "balanced_accuracy"
            ],
            -result[
                "train_seconds"
            ],
        ),
    )

    RESULT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "version": "V3",
        "stage":
            "Stage 2 attack-family classification",
        "purpose":
            "Internal candidate algorithm comparison",
        "dataset": {
            "path": str(
                DATASET_PATH
            ),
            "sha256": sha256_file(
                DATASET_PATH
            ),
            "total_rows": int(
                len(dataframe)
            ),
            "all_family_counts":
                all_family_counts,
            "core_families":
                CORE_FAMILIES,
            "core_rows": int(
                len(core)
            ),
            "core_family_counts":
                counts_dict(
                    core[
                        "family_label"
                    ]
                ),
            "non_core_rows_held_aside":
                int(
                    len(non_core)
                ),
            "non_core_family_counts":
                counts_dict(
                    non_core[
                        "family_label"
                    ]
                ),
            "source_family_counts":
                source_family_counts(
                    core
                ),
        },
        "split": {
            "method":
                "StratifiedGroupKFold first fold",
            "n_splits":
                N_SPLITS,
            "random_state":
                RANDOM_STATE,
            "group_definition":
                "exact Feature Set C vector hash",
            "train_rows":
                int(
                    len(X_train)
                ),
            "test_rows":
                int(
                    len(X_test)
                ),
            "train_family_counts":
                counts_dict(
                    train_dataframe[
                        "family_label"
                    ]
                ),
            "test_family_counts":
                counts_dict(
                    test_dataframe[
                        "family_label"
                    ]
                ),
            "unique_feature_signatures":
                unique_signatures,
            "duplicate_feature_rows":
                duplicate_feature_rows,
            "conflicting_label_signatures":
                conflicting_signatures,
            "train_test_signature_overlap":
                overlap,
        },
        "policy": {
            "development_partition_used":
                False,
            "final_holdout_used":
                False,
            "secondary_holdout_used":
                False,
            "non_core_mapped_attacks_used_for_training":
                False,
            "unmapped_attacks_used_for_training":
                False,
            "exact_feature_signature_leakage_prevented":
                True,
        },
        "models": model_results,
        "selection": {
            "rule":
                "highest macro_f1, then "
                "balanced_accuracy, then "
                "lower training time",
            "selected_model":
                selected["model"],
            "selected_macro_f1":
                selected[
                    "metrics"
                ]["macro_f1"],
            "selected_balanced_accuracy":
                selected[
                    "metrics"
                ][
                    "balanced_accuracy"
                ],
        },
    }

    with RESULT_JSON_PATH.open(
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

    RESULT_MARKDOWN_PATH.write_text(
        markdown,
        encoding="utf-8",
    )

    print()
    print("=" * 70)

    print(
        "Stage 2 algorithm comparison complete."
    )

    print()
    print(
        f"Selected internal candidate: "
        f"{selected['model']}"
    )

    print(
        f"Macro F1: "
        f"{selected['metrics']['macro_f1'] * 100:.4f}%"
    )

    print(
        f"Balanced accuracy: "
        f"{selected['metrics']['balanced_accuracy'] * 100:.4f}%"
    )

    print()
    print(
        f"JSON report: "
        f"{RESULT_JSON_PATH}"
    )

    print(
        f"Markdown report: "
        f"{RESULT_MARKDOWN_PATH}"
    )

    print()
    print(
        "No development or holdout "
        "datasets were opened."
    )


if __name__ == "__main__":
    main()
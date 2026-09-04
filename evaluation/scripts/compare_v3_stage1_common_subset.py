from pathlib import Path
import json
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS, V3_FEATURE_SETS
from src.ml.v3.label_schema import get_binary_label


RANDOM_STATE = 42
N_ESTIMATORS = 200
CHUNK_SIZE = 100_000

TRAINING_DIRECTORY = Path("data/v3")

DEVELOPMENT_PATH = Path(
    "evaluation/datasets/CSE-CIC-IDS2018/"
    "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
)

OUTPUT_JSON = Path(
    "evaluation/results/summary/"
    "v3_stage1_common_subset_comparison.json"
)

OUTPUT_MARKDOWN = Path(
    "evaluation/results/summary/"
    "v3_stage1_common_subset_comparison.md"
)


def load_training_data(feature_set_name: str):
    path = (
        TRAINING_DIRECTORY
        / f"stage1_feature_set_{feature_set_name.lower()}.csv"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Missing training dataset: {path}"
        )

    dataframe = pd.read_csv(
        path,
        low_memory=False,
    )

    features = V3_FEATURE_SETS[feature_set_name]

    X = dataframe[features].copy()
    y = dataframe["binary_label"].astype(str)

    return X, y


def train_model(X, y):
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    start = time.perf_counter()

    model.fit(
        X,
        y,
    )

    elapsed = time.perf_counter() - start

    return model, elapsed


def calculate_metrics(y_true, y_pred):
    labels = [
        "BENIGN",
        "ATTACK",
    ]

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=labels,
    )

    tn = int(matrix[0, 0])
    fp = int(matrix[0, 1])
    fn = int(matrix[1, 0])
    tp = int(matrix[1, 1])

    benign_total = tn + fp
    attack_total = tp + fn

    benign_recall = (
        tn / benign_total
        if benign_total
        else 0.0
    )

    false_positive_rate = (
        fp / benign_total
        if benign_total
        else 0.0
    )

    false_negative_rate = (
        fn / attack_total
        if attack_total
        else 0.0
    )

    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred,
        ),
        "balanced_accuracy": balanced_accuracy_score(
            y_true,
            y_pred,
        ),
        "attack_precision": precision_score(
            y_true,
            y_pred,
            pos_label="ATTACK",
            zero_division=0,
        ),
        "attack_recall": recall_score(
            y_true,
            y_pred,
            pos_label="ATTACK",
            zero_division=0,
        ),
        "attack_f1": f1_score(
            y_true,
            y_pred,
            pos_label="ATTACK",
            zero_division=0,
        ),
        "benign_recall": benign_recall,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.tolist(),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def evaluate_models(models):
    y_true_parts = []

    prediction_parts = {
        "A": [],
        "B": [],
        "C": [],
    }

    total_rows = 0
    common_valid_rows = 0
    excluded_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            DEVELOPMENT_PATH,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        chunk.columns = chunk.columns.str.strip()

        raw_labels = (
            chunk["Label"]
            .astype("string")
            .str.strip()
        )

        header_mask = raw_labels.eq("Label")

        chunk = chunk.loc[
            ~header_mask
        ].copy()

        raw_labels = raw_labels.loc[
            ~header_mask
        ]

        total_rows += len(chunk)

        common = transform_common_features(
            chunk,
            DATASET_MAPPINGS["cse_cic_ids2018"],
        )

        common = common.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        common_valid_mask = common[
            V3_FEATURE_SETS["C"]
        ].notna().all(axis=1)

        valid_common = common.loc[
            common_valid_mask
        ]

        valid_labels = raw_labels.loc[
            common_valid_mask
        ]

        binary_labels = valid_labels.map(
            lambda value: get_binary_label(
                "cse_cic_ids2018",
                value,
            )
        )

        y_true_parts.append(
            binary_labels.to_numpy()
        )

        valid_count = len(valid_common)

        common_valid_rows += valid_count

        excluded = len(chunk) - valid_count
        excluded_rows += excluded

        for feature_set_name in [
            "A",
            "B",
            "C",
        ]:
            X = valid_common[
                V3_FEATURE_SETS[
                    feature_set_name
                ]
            ]

            predictions = models[
                feature_set_name
            ].predict(X)

            prediction_parts[
                feature_set_name
            ].append(
                np.asarray(predictions)
            )

        print(
            f"Chunk {chunk_number}: "
            f"total={len(chunk):,}, "
            f"common_valid={valid_count:,}, "
            f"excluded={excluded:,}"
        )

    y_true = np.concatenate(
        y_true_parts
    )

    results = {
        "total_development_rows": total_rows,
        "common_valid_rows": common_valid_rows,
        "excluded_rows": excluded_rows,
        "coverage": (
            common_valid_rows / total_rows
            if total_rows
            else 0.0
        ),
        "true_distribution": {
            "BENIGN": int(
                np.sum(y_true == "BENIGN")
            ),
            "ATTACK": int(
                np.sum(y_true == "ATTACK")
            ),
        },
        "feature_sets": {},
    }

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        y_pred = np.concatenate(
            prediction_parts[
                feature_set_name
            ]
        )

        results["feature_sets"][
            feature_set_name
        ] = calculate_metrics(
            y_true,
            y_pred,
        )

    return results


def build_markdown(results, training_info):
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 1 Common-Subset Comparison"
    )
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append(
        "Feature Sets A, B, and C are evaluated on the "
        "exact same Tuesday development rows."
    )
    lines.append("")
    lines.append(
        "The common evaluation subset contains only rows "
        "for which every Feature Set C feature is defined."
    )
    lines.append("")
    lines.append(
        "This prevents Feature Set C from receiving an "
        "unfair comparison advantage by excluding rows "
        "that Feature Sets A and B previously evaluated."
    )
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(
        f"- Total development rows: "
        f"{results['total_development_rows']:,}"
    )
    lines.append(
        f"- Common valid rows: "
        f"{results['common_valid_rows']:,}"
    )
    lines.append(
        f"- Excluded rows: "
        f"{results['excluded_rows']:,}"
    )
    lines.append(
        f"- Common-subset coverage: "
        f"{results['coverage']:.4%}"
    )
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(
        "| Set | Features | Train Rows | Accuracy | "
        "Balanced Accuracy | Attack Precision | "
        "Attack Recall | Attack F1 | Benign Recall | FPR |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        metrics = results[
            "feature_sets"
        ][feature_set_name]

        info = training_info[
            feature_set_name
        ]

        lines.append(
            f"| {feature_set_name} "
            f"| {len(V3_FEATURE_SETS[feature_set_name])} "
            f"| {info['rows']:,} "
            f"| {metrics['accuracy']:.6f} "
            f"| {metrics['balanced_accuracy']:.6f} "
            f"| {metrics['attack_precision']:.6f} "
            f"| {metrics['attack_recall']:.6f} "
            f"| {metrics['attack_f1']:.6f} "
            f"| {metrics['benign_recall']:.6f} "
            f"| {metrics['false_positive_rate']:.6f} |"
        )

    lines.append("")
    lines.append("## Interpretation Rule")
    lines.append("")
    lines.append(
        "Feature selection should consider common-subset "
        "performance together with operational coverage. "
        "Feature Set C must justify its excluded rows with "
        "a meaningful improvement over simpler feature sets."
    )

    return "\n".join(lines)


def main():
    print(
        "Hybrid IDS V3 Stage 1 "
        "Common-Subset Feature Comparison"
    )
    print("=" * 70)

    models = {}
    training_info = {}

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        print()
        print(
            f"Training Feature Set "
            f"{feature_set_name}..."
        )

        X_train, y_train = load_training_data(
            feature_set_name
        )

        model, elapsed = train_model(
            X_train,
            y_train,
        )

        models[feature_set_name] = model

        training_info[
            feature_set_name
        ] = {
            "rows": len(X_train),
            "training_seconds": elapsed,
        }

        print(
            f"Rows: {len(X_train):,}"
        )

        print(
            f"Training time: "
            f"{elapsed:.2f} seconds"
        )

    print()
    print("=" * 70)
    print(
        "Evaluating identical development rows..."
    )
    print("=" * 70)

    results = evaluate_models(
        models
    )

    results["training"] = training_info

    print()
    print("=" * 70)
    print("Common-subset results")
    print("=" * 70)

    print(
        f"Total development rows: "
        f"{results['total_development_rows']:,}"
    )

    print(
        f"Common valid rows: "
        f"{results['common_valid_rows']:,}"
    )

    print(
        f"Excluded rows: "
        f"{results['excluded_rows']:,}"
    )

    print(
        f"Coverage: "
        f"{results['coverage']:.4%}"
    )

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        metrics = results[
            "feature_sets"
        ][feature_set_name]

        matrix = metrics[
            "confusion_matrix"
        ]

        print()
        print(
            f"Feature Set {feature_set_name}"
        )
        print("-" * 70)

        print(
            f"Accuracy: "
            f"{metrics['accuracy']:.4%}"
        )
        print(
            f"Balanced accuracy: "
            f"{metrics['balanced_accuracy']:.4%}"
        )
        print(
            f"Attack precision: "
            f"{metrics['attack_precision']:.4%}"
        )
        print(
            f"Attack recall: "
            f"{metrics['attack_recall']:.4%}"
        )
        print(
            f"Attack F1: "
            f"{metrics['attack_f1']:.4%}"
        )
        print(
            f"Benign recall: "
            f"{metrics['benign_recall']:.4%}"
        )
        print(
            f"False-positive rate: "
            f"{metrics['false_positive_rate']:.4%}"
        )

        print(
            "Confusion matrix "
            "[[TN, FP], [FN, TP]]:"
        )

        print(
            [
                [
                    matrix["tn"],
                    matrix["fp"],
                ],
                [
                    matrix["fn"],
                    matrix["tp"],
                ],
            ]
        )

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
        build_markdown(
            results,
            training_info,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print(
        f"JSON: {OUTPUT_JSON}"
    )
    print(
        f"Markdown: {OUTPUT_MARKDOWN}"
    )


if __name__ == "__main__":
    main()
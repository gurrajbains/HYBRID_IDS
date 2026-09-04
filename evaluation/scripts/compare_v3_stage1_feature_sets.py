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
    "v3_stage1_feature_comparison.json"
)

OUTPUT_MARKDOWN = Path(
    "evaluation/results/summary/"
    "v3_stage1_feature_comparison.md"
)


def load_training_data(feature_set_name: str):
    path = (
        TRAINING_DIRECTORY
        / f"stage1_feature_set_{feature_set_name.lower()}.csv"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Missing Stage 1 training dataset: {path}"
        )

    dataframe = pd.read_csv(
        path,
        low_memory=False,
    )

    features = V3_FEATURE_SETS[feature_set_name]

    required_columns = features + ["binary_label"]

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise KeyError(
            f"{path} is missing columns: {missing_columns}"
        )

    X = dataframe[features].copy()
    y = dataframe["binary_label"].astype(str)

    return X, y, path


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


def evaluate_development(
    model,
    feature_set_name: str,
):
    features = V3_FEATURE_SETS[feature_set_name]

    y_true_parts = []
    y_pred_parts = []

    total_raw_rows = 0
    repeated_header_rows = 0
    invalid_feature_rows = 0
    evaluated_rows = 0

    start = time.perf_counter()

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            DEVELOPMENT_PATH,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        chunk.columns = chunk.columns.str.strip()

        total_raw_rows += len(chunk)

        if "Label" not in chunk.columns:
            raise KeyError(
                f"{DEVELOPMENT_PATH} is missing Label"
            )

        raw_labels = (
            chunk["Label"]
            .astype("string")
            .str.strip()
        )

        header_mask = raw_labels.eq("Label")

        repeated_header_rows += int(
            header_mask.sum()
        )

        chunk = chunk.loc[
            ~header_mask
        ].copy()

        raw_labels = raw_labels.loc[
            ~header_mask
        ]

        common = transform_common_features(
            chunk,
            DATASET_MAPPINGS["cse_cic_ids2018"],
        )

        selected = common[
            features
        ].replace(
            [np.inf, -np.inf],
            np.nan,
        )

        valid_mask = selected.notna().all(
            axis=1
        )

        invalid_count = int(
            (~valid_mask).sum()
        )

        invalid_feature_rows += invalid_count

        selected = selected.loc[
            valid_mask
        ]

        raw_labels = raw_labels.loc[
            valid_mask
        ]

        binary_labels = raw_labels.map(
            lambda value: get_binary_label(
                "cse_cic_ids2018",
                value,
            )
        )

        predictions = model.predict(
            selected
        )

        y_true_parts.append(
            binary_labels.to_numpy()
        )

        y_pred_parts.append(
            np.asarray(predictions)
        )

        evaluated_rows += len(selected)

        print(
            f"  Chunk {chunk_number}: "
            f"raw={len(chunk):,}, "
            f"evaluated={len(selected):,}, "
            f"invalid={invalid_count:,}"
        )

    elapsed = time.perf_counter() - start

    y_true = np.concatenate(
        y_true_parts
    )

    y_pred = np.concatenate(
        y_pred_parts
    )

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

    benign_recall = (
        tn / benign_total
        if benign_total
        else 0.0
    )

    attack_recall = recall_score(
        y_true,
        y_pred,
        pos_label="ATTACK",
        zero_division=0,
    )

    attack_precision = precision_score(
        y_true,
        y_pred,
        pos_label="ATTACK",
        zero_division=0,
    )

    attack_f1 = f1_score(
        y_true,
        y_pred,
        pos_label="ATTACK",
        zero_division=0,
    )

    result = {
        "total_raw_rows": total_raw_rows,
        "repeated_header_rows": repeated_header_rows,
        "invalid_feature_rows": invalid_feature_rows,
        "evaluated_rows": evaluated_rows,
        "evaluation_seconds": elapsed,
        "true_distribution": {
            "BENIGN": int(
                np.sum(y_true == "BENIGN")
            ),
            "ATTACK": int(
                np.sum(y_true == "ATTACK")
            ),
        },
        "predicted_distribution": {
            "BENIGN": int(
                np.sum(y_pred == "BENIGN")
            ),
            "ATTACK": int(
                np.sum(y_pred == "ATTACK")
            ),
        },
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.tolist(),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
        "accuracy": accuracy_score(
            y_true,
            y_pred,
        ),
        "balanced_accuracy": (
            balanced_accuracy_score(
                y_true,
                y_pred,
            )
        ),
        "attack_precision": attack_precision,
        "attack_recall": attack_recall,
        "attack_f1": attack_f1,
        "benign_recall": benign_recall,
        "false_positive_rate": (
            false_positive_rate
        ),
        "false_negative_rate": (
            false_negative_rate
        ),
    }

    return result


def build_markdown(results):
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 1 Feature Comparison"
    )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Feature Sets A, B, and C were compared "
        "using the same Random Forest configuration."
    )
    lines.append("")
    lines.append(
        f"- Random Forest trees: {N_ESTIMATORS}"
    )
    lines.append(
        "- Class weighting: balanced_subsample"
    )
    lines.append(
        f"- Random state: {RANDOM_STATE}"
    )
    lines.append(
        "- Training data: V3 Stage 1 sampled "
        "cross-dataset training data"
    )
    lines.append(
        "- Development data: "
        "CSE-CIC-IDS2018 Tuesday-20-02-2018"
    )
    lines.append(
        "- Final and secondary holdouts were not used"
    )
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(
        "| Feature Set | Features | Training Rows | "
        "Dev Rows | Removed | Accuracy | "
        "Balanced Accuracy | Attack Precision | "
        "Attack Recall | Attack F1 | Benign Recall | FPR |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|"
        "---:|---:|---:|---:|---:|"
    )

    for name in [
        "A",
        "B",
        "C",
    ]:
        result = results[name]
        dev = result["development"]

        lines.append(
            f"| {name} "
            f"| {len(result['features'])} "
            f"| {result['training_rows']:,} "
            f"| {dev['evaluated_rows']:,} "
            f"| {dev['invalid_feature_rows']:,} "
            f"| {dev['accuracy']:.6f} "
            f"| {dev['balanced_accuracy']:.6f} "
            f"| {dev['attack_precision']:.6f} "
            f"| {dev['attack_recall']:.6f} "
            f"| {dev['attack_f1']:.6f} "
            f"| {dev['benign_recall']:.6f} "
            f"| {dev['false_positive_rate']:.6f} |"
        )

    for name in [
        "A",
        "B",
        "C",
    ]:
        result = results[name]
        dev = result["development"]
        matrix = dev["confusion_matrix"]

        lines.append("")
        lines.append(
            f"## Feature Set {name}"
        )
        lines.append("")
        lines.append(
            f"- Features: {len(result['features'])}"
        )
        lines.append(
            f"- Training rows: "
            f"{result['training_rows']:,}"
        )
        lines.append(
            f"- Training time: "
            f"{result['training_seconds']:.2f} seconds"
        )
        lines.append(
            f"- Development rows evaluated: "
            f"{dev['evaluated_rows']:,}"
        )
        lines.append(
            f"- Invalid development rows removed: "
            f"{dev['invalid_feature_rows']:,}"
        )
        lines.append(
            f"- Accuracy: "
            f"{dev['accuracy']:.6f}"
        )
        lines.append(
            f"- Balanced accuracy: "
            f"{dev['balanced_accuracy']:.6f}"
        )
        lines.append(
            f"- Attack precision: "
            f"{dev['attack_precision']:.6f}"
        )
        lines.append(
            f"- Attack recall: "
            f"{dev['attack_recall']:.6f}"
        )
        lines.append(
            f"- Attack F1: "
            f"{dev['attack_f1']:.6f}"
        )
        lines.append(
            f"- Benign recall: "
            f"{dev['benign_recall']:.6f}"
        )
        lines.append(
            f"- False-positive rate: "
            f"{dev['false_positive_rate']:.6f}"
        )
        lines.append(
            f"- False-negative rate: "
            f"{dev['false_negative_rate']:.6f}"
        )
        lines.append("")
        lines.append(
            "Confusion matrix "
            "[[TN, FP], [FN, TP]]:"
        )
        lines.append("")
        lines.append(
            f"- TN: {matrix['tn']:,}"
        )
        lines.append(
            f"- FP: {matrix['fp']:,}"
        )
        lines.append(
            f"- FN: {matrix['fn']:,}"
        )
        lines.append(
            f"- TP: {matrix['tp']:,}"
        )

    lines.append("")
    lines.append("## Selection Note")
    lines.append("")
    lines.append(
        "No feature set should be selected from "
        "accuracy alone. Attack recall, attack precision, "
        "attack F1, benign recall, false-positive rate, "
        "and balanced accuracy must be considered together."
    )

    return "\n".join(lines)


def main():
    if not DEVELOPMENT_PATH.exists():
        raise FileNotFoundError(
            f"Development dataset missing: "
            f"{DEVELOPMENT_PATH}"
        )

    print(
        "Hybrid IDS V3 Stage 1 "
        "Feature-Set Comparison"
    )
    print("=" * 70)

    print(
        "Development dataset: "
        f"{DEVELOPMENT_PATH}"
    )

    print(
        "Final and secondary holdouts "
        "are not used."
    )

    results = {}

    for feature_set_name in [
        "A",
        "B",
        "C",
    ]:
        print()
        print("=" * 70)
        print(
            f"Feature Set {feature_set_name}"
        )
        print("=" * 70)

        X_train, y_train, training_path = (
            load_training_data(
                feature_set_name
            )
        )

        print(
            f"Training file: {training_path}"
        )
        print(
            f"Training rows: "
            f"{len(X_train):,}"
        )
        print(
            f"Features: "
            f"{len(V3_FEATURE_SETS[feature_set_name])}"
        )
        print(
            "Training Random Forest..."
        )

        model, training_seconds = (
            train_model(
                X_train,
                y_train,
            )
        )

        print(
            f"Training completed in "
            f"{training_seconds:.2f} seconds"
        )

        print(
            "Evaluating Tuesday development data..."
        )

        development = (
            evaluate_development(
                model,
                feature_set_name,
            )
        )

        results[
            feature_set_name
        ] = {
            "features": V3_FEATURE_SETS[
                feature_set_name
            ],
            "training_file": str(
                training_path
            ),
            "training_rows": len(
                X_train
            ),
            "training_distribution": {
                str(label): int(count)
                for label, count
                in y_train.value_counts().items()
            },
            "training_seconds": (
                training_seconds
            ),
            "model": {
                "type": (
                    "RandomForestClassifier"
                ),
                "n_estimators": (
                    N_ESTIMATORS
                ),
                "class_weight": (
                    "balanced_subsample"
                ),
                "random_state": (
                    RANDOM_STATE
                ),
            },
            "development": development,
        }

        print()
        print(
            f"Feature Set {feature_set_name} results"
        )
        print("-" * 70)

        print(
            f"Accuracy: "
            f"{development['accuracy']:.4%}"
        )
        print(
            f"Balanced accuracy: "
            f"{development['balanced_accuracy']:.4%}"
        )
        print(
            f"Attack precision: "
            f"{development['attack_precision']:.4%}"
        )
        print(
            f"Attack recall: "
            f"{development['attack_recall']:.4%}"
        )
        print(
            f"Attack F1: "
            f"{development['attack_f1']:.4%}"
        )
        print(
            f"Benign recall: "
            f"{development['benign_recall']:.4%}"
        )
        print(
            f"False-positive rate: "
            f"{development['false_positive_rate']:.4%}"
        )

        matrix = development[
            "confusion_matrix"
        ]

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
        build_markdown(results),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("Comparison complete.")
    print(
        f"JSON: {OUTPUT_JSON}"
    )
    print(
        f"Markdown: {OUTPUT_MARKDOWN}"
    )


if __name__ == "__main__":
    main()
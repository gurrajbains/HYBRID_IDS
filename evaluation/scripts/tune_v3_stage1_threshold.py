from pathlib import Path
import json
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS, V3_FEATURE_SETS
from src.ml.v3.label_schema import get_binary_label


RANDOM_STATE = 42
CHUNK_SIZE = 100_000

FEATURE_SET_NAME = "C"
FEATURES = V3_FEATURE_SETS[FEATURE_SET_NAME]
THRESHOLDS = [
    0.650,
    0.655,
    0.660,
    0.665,
    0.670,
    0.675,
    0.680,
    0.685,
    0.690,
    0.695,
    0.700,
]

MIN_ATTACK_RECALL = 0.95

TRAINING_PATH = Path(
    "data/v3/stage1_feature_set_c.csv"
)

DEVELOPMENT_PATH = Path(
    "evaluation/datasets/CSE-CIC-IDS2018/"
    "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
)

OUTPUT_JSON = Path(
    "evaluation/results/summary/"
    "v3_stage1_threshold_refinement.json"
)

OUTPUT_MARKDOWN = Path(
    "evaluation/results/summary/"
    "v3_stage1_threshold_refinement.md"
)

def load_training_data():
    if not TRAINING_PATH.exists():
        raise FileNotFoundError(
            f"Missing training dataset: {TRAINING_PATH}"
        )

    dataframe = pd.read_csv(
        TRAINING_PATH,
        low_memory=False,
    )

    required = FEATURES + ["binary_label"]

    missing = [
        column
        for column in required
        if column not in dataframe.columns
    ]

    if missing:
        raise KeyError(
            f"Training dataset is missing columns: {missing}"
        )

    X = dataframe[FEATURES].copy()
    y = dataframe["binary_label"].astype(str)

    return X, y


def train_model(X_train, y_train):
    sample_weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train,
    )

    model = HistGradientBoostingClassifier(
        learning_rate=0.1,
        max_iter=200,
        max_leaf_nodes=31,
        random_state=RANDOM_STATE,
    )

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train,
        sample_weight=sample_weights,
    )

    elapsed = time.perf_counter() - start

    return model, elapsed


def get_attack_probabilities(model, X):
    probabilities = model.predict_proba(X)

    classes = list(model.classes_)

    if "ATTACK" not in classes:
        raise ValueError(
            f"ATTACK class missing from model classes: {classes}"
        )

    attack_index = classes.index("ATTACK")

    return probabilities[:, attack_index]


def initialize_threshold_counts():
    return {
        threshold: {
            "tn": 0,
            "fp": 0,
            "fn": 0,
            "tp": 0,
        }
        for threshold in THRESHOLDS
    }


def update_threshold_counts(
    counts,
    y_true_attack,
    attack_probabilities,
):
    for threshold in THRESHOLDS:
        predicted_attack = (
            attack_probabilities >= threshold
        )

        true_attack = y_true_attack
        true_benign = ~true_attack

        predicted_benign = ~predicted_attack

        counts[threshold]["tp"] += int(
            np.sum(
                true_attack
                & predicted_attack
            )
        )

        counts[threshold]["fn"] += int(
            np.sum(
                true_attack
                & predicted_benign
            )
        )

        counts[threshold]["tn"] += int(
            np.sum(
                true_benign
                & predicted_benign
            )
        )

        counts[threshold]["fp"] += int(
            np.sum(
                true_benign
                & predicted_attack
            )
        )


def evaluate_development(model):
    counts = initialize_threshold_counts()

    total_raw_rows = 0
    repeated_header_rows = 0
    evaluated_rows = 0
    excluded_rows = 0

    inference_seconds = 0.0

    true_attack_count = 0
    true_benign_count = 0

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
            FEATURES
        ].replace(
            [np.inf, -np.inf],
            np.nan,
        )

        valid_mask = selected.notna().all(
            axis=1
        )

        excluded = int(
            (~valid_mask).sum()
        )

        excluded_rows += excluded

        selected = selected.loc[
            valid_mask
        ]

        valid_labels = raw_labels.loc[
            valid_mask
        ]

        binary_labels = valid_labels.map(
            lambda value: get_binary_label(
                "cse_cic_ids2018",
                value,
            )
        )

        y_true_attack = (
            binary_labels.to_numpy()
            == "ATTACK"
        )

        true_attack_count += int(
            np.sum(y_true_attack)
        )

        true_benign_count += int(
            np.sum(~y_true_attack)
        )

        start = time.perf_counter()

        attack_probabilities = (
            get_attack_probabilities(
                model,
                selected,
            )
        )

        inference_seconds += (
            time.perf_counter() - start
        )

        update_threshold_counts(
            counts,
            y_true_attack,
            attack_probabilities,
        )

        evaluated_rows += len(selected)

        print(
            f"Chunk {chunk_number}: "
            f"raw={len(chunk):,}, "
            f"evaluated={len(selected):,}, "
            f"excluded={excluded:,}"
        )

    return {
        "counts": counts,
        "total_raw_rows": total_raw_rows,
        "repeated_header_rows": repeated_header_rows,
        "evaluated_rows": evaluated_rows,
        "excluded_rows": excluded_rows,
        "true_attack_count": true_attack_count,
        "true_benign_count": true_benign_count,
        "inference_seconds": inference_seconds,
    }


def calculate_metrics(counts):
    results = {}

    for threshold in THRESHOLDS:
        matrix = counts[threshold]

        tn = matrix["tn"]
        fp = matrix["fp"]
        fn = matrix["fn"]
        tp = matrix["tp"]

        total = tn + fp + fn + tp
        attack_total = tp + fn
        benign_total = tn + fp

        accuracy = (
            (tp + tn) / total
            if total
            else 0.0
        )

        attack_recall = (
            tp / attack_total
            if attack_total
            else 0.0
        )

        attack_precision = (
            tp / (tp + fp)
            if (tp + fp)
            else 0.0
        )

        attack_f1 = (
            2
            * attack_precision
            * attack_recall
            / (
                attack_precision
                + attack_recall
            )
            if (
                attack_precision
                + attack_recall
            )
            else 0.0
        )

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

        balanced_accuracy = (
            attack_recall
            + benign_recall
        ) / 2

        results[str(threshold)] = {
            "threshold": threshold,
            "accuracy": accuracy,
            "balanced_accuracy": balanced_accuracy,
            "attack_precision": attack_precision,
            "attack_recall": attack_recall,
            "attack_f1": attack_f1,
            "benign_recall": benign_recall,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            },
        }

    return results


def select_threshold(results):
    eligible = [
        result
        for result in results.values()
        if result["attack_recall"]
        >= MIN_ATTACK_RECALL
    ]

    if not eligible:
        raise RuntimeError(
            "No threshold preserved the required "
            f"{MIN_ATTACK_RECALL:.0%} attack recall."
        )

    selected = min(
        eligible,
        key=lambda result: (
            result["false_positive_rate"],
            -result["attack_f1"],
        ),
    )

    return selected


def build_markdown(
    results,
    selected,
    metadata,
):
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 1 Threshold Selection"
    )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "The selected HistGradientBoosting Stage 1 "
        "classifier was trained once using Feature Set C."
    )
    lines.append("")
    lines.append(
        "Its attack probabilities were evaluated using "
        "a pre-defined threshold grid on the Tuesday "
        "development dataset."
    )
    lines.append("")
    lines.append(
        "Final and secondary holdouts were not used."
    )
    lines.append("")
    lines.append("## Selection Rule")
    lines.append("")
    lines.append(
        "Choose the threshold with the lowest "
        "false-positive rate while preserving at least "
        "95% attack recall."
    )
    lines.append("")
    lines.append(
        "If multiple thresholds have the same "
        "false-positive rate, prefer the one with the "
        "highest attack F1."
    )
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(
        f"- Development rows evaluated: "
        f"{metadata['evaluated_rows']:,}"
    )
    lines.append(
        f"- Rows excluded for undefined Set C features: "
        f"{metadata['excluded_rows']:,}"
    )
    lines.append(
        f"- Attack rows: "
        f"{metadata['true_attack_count']:,}"
    )
    lines.append(
        f"- Benign rows: "
        f"{metadata['true_benign_count']:,}"
    )
    lines.append("")
    lines.append("## Threshold Results")
    lines.append("")
    lines.append(
        "| Threshold | Accuracy | Balanced Accuracy | "
        "Attack Precision | Attack Recall | Attack F1 | "
        "Benign Recall | FPR |"
    )
    lines.append(
        "|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    for threshold in THRESHOLDS:
        result = results[str(threshold)]

        lines.append(
            f"| {threshold:3f} "
            f"| {result['accuracy']:.6f} "
            f"| {result['balanced_accuracy']:.6f} "
            f"| {result['attack_precision']:.6f} "
            f"| {result['attack_recall']:.6f} "
            f"| {result['attack_f1']:.6f} "
            f"| {result['benign_recall']:.6f} "
            f"| {result['false_positive_rate']:.6f} |"
        )

    lines.append("")
    lines.append("## Selected Threshold")
    lines.append("")
    lines.append(
        f"- Threshold: {selected['threshold']:.3f}"
    )
    lines.append(
        f"- Attack recall: "
        f"{selected['attack_recall']:.4%}"
    )
    lines.append(
        f"- Attack precision: "
        f"{selected['attack_precision']:.4%}"
    )
    lines.append(
        f"- Attack F1: "
        f"{selected['attack_f1']:.4%}"
    )
    lines.append(
        f"- Benign recall: "
        f"{selected['benign_recall']:.4%}"
    )
    lines.append(
        f"- False-positive rate: "
        f"{selected['false_positive_rate']:.4%}"
    )
    lines.append(
        f"- Balanced accuracy: "
        f"{selected['balanced_accuracy']:.4%}"
    )

    matrix = selected[
        "confusion_matrix"
    ]

    lines.append("")
    lines.append(
        "Confusion matrix [[TN, FP], [FN, TP]]:"
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

    return "\n".join(lines)


def main():
    if not DEVELOPMENT_PATH.exists():
        raise FileNotFoundError(
            f"Development dataset missing: "
            f"{DEVELOPMENT_PATH}"
        )

    print(
        "Hybrid IDS V3 Stage 1 Threshold Selection"
    )
    print("=" * 70)

    print("Feature Set: C")
    print("Model: HistGradientBoostingClassifier")
    print(
        f"Required attack recall: "
        f"{MIN_ATTACK_RECALL:.0%}"
    )

    X_train, y_train = load_training_data()

    print()
    print(
        f"Training rows: {len(X_train):,}"
    )

    print("Training model once...")

    model, training_seconds = train_model(
        X_train,
        y_train,
    )

    print(
        f"Training completed in "
        f"{training_seconds:.3f} seconds"
    )

    print()
    print(
        "Evaluating threshold grid on "
        "Tuesday development data..."
    )

    evaluation = evaluate_development(
        model
    )

    threshold_results = calculate_metrics(
        evaluation["counts"]
    )

    selected = select_threshold(
        threshold_results
    )

    print()
    print("=" * 70)
    print("Threshold results")
    print("=" * 70)

    for threshold in THRESHOLDS:
        result = threshold_results[
            str(threshold)
        ]

        marker = ""

        if (
            threshold
            == selected["threshold"]
        ):
            marker = "  <-- SELECTED"

        print(
            f"{threshold:.3f} | "
            f"Recall={result['attack_recall']:.4%} | "
            f"Precision={result['attack_precision']:.4%} | "
            f"F1={result['attack_f1']:.4%} | "
            f"FPR={result['false_positive_rate']:.4%} | "
            f"BalancedAcc="
            f"{result['balanced_accuracy']:.4%}"
            f"{marker}"
        )

    print()
    print("=" * 70)
    print("Selected operating threshold")
    print("=" * 70)

    print(
        f"Threshold: "
        f"{selected['threshold']:.3f}"
    )

    print(
        f"Attack recall: "
        f"{selected['attack_recall']:.4%}"
    )

    print(
        f"Attack precision: "
        f"{selected['attack_precision']:.4%}"
    )

    print(
        f"Attack F1: "
        f"{selected['attack_f1']:.4%}"
    )

    print(
        f"Benign recall: "
        f"{selected['benign_recall']:.4%}"
    )

    print(
        f"False-positive rate: "
        f"{selected['false_positive_rate']:.4%}"
    )

    matrix = selected[
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

    report = {
        "feature_set": FEATURE_SET_NAME,
        "features": FEATURES,
        "model": {
            "type": (
                "HistGradientBoostingClassifier"
            ),
            "learning_rate": 0.1,
            "max_iter": 200,
            "max_leaf_nodes": 31,
            "balanced_sample_weights": True,
            "random_state": RANDOM_STATE,
        },
        "selection_rule": {
            "minimum_attack_recall": (
                MIN_ATTACK_RECALL
            ),
            "primary_objective": (
                "minimize_false_positive_rate"
            ),
            "secondary_objective": (
                "maximize_attack_f1"
            ),
        },
        "training_rows": len(X_train),
        "training_seconds": training_seconds,
        "development": {
            "total_raw_rows": evaluation[
                "total_raw_rows"
            ],
            "repeated_header_rows": evaluation[
                "repeated_header_rows"
            ],
            "evaluated_rows": evaluation[
                "evaluated_rows"
            ],
            "excluded_rows": evaluation[
                "excluded_rows"
            ],
            "true_attack_count": evaluation[
                "true_attack_count"
            ],
            "true_benign_count": evaluation[
                "true_benign_count"
            ],
            "inference_seconds": evaluation[
                "inference_seconds"
            ],
        },
        "thresholds": threshold_results,
        "selected_threshold": selected,
    }

    OUTPUT_JSON.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    OUTPUT_MARKDOWN.write_text(
        build_markdown(
            threshold_results,
            selected,
            evaluation,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("Threshold selection complete.")
    print(f"JSON: {OUTPUT_JSON}")
    print(f"Markdown: {OUTPUT_MARKDOWN}")


if __name__ == "__main__":
    main()
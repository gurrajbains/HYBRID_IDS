from pathlib import Path
import json
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight

from src.ml.v3.common_features import transform_common_features
from src.ml.v3.feature_schema import DATASET_MAPPINGS, V3_FEATURE_SETS
from src.ml.v3.label_schema import get_binary_label


RANDOM_STATE = 42
CHUNK_SIZE = 100_000

FEATURE_SET_NAME = "C"
FEATURES = V3_FEATURE_SETS[FEATURE_SET_NAME]

TRAINING_PATH = Path(
    "data/v3/stage1_feature_set_c.csv"
)

DEVELOPMENT_PATH = Path(
    "evaluation/datasets/CSE-CIC-IDS2018/"
    "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
)

OUTPUT_JSON = Path(
    "evaluation/results/summary/"
    "v3_stage1_algorithm_comparison.json"
)

OUTPUT_MARKDOWN = Path(
    "evaluation/results/summary/"
    "v3_stage1_algorithm_comparison.md"
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


def build_models():
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "extra_trees": ExtraTreesClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.1,
            max_iter=200,
            max_leaf_nodes=31,
            random_state=RANDOM_STATE,
        ),
    }


def train_models(X_train, y_train):
    models = build_models()
    results = {}

    balanced_weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train,
    )

    for name, model in models.items():
        print()
        print("=" * 70)
        print(f"Training {name}")
        print("=" * 70)

        start = time.perf_counter()

        if name == "hist_gradient_boosting":
            model.fit(
                X_train,
                y_train,
                sample_weight=balanced_weights,
            )
        else:
            model.fit(
                X_train,
                y_train,
            )

        elapsed = time.perf_counter() - start

        results[name] = {
            "model": model,
            "training_seconds": elapsed,
        }

        print(
            f"Training completed in "
            f"{elapsed:.2f} seconds"
        )

    return results


def get_attack_probability(model, X):
    probabilities = model.predict_proba(X)

    classes = list(model.classes_)

    if "ATTACK" not in classes:
        raise ValueError(
            f"ATTACK class missing from model classes: {classes}"
        )

    attack_index = classes.index("ATTACK")

    return probabilities[:, attack_index]


def calculate_metrics(y_true, y_pred, y_score):
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

    y_binary = (
        np.asarray(y_true) == "ATTACK"
    ).astype(int)

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
        "roc_auc": roc_auc_score(
            y_binary,
            y_score,
        ),
        "average_precision": average_precision_score(
            y_binary,
            y_score,
        ),
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.tolist(),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def evaluate_models(trained_models):
    y_true_parts = []

    prediction_parts = {
        name: []
        for name in trained_models
    }

    score_parts = {
        name: []
        for name in trained_models
    }

    inference_seconds = {
        name: 0.0
        for name in trained_models
    }

    total_rows = 0
    evaluated_rows = 0
    excluded_rows = 0
    repeated_header_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            DEVELOPMENT_PATH,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        chunk.columns = chunk.columns.str.strip()

        if "Label" not in chunk.columns:
            raise KeyError(
                f"{DEVELOPMENT_PATH} is missing Label"
            )

        total_rows += len(chunk)

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

        invalid_count = int(
            (~valid_mask).sum()
        )

        excluded_rows += invalid_count

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

        y_true_parts.append(
            binary_labels.to_numpy()
        )

        evaluated_rows += len(selected)

        for name, info in trained_models.items():
            model = info["model"]

            start = time.perf_counter()

            predictions = model.predict(
                selected
            )

            attack_scores = get_attack_probability(
                model,
                selected,
            )

            inference_seconds[name] += (
                time.perf_counter() - start
            )

            prediction_parts[name].append(
                np.asarray(predictions)
            )

            score_parts[name].append(
                np.asarray(attack_scores)
            )

        print(
            f"Chunk {chunk_number}: "
            f"raw={len(chunk):,}, "
            f"evaluated={len(selected):,}, "
            f"excluded={invalid_count:,}"
        )

    y_true = np.concatenate(
        y_true_parts
    )

    results = {
        "total_raw_rows": total_rows,
        "repeated_header_rows": repeated_header_rows,
        "evaluated_rows": evaluated_rows,
        "excluded_rows": excluded_rows,
        "coverage": (
            evaluated_rows
            / (total_rows - repeated_header_rows)
            if total_rows - repeated_header_rows
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
        "models": {},
    }

    for name, info in trained_models.items():
        y_pred = np.concatenate(
            prediction_parts[name]
        )

        y_score = np.concatenate(
            score_parts[name]
        )

        metrics = calculate_metrics(
            y_true,
            y_pred,
            y_score,
        )

        seconds = inference_seconds[name]

        rows_per_second = (
            evaluated_rows / seconds
            if seconds > 0
            else 0.0
        )

        results["models"][name] = {
            "training_seconds": info[
                "training_seconds"
            ],
            "inference_seconds": seconds,
            "inference_rows_per_second": rows_per_second,
            **metrics,
        }

    return results


def build_markdown(results, training_rows):
    lines = []

    lines.append(
        "# Hybrid IDS V3 Stage 1 Algorithm Comparison"
    )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Three classifiers were compared using the same "
        "V3 Feature Set C training data and the same "
        "Tuesday development rows."
    )
    lines.append("")
    lines.append(
        "- Feature representation: Set C"
    )
    lines.append(
        f"- Features: {len(FEATURES)}"
    )
    lines.append(
        f"- Training rows: {training_rows:,}"
    )
    lines.append(
        "- Development dataset: "
        "CSE-CIC-IDS2018 Tuesday-20-02-2018"
    )
    lines.append(
        "- Final and secondary holdout datasets were not used"
    )
    lines.append(
        "- Default classifier decision thresholds were used"
    )
    lines.append("")
    lines.append("## Development Coverage")
    lines.append("")
    lines.append(
        f"- Evaluated rows: "
        f"{results['evaluated_rows']:,}"
    )
    lines.append(
        f"- Excluded rows: "
        f"{results['excluded_rows']:,}"
    )
    lines.append(
        f"- Coverage: "
        f"{results['coverage']:.4%}"
    )
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(
        "| Model | Accuracy | Balanced Accuracy | "
        "Attack Precision | Attack Recall | Attack F1 | "
        "Benign Recall | FPR | ROC AUC | Avg Precision | "
        "Train Sec | Rows/Sec |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|"
        "---:|---:|---:|---:|"
    )

    for name, metrics in results["models"].items():
        lines.append(
            f"| {name} "
            f"| {metrics['accuracy']:.6f} "
            f"| {metrics['balanced_accuracy']:.6f} "
            f"| {metrics['attack_precision']:.6f} "
            f"| {metrics['attack_recall']:.6f} "
            f"| {metrics['attack_f1']:.6f} "
            f"| {metrics['benign_recall']:.6f} "
            f"| {metrics['false_positive_rate']:.6f} "
            f"| {metrics['roc_auc']:.6f} "
            f"| {metrics['average_precision']:.6f} "
            f"| {metrics['training_seconds']:.2f} "
            f"| {metrics['inference_rows_per_second']:.2f} |"
        )

    for name, metrics in results["models"].items():
        matrix = metrics["confusion_matrix"]

        lines.append("")
        lines.append(f"## {name}")
        lines.append("")
        lines.append(
            f"- Accuracy: {metrics['accuracy']:.6f}"
        )
        lines.append(
            f"- Balanced accuracy: "
            f"{metrics['balanced_accuracy']:.6f}"
        )
        lines.append(
            f"- Attack precision: "
            f"{metrics['attack_precision']:.6f}"
        )
        lines.append(
            f"- Attack recall: "
            f"{metrics['attack_recall']:.6f}"
        )
        lines.append(
            f"- Attack F1: "
            f"{metrics['attack_f1']:.6f}"
        )
        lines.append(
            f"- Benign recall: "
            f"{metrics['benign_recall']:.6f}"
        )
        lines.append(
            f"- False-positive rate: "
            f"{metrics['false_positive_rate']:.6f}"
        )
        lines.append(
            f"- ROC AUC: "
            f"{metrics['roc_auc']:.6f}"
        )
        lines.append(
            f"- Average precision: "
            f"{metrics['average_precision']:.6f}"
        )
        lines.append(
            f"- Training time: "
            f"{metrics['training_seconds']:.2f} seconds"
        )
        lines.append(
            f"- Development inference time: "
            f"{metrics['inference_seconds']:.2f} seconds"
        )
        lines.append(
            f"- Development throughput: "
            f"{metrics['inference_rows_per_second']:,.2f} rows/sec"
        )
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

    lines.append("")
    lines.append("## Selection Rule")
    lines.append("")
    lines.append(
        "The selected algorithm should not be chosen from "
        "accuracy alone. Attack recall, attack precision, "
        "attack F1, benign false-positive behavior, "
        "ranking metrics, and inference performance "
        "must be considered together."
    )

    return "\n".join(lines)


def main():
    if not DEVELOPMENT_PATH.exists():
        raise FileNotFoundError(
            f"Development dataset missing: {DEVELOPMENT_PATH}"
        )

    print(
        "Hybrid IDS V3 Stage 1 Algorithm Comparison"
    )
    print("=" * 70)
    print("Feature Set: C")
    print(f"Features: {len(FEATURES)}")
    print(
        "Development dataset: "
        f"{DEVELOPMENT_PATH}"
    )
    print(
        "Final and secondary holdouts are not used."
    )

    X_train, y_train = load_training_data()

    print()
    print(f"Training rows: {len(X_train):,}")
    print("Training distribution:")
    print(
        y_train.value_counts().to_string()
    )

    trained_models = train_models(
        X_train,
        y_train,
    )

    print()
    print("=" * 70)
    print("Evaluating Tuesday development data")
    print("=" * 70)

    results = evaluate_models(
        trained_models
    )

    results["feature_set"] = FEATURE_SET_NAME
    results["features"] = FEATURES
    results["training_rows"] = len(X_train)
    results["training_distribution"] = {
        str(label): int(count)
        for label, count
        in y_train.value_counts().items()
    }

    results["model_configurations"] = {
        "random_forest": {
            "n_estimators": 200,
            "class_weight": "balanced_subsample",
            "random_state": RANDOM_STATE,
        },
        "extra_trees": {
            "n_estimators": 200,
            "class_weight": "balanced_subsample",
            "random_state": RANDOM_STATE,
        },
        "hist_gradient_boosting": {
            "learning_rate": 0.1,
            "max_iter": 200,
            "max_leaf_nodes": 31,
            "balanced_sample_weights": True,
            "random_state": RANDOM_STATE,
        },
    }

    print()
    print("=" * 70)
    print("Algorithm results")
    print("=" * 70)

    for name, metrics in results["models"].items():
        matrix = metrics[
            "confusion_matrix"
        ]

        print()
        print(name)
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
            f"ROC AUC: "
            f"{metrics['roc_auc']:.4%}"
        )
        print(
            f"Average precision: "
            f"{metrics['average_precision']:.4%}"
        )
        print(
            f"Training time: "
            f"{metrics['training_seconds']:.2f} sec"
        )
        print(
            f"Inference throughput: "
            f"{metrics['inference_rows_per_second']:,.0f} "
            f"rows/sec"
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
            len(X_train),
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("Comparison complete.")
    print(f"JSON: {OUTPUT_JSON}")
    print(f"Markdown: {OUTPUT_MARKDOWN}")


if __name__ == "__main__":
    main()
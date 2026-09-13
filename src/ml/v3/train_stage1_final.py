from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

from src.ml.v3.feature_schema import V3_FEATURE_SETS


RANDOM_STATE = 42

FEATURE_SET_NAME = "C"
FEATURES = V3_FEATURE_SETS[FEATURE_SET_NAME]

OPERATING_THRESHOLD = 0.250

TRAINING_PATH = Path(
    "data/v3/stage1_feature_set_c.csv"
)

MODEL_DIRECTORY = Path(
    "models/v3"
)

MODEL_PATH = MODEL_DIRECTORY / (
    "stage1_hist_gradient_boosting.joblib"
)

METADATA_PATH = MODEL_DIRECTORY / (
    "stage1_hist_gradient_boosting_metadata.json"
)

HASH_PATH = MODEL_DIRECTORY / (
    "stage1_hist_gradient_boosting.sha256"
)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def get_git_commit():
    try:
        result = subprocess.run(
            [
                "git",
                "rev-parse",
                "HEAD",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        return result.stdout.strip()

    except Exception:
        return None


def load_training_data():
    if not TRAINING_PATH.exists():
        raise FileNotFoundError(
            f"Missing training dataset: "
            f"{TRAINING_PATH}"
        )

    dataframe = pd.read_csv(
        TRAINING_PATH,
        low_memory=False,
    )

    required_columns = (
        FEATURES
        + [
            "binary_label",
        ]
    )

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise KeyError(
            "Training dataset is missing "
            f"columns: {missing_columns}"
        )

    X = dataframe[
        FEATURES
    ].copy()

    y = (
        dataframe[
            "binary_label"
        ]
        .astype(str)
        .str.strip()
    )

    allowed_labels = {
        "BENIGN",
        "ATTACK",
    }

    observed_labels = set(
        y.unique()
    )

    unexpected_labels = (
        observed_labels
        - allowed_labels
    )

    if unexpected_labels:
        raise ValueError(
            "Unexpected Stage 1 labels: "
            f"{sorted(unexpected_labels)}"
        )

    values = X.to_numpy(
        dtype=float
    )

    if not np.isfinite(values).all():
        raise ValueError(
            "Training features contain "
            "NaN or infinite values."
        )

    return dataframe, X, y


def train_model(X, y):
    sample_weights = (
        compute_sample_weight(
            class_weight="balanced",
            y=y,
        )
    )

    model = (
        HistGradientBoostingClassifier(
            learning_rate=0.1,
            max_iter=200,
            max_leaf_nodes=31,
            random_state=RANDOM_STATE,
        )
    )

    start = time.perf_counter()

    model.fit(
        X,
        y,
        sample_weight=sample_weights,
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    return model, elapsed


def verify_model(model, X):
    classes = list(
        model.classes_
    )

    if "ATTACK" not in classes:
        raise ValueError(
            "Frozen model does not contain "
            "the ATTACK class."
        )

    if "BENIGN" not in classes:
        raise ValueError(
            "Frozen model does not contain "
            "the BENIGN class."
        )

    sample = X.iloc[
        :100
    ]

    probabilities = (
        model.predict_proba(
            sample
        )
    )

    if probabilities.shape != (
        len(sample),
        len(classes),
    ):
        raise RuntimeError(
            "Unexpected probability "
            f"shape: {probabilities.shape}"
        )

    if not np.isfinite(
        probabilities
    ).all():
        raise RuntimeError(
            "Model produced invalid "
            "probabilities."
        )

    attack_index = (
        classes.index(
            "ATTACK"
        )
    )

    return {
        "classes": classes,
        "attack_class_index": (
            attack_index
        ),
        "smoke_test_rows": (
            len(sample)
        ),
    }


def main():
    print(
        "Hybrid IDS V3 Stage 1 "
        "Final Model Freeze"
    )

    print("=" * 70)

    print(
        f"Feature Set: "
        f"{FEATURE_SET_NAME}"
    )

    print(
        f"Feature count: "
        f"{len(FEATURES)}"
    )

    print(
        f"Operating threshold: "
        f"{OPERATING_THRESHOLD:.3f}"
    )

    print()
    print(
        "Loading frozen Stage 1 "
        "training dataset..."
    )

    dataframe, X, y = (
        load_training_data()
    )

    distribution = (
        y.value_counts()
        .to_dict()
    )

    print(
        f"Training rows: "
        f"{len(X):,}"
    )

    print(
        "Training distribution:"
    )

    print(
        y.value_counts()
        .to_string()
    )

    print()
    print(
        "Calculating training "
        "dataset SHA-256..."
    )

    training_sha256 = (
        sha256_file(
            TRAINING_PATH
        )
    )

    print(
        f"Training SHA-256: "
        f"{training_sha256}"
    )

    print()
    print(
        "Training final "
        "HistGradientBoosting model..."
    )

    model, training_seconds = (
        train_model(
            X,
            y,
        )
    )

    print(
        "Training completed in "
        f"{training_seconds:.3f} "
        "seconds"
    )

    print()
    print(
        "Running model smoke test..."
    )

    verification = (
        verify_model(
            model,
            X,
        )
    )

    print(
        "Smoke test passed."
    )

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    print()
    print(
        f"Saving model: "
        f"{MODEL_PATH}"
    )

    joblib.dump(
        model,
        MODEL_PATH,
        compress=3,
    )

    model_sha256 = (
        sha256_file(
            MODEL_PATH
        )
    )

    model_size_bytes = (
        MODEL_PATH
        .stat()
        .st_size
    )

    HASH_PATH.write_text(
        (
            f"{model_sha256}  "
            f"{MODEL_PATH.name}\n"
        ),
        encoding="utf-8",
    )

    metadata = {
        "artifact": {
            "name": (
                "Hybrid IDS V3 "
                "Stage 1"
            ),
            "purpose": (
                "Binary BENIGN vs "
                "ATTACK classification"
            ),
            "model_path": str(
                MODEL_PATH
            ),
            "model_sha256": (
                model_sha256
            ),
            "model_size_bytes": (
                model_size_bytes
            ),
            "hash_file": str(
                HASH_PATH
            ),
            "frozen_at_utc": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
        },
        "training": {
            "dataset_path": str(
                TRAINING_PATH
            ),
            "dataset_sha256": (
                training_sha256
            ),
            "rows": len(X),
            "class_distribution": {
                str(label): int(
                    count
                )
                for label, count
                in distribution.items()
            },
            "training_seconds": (
                training_seconds
            ),
            "random_state": (
                RANDOM_STATE
            ),
        },
        "features": {
            "feature_set": (
                FEATURE_SET_NAME
            ),
            "count": len(
                FEATURES
            ),
            "names": FEATURES,
        },
        "model": {
            "type": (
                "HistGradientBoostingClassifier"
            ),
            "learning_rate": 0.1,
            "max_iter": 200,
            "max_leaf_nodes": 31,
            "balanced_sample_weights": (
                True
            ),
            "random_state": (
                RANDOM_STATE
            ),
            "classes": (
                verification[
                    "classes"
                ]
            ),
            "attack_class_index": (
                verification[
                    "attack_class_index"
                ]
            ),
        },
        "operating_point": {
            "threshold": (
                OPERATING_THRESHOLD
            ),
            "selection_dataset": (
                "Tuesday-20-02-2018 "
                "development dataset"
            ),
            "selection_rule": (
                "Minimize false-positive "
                "rate while preserving "
                "at least 95% attack recall"
            ),
            "development_metrics": {
                "attack_recall": (
                    0.952209
                ),
                "attack_precision": (
                    0.552817
                ),
                "attack_f1": (
                    0.699519
                ),
                "benign_recall": (
                    0.939312
                ),
                "false_positive_rate": (
                    0.060688
                ),
            },
        },
        "provenance": {
            "git_commit": (
                get_git_commit()
            ),
            "python_version": (
                sys.version
            ),
            "numpy_version": (
                np.__version__
            ),
            "pandas_version": (
                pd.__version__
            ),
            "scikit_learn_version": (
                sklearn.__version__
            ),
            "joblib_version": (
                joblib.__version__
            ),
        },
        "evaluation_policy": {
            "development_data_used_for_training": (
                False
            ),
            "final_holdout_used": (
                False
            ),
            "secondary_holdout_used": (
                False
            ),
            "model_changes_allowed_after_freeze": (
                False
            ),
        },
    }

    with METADATA_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=4,
        )

    print()
    print("=" * 70)

    print(
        "V3 Stage 1 model "
        "artifact created."
    )

    print(
        f"Model: {MODEL_PATH}"
    )

    print(
        f"Metadata: "
        f"{METADATA_PATH}"
    )

    print(
        f"SHA-256 file: "
        f"{HASH_PATH}"
    )

    print(
        f"Model SHA-256: "
        f"{model_sha256}"
    )

    print(
        f"Model size: "
        f"{model_size_bytes:,} "
        "bytes"
    )

    print()
    print(
        "No development or "
        "holdout datasets were "
        "opened by this script."
    )


if __name__ == "__main__":
    main()
import json
import time
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split


DATASET_PATH = Path("data/cicids2017_multiclass.csv")
MODEL_PATH = Path("models/random_forest_live_v2.joblib")
FEATURES_PATH = Path("models/live_feature_names_v2.json")
METRICS_PATH = Path("models/live_model_metrics_v2.json")
MAX_SAMPLES_PER_CLASS = 250000


LIVE_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count"
]


# V2 changes only the Random Forest configuration.
# Dataset, feature set, sampling, train/test split, and random state
# remain the same as V1 so the results can be compared fairly future versions will be more varied
V2_PARAMS = {
    "n_estimators": 500,
    "max_depth": 22,
    "min_samples_split": 5,
    "min_samples_leaf": 1,
    "max_features": 0.5,
    "class_weight": "balanced_subsample",
    "bootstrap": True,
    "random_state": 42,
    "n_jobs": -1
}


def load_data():
    print("Loading CICIDS2017 multiclass dataset...")

    data = pd.read_csv(DATASET_PATH)
    data.columns = data.columns.str.strip()

    # Keep the same V1 class setup.
    data = data[data["Label"] != "Infiltration"]

    sampled_classes = []

    for label, group in data.groupby("Label"):
        if len(group) > MAX_SAMPLES_PER_CLASS:
            group = group.sample(n=MAX_SAMPLES_PER_CLASS, random_state=42)

        sampled_classes.append(group)

    data = pd.concat(sampled_classes, ignore_index=True)

    print("\nTraining Distribution:")
    print(data["Label"].value_counts())

    return data


def prepare_data(data):
    missing_features = [feature for feature in LIVE_FEATURES if feature not in data.columns]

    if missing_features:
        print("\nMissing dataset features:")

        for feature in missing_features:
            print(feature)

        raise ValueError("Required live features are missing from the dataset.")

    X = data[LIVE_FEATURES]
    y = data["Label"]

    print(f"\nTotal samples: {len(X):,}")
    print(f"Live-compatible features: {len(LIVE_FEATURES)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples: {len(X_test):,}")

    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    print("\n--- Hybrid IDS V2 Configuration ---")

    for name, value in V2_PARAMS.items():
        print(f"{name}: {value}")

    model = RandomForestClassifier(**V2_PARAMS)

    print("\nTraining V2 Random Forest...")

    start_time = time.perf_counter()

    model.fit(X_train, y_train)

    training_time = time.perf_counter() - start_time

    print(f"Training time: {training_time:.2f} seconds")

    return model, training_time


def evaluate_model(model, X_test, y_test):
    print("\nEvaluating V2...")

    start_time = time.perf_counter()

    predictions = model.predict(X_test)

    inference_time = time.perf_counter() - start_time

    accuracy = accuracy_score(y_test, predictions)
    macro_f1 = f1_score(y_test, predictions, average="macro")
    weighted_f1 = f1_score(y_test, predictions, average="weighted")

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=model.classes_
    )

    print("\n--- V2 Internal Results ---")
    print(f"Accuracy: {accuracy:.4%}")
    print(f"Macro F1: {macro_f1:.4%}")
    print(f"Weighted F1: {weighted_f1:.4%}")

    print("\nPer-Class Recall:")

    for class_name in model.classes_:
        recall = report[class_name]["recall"]
        print(f"{class_name}: {recall:.4%}")

    print("\nPer-Class F1:")

    for class_name in model.classes_:
        class_f1 = report[class_name]["f1-score"]
        print(f"{class_name}: {class_f1:.4%}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            digits=4,
            zero_division=0
        )
    )

    print("Classes:")
    print(model.classes_)

    print("\nConfusion Matrix:")
    print(matrix)

    print(f"\nInference time for {len(X_test):,} samples: {inference_time:.2f} seconds")

    return {
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "inference_time_seconds": inference_time
    }


def save_results(model, training_time, results, total_samples):
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    metrics = {
        "version": "V2-E",
        "model": "RandomForestClassifier",
        "dataset": "CICIDS2017",
        "purpose": "Tuned live-compatible Hybrid IDS model",
        "comparison_baseline": "Hybrid IDS V1",
        "samples": total_samples,
        "features": len(LIVE_FEATURES),
        "max_samples_per_class": MAX_SAMPLES_PER_CLASS,
        "test_size": 0.20,
        "random_state": 42,
        "training_parameters": V2_PARAMS,
        "training_time_seconds": training_time,
        "accuracy": float(results["accuracy"]),
        "macro_f1": float(results["macro_f1"]),
        "weighted_f1": float(results["weighted_f1"]),
        "classes": model.classes_.tolist(),
        "classification_report": results["classification_report"],
        "confusion_matrix": results["confusion_matrix"],
        "inference_time_seconds": results["inference_time_seconds"]
    }

    joblib.dump(model, MODEL_PATH)

    with FEATURES_PATH.open("w", encoding="utf-8") as feature_file:
        json.dump(LIVE_FEATURES, feature_file, indent=4)

    with METRICS_PATH.open("w", encoding="utf-8") as metrics_file:
        json.dump(metrics, metrics_file, indent=4)

    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Feature schema saved to: {FEATURES_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")


def main():
    data = load_data()

    X_train, X_test, y_train, y_test = prepare_data(data)

    model, training_time = train_model(X_train, y_train)

    results = evaluate_model(model, X_test, y_test)

    save_results(model, training_time, results, len(data))


if __name__ == "__main__":
    main()
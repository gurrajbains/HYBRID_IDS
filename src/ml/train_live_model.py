import json
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split


DATASET_PATH = "data/cicids2017_multiclass.csv"
MODEL_PATH = "models/random_forest_live.joblib"
FEATURES_PATH = "models/live_feature_names.json"
METRICS_PATH = "models/live_model_metrics.json"

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


def load_data():
    print("Loading CICIDS2017 multiclass dataset...")

    data = pd.read_csv(DATASET_PATH)
    data.columns = data.columns.str.strip()

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


def train_model():
    data = load_data()

    missing_features = [feature for feature in LIVE_FEATURES if feature not in data.columns]

    if missing_features:
        print("\nMissing dataset features:")

        for feature in missing_features:
            print(feature)

        return

    X = data[LIVE_FEATURES]
    y = data["Label"]

    print(f"\nSamples: {X.shape[0]}")
    print(f"Live-compatible features: {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining live-compatible Random Forest...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    macro_f1 = f1_score(y_test, predictions, average="macro")
    weighted_f1 = f1_score(y_test, predictions, average="weighted")

    report = classification_report(
        y_test,
        predictions,
        output_dict=True
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=model.classes_
    )

    print("\n--- Live Model Results ---")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Macro F1: {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions
        )
    )

    print("Classes:")
    print(model.classes_)

    print("\nConfusion Matrix:")
    print(matrix)

    metrics = {
        "model": "RandomForestClassifier",
        "dataset": "CICIDS2017",
        "purpose": "Live-compatible Hybrid IDS model",
        "samples": int(X.shape[0]),
        "features": len(LIVE_FEATURES),
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "classes": model.classes_.tolist(),
        "classification_report": report,
        "confusion_matrix": matrix.tolist()
    }

    joblib.dump(model, MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as feature_file:
        json.dump(LIVE_FEATURES, feature_file, indent=4)

    with open(METRICS_PATH, "w", encoding="utf-8") as metrics_file:
        json.dump(metrics, metrics_file, indent=4)

    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Feature schema saved to: {FEATURES_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")


if __name__ == "__main__":
    train_model()
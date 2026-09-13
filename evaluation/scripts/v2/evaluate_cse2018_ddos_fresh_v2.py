from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import classification_report, confusion_matrix


DATASET_PATH = Path(
    "evaluation/datasets/CSE-CIC-IDS2018/"
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
)

MODEL_PATH = Path("models/random_forest_live_v2.joblib")
FEATURES_PATH = Path("models/live_feature_names_v2.json")


COLUMN_MAPPING = {
    "Dst Port": "Destination Port",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count"
}


def load_dataset():
    print("Loading fresh CSE-CIC-IDS2018 DDoS evaluation data...")

    data = pd.read_csv(DATASET_PATH, low_memory=False)
    data.columns = data.columns.str.strip()

    data = data[data["Label"] != "Label"].copy()

    print(f"Rows after removing repeated headers: {len(data):,}")

    print("\nOriginal label distribution:")
    print(data["Label"].value_counts())

    data = data.rename(columns=COLUMN_MAPPING)

    return data


def prepare_features(data, feature_names):
    missing_features = [
        feature
        for feature in feature_names
        if feature not in data.columns
    ]

    if missing_features:
        raise ValueError(f"Missing required features: {missing_features}")

    X = data[feature_names].apply(pd.to_numeric, errors="coerce")

    invalid_mask = (
        X.isna().any(axis=1)
        | np.isinf(X).any(axis=1)
    )

    invalid_count = int(invalid_mask.sum())

    print(f"\nRows with invalid feature values: {invalid_count:,}")

    valid_data = data.loc[~invalid_mask].copy()
    X = X.loc[~invalid_mask].copy()

    print(f"Rows used for evaluation: {len(X):,}")

    return X, valid_data


def run_binary_evaluation(data, predictions):
    actual_binary = np.where(
        data["Label"].str.lower() == "benign",
        "BENIGN",
        "ATTACK"
    )

    predicted_binary = np.where(
        predictions == "BENIGN",
        "BENIGN",
        "ATTACK"
    )

    labels = ["BENIGN", "ATTACK"]

    print("\n--- Binary Fresh External Evaluation ---")
    print("BENIGN = benign traffic")
    print("ATTACK = any non-BENIGN prediction")

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            actual_binary,
            predicted_binary,
            labels=labels
        )
    )

    print("\nClassification Report:")
    print(
        classification_report(
            actual_binary,
            predicted_binary,
            labels=labels,
            digits=4,
            zero_division=0
        )
    )


def run_mapped_evaluation(data, predictions):
    actual_mapped = data["Label"].map(
        {
            "Benign": "BENIGN",
            "DDOS attack-HOIC": "DDoS",
            "DDOS attack-LOIC-UDP": "DDoS"
        }
    )

    labels = ["BENIGN", "DDoS"]

    print("\n--- Mapped DDoS Fresh External Evaluation ---")
    print("Benign -> BENIGN")
    print("DDOS attack-HOIC -> DDoS")
    print("DDOS attack-LOIC-UDP -> DDoS")

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            actual_mapped,
            predictions,
            labels=labels
        )
    )

    print("\nClassification Report:")
    print(
        classification_report(
            actual_mapped,
            predictions,
            labels=labels,
            digits=4,
            zero_division=0
        )
    )


def show_prediction_distribution(predictions):
    print("\nRaw model prediction distribution:")

    print(
        pd.Series(predictions)
        .value_counts()
    )


def show_attack_breakdown(data, predictions):
    print("\n--- Per-Attack Prediction Breakdown ---")

    attack_labels = [
        "DDOS attack-HOIC",
        "DDOS attack-LOIC-UDP"
    ]

    for attack_label in attack_labels:
        mask = data["Label"] == attack_label
        attack_predictions = predictions[mask.to_numpy()]

        counts = pd.Series(attack_predictions).value_counts()

        total = len(attack_predictions)

        specific_ddos = int(
            np.sum(attack_predictions == "DDoS")
        )

        any_attack = int(
            np.sum(attack_predictions != "BENIGN")
        )

        specific_rate = (
            specific_ddos / total * 100
            if total
            else 0.0
        )

        any_attack_rate = (
            any_attack / total * 100
            if total
            else 0.0
        )

        print(f"\n{attack_label}:")
        print(counts)

        print(
            f"Predicted specifically as DDoS: "
            f"{specific_rate:.4f}%"
        )

        print(
            f"Detected as any non-BENIGN class: "
            f"{any_attack_rate:.4f}%"
        )


def main():
    data = load_dataset()

    print("\nLoading frozen Hybrid IDS V2 model...")

    model = joblib.load(MODEL_PATH)

    import json

    with FEATURES_PATH.open("r", encoding="utf-8") as file:
        feature_names = json.load(file)

    X, valid_data = prepare_features(
        data,
        feature_names
    )

    print("\nRunning frozen V2 on untouched CSE-CIC-IDS2018 day...")

    predictions = model.predict(X)

    run_binary_evaluation(
        valid_data,
        predictions
    )

    run_mapped_evaluation(
        valid_data,
        predictions
    )

    show_prediction_distribution(
        predictions
    )

    show_attack_breakdown(
        valid_data,
        predictions
    )


if __name__ == "__main__":
    main()
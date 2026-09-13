import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


DATASET_PATH = Path("evaluation/datasets/CSE-CIC-IDS2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
MODEL_PATH = Path("models/random_forest_live_v2e.joblib")
FEATURES_PATH = Path("models/live_feature_names.json")


COLUMN_MAP = {
    "Destination Port": "Dst Port",
    "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
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
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
    "Min Packet Length": "Pkt Len Min",
    "Max Packet Length": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "URG Flag Count": "URG Flag Cnt"
}


def load_data():
    print("Loading CSE-CIC-IDS2018 brute-force data...")

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    if "Label" not in df.columns:
        raise ValueError("Label column not found in dataset.")

    df = df[df["Label"] != "Label"].copy()

    print(f"Rows after removing repeated headers: {len(df):,}")

    return df


def prepare_features(df):
    with FEATURES_PATH.open("r", encoding="utf-8") as feature_file:
        expected_features = json.load(feature_file)

    selected_columns = [COLUMN_MAP[feature] for feature in expected_features]

    missing_columns = [column for column in selected_columns if column not in df.columns]

    if missing_columns:
        raise ValueError(f"Missing required dataset columns: {missing_columns}")

    X = df[selected_columns].copy()
    X.columns = expected_features

    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    X = X.replace([np.inf, -np.inf], np.nan)

    invalid_rows = X.isna().any(axis=1)

    print(f"Rows with invalid feature values: {invalid_rows.sum():,}")

    X = X.loc[~invalid_rows].copy()
    y_original = df.loc[~invalid_rows, "Label"].copy()

    return X, y_original


def create_binary_ground_truth(labels):
    return labels.apply(
        lambda label: "BENIGN" if label.strip().lower() == "benign" else "ATTACK"
    )


def create_binary_predictions(predictions):
    return np.where(predictions == "BENIGN", "BENIGN", "ATTACK")


def create_mapped_ground_truth(labels):
    def map_label(label):
        label = label.strip()

        if label == "Benign":
            return "BENIGN"

        if label in {"FTP-BruteForce", "SSH-Bruteforce"}:
            return "BruteForce"

        return "OTHER"

    return labels.apply(map_label)


def print_binary_evaluation(y_true, y_pred):
    print("\n--- Binary External Evaluation ---")
    print("BENIGN = benign traffic")
    print("ATTACK = any non-benign traffic")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, y_pred, labels=["BENIGN", "ATTACK"]))

    print("\nClassification Report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=["BENIGN", "ATTACK"],
            digits=4,
            zero_division=0
        )
    )


def print_mapped_evaluation(y_true, predictions):
    print("\n--- Mapped Multiclass External Evaluation ---")
    print("Benign -> BENIGN")
    print("FTP-BruteForce -> BruteForce")
    print("SSH-Bruteforce -> BruteForce")

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            y_true,
            predictions,
            labels=["BENIGN", "BruteForce"]
        )
    )

    print("\nClassification Report:")
    print(
        classification_report(
            y_true,
            predictions,
            labels=["BENIGN", "BruteForce"],
            digits=4,
            zero_division=0
        )
    )


def print_attack_breakdown(y_original, predictions):
    print("\n--- Per-Attack Prediction Breakdown ---")

    for attack_label in ["FTP-BruteForce", "SSH-Bruteforce"]:
        attack_mask = y_original == attack_label

        attack_predictions = pd.Series(predictions[attack_mask.to_numpy()])

        print(f"\n{attack_label}:")
        print(attack_predictions.value_counts())

        brute_force_rate = (attack_predictions == "BruteForce").mean()
        non_benign_rate = (attack_predictions != "BENIGN").mean()

        print(f"Predicted specifically as BruteForce: {brute_force_rate:.4%}")
        print(f"Detected as any non-BENIGN class: {non_benign_rate:.4%}")


def main():
    df = load_data()

    print("\nOriginal label distribution:")
    print(df["Label"].value_counts())

    X, y_original = prepare_features(df)

    print(f"\nRows used for evaluation: {len(X):,}")

    print("\nLoading frozen CIC-IDS-2017 Random Forest...")
    model = joblib.load(MODEL_PATH)

    print("Running model on CSE-CIC-IDS2018...")

    predictions = model.predict(X)

    y_true_binary = create_binary_ground_truth(y_original)
    y_pred_binary = create_binary_predictions(predictions)

    print_binary_evaluation(y_true_binary, y_pred_binary)

    y_true_mapped = create_mapped_ground_truth(y_original)

    valid_mapped_mask = y_true_mapped != "OTHER"

    print_mapped_evaluation(
        y_true_mapped.loc[valid_mapped_mask],
        predictions[valid_mapped_mask.to_numpy()]
    )

    print("\nRaw model prediction distribution:")
    print(pd.Series(predictions).value_counts())

    print_attack_breakdown(y_original, predictions)


if __name__ == "__main__":
    main()
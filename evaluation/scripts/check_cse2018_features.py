import json
from pathlib import Path

import pandas as pd


DATASET_PATH = Path("evaluation/datasets/CSE-CIC-IDS2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv")
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


def main():
    with FEATURES_PATH.open("r", encoding="utf-8") as feature_file:
        expected_features = json.load(feature_file)

    dataset_columns = pd.read_csv(DATASET_PATH, nrows=0).columns.tolist()

    missing_mappings = []
    missing_dataset_columns = []

    for feature in expected_features:
        mapped_column = COLUMN_MAP.get(feature)

        if mapped_column is None:
            missing_mappings.append(feature)
            continue

        if mapped_column not in dataset_columns:
            missing_dataset_columns.append((feature, mapped_column))

    print(f"Model features expected: {len(expected_features)}")
    print(f"Mappings defined: {len(COLUMN_MAP)}")
    print(f"Missing mappings: {len(missing_mappings)}")
    print(f"Missing dataset columns: {len(missing_dataset_columns)}")

    if missing_mappings:
        print("\nFeatures without mappings:")

        for feature in missing_mappings:
            print(f"- {feature}")

    if missing_dataset_columns:
        print("\nMapped columns missing from CSE-CIC-IDS2018:")

        for feature, column in missing_dataset_columns:
            print(f"- {feature} -> {column}")

    if not missing_mappings and not missing_dataset_columns:
        print("\nCOMPATIBLE: All live-model features have valid CSE-CIC-IDS2018 columns.")


if __name__ == "__main__":
    main()
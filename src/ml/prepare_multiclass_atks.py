import glob
import os
import pandas as pd
import numpy as np
DATA_PATH = "data"


def load_all_datasets():
    csv_files = glob.glob(os.path.join(DATA_PATH, "*.csv"))

    datasets = []

    for file_path in csv_files:
        print(f"Loading: {file_path}")

        data = pd.read_csv(file_path)
        data.columns = data.columns.str.strip()

        datasets.append(data)

    combined_data = pd.concat(datasets, ignore_index=True)

    return combined_data


def clean_dataset(data):
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.dropna()

    return data


def simplify_labels(label):
    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    if "PortScan" in label:
        return "PortScan"

    if "DDoS" in label:
        return "DDoS"

    if "DoS" in label or "Heartbleed" in label:
        return "DoS"

    if "FTP-Patator" in label or "SSH-Patator" in label:
        return "BruteForce"

    if "Web Attack" in label:
        return "WebAttack"

    if "Bot" in label:
        return "Bot"

    if "Infiltration" in label:
        return "Infiltration"

    return "OtherAttack"


def prepare_dataset():
    data = load_all_datasets()

    print(f"\nRows before cleaning: {len(data)}")

    data = clean_dataset(data)

    print(f"Rows after cleaning: {len(data)}")

    data["Label"] = data["Label"].apply(simplify_labels)

    print("\nClass Distribution:")
    print(data["Label"].value_counts())

    output_path = "data/cicids2017_multiclass.csv"

    data.to_csv(output_path, index=False)

    print(f"\nCombined dataset saved to: {output_path}")


if __name__ == "__main__":
    prepare_dataset()
import pandas as pd
import numpy as np


def load_dataset(file_path):
    print(f"Loading dataset: {file_path}")

    data = pd.read_csv(file_path)

    data.columns = data.columns.str.strip()

    print(f"Rows: {data.shape[0]}")
    print(f"Columns: {data.shape[1]}")

    return data


def inspect_dataset(data):
    print("\nColumns:")
    print(data.columns.tolist())

    if "Label" in data.columns:
        print("\nLabels:")
        print(data["Label"].value_counts())

    print("\nMissing Values:")
    print(data.isnull().sum().sum())

    print("\nInfinite Values:")
    numeric_data = data.select_dtypes(include=[np.number])
    print(np.isinf(numeric_data).sum().sum())


def clean_dataset(data):
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.dropna()

    return data


if __name__ == "__main__":
    dataset = load_dataset("data/cicids2017.csv")

    inspect_dataset(dataset)

    dataset = clean_dataset(dataset)

    print(f"\nRows after cleaning: {dataset.shape[0]}")
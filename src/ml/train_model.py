import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score
from src.ml.preprocess import load_dataset, clean_dataset


DATASET_PATH = "data/cicids2017.csv"
MODEL_PATH = "models/random_forest_ids.joblib"
FEATURES_PATH = "models/feature_names.json"


def prepare_data(data):
    data = clean_dataset(data)

    data["Label"] = data["Label"].apply(lambda label: 0 if label == "BENIGN" else 1)

    X = data.drop(columns=["Label"])
    y = data["Label"]

    X = X.select_dtypes(include=["number"])

    return X, y


def train_model():
    data = load_dataset(DATASET_PATH)

    X, y = prepare_data(data)

    print(f"\nFeatures used: {X.shape[1]}")
    print(f"Samples used: {X.shape[0]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"Training samples: {X_train.shape[0]}")
    print(f"Testing samples: {X_test.shape[0]}")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining Random Forest...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    matrix = confusion_matrix(y_test, predictions)

    metrics = {
        "model": "RandomForestClassifier",
        "dataset": "CICIDS2017 Friday PortScan",
        "samples": int(X.shape[0]),
        "training_samples": int(X_train.shape[0]),
        "testing_samples": int(X_test.shape[0]),
        "features": int(X.shape[1]),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "true_negatives": int(matrix[0][0]),
        "false_positives": int(matrix[0][1]),
        "false_negatives": int(matrix[1][0]),
        "true_positives": int(matrix[1][1])
    }
    print("\n--- Model Results ---")
    print(f"Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["BENIGN", "PortScan"]
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    joblib.dump(model, MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as feature_file:
        json.dump(X.columns.tolist(), feature_file, indent=4)
    with open("models/evaluation_metrics.json", "w", encoding="utf-8") as metrics_file:
        json.dump(metrics, metrics_file, indent=4)
    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Feature list saved to: {FEATURES_PATH}")
    


if __name__ == "__main__":
    train_model()
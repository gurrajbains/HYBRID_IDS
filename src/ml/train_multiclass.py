import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split


DATASET_PATH = "data/cicids2017_multiclass.csv"
MODEL_PATH = "models/random_forest_multiclass.joblib"
FEATURES_PATH = "models/multiclass_feature_names.json"
METRICS_PATH = "models/multiclass_evaluation_metrics.json"

MAX_SAMPLES_PER_CLASS = 250000


def load_and_prepare_data():
    print("Loading multiclass CICIDS2017 dataset...")

    data = pd.read_csv(DATASET_PATH)
    data.columns = data.columns.str.strip()

    data = data[data["Label"] != "Infiltration"]

    sampled_classes = []

    for label, group in data.groupby("Label"):
        if len(group) > MAX_SAMPLES_PER_CLASS:
            group = group.sample(
                n=MAX_SAMPLES_PER_CLASS,
                random_state=42
            )

        sampled_classes.append(group)

    data = pd.concat(sampled_classes, ignore_index=True)

    print("\nTraining Distribution:")
    print(data["Label"].value_counts())

    X = data.drop(columns=["Label"])
    y = data["Label"]

    X = X.select_dtypes(include=["number"])

    return X, y


def train_model():
    X, y = load_and_prepare_data()

    print(f"\nSamples used: {X.shape[0]}")
    print(f"Features used: {X.shape[1]}")

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
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining multiclass Random Forest...")

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

    print("\n--- Multiclass Model Results ---")
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
        "dataset": "CICIDS2017 Multiclass",
        "samples": int(X.shape[0]),
        "features": int(X.shape[1]),
        "training_samples": int(X_train.shape[0]),
        "testing_samples": int(X_test.shape[0]),
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "classes": model.classes_.tolist(),
        "classification_report": report,
        "confusion_matrix": matrix.tolist()
    }

    joblib.dump(model, MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as feature_file:
        json.dump(X.columns.tolist(), feature_file, indent=4)

    with open(METRICS_PATH, "w", encoding="utf-8") as metrics_file:
        
        json.dump(metrics, metrics_file, indent=4)

    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")


if __name__ == "__main__":
    train_model()
import pandas as pd

from src.ml.live_detector import LiveMLDetector


DATASET_PATH = "data/cicids2017_multiclass.csv"


def test_attack_prediction():
    print("Loading CICIDS2017 sample...")

    data = pd.read_csv(DATASET_PATH)
    data.columns = data.columns.str.strip()

    detector = LiveMLDetector()

    attack_classes = [
        "PortScan",
        "DDoS",
        "DoS",
        "BruteForce",
        "Bot",
        "WebAttack"
    ]

    print("\n--- ML Attack Prediction Test ---")

    for attack_class in attack_classes:
        matching_rows = data[data["Label"] == attack_class]

        if matching_rows.empty:
            print(f"\n{attack_class}: No sample found")
            continue

        sample = matching_rows.iloc[0]

        flow_features = {
            feature: sample[feature]
            for feature in detector.feature_names
        }

        result = detector.predict(flow_features)

        print(f"\nActual Label: {attack_class}")
        print(f"ML Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.2%}")

        print("Top probabilities:")

        sorted_probabilities = sorted(
            result["probabilities"].items(),
            key=lambda item: item[1],
            reverse=True
        )

        for class_name, probability in sorted_probabilities[:3]:
            print(f"  {class_name}: {probability:.2%}")


if __name__ == "__main__":
    test_attack_prediction()
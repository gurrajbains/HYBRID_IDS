import json

from src.flow.flow_tracker import FlowTracker


FEATURES_PATH = "models/multiclass_feature_names.json"


def get_generated_features():
    tracker = FlowTracker()

    sample_flow = {
        "start_time": 0,
        "last_time": 1,

        "origin_ip": "192.168.1.10",
        "origin_port": 50000,
        "destination_ip": "192.168.1.20",
        "destination_port": 443,

        "forward_packets": 2,
        "backward_packets": 2,

        "forward_bytes": 200,
        "backward_bytes": 300,

        "forward_lengths": [100, 100],
        "backward_lengths": [150, 150],
        "packet_lengths": [100, 150, 100, 150],

        "packet_times": [0, 0.1, 0.2, 0.3],
        "forward_times": [0, 0.2],
        "backward_times": [0.1, 0.3],

        "syn_count": 2,
        "ack_count": 3,
        "fin_count": 1,
        "rst_count": 0,
        "psh_count": 1,
        "urg_count": 0
    }

    features = tracker.extract_features(sample_flow)

    return list(features.keys())


def compare_features():
    with open(FEATURES_PATH, "r", encoding="utf-8") as feature_file:
        expected_features = json.load(feature_file)

    generated_features = get_generated_features()

    missing_features = [
        feature for feature in expected_features
        if feature not in generated_features
    ]

    extra_features = [
        feature for feature in generated_features
        if feature not in expected_features
    ]

    print("--- Feature Compatibility Check ---")

    print(f"\nModel expects: {len(expected_features)} features")
    print(f"FlowTracker generates: {len(generated_features)} features")
    print(f"Missing: {len(missing_features)}")
    print(f"Extra: {len(extra_features)}")

    print("\n--- Missing Features ---")

    for feature in missing_features:
        print(feature)

    if extra_features:
        print("\n--- Extra Features ---")

        for feature in extra_features:
            print(feature)


if __name__ == "__main__":
    compare_features()
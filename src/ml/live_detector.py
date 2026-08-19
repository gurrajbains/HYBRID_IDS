import json
import joblib
import pandas as pd


MODEL_PATH = "models/random_forest_live.joblib"
FEATURES_PATH = "models/live_feature_names.json"


class LiveMLDetector:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)

        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1

        with open(FEATURES_PATH, "r", encoding="utf-8") as feature_file:
            self.feature_names = json.load(feature_file)

    def prepare_flow(self, flow_features):
        missing_features = [feature for feature in self.feature_names if feature not in flow_features]

        if missing_features:
            raise ValueError(f"Flow is missing required features: {missing_features}")

        return {feature: flow_features[feature] for feature in self.feature_names}

    def predict(self, flow_features):
        feature_values = self.prepare_flow(flow_features)

        flow_data = pd.DataFrame([feature_values], columns=self.feature_names)

        prediction = self.model.predict(flow_data)[0]
        probabilities = self.model.predict_proba(flow_data)[0]

        probability_map = {
            class_name: float(probability)
            for class_name, probability in zip(self.model.classes_, probabilities)
        }

        confidence = probability_map[prediction]

        return {
            "prediction": prediction,
            "confidence": confidence,
            "probabilities": probability_map
        }

    def predict_batch(self, flows):
        if not flows:
            return []

        prepared_flows = [self.prepare_flow(flow) for flow in flows]

        flow_data = pd.DataFrame(prepared_flows, columns=self.feature_names)

        predictions = self.model.predict(flow_data)
        probabilities = self.model.predict_proba(flow_data)

        results = []

        for prediction, probability_values in zip(predictions, probabilities):
            probability_map = {
                class_name: float(probability)
                for class_name, probability in zip(self.model.classes_, probability_values)
            }

            results.append({
                "prediction": prediction,
                "confidence": probability_map[prediction],
                "probabilities": probability_map
            })

        return results
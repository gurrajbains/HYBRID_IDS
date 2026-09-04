from typing import Dict

import numpy as np
import pandas as pd

from src.ml.v3.feature_schema import DatasetFeatureMapping, V3_COMMON_FEATURES


def _safe_mean_bytes(byte_count: pd.Series, packet_count: pd.Series) -> pd.Series:
    result = np.zeros(len(byte_count), dtype=float)

    valid = packet_count > 0

    result[valid] = byte_count[valid] / packet_count[valid]

    return pd.Series(result, index=byte_count.index)


def _safe_rate(value: pd.Series, duration_seconds: pd.Series) -> pd.Series:
    result = pd.Series(np.nan, index=value.index, dtype=float)

    valid = duration_seconds > 0

    result.loc[valid] = value.loc[valid] / duration_seconds.loc[valid]

    return result


def _normalize_duration(duration: pd.Series, duration_unit: str) -> pd.Series:
    duration = pd.to_numeric(duration, errors="coerce")

    if duration_unit == "microseconds":
        return duration / 1_000_000.0

    if duration_unit == "seconds":
        return duration.astype(float)

    raise ValueError(f"Unsupported duration unit: {duration_unit}")


def transform_common_features(dataframe: pd.DataFrame, mapping: DatasetFeatureMapping) -> pd.DataFrame:
    source: Dict[str, pd.Series] = {}

    for common_name, source_name in mapping.columns.items():
        if source_name not in dataframe.columns:
            raise KeyError(
                f"{mapping.dataset} is missing required column "
                f"'{source_name}' for V3 feature '{common_name}'"
            )

        source[common_name] = pd.to_numeric(dataframe[source_name], errors="coerce")

    output = pd.DataFrame(index=dataframe.index)

    output["flow_duration"] = _normalize_duration(
        source["flow_duration"],
        mapping.duration_unit,
    )

    output["fwd_packets"] = source["fwd_packets"]
    output["bwd_packets"] = source["bwd_packets"]
    output["fwd_bytes"] = source["fwd_bytes"]
    output["bwd_bytes"] = source["bwd_bytes"]

    output["total_packets"] = output["fwd_packets"] + output["bwd_packets"]
    output["total_bytes"] = output["fwd_bytes"] + output["bwd_bytes"]

    output["packets_per_second"] = _safe_rate(
        output["total_packets"],
        output["flow_duration"],
    )

    output["bytes_per_second"] = _safe_rate(
        output["total_bytes"],
        output["flow_duration"],
    )

    output["fwd_mean_packet_bytes"] = _safe_mean_bytes(
        output["fwd_bytes"],
        output["fwd_packets"],
    )

    output["bwd_mean_packet_bytes"] = _safe_mean_bytes(
        output["bwd_bytes"],
        output["bwd_packets"],
    )

    output = output[V3_COMMON_FEATURES]

    return output


def validate_common_features(dataframe: pd.DataFrame) -> dict:
    numeric = dataframe.replace([np.inf, -np.inf], np.nan)

    return {
        "rows": int(len(numeric)),
        "features": int(len(numeric.columns)),
        "missing_values": {
            column: int(numeric[column].isna().sum())
            for column in numeric.columns
        },
        "negative_values": {
            column: int((numeric[column] < 0).sum())
            for column in numeric.columns
        },
        "fully_valid_rows": int(numeric.notna().all(axis=1).sum()),
    }
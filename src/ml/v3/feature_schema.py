from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class DatasetFeatureMapping:
    dataset: str
    columns: Dict[str, str]
    duration_unit: str


COMMON_BASE_FEATURES = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
]


COMMON_DERIVED_FEATURES = [
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "fwd_mean_packet_bytes",
    "bwd_mean_packet_bytes",
]


V3_COMMON_FEATURES = COMMON_BASE_FEATURES + COMMON_DERIVED_FEATURES
V3_FEATURE_SET_A = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
]


V3_FEATURE_SET_B = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_packets",
    "total_bytes",
    "fwd_mean_packet_bytes",
    "bwd_mean_packet_bytes",
]


V3_FEATURE_SET_C = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_packets",
    "total_bytes",
    "fwd_mean_packet_bytes",
    "bwd_mean_packet_bytes",
    "packets_per_second",
    "bytes_per_second",
]


V3_FEATURE_SETS = {
    "A": V3_FEATURE_SET_A,
    "B": V3_FEATURE_SET_B,
    "C": V3_FEATURE_SET_C,
}

CICIDS2017_MAPPING = DatasetFeatureMapping(
    dataset="CIC-IDS-2017",
    duration_unit="microseconds",
    columns={
        "flow_duration": "Flow Duration",
        "fwd_packets": "Total Fwd Packets",
        "bwd_packets": "Total Backward Packets",
        "fwd_bytes": "Total Length of Fwd Packets",
        "bwd_bytes": "Total Length of Bwd Packets",
    },
)


CSECICIDS2018_MAPPING = DatasetFeatureMapping(
    dataset="CSE-CIC-IDS2018",
    duration_unit="microseconds",
    columns={
        "flow_duration": "Flow Duration",
        "fwd_packets": "Tot Fwd Pkts",
        "bwd_packets": "Tot Bwd Pkts",
        "fwd_bytes": "TotLen Fwd Pkts",
        "bwd_bytes": "TotLen Bwd Pkts",
    },
)


UNSWNB15_MAPPING = DatasetFeatureMapping(
    dataset="UNSW-NB15",
    duration_unit="seconds",
    columns={
        "flow_duration": "dur",
        "fwd_packets": "spkts",
        "bwd_packets": "dpkts",
        "fwd_bytes": "sbytes",
        "bwd_bytes": "dbytes",
    },
)


DATASET_MAPPINGS = {
    "cicids2017": CICIDS2017_MAPPING,
    "cse_cic_ids2018": CSECICIDS2018_MAPPING,
    "unsw_nb15": UNSWNB15_MAPPING,
}


def get_mapping(dataset_key: str) -> DatasetFeatureMapping:
    if dataset_key not in DATASET_MAPPINGS:
        raise KeyError(f"Unknown dataset key: {dataset_key}")

    return DATASET_MAPPINGS[dataset_key]
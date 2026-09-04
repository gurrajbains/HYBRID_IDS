BENIGN = "BENIGN"
ATTACK = "ATTACK"
UNMAPPED_ATTACK = "UNMAPPED_ATTACK"


BENIGN_LABELS = {
    "cicids2017": {
        "BENIGN",
    },
    "cse_cic_ids2018": {
        "Benign",
    },
    "unsw_nb15": {
        "Normal",
    },
}


FAMILY_MAPPINGS = {
    "cicids2017": {
        "BENIGN": BENIGN,
        "Bot": "Bot",
        "BruteForce": "BruteForce",
        "DDoS": "DDoS",
        "DoS": "DoS",
        "Infiltration": "Infiltration",
        "PortScan": "Reconnaissance",
        "WebAttack": "WebAttack",
    },

    "cse_cic_ids2018": {
        "Benign": BENIGN,
        "FTP-BruteForce": "BruteForce",
        "SSH-Bruteforce": "BruteForce",
        "DoS attacks-GoldenEye": "DoS",
        "DoS attacks-Slowloris": "DoS",
        "DoS attacks-Hulk": "DoS",
        "DoS attacks-SlowHTTPTest": "DoS",
        "DDOS attack-HOIC": "DDoS",
        "DDOS attack-LOIC-UDP": "DDoS",
        "DDoS attacks-LOIC-HTTP": "DDoS",
        "Infilteration": "Infiltration",
    },

    "unsw_nb15": {
        "Normal": BENIGN,
        "DoS": "DoS",
        "Reconnaissance": "Reconnaissance",
    },
}


def normalize_raw_label(raw_label: str) -> str:
    return str(raw_label).strip()


def get_binary_label(dataset_key: str, raw_label: str) -> str:
    raw_label = normalize_raw_label(raw_label)

    if dataset_key not in BENIGN_LABELS:
        raise KeyError(f"Unknown dataset key: {dataset_key}")

    if raw_label in BENIGN_LABELS[dataset_key]:
        return BENIGN

    return ATTACK


def get_family_label(dataset_key: str, raw_label: str) -> str:
    raw_label = normalize_raw_label(raw_label)

    if dataset_key not in FAMILY_MAPPINGS:
        raise KeyError(f"Unknown dataset key: {dataset_key}")

    if raw_label in FAMILY_MAPPINGS[dataset_key]:
        return FAMILY_MAPPINGS[dataset_key][raw_label]

    if get_binary_label(dataset_key, raw_label) == ATTACK:
        return UNMAPPED_ATTACK

    return BENIGN


def is_stage2_trainable(dataset_key: str, raw_label: str) -> bool:
    family = get_family_label(dataset_key, raw_label)

    return family not in {
        BENIGN,
        UNMAPPED_ATTACK,
    }
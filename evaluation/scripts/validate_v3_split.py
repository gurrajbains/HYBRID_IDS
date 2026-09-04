from pathlib import Path
import json


MANIFEST_PATH = Path("evaluation/v3_split_manifest.json")

CSE_DIRECTORY = Path("evaluation/datasets/CSE-CIC-IDS2018")
UNSW_DIRECTORY = Path("evaluation/datasets/UNSW-NB15")


def flatten_section(section):
    files = []

    for dataset, entries in section.items():
        for entry in entries:
            files.append((dataset, entry))

    return files


def check_overlap(manifest):
    roles = {
        "training": set(flatten_section(manifest["training"])),
        "development": set(flatten_section(manifest["development"])),
        "final_holdout": set(flatten_section(manifest["final_holdout"])),
        "secondary_holdout": set(flatten_section(manifest["secondary_holdout"])),
    }

    failures = []

    role_names = list(roles.keys())

    for index, role_a in enumerate(role_names):
        for role_b in role_names[index + 1:]:
            overlap = roles[role_a] & roles[role_b]

            for dataset, filename in sorted(overlap):
                failures.append(
                    f"{dataset}:{filename} appears in both "
                    f"{role_a} and {role_b}"
                )

    return failures


def resolve_path(dataset, filename):
    if dataset == "cicids2017":
        return Path(filename)

    if dataset == "cse_cic_ids2018":
        return CSE_DIRECTORY / filename

    if dataset == "unsw_nb15":
        return UNSW_DIRECTORY / filename

    raise KeyError(f"Unknown dataset: {dataset}")


def check_local_files(manifest):
    results = []

    for role in [
        "training",
        "development",
        "final_holdout",
        "secondary_holdout",
    ]:
        for dataset, filename in flatten_section(manifest[role]):
            path = resolve_path(dataset, filename)

            results.append(
                {
                    "role": role,
                    "dataset": dataset,
                    "filename": filename,
                    "path": str(path),
                    "exists": path.exists(),
                }
            )

    return results


def main():
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Missing manifest: {MANIFEST_PATH}"
        )

    with MANIFEST_PATH.open("r", encoding="utf-8") as file:
        manifest = json.load(file)

    print("Hybrid IDS V3 Split Integrity Check")
    print("=" * 65)

    overlaps = check_overlap(manifest)

    print()
    print("Split overlap check")
    print("-" * 65)

    if overlaps:
        for failure in overlaps:
            print(f"FAIL  {failure}")
    else:
        print("PASS  No dataset file appears in multiple roles.")

    print()
    print("Local file availability")
    print("-" * 65)

    local_results = check_local_files(manifest)

    for item in local_results:
        marker = "FOUND" if item["exists"] else "MISSING"

        print(
            f"{marker:<8} "
            f"{item['role']:<18} "
            f"{item['dataset']:<18} "
            f"{item['filename']}"
        )

    training_missing = [
        item
        for item in local_results
        if item["role"] == "training" and not item["exists"]
    ]

    development_missing = [
        item
        for item in local_results
        if item["role"] == "development" and not item["exists"]
    ]

    print()
    print("Summary")
    print("-" * 65)

    print(f"Overlap failures: {len(overlaps)}")
    print(f"Missing training files: {len(training_missing)}")
    print(f"Missing development files: {len(development_missing)}")

    if overlaps:
        print()
        print("RESULT: FAIL")
        print("Fix split overlap before continuing.")
        return

    if training_missing:
        print()
        print("RESULT: WAITING FOR TRAINING DATA")
        print("Obtain the missing training files before V3 model construction.")
        return

    if development_missing:
        print()
        print("RESULT: WAITING FOR DEVELOPMENT DATA")
        print("Obtain the development dataset before candidate comparison.")
        return

    print()
    print("RESULT: SPLIT STRUCTURE READY")


if __name__ == "__main__":
    main()
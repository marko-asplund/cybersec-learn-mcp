"""Prepare Enterprise ATT&CK technique resources (no embeddings).

Run from the repository root: uv run python scripts/prepare_attack.py
The pinned source is downloaded once and reused on subsequent runs.
"""

import hashlib
import json
from pathlib import Path
import re
from urllib.request import urlopen

import yaml

RELEASE = "20.0"
BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
SOURCE_URL = f"{BASE_URL}/enterprise-attack/enterprise-attack-{RELEASE}.json"
LICENSE_URL = f"{BASE_URL}/LICENSE.txt"
UPSTREAM = Path("data/upstream/attack")
OUTPUT = Path("data/attack/techniques.json")


def prepare_techniques(bundle):
    """Keep active technique text and citation references directly from STIX."""
    techniques = {}
    excluded = {}
    for obj in bundle["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        reference = next(ref for ref in obj["external_references"]
                         if ref.get("source_name") == "mitre-attack"
                         and re.fullmatch(r"T\d{4}(?:\.\d{3})?", ref.get("external_id", "")))
        technique_id = reference["external_id"]
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            excluded[technique_id] = "revoked" if obj.get("revoked") else "deprecated"
            continue
        if technique_id in techniques:
            raise ValueError(f"Duplicate active technique ID: {technique_id}")
        techniques[technique_id] = {
            "stix_id": obj["id"],
            "name": obj["name"],
            "description": obj.get("description", ""),
            "url": reference["url"],
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])
                        if phase["kill_chain_name"] == "mitre-attack"],
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "version": obj.get("x_mitre_version"),
            "modified": obj["modified"],
            # Descriptions contain citation markers; retain their supporting references.
            "external_references": obj["external_references"],
        }
    return dict(sorted(techniques.items())), dict(sorted(excluded.items()))


def download_once(url, path):
    if not path.exists():
        print(f"Downloading {url}", flush=True)
        with urlopen(url, timeout=120) as response:
            content = response.read()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return path.read_bytes()


def main():
    raw_path = UPSTREAM / f"enterprise-attack-{RELEASE}.json"
    raw = download_once(SOURCE_URL, raw_path)
    license_text = download_once(LICENSE_URL, UPSTREAM / "LICENSE.txt").decode("utf-8")
    bundle = json.loads(raw)
    techniques, excluded = prepare_techniques(bundle)
    counts = {
        "techniques": sum(not obj["is_subtechnique"] for obj in techniques.values()),
        "subtechniques": sum(obj["is_subtechnique"] for obj in techniques.values()),
        "revoked": sum(reason == "revoked" for reason in excluded.values()),
        "deprecated": sum(reason == "deprecated" for reason in excluded.values()),
    }
    sigma_ids = set()
    sigma_root = Path("data/upstream/sigma/rules")
    if sigma_root.is_dir():
        for path in sorted(sigma_root.rglob("*.yml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for tag in rule.get("tags", []):
                if isinstance(tag, str) and re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag):
                    sigma_ids.add(tag.removeprefix("attack.").upper())
    unresolved = {tid: excluded.get(tid, "not found in Enterprise release")
                  for tid in sorted(sigma_ids - techniques.keys())}
    result = {
        "source": {
            "release": RELEASE, "url": SOURCE_URL,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license_url": LICENSE_URL, "license": license_text,
        },
        "counts": counts,
        "techniques": techniques,
        "sigma_coverage": {
            "checked": sigma_root.is_dir(), "unique_technique_ids": len(sigma_ids),
            "resolved": len(sigma_ids & techniques.keys()), "unresolved": unresolved,
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Prepared {len(techniques)} entries: {counts['techniques']} techniques, {counts['subtechniques']} sub-techniques")
    print(f"Excluded {counts['revoked']} revoked and {counts['deprecated']} deprecated entries")
    print(f"Sigma technique IDs: {len(sigma_ids)} checked, {len(unresolved)} unresolved")
    for tid, reason in unresolved.items():
        print(f"  {tid}: {reason}")
    print(f"Saved {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

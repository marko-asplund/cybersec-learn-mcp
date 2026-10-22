"""Prepare Enterprise ATT&CK technique resources (no embeddings).

Run from the repository root: uv run python scripts/prepare_attack.py
The pinned source is downloaded once and reused on subsequent runs.
"""

import hashlib
import json
import re
from pathlib import Path
from urllib.request import urlopen

import yaml

RELEASE = "20.0"
BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
SOURCE_URL = f"{BASE_URL}/enterprise-attack/enterprise-attack-{RELEASE}.json"
LICENSE_URL = f"{BASE_URL}/LICENSE.txt"
UPSTREAM = Path("data/upstream/attack")
OUTPUT = Path("data/attack/techniques.json")


def is_active(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack_reference(obj):
    return next(
        ref
        for ref in obj["external_references"]
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
    )


def identity(obj):
    reference = attack_reference(obj)
    return {
        "id": reference["external_id"],
        "stix_id": obj["id"],
        "name": obj["name"],
        "url": reference["url"],
    }


def related_record(obj):
    return identity(obj) | {
        "type": obj["type"],
        "description": obj.get("description", ""),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "version": obj.get("x_mitre_version"),
        "external_references": obj.get("external_references", []),
    }


def relationship_record(rel):
    # Relationship descriptions explain the connection to this particular technique.
    return {
        key: rel[key]
        for key in (
            "id",
            "relationship_type",
            "source_ref",
            "target_ref",
            "created",
            "modified",
        )
        if key in rel
    }


def prepare_techniques(bundle):
    """Resolve local STIX relationships once, preserving original text/citations."""
    objects = {obj["id"]: obj for obj in bundle["objects"] if "id" in obj}
    techniques = {}
    excluded = {}
    by_stix_id = {}
    for obj in bundle["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        technique_id = attack_reference(obj)["external_id"]
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
            raise ValueError(f"Invalid technique ID: {technique_id}")
        if not is_active(obj):
            excluded[technique_id] = "revoked" if obj.get("revoked") else "deprecated"
            continue
        if technique_id in techniques:
            raise ValueError(f"Duplicate active technique ID: {technique_id}")
        record = related_record(obj)
        record.pop("id")  # ATT&CK ID is already the dictionary key.
        record.update(
            {
                "platforms": obj.get("x_mitre_platforms", []),
                "tactics": [
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase["kill_chain_name"] == "mitre-attack"
                ],
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "contributors": obj.get("x_mitre_contributors", []),
                "parent": None,
                "related_techniques": [],
                "procedure_examples": [],
                "mitigations": [],
                "detection_strategies": [],
            }
        )
        techniques[technique_id] = record
        by_stix_id[obj["id"]] = record

    def prepare_strategy(obj):
        strategy = related_record(obj)
        strategy["analytics"] = []
        for analytic_ref in obj.get("x_mitre_analytic_refs", []):
            analytic_obj = objects[analytic_ref]
            if not is_active(analytic_obj):
                continue
            analytic = related_record(analytic_obj)
            analytic["platforms"] = analytic_obj.get("x_mitre_platforms", [])
            analytic["mutable_elements"] = analytic_obj.get(
                "x_mitre_mutable_elements", []
            )
            analytic["log_sources"] = []
            for log_ref in analytic_obj.get("x_mitre_log_source_references", []):
                # Preserve the named log/channel even when its component is inactive.
                log_source = dict(log_ref)
                component_ref = log_ref.get("x_mitre_data_component_ref")
                if component_ref:
                    component = objects[component_ref]
                    log_source["data_component"] = related_record(component) | {
                        "revoked": component.get("revoked", False),
                        "deprecated": component.get("x_mitre_deprecated", False),
                    }
                analytic["log_sources"].append(log_source)
            strategy["analytics"].append(analytic)
        strategy["analytics"].sort(key=lambda analytic: analytic["id"])
        return strategy

    children = {}
    for rel in bundle["objects"]:
        if rel["type"] != "relationship" or not is_active(rel):
            continue
        kind = rel.get("relationship_type")
        source_id, target_id = rel.get("source_ref"), rel.get("target_ref")
        if (
            kind == "subtechnique-of"
            and source_id in by_stix_id
            and target_id in by_stix_id
        ):
            by_stix_id[source_id]["parent"] = identity(objects[target_id])
            children.setdefault(target_id, []).append(source_id)
        elif kind in ("uses", "mitigates", "detects") and target_id in by_stix_id:
            obj = objects[source_id]
            if not is_active(obj):
                continue
            technique = by_stix_id[target_id]
            if kind == "detects" and obj["type"] == "x-mitre-detection-strategy":
                entry = prepare_strategy(obj)
                entry["relationship"] = relationship_record(rel)
                technique["detection_strategies"].append(entry)
            elif kind in ("uses", "mitigates"):
                entry = related_record(obj)
                entry["relationship"] = relationship_record(rel)
                if kind == "mitigates":
                    entry["general_description"] = entry["description"]
                # A procedure example is the uses relationship, not the actor biography.
                entry["description"] = rel.get("description", "")
                entry["external_references"] = rel.get("external_references", [])
                if kind == "mitigates":
                    entry["object_external_references"] = obj.get(
                        "external_references", []
                    )
                technique[
                    "procedure_examples" if kind == "uses" else "mitigations"
                ].append(entry)

    for stix_id, record in by_stix_id.items():
        parent_id = record["parent"]["stix_id"] if record["parent"] else stix_id
        # Sub-techniques list siblings; parent techniques list their children.
        record["related_techniques"] = sorted(
            [
                identity(objects[child])
                for child in children.get(parent_id, [])
                if child != stix_id
            ],
            key=lambda child: child["id"],
        )
        for key in ("procedure_examples", "mitigations", "detection_strategies"):
            record[key].sort(
                key=lambda entry: (entry["id"], entry["relationship"].get("id", ""))
            )
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
    counts.update(
        {
            key: sum(len(record[key]) for record in techniques.values())
            for key in ("procedure_examples", "mitigations", "detection_strategies")
        }
    )
    counts["analytics"] = sum(
        len(strategy["analytics"])
        for record in techniques.values()
        for strategy in record["detection_strategies"]
    )
    sigma_ids = set()
    sigma_root = Path("data/upstream/sigma/rules")
    if sigma_root.is_dir():
        for path in sorted(sigma_root.rglob("*.yml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for tag in rule.get("tags", []):
                if isinstance(tag, str) and re.fullmatch(
                    r"attack\.t\d{4}(?:\.\d{3})?", tag
                ):
                    sigma_ids.add(tag.removeprefix("attack.").upper())
    unresolved = {
        tid: excluded.get(tid, "not found in Enterprise release")
        for tid in sorted(sigma_ids - techniques.keys())
    }
    result = {
        "source": {
            "release": RELEASE,
            "url": SOURCE_URL,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "license_url": LICENSE_URL,
            "license": license_text,
        },
        "counts": counts,
        "format_version": 2,
        "techniques": techniques,
        "sigma_coverage": {
            "checked": sigma_root.is_dir(),
            "unique_technique_ids": len(sigma_ids),
            "resolved": len(sigma_ids & techniques.keys()),
            "unresolved": unresolved,
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"Prepared {len(techniques)} entries: {counts['techniques']} techniques, {counts['subtechniques']} sub-techniques"
    )
    print(
        f"Excluded {counts['revoked']} revoked and {counts['deprecated']} deprecated entries"
    )
    print(
        f"Sigma technique IDs: {len(sigma_ids)} checked, {len(unresolved)} unresolved"
    )
    for tid, reason in unresolved.items():
        print(f"  {tid}: {reason}")
    print(
        "Nested records (including shared records per technique): "
        + ", ".join(
            f"{counts[key]} {key}"
            for key in (
                "procedure_examples",
                "mitigations",
                "detection_strategies",
                "analytics",
            )
        )
    )
    print(f"Saved {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

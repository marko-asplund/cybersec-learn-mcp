from copy import deepcopy

from scripts.prepare_attack import prepare_techniques


def technique(technique_id="T1078.004"):
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--fixture",
        "name": "Cloud Accounts",
        "description": "Original text (Citation: example).",
        "x_mitre_platforms": ["IaaS"],
        "x_mitre_is_subtechnique": True,
        "x_mitre_version": "2.0",
        "modified": "2026-05-12T00:00:00Z",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": "https://attack.mitre.org/techniques/T1078/004/",
            },
            {"source_name": "example", "url": "https://example.com/reference"},
        ],
    }


def test_preserves_original_text_and_citations():
    obj = technique()
    original = deepcopy(obj)
    prepared, excluded = prepare_techniques(
        {"objects": [obj, {"type": "relationship"}]}
    )
    record = prepared["T1078.004"]
    assert record["description"] == obj["description"]
    assert record["external_references"] == obj["external_references"]
    assert record["tactics"] == ["initial-access"]
    assert record["is_subtechnique"] is True
    assert excluded == {}
    assert obj == original


def test_excludes_revoked_and_deprecated_techniques():
    revoked = technique("T1000") | {"revoked": True}
    deprecated = technique("T1001") | {"x_mitre_deprecated": True}
    prepared, excluded = prepare_techniques(
        {"objects": [revoked, technique(), deprecated]}
    )
    assert list(prepared) == ["T1078.004"]
    assert excluded == {"T1000": "revoked", "T1001": "deprecated"}


def test_related_content_and_markdown_preserve_relationship_context():
    from app.attack_technique_render import render_attack_technique

    child = technique() | {
        "created": "2020-03-13",
        "x_mitre_contributors": ["Contributor"],
    }
    parent = technique("T1078") | {
        "id": "attack-pattern--parent",
        "name": "Valid Accounts",
        "x_mitre_is_subtechnique": False,
    }
    sibling = technique("T1078.001") | {
        "id": "attack-pattern--sibling",
        "name": "Default Accounts",
    }

    def obj(kind, stix_id, attack_id, name, **fields):
        return {
            "type": kind,
            "id": stix_id,
            "name": name,
            "description": "General object description.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": attack_id,
                    "url": f"https://example.com/{attack_id}",
                }
            ],
            **fields,
        }

    def rel(kind, source, target, **fields):
        return {
            "type": "relationship",
            "id": f"relationship--{kind}-{source}-{target}",
            "relationship_type": kind,
            "source_ref": source,
            "target_ref": target,
            **fields,
        }

    campaign = obj("campaign", "campaign--example", "C0001", "Example campaign")
    mitigation = obj(
        "course-of-action", "mitigation--example", "M0001", "Example mitigation"
    )
    strategy = obj(
        "x-mitre-detection-strategy",
        "strategy--example",
        "DET0001",
        "Example strategy",
        x_mitre_analytic_refs=["analytic--example", "analytic--revoked"],
    )
    analytic = obj(
        "x-mitre-analytic",
        "analytic--example",
        "AN0001",
        "Example analytic",
        description="Original analytic description.",
        x_mitre_platforms=["IaaS"],
        x_mitre_mutable_elements=[
            {"field": "Threshold", "description": "Tune this threshold."}
        ],
        x_mitre_log_source_references=[
            {
                "name": "audit",
                "channel": "sign-in",
                "x_mitre_data_component_ref": "component--example",
            }
        ],
    )
    component = obj(
        "x-mitre-data-component",
        "component--example",
        "DC0001",
        "Authentication activity",
    )
    citation = {
        "source_name": "relationship citation",
        "url": "https://example.com/evidence",
    }
    bundle = {
        "objects": [
            child,
            parent,
            sibling,
            campaign,
            mitigation,
            strategy,
            analytic,
            component,
            analytic | {"id": "analytic--revoked", "revoked": True},
            rel("subtechnique-of", child["id"], parent["id"]),
            rel("subtechnique-of", sibling["id"], parent["id"]),
            rel(
                "uses",
                campaign["id"],
                child["id"],
                description="Technique-specific example (Citation: relationship citation).",
                external_references=[citation],
            ),
            rel(
                "uses",
                campaign["id"],
                child["id"],
                revoked=True,
                description="Excluded example.",
            ),
            rel("uses", child["id"], campaign["id"], description="Wrong direction."),
            rel(
                "mitigates",
                mitigation["id"],
                child["id"],
                description="Technique-specific mitigation.",
            ),
            rel("detects", strategy["id"], child["id"]),
        ]
    }
    original = deepcopy(bundle)
    prepared, _ = prepare_techniques(bundle)
    record = prepared["T1078.004"]
    assert record["parent"]["id"] == "T1078"
    assert [item["id"] for item in record["related_techniques"]] == ["T1078.001"]
    assert [item["id"] for item in prepared["T1078"]["related_techniques"]] == [
        "T1078.001",
        "T1078.004",
    ]
    assert len(record["procedure_examples"]) == 1
    assert record["procedure_examples"][0]["description"].startswith(
        "Technique-specific example"
    )
    assert record["procedure_examples"][0]["external_references"] == [citation]
    assert record["mitigations"][0]["description"] == "Technique-specific mitigation."
    assert record["mitigations"][0]["general_description"] == mitigation["description"]
    analytics = record["detection_strategies"][0]["analytics"]
    assert len(analytics) == 1
    assert analytics[0]["log_sources"][0]["data_component"]["id"] == "DC0001"
    assert bundle == original

    markdown = render_attack_technique(
        "T1078.004",
        record,
        {
            "release": "20.0",
            "url": "https://example.com/dataset",
            "license": "Original license text.",
        },
    )
    for expected in [
        "# T1078.004 — Cloud Accounts",
        "T1078 — Valid Accounts",
        "T1078.001 — Default Accounts",
        "Technique-specific example (Citation: relationship citation).",
        "https://example.com/evidence",
        "Technique-specific mitigation.",
        "Original analytic description.",
        "DC0001 — Authentication activity",
        "**audit** — sign-in",
        "**Threshold**: Tune this threshold.",
        "Contributor",
        "2020-03-13",
        "Original license text.",
    ]:
        assert expected in markdown
    assert "Excluded example." not in markdown and "Wrong direction." not in markdown


def test_markdown_handles_absent_optional_content():
    from app.attack_technique_render import render_attack_technique

    prepared, _ = prepare_techniques({"objects": [technique()]})
    markdown = render_attack_technique(
        "T1078.004",
        prepared["T1078.004"],
        {
            "release": "20.0",
            "url": "https://example.com/dataset",
            "license": "License.",
        },
    )
    assert "Not provided in this ATT&CK release." in markdown
    assert "## Mitigations" in markdown and "## Detection strategies" in markdown
    assert "None" not in markdown

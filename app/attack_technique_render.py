"""Deterministic Markdown rendering for prepared ATT&CK resource records."""

from collections.abc import Mapping
from typing import Any

NOT_PROVIDED = "Not provided in this ATT&CK release."


def _link(record: Mapping[str, Any]) -> str:
    label = f"{record['id']} — {record['name']}"
    return f"[{label}]({record['url']})" if record.get("url") else label


def _references(references: list[dict[str, Any]]) -> str:
    lines = []
    seen = set()
    for reference in references:
        key = tuple(
            reference.get(field, "") for field in ("source_name", "url", "description")
        )
        if key in seen:
            continue
        seen.add(key)
        name, url, description = key
        label = f"[{name}]({url})" if url else name
        lines.append(f"- **{label}**" + (f": {description}" if description else ""))
    return "\n".join(lines)


def _record_references(record: Mapping[str, Any]) -> str:
    return _references(
        record.get("external_references", [])
        + record.get("object_external_references", [])
    )


def _analytic_markdown(analytic: Mapping[str, Any]) -> str:
    sections = [
        f"#### {_link(analytic)}",
        analytic.get("description") or NOT_PROVIDED,
        "Platforms: " + (", ".join(analytic.get("platforms", [])) or NOT_PROVIDED),
        "##### Log sources",
    ]
    logs = []
    for log in analytic.get("log_sources", []):
        text = f"**{log.get('name', 'Unnamed log source')}** — {log.get('channel') or NOT_PROVIDED}"
        component = log.get("data_component")
        if component:
            text += f"\n\nData component: {_link(component)}"
            if component.get("revoked") or component.get("deprecated"):
                text += " (revoked or deprecated in this release)"
            if component.get("description"):
                text += f"\n\n{component['description']}"
            references = _record_references(component)
            if references:
                text += f"\n\n{references}"
        logs.append(text)
    sections.append("\n\n".join(logs) or NOT_PROVIDED)
    sections.append("##### Parameters to tune")
    sections.append(
        "\n\n".join(
            f"**{element['field']}**: {element.get('description') or NOT_PROVIDED}"
            for element in analytic.get("mutable_elements", [])
        )
        or NOT_PROVIDED
    )
    references = _record_references(analytic)
    if references:
        sections.extend(["##### Analytic references", references])
    return "\n\n".join(sections)


def render_attack_technique(
    technique_id: str,
    technique: Mapping[str, Any],
    source: Mapping[str, Any],
) -> str:
    """Render one expanded technique, using shared dataset provenance/license.

    Inputs come from prepared['techniques'][technique_id] and prepared['source'].
    Original descriptions and citation markers are inserted unchanged; no LLM is used.
    """
    parent = technique.get("parent")
    parent_text = (
        _link(parent)
        if parent
        else (
            NOT_PROVIDED
            if technique.get("is_subtechnique")
            else "None (top-level technique)."
        )
    )
    sections = [
        f"# {technique_id} — {technique['name']}",
        (
            f"Source: [{technique_id}]({technique['url']})\n"
            f"Dataset: [Enterprise ATT&CK {source['release']}]({source['url']})\n"
            f"Technique version: {technique.get('version') or NOT_PROVIDED}\n"
            f"Created: {technique.get('created') or NOT_PROVIDED}\n"
            f"Last modified: {technique.get('modified') or NOT_PROVIDED}\n"
            f"Type: {'Sub-technique' if technique.get('is_subtechnique') else 'Technique'}"
        ),
        "## Description",
        technique.get("description") or NOT_PROVIDED,
        "## Classification",
        "\n".join(
            [
                "- Platforms: "
                + (", ".join(technique.get("platforms", [])) or NOT_PROVIDED),
                "- Tactics: "
                + (", ".join(technique.get("tactics", [])) or NOT_PROVIDED),
                f"- Parent technique: {parent_text}",
                "- Contributors: "
                + ("; ".join(technique.get("contributors", [])) or NOT_PROVIDED),
            ]
        ),
        "## Related techniques",
        "\n".join(
            f"- {_link(item)}" for item in technique.get("related_techniques", [])
        )
        or NOT_PROVIDED,
    ]
    for key, heading in [
        ("procedure_examples", "Procedure examples"),
        ("mitigations", "Mitigations"),
    ]:
        sections.append(f"## {heading}")
        entries = technique.get(key, [])
        if not entries:
            sections.append(NOT_PROVIDED)
        for entry in entries:
            sections.extend(
                [f"### {_link(entry)}", entry.get("description") or NOT_PROVIDED]
            )
            if key == "mitigations" and entry.get("general_description"):
                sections.extend(
                    ["#### General mitigation guidance", entry["general_description"]]
                )
            references = _record_references(entry)
            if references:
                sections.extend(["#### References", references])
    sections.append("## Detection strategies")
    strategies = technique.get("detection_strategies", [])
    if not strategies:
        sections.append(NOT_PROVIDED)
    for strategy in strategies:
        sections.append(f"### {_link(strategy)}")
        if strategy.get("description"):
            sections.append(strategy["description"])
        analytics = strategy.get("analytics", [])
        sections.extend(_analytic_markdown(analytic) for analytic in analytics)
        if not analytics:
            sections.extend(["#### Analytics", NOT_PROVIDED])
        references = _record_references(strategy)
        if references:
            sections.extend(["#### Strategy references", references])
    sections.extend(
        [
            "## References",
            _record_references(technique) or NOT_PROVIDED,
            "## Attribution",
            source["license"],
        ]
    )
    return "\n\n".join(sections) + "\n"

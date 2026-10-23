import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlparse

from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ResourceNotFoundError, ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

from app.attack_technique_repository import AttackTechniqueRepository
from app.errors import InvalidSearchInput, ResourceNotFound
from app.sigma_rule_index import SigmaRuleIndex
from app.sigma_rule_repository import SigmaRuleRepository
from app.sigma_rule_search import RuleMatch, SigmaRuleSearch

_ = load_dotenv()


@dataclass
class AppState:
    attack_technique_repository: AttackTechniqueRepository
    sigma_rule_repository: SigmaRuleRepository
    sigma_rule_search: SigmaRuleSearch


@asynccontextmanager
async def lifespan(server: MCPServer[AppState]) -> AsyncIterator[AppState]:
    index = SigmaRuleIndex()

    yield AppState(
        AttackTechniqueRepository(),
        SigmaRuleRepository(index),
        SigmaRuleSearch(index),
    )


def _get_app_state(ctx: Context[AppState]) -> AppState:
    return ctx.request_context.lifespan_context


mcp = MCPServer[AppState]("cybersec-learn-mcp", lifespan=lifespan)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, open_world_hint=False
    ),
)
async def search_sigma_rules(
    query: str = "",
    product: str | None = None,
    technique_id: str | None = None,
    limit: Annotated[int, Field(ge=1, le=10, strict=True)] = 5,
    *,
    ctx: Context[AppState],
) -> list[RuleMatch]:
    """Search Sigma rules with optional exact product and ATT&CK technique filters.

    Leave query empty for filter-only lookup. Returns compact matches and resource
    URIs for full YAML. Technique IDs accept T1078.004 or attack.t1078.004.
    """
    sigma_rule_search = _get_app_state(ctx).sigma_rule_search

    try:
        hits: list[RuleMatch] = await sigma_rule_search.search_sigma_rules(
            query, product, technique_id, limit
        )
    except InvalidSearchInput as exc:
        raise ToolError(str(exc)) from exc

    return hits


@mcp.resource(
    "cyberseclearn://catalog",
    mime_type="text/markdown",
)
def get_resource_catalog() -> str:
    """Describe available Sigma rule and ATT&CK technique resources."""
    return """# CyberSec Learn resources

## Sigma rules

Read original YAML using:
`cyberseclearn://rules/{rule_id}`

Use the exact resource URI returned by search_sigma_rules.

## ATT&CK techniques

Read a technique reference using:
`cyberseclearn://techniques/{technique_id}`

Technique IDs include sub-techniques, for example:
- cyberseclearn://techniques/T1531
- cyberseclearn://techniques/T1078.004
"""


@mcp.resource("cyberseclearn://rules/{rule_id}", mime_type="application/yaml")
def get_sigma_rule(rule_id: str, ctx: Context[AppState]) -> str:
    """Read the original Sigma detection YAML by rule UUID."""
    sigma_rule_repository = _get_app_state(ctx).sigma_rule_repository
    try:
        yaml = sigma_rule_repository.get_rule_by_id(rule_id)
    except ResourceNotFound as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    return yaml


@mcp.resource("cyberseclearn://techniques/{technique_id}", mime_type="text/markdown")
def get_mitre_attack_technique(technique_id: str, ctx: Context[AppState]) -> str:
    """Read an Enterprise ATT&CK technique as Markdown with detection context and references."""
    attack_technique_repository = _get_app_state(ctx).attack_technique_repository
    try:
        return attack_technique_repository.get_technique_by_id(technique_id)
    except ResourceNotFound as exc:
        raise ResourceNotFoundError(str(exc)) from exc


@mcp.prompt()
def explain_sigma_rule(
    rule_id: str,
    experience_level: str = "intermediate",
) -> str:
    """Explain a Sigma rule and its ATT&CK mapping as a learning exercise."""
    return f"""
Explain the Sigma rule at cyberseclearn://rules/{rule_id}.
Adapt the explanation for a learner with {experience_level} experience.

1. Read the rule resource before explaining it.
2. Explain its purpose, log source, and detection conditions.
3. Give a hypothetical matching event, clearly labeled as hypothetical.
4. Read the ATT&CK resources for its technique tags using
   cyberseclearn://techniques/{{technique_id}}. Convert technique tags such as
   attack.t1078.004 to T1078.004. Skip tactic tags such as attack.persistence.
5. Explain the mappings, required telemetry, and likely false positives.
6. Distinguish source facts from your interpretation.
7. Finish with one comprehension question and wait for my answer.

If a resource cannot be read, report that limitation rather than guessing.
""".strip()


@mcp.prompt()
def investigate_technique(
    technique_id: str,
    product: str = "",
) -> str:
    """Explore an ATT&CK technique through relevant Sigma detections."""
    technique_id = technique_id.strip().lower().removeprefix("attack.").upper()
    product_instruction = (
        f"Apply the exact product filter {product!r}."
        if product
        else "Do not apply a product filter."
    )

    return f"""
Help me learn about ATT&CK technique {technique_id}.

1. Read cyberseclearn://techniques/{technique_id}.
2. Use search_sigma_rules with technique_id={technique_id!r},
   an empty query, and limit=5. {product_instruction}
3. Read the original YAML resources for the returned matches.
4. Explain the technique, then compare the rules' detection approaches,
   telemetry requirements, and false-positive considerations.
5. Cite the resource URIs used.
6. Explain that these matches are examples from this dataset, not a complete
   assessment of detection coverage.
7. Ask which detection I would like to examine further.

If no rules match, say so and continue using the technique reference.
""".strip()


@mcp.prompt()
def quiz_me_on_rule(rule_id: str) -> str:
    """Practice interpreting a Sigma rule through an interactive quiz."""
    return f"""
Help me practice interpreting the Sigma rule at cyberseclearn://rules/{rule_id}.

1. Read the rule resource and show its YAML before starting the quiz.
2. Ask one question at a time about its detection conditions, required telemetry,
   or possible false positives. Start with the detection conditions.
3. Wait for my answer before explaining the answer or asking another question.
4. After each answer, give feedback grounded in the rule, explain any mistakes,
   and distinguish source facts from your interpretation.
5. Clearly label any hypothetical events as hypothetical. Do not claim to have
   executed the rule or tested it against real logs.

If the resource cannot be read, report that limitation and stop the quiz.
""".strip()


allowed_origins = os.getenv("ALLOWED_ORIGINS", "").replace(" ", "").splitlines()
allowed_hosts = [urlparse(o).netloc for o in allowed_origins]

app = mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    ),
)

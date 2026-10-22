import os
from contextlib import asynccontextmanager
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


@asynccontextmanager
async def lifespan(server: MCPServer):
    index = SigmaRuleIndex()

    yield {
        "attack_technique_repository": AttackTechniqueRepository(),
        "sigma_rule_repository": SigmaRuleRepository(index),
        "sigma_rule_search": SigmaRuleSearch(index),
    }


def _get_attack_technique_repository(ctx: Context) -> AttackTechniqueRepository:
    return ctx.request_context.lifespan_context["attack_technique_repository"]


def _get_sigma_rule_repository(ctx: Context) -> SigmaRuleRepository:
    return ctx.request_context.lifespan_context["sigma_rule_repository"]


def _get_sigma_rule_search(ctx: Context) -> SigmaRuleSearch:
    return ctx.request_context.lifespan_context["sigma_rule_search"]


mcp = MCPServer("cybersec-learn-mcp", lifespan=lifespan)


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
    ctx: Context = None,
) -> list[RuleMatch]:
    """Search Sigma rules with optional exact product and ATT&CK technique filters.

    Leave query empty for filter-only lookup. Returns compact matches and resource
    URIs for full YAML. Technique IDs accept T1078.004 or attack.t1078.004.
    """
    sigma_rule_search = _get_sigma_rule_search(ctx)

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
def get_sigma_rule(rule_id: str, ctx: Context = None) -> str:
    """Read the original Sigma detection YAML by rule UUID."""
    sigma_rule_repository = _get_sigma_rule_repository(ctx)
    try:
        yaml = sigma_rule_repository.get_rule_by_id(rule_id)
    except ResourceNotFound as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    return yaml


@mcp.resource("cyberseclearn://techniques/{technique_id}", mime_type="text/markdown")
def get_mitre_attack_technique(technique_id: str, ctx: Context = None) -> str:
    """Read an Enterprise ATT&CK technique as Markdown with detection context and references."""
    attack_technique_repository = _get_attack_technique_repository(ctx)
    try:
        return attack_technique_repository.get_technique_by_id(technique_id)
    except ResourceNotFound as exc:
        raise ResourceNotFoundError(str(exc)) from exc


allowed_origins = os.getenv("ALLOWED_ORIGINS", "").replace(" ", "").splitlines()
allowed_hosts = [urlparse(o).netloc for o in allowed_origins]

app = mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    ),
)

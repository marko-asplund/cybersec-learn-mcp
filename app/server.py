from contextlib import asynccontextmanager
from typing import TypedDict

from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from app.attack_technique_repository import AttackTechniqueRepository


@asynccontextmanager
async def lifespan(server: MCPServer):
    yield {"attack_technique_repository": AttackTechniqueRepository()}


def _get_attack_technique_repository(ctx: Context):
    return ctx.request_context.lifespan_context["attack_technique_repository"]


mcp = MCPServer("cybersec-learn-mcp", lifespan=lifespan)


class RuleMatch(TypedDict):
    foo: str


@mcp.tool()
async def search_sigma_rules(
    query: str = "",
    product: str | None = None,
    technique_id: str | None = None,
    limit: int = 5,
) -> list[RuleMatch]:
    return []


@mcp.resource("cyberseclearn://rules/{rule_id}", mime_type="application/yaml")
def get_sigma_rule(rule_id: str) -> str:
    pass


@mcp.resource("cyberseclearn://techniques/{technique_id}", mime_type="text/markdown")
def get_mitre_attack_technique(technique_id: str, ctx: Context = None) -> str:
    attack_technique_repository = _get_attack_technique_repository(ctx)
    return attack_technique_repository.get_technique_by_id(technique_id)


app = mcp.streamable_http_app()

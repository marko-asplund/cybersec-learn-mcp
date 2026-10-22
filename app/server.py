from contextlib import asynccontextmanager

from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from app.attack_technique_repository import AttackTechniqueRepository
from app.sigma_rule_index import SigmaRuleIndex
from app.sigma_rule_repository import SigmaRuleRepository
from app.sigma_rule_search import RuleMatch, SigmaRuleSearch


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


@mcp.tool()
async def search_sigma_rules(
    query: str = "",
    product: str | None = None,
    technique_id: str | None = None,
    limit: int = 5,
    ctx: Context = None,
) -> list[RuleMatch]:
    sigma_rule_search = _get_sigma_rule_search(ctx)

    hits: list[RuleMatch] = await sigma_rule_search.search_sigma_rules(
        query, product, technique_id, limit
    )

    return hits


@mcp.resource("cyberseclearn://rules/{rule_id}", mime_type="application/yaml")
def get_sigma_rule(rule_id: str, ctx: Context = None) -> str:
    sigma_rule_repository = _get_sigma_rule_repository(ctx)
    yaml = sigma_rule_repository.get_rule_by_id(rule_id)
    return yaml


@mcp.resource("cyberseclearn://techniques/{technique_id}", mime_type="text/markdown")
def get_mitre_attack_technique(technique_id: str, ctx: Context = None) -> str:
    attack_technique_repository = _get_attack_technique_repository(ctx)
    return attack_technique_repository.get_technique_by_id(technique_id)


app = mcp.streamable_http_app()

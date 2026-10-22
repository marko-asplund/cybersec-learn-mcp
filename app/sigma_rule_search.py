import json
from typing import TypedDict

from app.sigma_rule_index import SigmaRuleIndex


class RuleMatch(TypedDict):
    rule_id: str
    title: str
    description: str
    product: str
    logsource: dict[str, str]
    status: str
    level: str
    technique_ids: list[str]
    source_url: str
    resource_uri: str
    score: float | None


class SigmaRuleSearch:
    def __init__(self, sigma_rule_index: SigmaRuleIndex):
        self._sigma_rule_index = sigma_rule_index

    async def search_sigma_rules(
        self,
        query: str = "",
        product: str | None = None,
        technique_id: str | None = None,
        limit: int = 5,
    ) -> list[RuleMatch]:

        filters = []
        if product:
            filters.append({"product": {"$eq": product}})
        if technique_id:
            filters.append({"technique_ids": {"$contains": technique_id}})

        where = (
            {"$and": filters} if len(filters) > 1 else filters[0] if filters else None
        )
        retriever = self._sigma_rule_index._index.as_retriever(
            similarity_top_k=limit,
            vector_store_kwargs={"where": where} if where else {},
        )

        raw_hits = await retriever.aretrieve(query)
        hits: list[RuleMatch] = []
        for r in raw_hits:
            rule = r.node.metadata
            rule_id = rule["rule_id"]
            hits.append(
                {
                    "rule_id": rule_id,
                    "title": rule["title"],
                    "description": rule.get("description", ""),
                    "product": rule["product"],
                    "logsource": json.loads(rule["logsource"]),
                    "status": rule["status"],
                    "level": rule["level"],
                    "technique_ids": rule.get("technique_ids", []),
                    "source_url": rule["source_url"],
                    "resource_uri": f"cyberseclearn://rules/{rule_id}",
                    "score": r.score,
                }
            )

        return hits

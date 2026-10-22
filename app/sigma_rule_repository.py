from pathlib import Path

from app.sigma_rule_index import SigmaRuleIndex


class SigmaRuleRepository:
    def __init__(self, sigma_rule_index: SigmaRuleIndex):
        self._sigma_rule_index: SigmaRuleIndex = sigma_rule_index

    def get_rule_by_id(self, rule_id: str):
        res = self._sigma_rule_index.collection.get(
            ids=[rule_id],
            include=["metadatas"],
        )
        if not res["ids"]:
            raise ValueError(f"Unknown Sigma rule: {rule_id}")

        source_path = res["metadatas"][0]["source_path"]
        path = Path("data/upstream/sigma") / source_path
        yaml = path.read_text()
        return yaml

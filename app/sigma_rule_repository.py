from pathlib import Path
from typing import cast

from chromadb.api.types import Metadata

from app.errors import ResourceNotFound
from app.sigma_rule_index import SigmaRuleIndex


class SigmaRuleRepository:
    def __init__(self, sigma_rule_index: SigmaRuleIndex) -> None:
        self._sigma_rule_index: SigmaRuleIndex = sigma_rule_index

    def get_rule_by_id(self, rule_id: str) -> str:
        res = self._sigma_rule_index.collection.get(
            ids=[rule_id],
            include=["metadatas"],
        )
        if not res["ids"]:
            raise ResourceNotFound(f"Unknown Sigma rule: {rule_id}")

        metadatas = cast(list[Metadata], res["metadatas"])
        source_path = cast(str, metadatas[0]["source_path"])
        path = Path("data/upstream/sigma") / source_path
        yaml = path.read_text()
        return yaml

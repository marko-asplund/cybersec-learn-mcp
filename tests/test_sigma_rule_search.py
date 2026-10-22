import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.sigma_rule_search import SigmaRuleSearch


@pytest.mark.parametrize("technique_id", ["T1531", "attack.t1531", " ATTACK.T1531 "])
def test_normalizes_technique_before_combined_chroma_filter(technique_id):
    retriever = SimpleNamespace(aretrieve=AsyncMock(return_value=[]))
    vector_index = Mock()
    vector_index.as_retriever.return_value = retriever
    search = SigmaRuleSearch(SimpleNamespace(_index=vector_index))

    assert (
        asyncio.run(
            search.search_sigma_rules(
                "cloud account abuse", product="aws", technique_id=technique_id, limit=3
            )
        )
        == []
    )
    vector_index.as_retriever.assert_called_once_with(
        similarity_top_k=3,
        vector_store_kwargs={
            "where": {
                "$and": [
                    {"product": {"$eq": "aws"}},
                    {"technique_ids": {"$contains": "T1531"}},
                ]
            }
        },
    )


@pytest.mark.parametrize("limit", [0, -1, 11, True, 1.5, "5"])
def test_invalid_limits_are_rejected_before_retrieval(limit):
    vector_index = Mock()
    search = SigmaRuleSearch(SimpleNamespace(_index=vector_index))
    with pytest.raises(ValueError, match="limit must be"):
        asyncio.run(search.search_sigma_rules("AWS", limit=limit))
    vector_index.as_retriever.assert_not_called()


def test_malformed_technique_is_rejected_before_retrieval():
    vector_index = Mock()
    search = SigmaRuleSearch(SimpleNamespace(_index=vector_index))
    with pytest.raises(ValueError, match="technique_id must be"):
        asyncio.run(search.search_sigma_rules("AWS", technique_id="T1531 OR T1078"))
    vector_index.as_retriever.assert_not_called()

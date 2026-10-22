import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError

from app import server
from app.attack_technique_repository import AttackTechniqueRepository


@pytest.fixture
def repositories(monkeypatch):
    index = SimpleNamespace(collection=Mock(), _index=Mock())
    index.collection.get.return_value = {"ids": [], "metadatas": []}
    attack = AttackTechniqueRepository.__new__(AttackTechniqueRepository)
    attack.techniques = {}
    attack.source = {}
    monkeypatch.setattr(server, "SigmaRuleIndex", lambda: index)
    monkeypatch.setattr(server, "AttackTechniqueRepository", lambda: attack)
    return index, attack


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        (
            "cyberseclearn://rules/00000000-0000-0000-0000-000000000000",
            "Unknown Sigma rule: 00000000-0000-0000-0000-000000000000",
        ),
        ("cyberseclearn://techniques/T9999", "Unknown ATT&CK technique: T9999"),
    ],
)
def test_missing_resource_returns_not_found(repositories, caplog, uri, message):
    async def exercise():
        async with Client(server.mcp, mode="legacy") as client:
            with pytest.raises(MCPError) as exc_info:
                await client.read_resource(uri)
            assert exc_info.value.code == -32602
            assert exc_info.value.message == message

    asyncio.run(exercise())
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


def test_invalid_filter_returns_useful_tool_error(repositories, caplog):
    async def exercise():
        async with Client(server.mcp, mode="legacy") as client:
            result = await client.call_tool(
                "search_sigma_rules", {"technique_id": "invalid"}
            )
            assert result.is_error
            assert result.content[0].text == (
                "Error executing tool search_sigma_rules: "
                "technique_id must be T1078.004 or attack.t1078.004 format"
            )

    asyncio.run(exercise())
    repositories[0]._index.as_retriever.assert_not_called()
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


def test_backend_value_error_remains_unexpected(repositories, caplog):
    index, _ = repositories
    retriever = SimpleNamespace(
        aretrieve=AsyncMock(side_effect=ValueError("private backend detail"))
    )
    index._index.as_retriever.return_value = retriever

    async def exercise():
        async with Client(server.mcp, mode="legacy") as client:
            result = await client.call_tool("search_sigma_rules", {"query": "AWS"})
            assert result.is_error
            assert result.content[0].text == "Error executing tool search_sigma_rules"

    asyncio.run(exercise())
    assert any(record.exc_info for record in caplog.records)


def test_corrupt_technique_remains_unexpected(repositories, caplog):
    _, attack = repositories
    attack.techniques["T1531"] = {}

    async def exercise():
        async with Client(server.mcp, mode="legacy") as client:
            with pytest.raises(MCPError) as exc_info:
                await client.read_resource("cyberseclearn://techniques/T1531")
            assert exc_info.value.code == -32603
            assert "Unknown ATT&CK technique" not in exc_info.value.message

    asyncio.run(exercise())
    assert any(record.exc_info for record in caplog.records)

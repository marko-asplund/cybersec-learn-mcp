"""Data preparation checks; no embedding model or Chroma index required."""

from pathlib import Path

import pytest

from scripts.rag_sigma_index import prepare_rule


def test_real_rule_preserves_id_tags_and_original():
    snapshot = Path("data/upstream/sigma")
    path = next((snapshot / "rules/cloud/aws").rglob("*.yml"))
    original = path.read_text()
    node = prepare_rule(path, snapshot, "test-commit")
    assert node.node_id == node.metadata["rule_id"]
    assert node.metadata["product"] == "aws"
    assert "/blob/test-commit/rules/" in node.metadata["source_url"]
    assert "Title:" in node.text and "Detection:" in node.text
    assert path.read_text() == original


def test_exact_technique_tags_and_search_metadata(tmp_path):
    path = tmp_path / "rule.yml"
    path.write_text("""id: 56a20c64-8900-4c89-8b96-e01444a84046
title: Test cloud rule
logsource:
  product: aws
tags: [attack.t1078.004, attack.initial_access, attack.t1078]
detection:
  selection:
    eventName: ConsoleLogin
  condition: selection
""")
    node = prepare_rule(path, tmp_path, "test-commit")
    assert node.metadata["technique_ids"] == ["T1078", "T1078.004"]
    assert set(node.excluded_embed_metadata_keys) == set(node.metadata)
    assert "ConsoleLogin" in node.text


def test_incomplete_rule_is_rejected(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("title: Missing ID and detection\n")
    with pytest.raises(ValueError):
        prepare_rule(path, tmp_path, "test-commit")


@pytest.mark.parametrize("query", ["", "cloud account abuse"])
def test_chroma_array_filters_without_catalog(tmp_path, monkeypatch, capsys, query):
    import json
    import sys

    import chromadb
    import yaml
    from llama_index.core import VectorStoreIndex
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.vector_stores.chroma import ChromaVectorStore

    from scripts import rag_sigma_query

    collection = chromadb.PersistentClient(
        path=str(tmp_path / "index")
    ).create_collection("sigma_rules")
    store = ChromaVectorStore(chroma_collection=collection)
    store.flat_metadata = False
    embed_model = MockEmbedding(embed_dim=8)
    index = VectorStoreIndex.from_vector_store(store, embed_model=embed_model)
    nodes = []
    for number, (product, tags) in enumerate(
        [
            ("aws", ["attack.t1078.004", "attack.t1531"]),
            ("aws", ["attack.t1078"]),
            ("azure", ["attack.t1078.004"]),
            ("aws", []),
        ],
        start=1,
    ):
        path = tmp_path / f"{number}.yml"
        path.write_text(
            yaml.safe_dump(
                {
                    "id": f"56a20c64-8900-4c89-8b96-{number:012d}",
                    "title": f"Fixture rule {number}",
                    "logsource": {"product": product},
                    "tags": tags,
                    "detection": {
                        "selection": {"eventName": "Test"},
                        "condition": "selection",
                    },
                }
            )
        )
        nodes.append(prepare_rule(path, tmp_path, "test-commit"))
    assert "technique_ids" not in nodes[-1].metadata
    index.insert_nodes(nodes)
    (tmp_path / "index/manifest.json").write_text(
        json.dumps(
            {
                "model": "test",
                "normalize": True,
                "collection": "sigma_rules",
                "indexed": 4,
                "upstream_commit": "test-commit",
                "technique_metadata": "array",
            }
        )
    )
    assert not (tmp_path / "index/catalog.json").exists()

    def load_embedding(**kwargs):
        if not query:
            pytest.fail("Filter-only lookup must not load an embedding model")
        return embed_model

    monkeypatch.setattr(rag_sigma_query, "HuggingFaceEmbedding", load_embedding)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rag_sigma_query.py",
            query,
            "--index-dir",
            str(tmp_path / "index"),
            "--product",
            "aws",
            "--technique-id",
            "attack.t1078.004",
        ],
    )
    rag_sigma_query.main()
    output = capsys.readouterr().out
    assert "Fixture rule 1" in output
    assert all(f"Fixture rule {number}" not in output for number in [2, 3, 4])

    # A parent ID does not match the sub-technique; membership is exact.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rag_sigma_query.py",
            query,
            "--index-dir",
            str(tmp_path / "index"),
            "--product",
            "aws",
            "--technique-id",
            "T1078",
        ],
    )
    rag_sigma_query.main()
    output = capsys.readouterr().out
    assert "Fixture rule 2" in output
    assert "Fixture rule 1" not in output

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rag_sigma_query.py",
            query,
            "--index-dir",
            str(tmp_path / "index"),
            "--product",
            "nonexistent",
        ],
    )
    rag_sigma_query.main()
    assert "No matching rules." in capsys.readouterr().out

"""Index local Sigma rules into Chroma. Run from the repository root.

    uv run python scripts/rag_sigma_index.py
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
from uuid import UUID

import chromadb
from llama_index.core import VectorStoreIndex
from llama_index.core.schema import TextNode
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.chroma import ChromaVectorStore
import yaml


def prepare_rule(path: Path, snapshot: Path, commit: str) -> TextNode:
    """One compact search representation per rule; leave original YAML intact."""
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(rule, dict):
        raise ValueError("Expected a YAML mapping")
    rule_id = str(UUID(str(rule.get("id", ""))))
    if not rule.get("title") or not isinstance(rule.get("logsource"), dict) or not isinstance(rule.get("detection"), dict):
        raise ValueError("Missing title, logsource, or detection")

    source_path = path.relative_to(snapshot).as_posix()
    # Chroma supports scalar arrays, but nested mappings still need serialization.
    metadata = {
        "rule_id": rule_id,
        "title": str(rule["title"]),
        "description": str(rule.get("description", "")).strip()[:600],
        "product": str(rule["logsource"].get("product", "")),
        "status": str(rule.get("status", "")),
        "level": str(rule.get("level", "")),
        "logsource": json.dumps(rule["logsource"]),
        "source_path": source_path,
        "source_url": f"https://github.com/SigmaHQ/sigma/blob/{commit}/{source_path}",
    }
    tags = rule.get("tags") or []
    technique_ids = sorted({tag.removeprefix("attack.").upper() for tag in tags
                            if isinstance(tag, str) and re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag)})
    # Chroma rejects empty arrays; untagged rules omit the field.
    if technique_ids:
        metadata["technique_ids"] = technique_ids
    # Put the most useful concepts first: the embedding model has a finite token window.
    text = "\n".join([
        f"Title: {rule['title']}",
        f"Description: {str(rule.get('description', '')).strip()}",
        f"Log source: {yaml.safe_dump(rule['logsource'], sort_keys=False).strip()}",
        f"Tags: {', '.join(tags)}",
        f"False positives: {rule.get('falsepositives', [])}",
        f"Detection: {yaml.safe_dump(rule['detection'], sort_keys=False)[:1800]}",
    ])[:5000]
    # TextNode avoids the default document splitter creating multiple chunks per rule.
    return TextNode(id_=rule_id, text=text, metadata=metadata,
                    excluded_embed_metadata_keys=list(metadata),
                    excluded_llm_metadata_keys=list(metadata))


def main():
    model_name = "BAAI/bge-small-en-v1.5"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="Index only the first N valid rules")
    parser.add_argument("--index-dir", type=Path, default=Path("data/chroma"))
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    if (args.index_dir / "chroma.sqlite3").exists():
        raise SystemExit(f"Chroma database already exists at {args.index_dir}. Use a new directory or delete it before reindexing.")

    snapshot = Path("data/upstream/sigma")
    if not (snapshot / "rules").is_dir():
        raise SystemExit("Missing data/upstream/sigma/rules; run from the repository root.")
    paths = sorted((snapshot / "rules").rglob("*.yml"))
    target = min(args.limit, len(paths)) if args.limit is not None else len(paths)
    print(f"Found {len(paths):,} YAML files; indexing up to {target:,} rules (invalid files may be skipped).", flush=True)
    commit = subprocess.check_output(["git", "-C", str(snapshot), "rev-parse", "HEAD"], text=True).strip()
    embed_model = HuggingFaceEmbedding(model_name=model_name, device="cpu", normalize=True)
    db = chromadb.PersistentClient(path=str(args.index_dir))
    collection = db.create_collection("sigma_rules")
    vector_store = ChromaVectorStore(chroma_collection=collection)
    # Allow native Chroma array metadata through LlamaIndex validation.
    vector_store.flat_metadata = False
    index = VectorStoreIndex.from_vector_store(vector_store, embed_model=embed_model)

    batch = []
    rule_ids = set()
    skipped = []
    for path in paths:
        try:
            node = prepare_rule(path, snapshot, commit)
            if node.node_id in rule_ids:
                raise ValueError(f"Duplicate rule ID: {node.node_id}")
        except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
            skipped.append({"path": str(path), "reason": str(exc)})
            print(f"Skipping {path}: {exc}", flush=True)
            continue
        rule_ids.add(node.node_id)
        batch.append(node)
        if len(batch) == 100:
            index.insert_nodes(batch)
            print(f"Indexed {len(rule_ids):,}/{target:,} rules; skipped {len(skipped)} files", flush=True)
            batch = []
        if args.limit is not None and len(rule_ids) >= args.limit:
            break
    if batch:
        index.insert_nodes(batch)

    # Written only after successful indexing; query script rejects unfinished indexes.
    manifest = {
        "upstream_commit": commit, "model": model_name, "normalize": True,
        "collection": "sigma_rules", "indexed": collection.count(), "skipped": skipped,
        "complete_corpus": args.limit is None, "technique_metadata": "array",
    }
    (args.index_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Indexed {collection.count()} rules; skipped {len(skipped)}; upstream commit {commit}")
    print(f"Index and provenance saved to {args.index_dir}")


if __name__ == "__main__":
    main()

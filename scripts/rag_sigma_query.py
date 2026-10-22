"""Test retrieval without an LLM or MCP. Run from the repository root.

uv run python scripts/rag_sigma_query.py "stolen AWS credentials"
uv run python scripts/rag_sigma_query.py "" --technique-id T1078.004
"""

import argparse
import json
import re
from pathlib import Path

import chromadb
from llama_index.core import VectorStoreIndex
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.chroma import ChromaVectorStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="?", default="stolen AWS credentials")
    parser.add_argument("--index-dir", type=Path, default=Path("data/chroma"))
    parser.add_argument("--product")
    parser.add_argument("--technique-id")
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.limit <= 10:
        parser.error("--limit must be between 1 and 10")
    if not (args.index_dir / "manifest.json").exists():
        raise SystemExit(
            f"No completed index at {args.index_dir}; run scripts/rag_sigma_index.py first."
        )
    manifest = json.loads((args.index_dir / "manifest.json").read_text())
    if manifest.get("technique_metadata") != "array":
        raise SystemExit(
            "Index uses the old technique metadata format; rebuild it with scripts/rag_sigma_index.py."
        )
    technique_id = (
        args.technique_id.lower().removeprefix("attack.").upper()
        if args.technique_id
        else None
    )
    if technique_id and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
        parser.error("Expected a technique such as T1078.004 or attack.t1078.004")
    filters = []
    if args.product:
        filters.append({"product": {"$eq": args.product}})
    if technique_id:
        filters.append({"technique_ids": {"$contains": technique_id}})
    where = {"$and": filters} if len(filters) > 1 else filters[0] if filters else None
    db = chromadb.PersistentClient(path=str(args.index_dir))
    collection = db.get_collection(manifest["collection"])
    if collection.count() != manifest["indexed"]:
        raise SystemExit("Index count differs from manifest; rebuild the index.")

    if args.query.strip():
        embed_model = HuggingFaceEmbedding(
            model_name=manifest["model"], device="cpu", normalize=manifest["normalize"]
        )
        index = VectorStoreIndex.from_vector_store(
            ChromaVectorStore(chroma_collection=collection), embed_model=embed_model
        )
        # Native where supports array membership; this adapter's generic filters do not.
        retriever = index.as_retriever(
            similarity_top_k=args.limit,
            vector_store_kwargs={"where": where} if where else {},
        )
        matches = [
            (result.node.metadata, result.score, result.node.get_content())
            for result in retriever.retrieve(args.query)
        ]
    else:
        # Filter-only lookup reads directly from Chroma, without loading a model.
        result = collection.get(
            where=where, limit=args.limit, include=["metadatas", "documents"]
        )
        matches = [
            (rule, None, text or "")
            for rule, text in zip(result["metadatas"], result["documents"])
        ]

    if not matches:
        print("No matching rules.")
        return

    print(
        f"Index: {manifest['indexed']} rules; Sigma commit: {manifest['upstream_commit']}"
    )
    for rule, score, text in matches:
        print("\n--- MATCH ---")
        print("Title:", rule["title"])
        print("Rule ID:", rule["rule_id"])
        print("Score:", score, "(similarity ranking, not a probability)")
        print("Product:", rule["product"])
        print("ATT&CK:", ", ".join(rule.get("technique_ids", [])))
        print("Status / level:", rule["status"], "/", rule["level"])
        print("Source:", rule["source_url"])
        print("Local YAML:", Path("data/upstream/sigma") / rule["source_path"])
        print(text[:1000] if text else rule["description"])


if __name__ == "__main__":
    main()

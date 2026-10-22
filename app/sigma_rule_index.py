import chromadb
from llama_index.core import (
    VectorStoreIndex,
)
from llama_index.embeddings.huggingface import HuggingFaceEmbedding  # pyright: ignore[reportMissingTypeStubs]
from llama_index.vector_stores.chroma import ChromaVectorStore  # pyright: ignore[reportMissingTypeStubs]


class SigmaRuleIndex:
    EMBEDDING_MODEL_NAME: str = "BAAI/bge-small-en-v1.5"
    DB_PATH: str = "./data/chroma"
    COLLECTION_NAME: str = "sigma_rules"

    def __init__(self):
        db = chromadb.PersistentClient(path=self.DB_PATH)
        self.collection = db.get_collection(self.COLLECTION_NAME)

        vector_store = ChromaVectorStore(chroma_collection=self.collection)

        embed_model = HuggingFaceEmbedding(model_name=self.EMBEDDING_MODEL_NAME)

        self._index: VectorStoreIndex = VectorStoreIndex.from_vector_store(  # pyright: ignore[reportUnknownMemberType]
            vector_store,
            embed_model=embed_model,
        )

"""
ChromaDB indexer for log chunks.
Stores embeddings and metadata for RAG retrieval across multiple collections.
"""
import chromadb
from chromadb.config import Settings
import logging
import time
from typing import List, Optional, Dict
from pathlib import Path
from django.conf import settings as django_settings

logger = logging.getLogger(__name__)


class LogIndexer:
    """
    Manages multiple ChromaDB collections for two-tier embedding system:
    - individual_logs: Fast-embedded sentencified individual logs
    - log_chunks: Context-embedded grouped summaries
    - analysis_summaries: Context-embedded LLM analysis summaries
    """

    def __init__(self):
        """Initialize ChromaDB client with 3 separate collections."""
        # Initialize ChromaDB client
        chroma_path = Path(django_settings.CHROMA_DATA_DIR)
        chroma_path.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(chroma_path),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            )
        )

        # Create 3 separate collections
        self.individual_logs = self.client.get_or_create_collection(
            name="individual_logs",
            metadata={"hnsw:space": "cosine", "description": "Fast-embedded individual log sentences"}
        )

        self.log_chunks = self.client.get_or_create_collection(
            name="log_chunks",
            metadata={"hnsw:space": "cosine", "description": "Context-embedded grouped summaries"}
        )

        self.analysis_summaries = self.client.get_or_create_collection(
            name="analysis_summaries",
            metadata={"hnsw:space": "cosine", "description": "Context-embedded LLM analysis summaries"}
        )

        # Legacy collection for backward compatibility (batch mode)
        self.collection = self.client.get_or_create_collection(
            name="log_chunks_legacy",
            metadata={"hnsw:space": "cosine"}
        )

        logger.info(f"Initialized ChromaDB with 3 collections: individual_logs, log_chunks, analysis_summaries")

    def index_chunk(self, chunk_id: str, embedding: List[float],
                   document: str, metadata: dict):
        """
        Index a single log chunk.

        Args:
            chunk_id: Unique identifier for the chunk
            embedding: Embedding vector
            document: Text representation of the chunk
            metadata: Chunk metadata (timestamps, IPs, etc.)
        """
        try:
            self.collection.add(
                ids=[chunk_id],
                embeddings=[embedding],
                documents=[document],
                metadatas=[metadata]
            )
        except Exception as e:
            logger.error(f"Error indexing chunk {chunk_id}: {e}")
            raise

    def index_individual_log(self, log_id: str, embedding: List[float],
                            sentencified_text: str, metadata: dict):
        """
        Index a single sentencified log in individual_logs collection.

        Args:
            log_id: Unique identifier for the log
            embedding: Embedding vector from fast model (mxbai)
            sentencified_text: Human-readable key-value format text
            metadata: Log metadata (should include timestamp, ip, line_number)
        """
        try:
            # Ensure timestamp is present
            if 'timestamp' not in metadata:
                metadata['timestamp'] = int(time.time())

            self.individual_logs.add(
                ids=[log_id],
                embeddings=[embedding],
                documents=[sentencified_text],
                metadatas=[metadata]
            )
        except Exception as e:
            logger.error(f"Error indexing individual log {log_id}: {e}")
            raise

    def index_group_summaries(self, summaries: Dict[str, str],
                             embeddings: Dict[str, List[float]], batch_id: str):
        """
        Index grouped summaries in log_chunks collection.

        Args:
            summaries: Dict of {group_id: summary_text}
            embeddings: Dict of {group_id: embedding_vector}
            batch_id: Unique ID for this batch (e.g., "batch_1738461234")
        """
        if not summaries:
            return

        try:
            ids = [f"{batch_id}_{group_id}" for group_id in summaries.keys()]
            docs = list(summaries.values())
            embs = [embeddings[gid] for gid in summaries.keys()]
            metas = [
                {
                    'timestamp': int(time.time()),
                    'group_id': gid,
                    'batch_id': batch_id,
                    'log_count': len([line for line in text.split('\n') if line.strip()])
                }
                for gid, text in summaries.items()
            ]

            self.log_chunks.add(
                ids=ids,
                embeddings=embs,
                documents=docs,
                metadatas=metas
            )
            logger.info(f"Indexed {len(ids)} group summaries for batch {batch_id}")
        except Exception as e:
            logger.error(f"Error indexing group summaries: {e}")
            raise

    def index_analysis_summary(self, summary_id: str, embedding: List[float],
                              summary_text: str, metadata: dict):
        """
        Index LLM analysis summary in analysis_summaries collection.

        Args:
            summary_id: Unique identifier for the summary
            embedding: Embedding vector from context model (bge-m3)
            summary_text: LLM-generated analysis summary
            metadata: Should include timestamp, threats_found, batch_id
        """
        try:
            # Ensure timestamp is present
            if 'timestamp' not in metadata:
                metadata['timestamp'] = int(time.time())

            self.analysis_summaries.add(
                ids=[summary_id],
                embeddings=[embedding],
                documents=[summary_text],
                metadatas=[metadata]
            )
            logger.info(f"Indexed analysis summary {summary_id}")
        except Exception as e:
            logger.error(f"Error indexing analysis summary {summary_id}: {e}")
            raise

    def cleanup_old_entries(self, collection_name: str, max_age_seconds: int):
        """
        Delete entries older than max_age from specified collection.

        Args:
            collection_name: Name of collection ('individual_logs', 'log_chunks', 'analysis_summaries')
            max_age_seconds: Maximum age in seconds (TTL)
        """
        try:
            collection = getattr(self, collection_name, None)
            if not collection:
                logger.warning(f"Collection {collection_name} not found for cleanup")
                return

            cutoff_timestamp = int(time.time()) - max_age_seconds

            # Query old entries
            results = collection.get(
                where={"timestamp": {"$lt": cutoff_timestamp}},
                limit=10000
            )

            if results['ids']:
                collection.delete(ids=results['ids'])
                logger.info(f"Deleted {len(results['ids'])} old entries from {collection_name} (older than {max_age_seconds}s)")
            else:
                logger.debug(f"No old entries to delete from {collection_name}")

        except Exception as e:
            logger.error(f"Error cleaning up {collection_name}: {e}")

    def index_chunks(self, chunks_with_embeddings: List[tuple]):
        """
        Index multiple log chunks (LEGACY - for backward compatibility with batch mode).

        Args:
            chunks_with_embeddings: List of (LogChunk, embedding) tuples
        """
        if not chunks_with_embeddings:
            return

        ids = []
        embeddings = []
        documents = []
        metadatas = []

        for chunk, embedding in chunks_with_embeddings:
            ids.append(chunk.chunk_id)
            embeddings.append(embedding)
            documents.append(chunk.to_text())
            metadatas.append(chunk.to_metadata())

        try:
            self.collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )
            logger.info(f"Indexed {len(ids)} chunks (legacy mode)")
        except Exception as e:
            logger.error(f"Error indexing chunks: {e}")
            raise

    def count(self) -> int:
        """Get total number of indexed chunks (legacy collection)."""
        return self.collection.count()

    def count_all(self) -> Dict[str, int]:
        """Get counts for all collections."""
        return {
            'individual_logs': self.individual_logs.count(),
            'log_chunks': self.log_chunks.count(),
            'analysis_summaries': self.analysis_summaries.count(),
            'legacy': self.collection.count()
        }

    def clear(self):
        """Clear all chunks from the legacy collection."""
        try:
            self.client.delete_collection("log_chunks_legacy")
            self.collection = self.client.create_collection(
                name="log_chunks_legacy",
                metadata={"hnsw:space": "cosine"}
            )
            logger.info(f"Cleared legacy collection")
        except Exception as e:
            logger.error(f"Error clearing legacy collection: {e}")
            raise

    def clear_all(self):
        """Clear all collections (fresh start)."""
        try:
            for collection_name in ["individual_logs", "log_chunks", "analysis_summaries", "log_chunks_legacy"]:
                try:
                    self.client.delete_collection(collection_name)
                    logger.info(f"Deleted collection: {collection_name}")
                except:
                    pass

            # Recreate collections
            self.__init__()
            logger.info("Cleared and recreated all collections")
        except Exception as e:
            logger.error(f"Error clearing all collections: {e}")
            raise

    def get_chunk(self, chunk_id: str) -> Optional[dict]:
        """
        Retrieve a specific chunk by ID.

        Args:
            chunk_id: Chunk identifier

        Returns:
            Dict with chunk data or None if not found
        """
        try:
            result = self.collection.get(ids=[chunk_id])
            if result['ids']:
                return {
                    'id': result['ids'][0],
                    'document': result['documents'][0],
                    'metadata': result['metadatas'][0],
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving chunk {chunk_id}: {e}")
            return None

    def delete_old_chunks(self, before_timestamp: str):
        """
        Delete chunks older than a given timestamp.

        Args:
            before_timestamp: ISO format timestamp
        """
        try:
            # Query chunks older than timestamp
            results = self.collection.get(
                where={"end_time": {"$lt": before_timestamp}}
            )

            if results['ids']:
                self.collection.delete(ids=results['ids'])
                logger.info(f"Deleted {len(results['ids'])} old chunks")
        except Exception as e:
            logger.error(f"Error deleting old chunks: {e}")

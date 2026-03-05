"""
Background thread for TTL-based cleanup of ChromaDB collections.
Prevents unbounded growth of vector database.
"""
import time
import threading
import logging

logger = logging.getLogger(__name__)


class VectorDBCleaner(threading.Thread):
    """
    Background thread for TTL-based cleanup of ChromaDB collections.

    Runs cleanup every 5 minutes to delete entries older than retention_seconds.
    """

    def __init__(self, indexer, retention_seconds: int = 3600):
        """
        Initialize cleanup thread.

        Args:
            indexer: LogIndexer instance with access to collections
            retention_seconds: TTL in seconds (default: 3600 = 1 hour)
        """
        super().__init__(daemon=True, name="VectorDBCleaner")
        self.indexer = indexer
        self.retention_seconds = retention_seconds
        self.running = True
        logger.info(f"Initialized VectorDBCleaner with TTL={retention_seconds}s ({retention_seconds // 60} minutes)")

    def run(self):
        """
        Run cleanup loop.
        Executes cleanup every 5 minutes while running flag is True.
        """
        logger.info(f"VectorDB cleanup thread started (TTL: {self.retention_seconds}s)")

        # Run initial cleanup immediately
        self._cleanup_all()

        while self.running:
            try:
                # Sleep for 5 minutes (or until stop() is called)
                for _ in range(300):  # 300 seconds = 5 minutes
                    if not self.running:
                        break
                    time.sleep(1)

                if self.running:
                    self._cleanup_all()

            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}", exc_info=True)
                # Continue running even if cleanup fails

        logger.info("VectorDB cleanup thread stopped")

    def _cleanup_all(self):
        """Clean up all 3 collections."""
        try:
            for collection_name in ['individual_logs', 'log_chunks', 'analysis_summaries']:
                self.indexer.cleanup_old_entries(collection_name, self.retention_seconds)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def stop(self):
        """Stop the cleanup thread gracefully."""
        logger.info("Stopping VectorDB cleanup thread...")
        self.running = False

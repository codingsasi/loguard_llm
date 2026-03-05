"""
RAG retriever for log chunks.
Implements multiple retrieval strategies for threat detection.
Supports retrieval from multiple collections (individual logs + groups + summaries).
"""
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from engine.indexer.embedder import LogEmbedder, ContextEmbedder

logger = logging.getLogger(__name__)


class LogRetriever:
    """
    Retrieves relevant log chunks using RAG strategies.
    Combines time-window, semantic, and anomaly-based retrieval.
    Supports multi-collection retrieval for two-tier embedding system.
    """
    
    def __init__(self, indexer, embedder: Optional[Any] = None):
        self.indexer = indexer
        # Accept either LogEmbedder or ContextEmbedder
        self.embedder = embedder or LogEmbedder()
    
    def retrieve_recent_context(
        self, 
        semantic_queries: List[str],
        time_window_minutes: int = 30,
        max_individual: int = 20,
        max_groups: int = 10,
        max_summaries: int = 5
    ) -> Dict[str, List[str]]:
        """
        Retrieve both individual sentencified logs and grouped summaries from recent history.
        
        This provides RAG context for LLM analysis by retrieving relevant embeddings
        from the last N minutes across all collection types.
        
        Args:
            semantic_queries: List of queries to search for (e.g., "failed login", "SQL injection")
            time_window_minutes: How far back to search (default: 30 minutes)
            max_individual: Max individual logs to retrieve
            max_groups: Max group summaries to retrieve
            max_summaries: Max analysis summaries to retrieve
        
        Returns:
            Dict with keys:
                - 'individual_logs': List of sentencified log texts
                - 'grouped_summaries': List of group summary texts
                - 'analysis_summaries': List of previous analysis summary texts
        """
        cutoff_ts = int(time.time()) - (time_window_minutes * 60)
        context = {
            'individual_logs': [],
            'grouped_summaries': [],
            'analysis_summaries': []
        }
        
        try:
            # Retrieve individual sentencified logs
            for query in semantic_queries:
                try:
                    query_embedding = self.embedder.embed(query)
                    results = self.indexer.individual_logs.query(
                        query_embeddings=[query_embedding],
                        n_results=max_individual // len(semantic_queries),  # Distribute across queries
                        where={"timestamp": {"$gte": cutoff_ts}}
                    )
                    if results['documents'] and len(results['documents']) > 0:
                        context['individual_logs'].extend(results['documents'][0])
                except Exception as e:
                    logger.warning(f"Error querying individual_logs for '{query}': {e}")
            
            # Retrieve grouped summaries
            for query in semantic_queries:
                try:
                    query_embedding = self.embedder.embed(query)
                    results = self.indexer.log_chunks.query(
                        query_embeddings=[query_embedding],
                        n_results=max_groups // len(semantic_queries),
                        where={"timestamp": {"$gte": cutoff_ts}}
                    )
                    if results['documents'] and len(results['documents']) > 0:
                        context['grouped_summaries'].extend(results['documents'][0])
                except Exception as e:
                    logger.warning(f"Error querying log_chunks for '{query}': {e}")
            
            # Retrieve previous analysis summaries (most recent ones)
            try:
                results = self.indexer.analysis_summaries.get(
                    where={"timestamp": {"$gte": cutoff_ts}},
                    limit=max_summaries
                )
                if results['documents']:
                    context['analysis_summaries'].extend(results['documents'])
            except Exception as e:
                logger.warning(f"Error querying analysis_summaries: {e}")
            
            # Deduplicate and limit
            context['individual_logs'] = list(set(context['individual_logs']))[:max_individual]
            context['grouped_summaries'] = list(set(context['grouped_summaries']))[:max_groups]
            context['analysis_summaries'] = list(set(context['analysis_summaries']))[:max_summaries]
            
            logger.info(f"Retrieved RAG context: {len(context['individual_logs'])} individual, "
                       f"{len(context['grouped_summaries'])} groups, {len(context['analysis_summaries'])} summaries")
            
        except Exception as e:
            logger.error(f"Error retrieving recent context: {e}")
        
        return context

    def retrieve_by_time_window(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve chunks within a time window.

        Args:
            start_time: Start of time window
            end_time: End of time window (default: now)
            max_results: Maximum number of chunks to return

        Returns:
            List of chunk dictionaries
        """
        if end_time is None:
            end_time = datetime.now()

        try:
            # Convert datetime to Unix timestamps for comparison
            start_ts = int(start_time.timestamp())
            end_ts = int(end_time.timestamp())

            results = self.indexer.collection.get(
                where={
                    "$and": [
                        {"start_time": {"$gte": start_ts}},
                        {"end_time": {"$lte": end_ts}}
                    ]
                },
                limit=max_results
            )

            return self._format_results(results)
        except Exception as e:
            logger.error(f"Error retrieving by time window: {e}")
            return []

    def retrieve_by_semantic_query(
        self,
        query: str,
        max_results: int = 50,
        time_window_hours: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve chunks semantically similar to a query.

        Args:
            query: Natural language query (e.g., "failed login attempts")
            max_results: Maximum number of chunks to return
            time_window_hours: Optional time constraint (last N hours)

        Returns:
            List of chunk dictionaries with similarity scores
        """
        try:
            # Generate query embedding
            query_embedding = self.embedder.embed(query)

            # Build where clause for time filtering
            where_clause = None
            if time_window_hours:
                cutoff = datetime.now() - timedelta(hours=time_window_hours)
                cutoff_ts = int(cutoff.timestamp())
                where_clause = {"start_time": {"$gte": cutoff_ts}}

            # Query ChromaDB
            results = self.indexer.collection.query(
                query_embeddings=[query_embedding],
                n_results=max_results,
                where=where_clause
            )

            return self._format_query_results(results)
        except Exception as e:
            logger.error(f"Error retrieving by semantic query: {e}")
            return []

    def retrieve_by_anomaly_patterns(
        self,
        max_results: int = 50,
        time_window_hours: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Retrieve chunks with anomalous patterns.
        Looks for high error rates, unusual IPs, etc.

        Args:
            max_results: Maximum number of chunks to return
            time_window_hours: Time window to search

        Returns:
            List of chunk dictionaries
        """
        cutoff = datetime.now() - timedelta(hours=time_window_hours)
        cutoff_ts = int(cutoff.timestamp())

        anomaly_chunks = []

        try:
            # Query 1: High error rate (4xx, 5xx status codes)
            error_results = self.indexer.collection.get(
                where={
                    "$and": [
                        {"start_time": {"$gte": cutoff_ts}},
                        {
                            "$or": [
                                {"status_codes.401": {"$gte": 5}},
                                {"status_codes.403": {"$gte": 5}},
                                {"status_codes.404": {"$gte": 10}},
                                {"status_codes.500": {"$gte": 3}},
                            ]
                        }
                    ]
                },
                limit=max_results // 2
            )
            anomaly_chunks.extend(self._format_results(error_results))

            # Query 2: High request rate from single IP
            # (This requires analyzing metadata, done in post-processing)

            # Query 3: Recent chunks with multiple unique IPs (potential DDoS)
            multi_ip_results = self.indexer.collection.get(
                where={
                    "$and": [
                        {"start_time": {"$gte": cutoff_ts}},
                        {"log_count": {"$gte": 20}}  # High activity chunks
                    ]
                },
                limit=max_results // 2
            )
            anomaly_chunks.extend(self._format_results(multi_ip_results))

        except Exception as e:
            logger.error(f"Error retrieving anomaly patterns: {e}")

        # Deduplicate and limit
        seen_ids = set()
        unique_chunks = []
        for chunk in anomaly_chunks:
            if chunk['id'] not in seen_ids:
                seen_ids.add(chunk['id'])
                unique_chunks.append(chunk)
                if len(unique_chunks) >= max_results:
                    break

        return unique_chunks

    def retrieve_combined(
        self,
        semantic_queries: List[str],
        time_window_hours: int = 1,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Combined retrieval using multiple strategies.
        This is the main method for threat analysis.

        Args:
            semantic_queries: List of threat-related queries
            time_window_hours: Time window to search (None = all time)
            max_results: Maximum total chunks to return

        Returns:
            List of chunk dictionaries, deduplicated and ranked
        """
        all_chunks = []

        # If time_window_hours is None, retrieve all chunks
        if time_window_hours is None:
            logger.info("Retrieving all chunks (no time window)")
            # Get all chunks via semantic queries without time filter
            for query in semantic_queries:
                semantic_chunks = self.retrieve_by_semantic_query(
                    query=query,
                    max_results=max_results // len(semantic_queries),
                    time_window_hours=None
                )
                all_chunks.extend(semantic_chunks)
        else:
            # Strategy 1: Time window (recent activity)
            cutoff = datetime.now() - timedelta(hours=time_window_hours)
            time_chunks = self.retrieve_by_time_window(
                start_time=cutoff,
                max_results=max_results // 3
            )
            all_chunks.extend(time_chunks)

            # Strategy 2: Semantic queries
            for query in semantic_queries:
                semantic_chunks = self.retrieve_by_semantic_query(
                    query=query,
                    max_results=max_results // (3 * len(semantic_queries)),
                    time_window_hours=time_window_hours
                )
                all_chunks.extend(semantic_chunks)

            # Strategy 3: Anomaly patterns
            anomaly_chunks = self.retrieve_by_anomaly_patterns(
                max_results=max_results // 3,
                time_window_hours=time_window_hours
            )
            all_chunks.extend(anomaly_chunks)

        # Deduplicate and rank
        seen_ids = set()
        unique_chunks = []
        for chunk in all_chunks:
            if chunk['id'] not in seen_ids:
                seen_ids.add(chunk['id'])
                unique_chunks.append(chunk)

        # Sort by timestamp (most recent first)
        # Ensure start_time is always an integer for sorting
        def get_sort_key(chunk):
            start_time = chunk['metadata'].get('start_time', 0)
            # Convert to int if it's a string
            if isinstance(start_time, str):
                try:
                    return int(start_time) if start_time.isdigit() else 0
                except (ValueError, AttributeError):
                    return 0
            return int(start_time) if start_time else 0

        unique_chunks.sort(key=get_sort_key, reverse=True)

        return unique_chunks[:max_results]

    def _format_results(self, results: Dict) -> List[Dict[str, Any]]:
        """Format ChromaDB get() results."""
        formatted = []
        for i in range(len(results['ids'])):
            formatted.append({
                'id': results['ids'][i],
                'document': results['documents'][i],
                'metadata': results['metadatas'][i],
            })
        return formatted

    def _format_query_results(self, results: Dict) -> List[Dict[str, Any]]:
        """Format ChromaDB query() results (includes distances)."""
        formatted = []
        for i in range(len(results['ids'][0])):
            formatted.append({
                'id': results['ids'][0][i],
                'document': results['documents'][0][i],
                'metadata': results['metadatas'][0][i],
                'distance': results['distances'][0][i],
            })
        return formatted


# Predefined semantic queries for threat detection
THREAT_QUERIES = [
    "failed login authentication attempts brute force",
    "SQL injection union select database attack",
    "directory traversal path manipulation etc passwd",
    "high frequency requests denial of service",
    "scanning reconnaissance probing vulnerability",
    "suspicious user agent bot crawler scanner",
]

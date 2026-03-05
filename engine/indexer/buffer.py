"""
Intelligent log buffer for accumulating logs before analysis.
Implements hardcoded intelligent grouping strategy.
"""
import threading
import logging
from typing import List, Tuple, Dict
from collections import defaultdict
from engine.collector.parsers.base import ParsedLogEntry
from engine.indexer.groupsummary import summarize_group, get_cidr_block

logger = logging.getLogger(__name__)


class LogBuffer:
    """
    Thread-safe buffer for accumulating logs until batch size reached.
    Uses HARDCODED intelligent grouping (not configurable).
    """
    
    def __init__(self, max_size: int = 50):
        """
        Initialize buffer.
        
        Args:
            max_size: Maximum number of logs to buffer before flushing (default: 50)
        """
        self.max_size = max_size
        self.logs = []
        self.lock = threading.Lock()
        logger.info(f"Initialized LogBuffer with max_size={max_size}")
    
    def add_log(self, log: ParsedLogEntry):
        """
        Add log to buffer (thread-safe).
        
        Args:
            log: Parsed log entry to buffer
        """
        with self.lock:
            self.logs.append(log)
    
    def should_flush(self) -> bool:
        """
        Check if buffer has reached threshold.
        
        Returns:
            True if buffer is full and should be flushed
        """
        with self.lock:
            return len(self.logs) >= self.max_size
    
    def current_size(self) -> int:
        """Get current number of logs in buffer."""
        with self.lock:
            return len(self.logs)
    
    def flush(self) -> Tuple[List[ParsedLogEntry], Dict[str, str]]:
        """
        Flush buffer and return raw logs + grouped summaries.
        
        This performs intelligent grouping and generates summaries
        for each group.
        
        Returns:
            Tuple of:
                - raw_logs: List of all buffered logs
                - grouped_summaries: Dict of {group_id: summary_text}
        """
        with self.lock:
            if not self.logs:
                return [], {}
            
            # Copy logs for processing
            raw_logs = self.logs.copy()
            
            # Generate grouped summaries
            grouped_summaries = self._group_and_summarize(raw_logs)
            
            # Clear buffer
            self.logs = []
            
            logger.info(f"Flushed buffer: {len(raw_logs)} logs, {len(grouped_summaries)} groups")
            
            return raw_logs, grouped_summaries
    
    def _group_and_summarize(self, logs: List[ParsedLogEntry]) -> Dict[str, str]:
        """
        HARDCODED intelligent grouping (not configurable).
        Groups logs by status codes (4xx, 5xx) and IPs/CIDR blocks (200s).
        
        Args:
            logs: List of log entries to group
        
        Returns:
            Dict of {group_id: summary_text}
        """
        # Initialize groups
        groups = {
            '4xx_errors': [],
            '5xx_errors': [],
        }
        ip_groups = defaultdict(list)
        other_logs = []
        
        # Sort logs by timestamp
        logs.sort(key=lambda x: x.timestamp)
        
        # Categorize logs
        for log in logs:
            status = log.status_code
            
            # Group 4xx errors (client errors - auth failures, not found, etc.)
            if status and 400 <= status < 500:
                groups['4xx_errors'].append(log)
            
            # Group 5xx errors (server errors - crashes, timeouts, etc.)
            elif status and 500 <= status < 600:
                groups['5xx_errors'].append(log)
            
            # Group 200s by CIDR block (for DDoS detection)
            elif status and status == 200:
                if log.client_ip:
                    cidr = get_cidr_block(log.client_ip)
                    ip_groups[f'cidr_{cidr}'].append(log)
                else:
                    other_logs.append(log)
            
            # Other statuses (3xx redirects, etc.)
            else:
                other_logs.append(log)
        
        # Add "other" group if significant
        if other_logs:
            groups['other_status'] = other_logs
        
        # Merge IP groups into main groups dict
        groups.update(ip_groups)
        
        # Generate summaries for each group
        summaries = {}
        for group_id, group_logs in groups.items():
            if group_logs:  # Only create summary if group has logs
                try:
                    summary = summarize_group(group_id, group_logs)
                    if summary:
                        summaries[group_id] = summary
                except Exception as e:
                    logger.error(f"Error summarizing group {group_id}: {e}")
        
        return summaries
    
    def clear(self):
        """Clear the buffer without flushing."""
        with self.lock:
            count = len(self.logs)
            self.logs = []
            logger.info(f"Cleared buffer ({count} logs discarded)")

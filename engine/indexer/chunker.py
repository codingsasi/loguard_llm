"""
Log chunking strategies for embedding.
Groups multiple log entries into chunks to capture temporal patterns.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List
from engine.collector.parsers.base import ParsedLogEntry


@dataclass
class LogChunk:
    """
    A chunk of log entries grouped together.
    """
    logs: List[ParsedLogEntry]
    start_time: datetime
    end_time: datetime
    chunk_id: str

    @property
    def log_count(self) -> int:
        return len(self.logs)

    @property
    def unique_ips(self) -> set:
        return {log.client_ip for log in self.logs if log.client_ip}

    @property
    def status_codes(self) -> dict:
        """Count of each status code in chunk."""
        codes = {}
        for log in self.logs:
            if log.status_code:
                codes[log.status_code] = codes.get(log.status_code, 0) + 1
        return codes

    @property
    def methods(self) -> dict:
        """Count of each HTTP method in chunk."""
        methods = {}
        for log in self.logs:
            if log.method:
                methods[log.method] = methods.get(log.method, 0) + 1
        return methods

    def to_text(self) -> str:
        """
        Generate text representation for embedding.
        Includes all logs in the chunk.
        """
        lines = []
        for log in self.logs:
            lines.append(log.to_text())
        return "\n".join(lines)

    def to_metadata(self) -> dict:
        """Generate metadata for ChromaDB storage."""
        import json
        
        # ChromaDB only accepts str, int, float, bool - convert complex types
        # Use Unix timestamps for time comparisons (ChromaDB can compare numbers)
        return {
            "start_time": int(self.start_time.timestamp()),  # Unix timestamp (int)
            "end_time": int(self.end_time.timestamp()),  # Unix timestamp (int)
            "start_time_iso": self.start_time.isoformat(),  # Keep ISO for display
            "end_time_iso": self.end_time.isoformat(),  # Keep ISO for display
            "log_count": self.log_count,
            "unique_ips": ",".join(sorted(self.unique_ips)),  # Convert list to comma-separated string
            "status_codes": json.dumps(self.status_codes),  # Convert dict to JSON string
            "methods": json.dumps(self.methods),  # Convert dict to JSON string
            "raw_logs": json.dumps([log.to_dict() for log in self.logs]),  # Convert list to JSON string
        }


class LogChunker:
    """
    Base class for log chunking strategies.
    """

    def chunk(self, logs: List[ParsedLogEntry]) -> List[LogChunk]:
        """
        Group logs into chunks.

        Args:
            logs: List of parsed log entries

        Returns:
            List of LogChunk objects
        """
        raise NotImplementedError


class FixedSizeChunker(LogChunker):
    """
    Chunk logs by fixed number of entries.
    Example: Every 10 logs become one chunk.
    """

    def __init__(self, chunk_size: int = 10):
        self.chunk_size = chunk_size

    def chunk(self, logs: List[ParsedLogEntry]) -> List[LogChunk]:
        """Group logs into fixed-size chunks."""
        if not logs:
            return []

        chunks = []
        for i in range(0, len(logs), self.chunk_size):
            chunk_logs = logs[i:i + self.chunk_size]
            if not chunk_logs:
                continue

            chunk = LogChunk(
                logs=chunk_logs,
                start_time=chunk_logs[0].timestamp,
                end_time=chunk_logs[-1].timestamp,
                chunk_id=f"fixed_{i}_{i + len(chunk_logs)}"
            )
            chunks.append(chunk)

        return chunks


class TimeWindowChunker(LogChunker):
    """
    Chunk logs by time window.
    Example: All logs within a 60-second window become one chunk.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

    def chunk(self, logs: List[ParsedLogEntry]) -> List[LogChunk]:
        """Group logs into time-based chunks."""
        if not logs:
            return []

        # Sort by timestamp
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)

        chunks = []
        current_chunk_logs = []
        window_start = sorted_logs[0].timestamp
        chunk_index = 0

        for log in sorted_logs:
            # Check if log is within current window
            if log.timestamp <= window_start + timedelta(seconds=self.window_seconds):
                current_chunk_logs.append(log)
            else:
                # Save current chunk and start new one
                if current_chunk_logs:
                    chunk = LogChunk(
                        logs=current_chunk_logs,
                        start_time=current_chunk_logs[0].timestamp,
                        end_time=current_chunk_logs[-1].timestamp,
                        chunk_id=f"time_{chunk_index}_{window_start.isoformat()}"
                    )
                    chunks.append(chunk)
                    chunk_index += 1

                # Start new window
                current_chunk_logs = [log]
                window_start = log.timestamp

        # Don't forget the last chunk
        if current_chunk_logs:
            chunk = LogChunk(
                logs=current_chunk_logs,
                start_time=current_chunk_logs[0].timestamp,
                end_time=current_chunk_logs[-1].timestamp,
                chunk_id=f"time_{chunk_index}_{window_start.isoformat()}"
            )
            chunks.append(chunk)

        return chunks


class IntelligentChunker(LogChunker):
    """
    Intelligent chunking based on status codes and IP patterns.
    Prioritizes suspicious activity for better threat detection.
    
    Strategy:
    1. Group 4xx errors (403, 404, 401) - authentication/scanning attempts
    2. Group 5xx errors - server errors/exploitation attempts  
    3. Group 200s by IP/CIDR blocks - detect DDoS patterns
    """
    
    def __init__(self, max_chunk_size: int = 20):
        self.max_chunk_size = max_chunk_size
    
    def _get_cidr_block(self, ip: str) -> str:
        """Get /24 CIDR block from IP (e.g., 192.168.1.x -> 192.168.1)"""
        if not ip:
            return "unknown"
        parts = ip.split('.')
        if len(parts) >= 3:
            return '.'.join(parts[:3])  # /24 block
        return ip
    
    def chunk(self, logs: List[ParsedLogEntry]) -> List[LogChunk]:
        """Group logs intelligently by status codes and IPs."""
        if not logs:
            return []
        
        # Sort by timestamp first
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        # Separate logs by category
        error_4xx = []  # Client errors (auth failures, not found)
        error_5xx = []  # Server errors (exploitation attempts)
        success_by_ip = {}  # 200s grouped by CIDR block
        other_logs = []
        
        for log in sorted_logs:
            status = log.status_code or 0
            
            if 400 <= status < 500:
                error_4xx.append(log)
            elif 500 <= status < 600:
                error_5xx.append(log)
            elif status == 200:
                cidr = self._get_cidr_block(log.client_ip)
                if cidr not in success_by_ip:
                    success_by_ip[cidr] = []
                success_by_ip[cidr].append(log)
            else:
                other_logs.append(log)
        
        chunks = []
        chunk_idx = 0
        
        # Priority 1: Group 4xx errors (suspicious activity)
        chunks.extend(self._chunk_by_status(error_4xx, "4xx", chunk_idx))
        chunk_idx += len(chunks)
        
        # Priority 2: Group 5xx errors (potential exploitation)
        chunks.extend(self._chunk_by_status(error_5xx, "5xx", chunk_idx))
        chunk_idx += len(chunks)
        
        # Priority 3: Group 200s by CIDR block (DDoS detection)
        for cidr, cidr_logs in success_by_ip.items():
            chunks.extend(self._chunk_by_ip(cidr_logs, cidr, chunk_idx))
            chunk_idx += len(chunks)
        
        # Priority 4: Other status codes
        if other_logs:
            chunks.extend(self._chunk_by_status(other_logs, "other", chunk_idx))
        
        return chunks
    
    def _chunk_by_status(self, logs: List[ParsedLogEntry], status_type: str, start_idx: int) -> List[LogChunk]:
        """Chunk logs by status code type."""
        chunks = []
        for i in range(0, len(logs), self.max_chunk_size):
            chunk_logs = logs[i:i + self.max_chunk_size]
            if not chunk_logs:
                continue
            
            chunk = LogChunk(
                logs=chunk_logs,
                start_time=chunk_logs[0].timestamp,
                end_time=chunk_logs[-1].timestamp,
                chunk_id=f"{status_type}_{start_idx + len(chunks)}_{i}"
            )
            chunks.append(chunk)
        
        return chunks
    
    def _chunk_by_ip(self, logs: List[ParsedLogEntry], cidr: str, start_idx: int) -> List[LogChunk]:
        """Chunk logs by IP/CIDR block."""
        chunks = []
        for i in range(0, len(logs), self.max_chunk_size):
            chunk_logs = logs[i:i + self.max_chunk_size]
            if not chunk_logs:
                continue
            
            chunk = LogChunk(
                logs=chunk_logs,
                start_time=chunk_logs[0].timestamp,
                end_time=chunk_logs[-1].timestamp,
                chunk_id=f"cidr_{cidr}_{start_idx + len(chunks)}_{i}"
            )
            chunks.append(chunk)
        
        return chunks


def get_chunker(strategy: str, chunk_size: int = 10) -> LogChunker:
    """
    Factory function to get the appropriate chunker.

    Args:
        strategy: 'fixed_size' or 'intelligent'
        chunk_size: Maximum number of logs per chunk

    Returns:
        LogChunker instance
    """
    if strategy == 'fixed_size':
        return FixedSizeChunker(chunk_size=chunk_size)
    elif strategy == 'intelligent':
        return IntelligentChunker(max_chunk_size=chunk_size)
    else:
        raise ValueError(f"Unknown chunking strategy: {strategy}")

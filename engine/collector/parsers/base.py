"""
Base parser interface for log formats.
Allows easy extension to support new log formats.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ParsedLogEntry:
    """
    Unified structure for parsed log entries.
    All parsers normalize to this format.
    """
    # Core fields (always present)
    timestamp: datetime
    raw_line: str
    line_number: int
    
    # HTTP fields (for web logs)
    client_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query_string: Optional[str] = None
    protocol: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    
    # Extended fields (Combined/Extended format)
    referer: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Authentication
    remote_user: Optional[str] = None
    
    def to_text(self) -> str:
        """
        Generate text representation for embedding.
        Focuses on security-relevant fields.
        """
        parts = []
        
        if self.method and self.path:
            parts.append(f"{self.method} {self.path}")
        
        if self.query_string:
            parts.append(f"Query: {self.query_string}")
        
        if self.status_code:
            parts.append(f"Status: {self.status_code}")
        
        if self.client_ip:
            parts.append(f"IP: {self.client_ip}")
        
        if self.user_agent:
            # Truncate long user agents
            ua = self.user_agent[:100] if len(self.user_agent) > 100 else self.user_agent
            parts.append(f"UA: {ua}")
        
        return " | ".join(parts) if parts else self.raw_line
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'raw_line': self.raw_line,
            'line_number': self.line_number,
            'client_ip': self.client_ip,
            'method': self.method,
            'path': self.path,
            'query_string': self.query_string,
            'protocol': self.protocol,
            'status_code': self.status_code,
            'bytes_sent': self.bytes_sent,
            'referer': self.referer,
            'user_agent': self.user_agent,
            'remote_user': self.remote_user,
        }


class LogParser(ABC):
    """
    Abstract base class for log parsers.
    Implement this to add support for new log formats.
    """
    
    @abstractmethod
    def parse(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Raw log line
            line_number: Line number in file
        
        Returns:
            ParsedLogEntry if successful, None if line cannot be parsed
        """
        pass
    
    @abstractmethod
    def detect(self, sample_lines: list[str]) -> bool:
        """
        Detect if this parser can handle the given log format.
        
        Args:
            sample_lines: First few lines of the log file
        
        Returns:
            True if this parser can handle the format
        """
        pass
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return human-readable format name."""
        pass

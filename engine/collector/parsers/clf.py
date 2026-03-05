"""
Common Log Format (CLF) and NCSA Combined/Extended format parser.

CLF Format:
    host ident authuser date request status bytes

Combined Format (adds referer and user-agent):
    host ident authuser date request status bytes referer user-agent

Example CLF:
    127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326

Example Combined:
    127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://example.com" "Mozilla/5.0"
"""
import re
from datetime import datetime
from typing import Optional
from .base import LogParser, ParsedLogEntry


class CLFParser(LogParser):
    """Parser for Common Log Format and NCSA Combined/Extended format."""
    
    # CLF regex pattern
    CLF_PATTERN = re.compile(
        r'^(?P<host>\S+) '                          # Host/IP
        r'(?P<ident>\S+) '                          # Identity (usually -)
        r'(?P<authuser>\S+) '                       # Authenticated user (usually -)
        r'\[(?P<date>[^\]]+)\] '                    # Date in brackets
        r'"(?P<request>[^"]*)" '                    # Request in quotes
        r'(?P<status>\d{3}) '                       # Status code
        r'(?P<bytes>\S+)'                           # Bytes sent (or -)
        r'(?: "(?P<referer>[^"]*)")?'               # Optional referer
        r'(?: "(?P<user_agent>[^"]*)")?'            # Optional user agent
    )
    
    # Date format: [10/Oct/2000:13:55:36 -0700]
    DATE_FORMAT = '%d/%b/%Y:%H:%M:%S %z'
    
    @property
    def format_name(self) -> str:
        return "Common Log Format (CLF/Combined)"
    
    def parse(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """Parse a CLF or Combined format log line."""
        line = line.strip()
        if not line:
            return None
        
        match = self.CLF_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(groups['date'], self.DATE_FORMAT)
        except ValueError:
            # If timezone parsing fails, try without timezone
            try:
                timestamp = datetime.strptime(groups['date'].rsplit(' ', 1)[0], '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                return None
        
        # Parse request line: "GET /path HTTP/1.1"
        request = groups['request']
        method, path, protocol = None, None, None
        query_string = None
        
        if request:
            parts = request.split(' ', 2)
            if len(parts) >= 1:
                method = parts[0]
            if len(parts) >= 2:
                full_path = parts[1]
                # Split path and query string
                if '?' in full_path:
                    path, query_string = full_path.split('?', 1)
                else:
                    path = full_path
            if len(parts) >= 3:
                protocol = parts[2]
        
        # Parse status code
        try:
            status_code = int(groups['status'])
        except (ValueError, TypeError):
            status_code = None
        
        # Parse bytes sent
        bytes_sent = None
        if groups['bytes'] and groups['bytes'] != '-':
            try:
                bytes_sent = int(groups['bytes'])
            except ValueError:
                pass
        
        # Remote user
        remote_user = groups['authuser'] if groups['authuser'] != '-' else None
        
        # Referer and user agent (Combined format)
        referer = groups.get('referer') if groups.get('referer') and groups.get('referer') != '-' else None
        user_agent = groups.get('user_agent') if groups.get('user_agent') and groups.get('user_agent') != '-' else None
        
        return ParsedLogEntry(
            timestamp=timestamp,
            raw_line=line,
            line_number=line_number,
            client_ip=groups['host'],
            method=method,
            path=path,
            query_string=query_string,
            protocol=protocol,
            status_code=status_code,
            bytes_sent=bytes_sent,
            referer=referer,
            user_agent=user_agent,
            remote_user=remote_user,
        )
    
    def detect(self, sample_lines: list[str]) -> bool:
        """
        Detect if logs are in CLF/Combined format.
        Check if at least 80% of sample lines match the pattern.
        """
        if not sample_lines:
            return False
        
        matches = 0
        for line in sample_lines[:10]:  # Check first 10 lines
            line = line.strip()
            if not line:
                continue
            if self.CLF_PATTERN.match(line):
                matches += 1
        
        # At least 80% of lines should match
        return matches >= len([l for l in sample_lines[:10] if l.strip()]) * 0.8

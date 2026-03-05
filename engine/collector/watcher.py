"""
Log file watcher using watchdog library.
Monitors log files for changes and yields new entries.
"""
import time
from pathlib import Path
from typing import Iterator, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
import logging

logger = logging.getLogger(__name__)


class LogFileHandler(FileSystemEventHandler):
    """Handler for log file modification events."""

    def __init__(self, log_path: Path, callback):
        self.log_path = log_path
        self.callback = callback
        self.last_position = 0

        # Initialize position to end of file
        if self.log_path.exists():
            self.last_position = self.log_path.stat().st_size

    def on_modified(self, event):
        """Called when the log file is modified."""
        if event.src_path == str(self.log_path):
            self._read_new_lines()

    def _read_new_lines(self):
        """Read new lines from the log file since last position."""
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

                if new_lines:
                    self.callback(new_lines)
        except Exception as e:
            logger.error(f"Error reading log file: {e}")


class LogWatcher:
    """
    Watches a log file for new entries.
    Can operate in two modes:
    1. Real-time watching (using watchdog)
    2. Batch reading (read all lines once)
    """

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.observer = None
        self._new_lines = []
        self._line_number = 0

    def _on_new_lines(self, lines: list[str]):
        """Callback when new lines are detected."""
        self._new_lines.extend(lines)

    def start_watching(self):
        """Start watching the log file in real-time."""
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        # Set up watchdog observer
        event_handler = LogFileHandler(self.log_path, self._on_new_lines)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.log_path.parent), recursive=False)
        self.observer.start()

        logger.info(f"Started watching log file: {self.log_path}")

    def stop_watching(self):
        """Stop watching the log file."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped watching log file")

    def get_new_lines(self) -> list[tuple[int, str]]:
        """
        Get new lines that have been detected.
        Returns list of (line_number, line_content) tuples.
        """
        if not self._new_lines:
            return []

        lines_with_numbers = []
        for line in self._new_lines:
            self._line_number += 1
            lines_with_numbers.append((self._line_number, line))

        self._new_lines.clear()
        return lines_with_numbers

    def read_all_lines(self) -> Iterator[tuple[int, str]]:
        """
        Read all lines from the log file (batch mode).
        Yields (line_number, line_content) tuples.
        """
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        line_number = 0
        with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_number += 1
                yield (line_number, line)

    def tail(self, n: int = 100) -> list[tuple[int, str]]:
        """
        Get the last N lines from the log file.
        Returns list of (line_number, line_content) tuples.
        """
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        # Read all lines and keep last N
        all_lines = list(self.read_all_lines())
        return all_lines[-n:] if len(all_lines) > n else all_lines

    def __enter__(self):
        """Context manager entry."""
        self.start_watching()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_watching()


class LogCollector:
    """
    High-level log collector that combines watcher and parser.
    """

    # Default static asset extensions to filter out
    DEFAULT_STATIC_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',  # Fonts
        '.map', '.json', '.xml',  # Source maps and data
        '.mp4', '.webm', '.mp3', '.wav',  # Media
        '.zip', '.pdf', '.doc', '.docx',  # Documents
    }

    def __init__(self, log_path: str, parser, filter_static: bool = True, 
                 excluded_extensions: str = None, excluded_user_agents: str = None,
                 excluded_status_codes: str = None, excluded_methods: str = None,
                 included_methods_override: str = None, excluded_paths: str = None):
        self.watcher = LogWatcher(log_path)
        self.parser = parser
        self.filter_static = filter_static
        
        # Parse excluded extensions from comma-separated string
        if excluded_extensions:
            # Split by comma, strip whitespace, ensure lowercase, ensure leading dot
            self.excluded_extensions = {
                ext.strip().lower() if ext.strip().startswith('.') else f".{ext.strip().lower()}"
                for ext in excluded_extensions.split(',')
                if ext.strip()
            }
        else:
            self.excluded_extensions = self.DEFAULT_STATIC_EXTENSIONS
        
        # Parse excluded user agents (case-insensitive substrings)
        if excluded_user_agents:
            self.excluded_user_agents = {
                ua.strip().lower()
                for ua in excluded_user_agents.split(',')
                if ua.strip()
            }
        else:
            self.excluded_user_agents = set()
        
        # Parse excluded status codes
        if excluded_status_codes:
            self.excluded_status_codes = {
                int(code.strip())
                for code in excluded_status_codes.split(',')
                if code.strip().isdigit()
            }
        else:
            self.excluded_status_codes = set()
        
        # Parse excluded methods (e.g., HEAD, OPTIONS)
        if excluded_methods:
            self.excluded_methods = {
                method.strip().upper()
                for method in excluded_methods.split(',')
                if method.strip()
            }
        else:
            self.excluded_methods = set()
        
        # Parse included methods that override status code filtering (e.g., POST, PUT, DELETE)
        if included_methods_override:
            self.included_methods_override = {
                method.strip().upper()
                for method in included_methods_override.split(',')
                if method.strip()
            }
        else:
            self.included_methods_override = set()
        
        # Parse excluded paths (substring matching for legitimate app endpoints)
        if excluded_paths:
            self.excluded_paths = {
                path.strip().lower()
                for path in excluded_paths.split(',')
                if path.strip()
            }
        else:
            self.excluded_paths = set()

    def _is_static_asset(self, entry) -> bool:
        """Check if log entry is for a static asset."""
        if not entry or not entry.path:
            return False

        # Extract path without query string
        path = entry.path.split('?')[0].lower()

        # Check extension
        for ext in self.excluded_extensions:
            if path.endswith(ext):
                return True

        return False

    def _is_excluded_user_agent(self, entry) -> bool:
        """Check if log entry is from an excluded user agent."""
        if not entry or not entry.user_agent or not self.excluded_user_agents:
            return False

        ua_lower = entry.user_agent.lower()
        for excluded_ua in self.excluded_user_agents:
            if excluded_ua in ua_lower:
                return True

        return False

    def _is_excluded_status_code(self, entry) -> bool:
        """Check if log entry has an excluded status code."""
        if not entry or not entry.status_code or not self.excluded_status_codes:
            return False

        return entry.status_code in self.excluded_status_codes

    def _is_excluded_method(self, entry) -> bool:
        """Check if log entry has an excluded HTTP method."""
        if not entry or not entry.method or not self.excluded_methods:
            return False

        return entry.method.upper() in self.excluded_methods

    def _is_included_method_override(self, entry) -> bool:
        """
        Check if log entry has a method that overrides status code filtering.
        Example: POST requests are always included even if status 200 is excluded.
        """
        if not entry or not entry.method or not self.included_methods_override:
            return False
        
        return entry.method.upper() in self.included_methods_override
    
    def _is_excluded_path(self, entry) -> bool:
        """
        Check if log entry path should be excluded (legitimate app endpoints).
        Uses substring matching - excludes if ANY excluded path appears in the entry path.
        """
        if not entry or not entry.path or not self.excluded_paths:
            return False
        
        path_lower = entry.path.lower()
        for excluded_path in self.excluded_paths:
            if excluded_path in path_lower:
                return True
        
        return False

    def _should_include(self, entry) -> bool:
        """
        Determine if log entry should be included in analysis.
        
        Filtering logic:
        1. Filter out static assets (if enabled)
        2. Filter out excluded paths (legitimate app endpoints like /nodeviewcount)
        3. Filter out excluded methods (e.g., HEAD, OPTIONS)
        4. Include override methods (e.g., POST, PUT, DELETE) - SKIPS status code check
        5. Filter out excluded status codes (e.g., 200 OK for GET requests)
        6. Filter out excluded user agents (bots, crawlers)
        """
        if not entry:
            return False
        
        # Filter 1: Static assets
        if self.filter_static and self._is_static_asset(entry):
            return False
        
        # Filter 2: Excluded paths (legitimate app endpoints - analytics, tracking, etc.)
        if self._is_excluded_path(entry):
            return False
        
        # Filter 3: Excluded methods (e.g., HEAD, OPTIONS)
        if self._is_excluded_method(entry):
            return False
        
        # Filter 4: Method override - always include these methods regardless of status
        # Example: POST with 200 OK (spam submission) should be included even if 200 is excluded
        # BUT: This is AFTER path filtering, so /nodeviewcount POST is already excluded
        if self._is_included_method_override(entry):
            # Skip status code check for these methods
            # But still check user agents
            if self._is_excluded_user_agent(entry):
                return False
            return True
        
        # Filter 5: Excluded status codes (e.g., 200 OK if focusing on errors)
        if self._is_excluded_status_code(entry):
            return False
        
        # Filter 6: Excluded user agents (bots, crawlers)
        if self._is_excluded_user_agent(entry):
            return False
        
        return True

    def start(self):
        """Start collecting logs."""
        self.watcher.start_watching()

    def stop(self):
        """Stop collecting logs."""
        self.watcher.stop_watching()

    def collect_new_entries(self) -> list:
        """
        Collect and parse new log entries.
        Returns list of ParsedLogEntry objects (filtered).
        """
        raw_lines = self.watcher.get_new_lines()
        parsed_entries = []

        for line_number, line in raw_lines:
            entry = self.parser.parse(line, line_number)
            if self._should_include(entry):
                parsed_entries.append(entry)

        return parsed_entries

    def collect_all_entries(self) -> list:
        """
        Collect and parse all log entries (batch mode).
        Returns list of ParsedLogEntry objects (filtered).
        """
        parsed_entries = []

        for line_number, line in self.watcher.read_all_lines():
            entry = self.parser.parse(line, line_number)
            if self._should_include(entry):
                parsed_entries.append(entry)

        return parsed_entries

    def collect_recent_entries(self, n: int = 100) -> list:
        """
        Collect and parse the last N log entries.
        Returns list of ParsedLogEntry objects (filtered).
        """
        raw_lines = self.watcher.tail(n)
        parsed_entries = []

        for line_number, line in raw_lines:
            entry = self.parser.parse(line, line_number)
            if self._should_include(entry):
                parsed_entries.append(entry)

        return parsed_entries

"""
Log sentencification - convert raw logs to human-readable key-value format.
Optimized for better embedding quality.
"""
from engine.collector.parsers.base import ParsedLogEntry
from urllib.parse import urlparse


def sentencify_log(log: ParsedLogEntry) -> str:
    """
    Convert log to human-readable key-value format (NOT JSON).

    Example output:
    ```
    GET request
    IP: 165.225.212.252
    Path: /pwa/phone-home
    Status: 302 redirect
    Referrer: /en/service-worker-data
    User-Agent: Chrome (Windows)
    Timestamp: 2026-01-19T01:49:14Z
    ```

    Args:
        log: ParsedLogEntry object

    Returns:
        Multiline key-value formatted string
    """
    lines = []

    # HTTP Method
    lines.append(f"{log.method or 'UNKNOWN'} request")

    # Client IP
    if log.client_ip:
        lines.append(f"IP: {log.client_ip}")

    # Request path
    lines.append(f"Path: {log.path or '/'}")

    # Status code with human-readable description
    status_map = {
        200: "success", 201: "created", 204: "no content",
        301: "redirect", 302: "redirect", 304: "not modified",
        400: "bad request", 401: "unauthorized", 403: "forbidden", 404: "not found",
        500: "server error", 502: "bad gateway", 503: "service unavailable"
    }
    status_desc = status_map.get(log.status_code, "")
    if status_desc:
        lines.append(f"Status: {log.status_code} {status_desc}")
    else:
        lines.append(f"Status: {log.status_code}")

    # Referrer (extract path only)
    if log.referer and log.referer != "-":
        ref_path = extract_path(log.referer)
        lines.append(f"Referrer: {ref_path}")

    # User Agent (simplified)
    if log.user_agent:
        ua_simple = simplify_user_agent(log.user_agent)
        lines.append(f"User-Agent: {ua_simple}")

    # Timestamp
    lines.append(f"Timestamp: {log.timestamp.isoformat()}")

    # Query string (if suspicious patterns)
    if log.query_string and is_suspicious_query(log.query_string):
        # Truncate long query strings
        qs = log.query_string[:200] if len(log.query_string) > 200 else log.query_string
        lines.append(f"Query: {qs}")

    return "\n".join(lines)


def simplify_user_agent(ua: str) -> str:
    """
    Extract browser and OS from user agent string.

    Args:
        ua: Full user agent string

    Returns:
        Simplified format like "Chrome (Windows)" or "curl (Linux)"
    """
    browser = "Other"

    # Identify browser
    if "curl" in ua.lower():
        browser = "curl"
    elif "wget" in ua.lower():
        browser = "wget"
    elif "Python" in ua or "python-requests" in ua.lower():
        browser = "Python-requests"
    elif "bot" in ua.lower() or "crawler" in ua.lower() or "spider" in ua.lower():
        browser = "Bot/Crawler"
    elif "Edg" in ua:
        browser = "Edge"
    elif "Chrome" in ua and "Edg" not in ua:
        # Extract version if possible
        try:
            version = ua.split("Chrome/")[1].split()[0].split(".")[0]
            browser = f"Chrome {version}"
        except:
            browser = "Chrome"
    elif "Firefox" in ua:
        try:
            version = ua.split("Firefox/")[1].split()[0].split(".")[0]
            browser = f"Firefox {version}"
        except:
            browser = "Firefox"
    elif "Safari" in ua and "Chrome" not in ua:
        browser = "Safari"

    # Identify OS
    os_name = "Unknown"
    if "Windows NT 10.0" in ua or "Windows NT 11.0" in ua:
        os_name = "Windows 10/11"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Linux" in ua and "Android" not in ua:
        os_name = "Linux"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"

    return f"{browser} ({os_name})"


def extract_path(url: str) -> str:
    """
    Extract path from full URL.

    Args:
        url: Full URL like "https://example.com/path"

    Returns:
        Just the path like "/path"
    """
    if not url or url == "-":
        return "/"

    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except:
        # If parsing fails, try to extract path manually
        if "/" in url:
            parts = url.split("/", 3)
            if len(parts) >= 4:
                return "/" + parts[3]
        return url


def is_suspicious_query(query_string: str) -> bool:
    """
    Check if query string contains suspicious patterns.

    Args:
        query_string: URL query string

    Returns:
        True if query string contains potential attack patterns
    """
    if not query_string:
        return False

    suspicious_patterns = [
        'union', 'select', 'drop', 'insert', 'delete', 'update',  # SQL injection
        '../', '..\\', '/etc/', '/passwd', '/shadow',  # Path traversal
        '<script', 'javascript:', 'onerror=', 'onload=',  # XSS
        'exec', 'eval', 'system', 'cmd',  # Code execution
        '0x', '%27', '%22', '%3C', '%3E',  # Encoded attacks
    ]

    query_lower = query_string.lower()
    return any(pattern in query_lower for pattern in suspicious_patterns)

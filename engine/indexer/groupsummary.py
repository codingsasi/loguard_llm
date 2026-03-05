"""
Grouped log summary generation.
Creates human-readable summaries of intelligently grouped logs.
"""
from typing import List
from collections import Counter
from engine.collector.parsers.base import ParsedLogEntry
from engine.indexer.sentencify import simplify_user_agent


def summarize_group(group_name: str, logs: List[ParsedLogEntry]) -> str:
    """
    Create human-readable summary of grouped logs (no raw logs included).

    This generates a key-value format summary that captures the essence of
    the group without including individual log lines.

    Args:
        group_name: Name of group (e.g., "4xx_errors", "5xx_errors", "cidr_192.168.1.0/24")
        logs: List of logs in this group

    Returns:
        Multiline key-value format summary
    """
    if not logs:
        return ""

    lines = []

    # Determine group type and title
    if group_name.startswith("4xx_errors"):
        lines.append("Group: 4xx Client Errors")
    elif group_name.startswith("5xx_errors"):
        lines.append("Group: 5xx Server Errors")
    elif group_name.startswith("cidr_"):
        cidr_block = group_name.replace("cidr_", "")
        lines.append(f"Group: Requests from CIDR {cidr_block}")
    elif group_name.startswith("ip_"):
        ip_addr = group_name.replace("ip_", "")
        lines.append(f"Group: Requests from IP {ip_addr}")
    else:
        lines.append(f"Group: {group_name}")

    # Request count
    lines.append(f"Count: {len(logs)} requests")

    # Time range
    timestamps = [log.timestamp for log in logs]
    start_time = min(timestamps)
    end_time = max(timestamps)
    duration_seconds = (end_time - start_time).total_seconds()
    lines.append(f"Time Range: {start_time.isoformat()} to {end_time.isoformat()}")

    # Request rate (if meaningful)
    if duration_seconds > 1:
        rate = len(logs) / duration_seconds
        lines.append(f"Request Rate: {rate:.2f} requests/second")

    # Top IPs (for error groups)
    if not group_name.startswith("cidr_") and not group_name.startswith("ip_"):
        ip_counts = Counter(log.client_ip for log in logs)
        top_ips = ip_counts.most_common(3)
        ip_str = ", ".join([f"{ip} ({count} requests)" for ip, count in top_ips])
        lines.append(f"Top IPs: {ip_str}")

    # Top paths
    path_counts = Counter(log.path for log in logs if log.path)
    top_paths = path_counts.most_common(5)
    path_str = ", ".join([f"{path} ({count})" for path, count in top_paths])
    lines.append(f"Top Paths: {path_str}")

    # HTTP methods
    method_counts = Counter(log.method for log in logs if log.method)
    method_str = ", ".join([f"{method} ({count})" for method, count in method_counts.most_common()])
    lines.append(f"Methods: {method_str}")

    # Status codes distribution (for CIDR/IP groups)
    status_counts = Counter(log.status_code for log in logs if log.status_code)
    status_str = ", ".join([f"{status} ({count})" for status, count in status_counts.most_common(5)])
    lines.append(f"Status Codes: {status_str}")

    # User agents (simplified)
    ua_list = []
    for log in logs:
        if log.user_agent:
            ua_list.append(simplify_user_agent(log.user_agent))

    if ua_list:
        ua_counts = Counter(ua_list)
        ua_str = ", ".join([f"{ua} ({count})" for ua, count in ua_counts.most_common(3)])
        lines.append(f"User-Agents: {ua_str}")

    # Suspicious patterns
    suspicious_elements = []

    # Check for suspicious query strings
    for log in logs:
        if log.query_string:
            qs_lower = log.query_string.lower()
            if any(pattern in qs_lower for pattern in ['union', 'select', '../', 'script', 'exec']):
                suspicious_elements.append("suspicious query strings detected")
                break

    # Check for auth failures (401, 403)
    auth_failures = sum(1 for log in logs if log.status_code in [401, 403])
    if auth_failures > 0:
        suspicious_elements.append(f"{auth_failures} authentication failures")

    if suspicious_elements:
        lines.append(f"Suspicious Patterns: {', '.join(suspicious_elements)}")

    return "\n".join(lines)


def get_cidr_block(ip: str) -> str:
    """
    Get /24 CIDR block from IP address.

    Args:
        ip: IP address like "192.168.1.50"

    Returns:
        CIDR block like "192.168.1.0/24"
    """
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip
    except:
        return ip

"""
Prompt templates for threat detection with LLMs.
"""

SYSTEM_PROMPT = """Analyze the provided web server logs and identify threats and attack patterns from the logs."""


THREAT_ANALYSIS_PROMPT = """
Attack Types:
brute_force - Logs indicating repeated attempts same path with  different parameters
ddos - Logs indicating high frequency requests in an extremely short interval (2 second or less)
sql_injection - Logs indicating SQL injection attempts
path_traversal - Logs indicating path traversal attempts
reconnaissance - Logs indicating reconnaissance attempts (e.g. scanning for open ports, directories, files)
bot - Logs indicating bot activity
other - Logs indicating other ambiguous but suspicious threats or patterns

It's a threat only if detected with high confidence.

Retrieved Log Chunks:
{log_chunks}

Instructions:
1. Examine the logs for suspicious patterns and anomalies
2. Identify specific threat types if present
3. Assess the severity of each threat
4. Provide evidence from the logs
5. Suggest remediation actions

For each threat detected, respond in this exact JSON format:
{{
  "threats": [
    {{
      "type": "<brute_force|ddos|sql_injection|path_traversal|reconnaissance|bot|other>",
      "severity": "<critical|high|medium|low|info>",
      "confidence": <0.0-1.0>,
      "description": "<brief description of the threat>",
      "evidence": ["<specific log entries or patterns>"],
      "source_ips": ["<IP addresses involved>"],
      "target_paths": ["<targeted URLs/endpoints>"],
      "recommendation": "<suggested action to mitigate>"
    }}
  ],
  "summary": "<overall assessment of the log analysis>"
}}

If no threats are detected, respond:
{{
  "threats": [],
  "summary": "No security threats detected in the analyzed logs."
}}

Respond ONLY with valid JSON. Do not include any other text."""


def format_chunks_for_prompt(chunks: list) -> str:
    """
    Format retrieved log chunks for the LLM prompt.

    Args:
        chunks: List of chunk dictionaries from retriever

    Returns:
        Formatted string for prompt
    """
    if not chunks:
        return "No log entries retrieved."

    formatted_lines = []
    for i, chunk in enumerate(chunks, 1):
        metadata = chunk.get('metadata', {})
        document = chunk.get('document', '')

        # Add chunk header
        formatted_lines.append(f"\n--- Chunk {i} ---")
        formatted_lines.append(f"Time: {metadata.get('start_time', 'Unknown')} to {metadata.get('end_time', 'Unknown')}")
        formatted_lines.append(f"Log Count: {metadata.get('log_count', 0)}")
        formatted_lines.append(f"Unique IPs: {len(metadata.get('unique_ips', []))}")
        formatted_lines.append(f"Status Codes: {metadata.get('status_codes', {})}")
        formatted_lines.append(f"\nLogs:")
        formatted_lines.append(document)

    return "\n".join(formatted_lines)


def build_analysis_prompt(chunks: list) -> str:
    """
    Build the complete analysis prompt with chunks.

    Args:
        chunks: List of chunk dictionaries from retriever

    Returns:
        Complete prompt string
    """
    formatted_chunks = format_chunks_for_prompt(chunks)
    return THREAT_ANALYSIS_PROMPT.format(log_chunks=formatted_chunks)

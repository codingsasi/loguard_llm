"""
Threat detector using LLM analysis.
Orchestrates RAG retrieval and LLM inference.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from engine.llm.ollama_client import OllamaClient
from engine.indexer.retriever import LogRetriever, THREAT_QUERIES
from engine.analyzer.prompts import SYSTEM_PROMPT, build_analysis_prompt

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Main threat detection engine.
    Uses RAG + LLM to analyze logs for security threats.
    """

    def __init__(
        self,
        retriever: LogRetriever,
        llm_model: str = "mistral:7b-instruct",
        temperature: float = 0.1
    ):
        self.retriever = retriever
        self.llm_model = llm_model
        self.temperature = temperature
        self.llm_client = OllamaClient()

    def analyze(
        self,
        time_window_hours: Optional[int] = 1,
        max_logs: int = 100,
        semantic_queries: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze logs for threats using RAG + LLM.

        Args:
            time_window_hours: How far back to analyze (None = all time)
            max_logs: Maximum log chunks to retrieve
            semantic_queries: Custom queries (default: use THREAT_QUERIES)

        Returns:
            Dict with analysis results:
            {
                'threats': List of detected threats,
                'summary': Overall assessment,
                'chunks_analyzed': Number of chunks,
                'time_window': Time range analyzed,
                'model_used': LLM model name
            }
        """
        start_time = datetime.now()

        # Use default threat queries if none provided
        if semantic_queries is None:
            semantic_queries = THREAT_QUERIES

        try:
            # Step 1: Retrieve relevant log chunks using RAG
            if time_window_hours is None:
                logger.info("Retrieving all logs (no time window)...")
            else:
                logger.info(f"Retrieving logs from last {time_window_hours} hours...")

            chunks = self.retriever.retrieve_combined(
                semantic_queries=semantic_queries,
                time_window_hours=time_window_hours,
                max_results=max_logs
            )

            if not chunks:
                logger.warning("No log chunks retrieved for analysis")
                return {
                    'threats': [],
                    'summary': 'No logs available for analysis in the specified time window.',
                    'chunks_analyzed': 0,
                    'time_window': {'start': None, 'end': None},
                    'model_used': self.llm_model,
                    'duration_seconds': (datetime.now() - start_time).total_seconds()
                }

            logger.info(f"Retrieved {len(chunks)} log chunks for analysis")

            # Step 2: Build prompt with retrieved chunks
            prompt = build_analysis_prompt(chunks)

            # Estimate token count (rough approximation)
            estimated_tokens = len(prompt.split()) * 1.3
            logger.info(f"Estimated tokens: {int(estimated_tokens)}")

            # Step 3: Send to LLM for analysis
            logger.info(f"Analyzing with {self.llm_model}...")
            response = self.llm_client.generate(
                model=self.llm_model,
                prompt=prompt,
                system=SYSTEM_PROMPT,
                temperature=self.temperature
            )

            # Step 4: Parse LLM response
            llm_output = response.get('response', '')
            threats_data = self._parse_llm_response(llm_output)

            # Calculate time window
            time_window = self._calculate_time_window(chunks)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Analysis complete in {duration:.2f}s. Found {len(threats_data['threats'])} threats.")

            return {
                'threats': threats_data['threats'],
                'summary': threats_data['summary'],
                'chunks_analyzed': len(chunks),
                'chunks': chunks,  # Include chunks for evidence extraction
                'time_window': time_window,
                'model_used': self.llm_model,
                'duration_seconds': duration,
                'estimated_tokens': int(estimated_tokens)
            }

        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            return {
                'threats': [],
                'summary': f'Analysis failed: {str(e)}',
                'chunks_analyzed': 0,
                'time_window': {'start': None, 'end': None},
                'model_used': self.llm_model,
                'duration_seconds': (datetime.now() - start_time).total_seconds(),
                'error': str(e)
            }

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON response from LLM.

        Args:
            response: Raw LLM output

        Returns:
            Dict with 'threats' and 'summary' keys
        """
        try:
            # Try to extract JSON from response
            # Sometimes LLMs add extra text before/after JSON
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                data = json.loads(json_str)

                # Validate structure
                if 'threats' in data and 'summary' in data:
                    return data

            logger.warning(f"LLM response not in expected JSON format. Response preview: {response[:200]}")
            return {
                'threats': [],
                'summary': 'Unable to parse LLM response. Raw output: ' + response[:500]
            }

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            logger.debug(f"Failed JSON string: {response[:500]}")
            return {
                'threats': [],
                'summary': f'JSON parsing failed: {str(e)}. Check LLM model compatibility.'
            }

    def _calculate_time_window(self, chunks: List[Dict]) -> Dict[str, Optional[datetime]]:
        """Calculate the actual time window of analyzed chunks."""
        if not chunks:
            return {'start': None, 'end': None}

        timestamps = []
        for chunk in chunks:
            metadata = chunk.get('metadata', {})
            # Use ISO format strings which can be converted to datetime
            if 'start_time_iso' in metadata:
                try:
                    timestamps.append(datetime.fromisoformat(metadata['start_time_iso']))
                except (ValueError, TypeError):
                    pass
            if 'end_time_iso' in metadata:
                try:
                    timestamps.append(datetime.fromisoformat(metadata['end_time_iso']))
                except (ValueError, TypeError):
                    pass

        if timestamps:
            return {
                'start': min(timestamps),
                'end': max(timestamps)
            }

        return {'start': None, 'end': None}

    def analyze_with_context(
        self,
        raw_logs: List,
        rag_context: Dict[str, List[str]],
        config
    ) -> Dict[str, Any]:
        """
        Analyze logs with RAG-retrieved context (NEW real-time mode).

        Args:
            raw_logs: List of ParsedLogEntry objects from buffer (50 logs)
            rag_context: Retrieved context from RAG with keys:
                - 'individual_logs': Sentencified individual logs
                - 'grouped_summaries': Group summaries
                - 'analysis_summaries': Previous analysis summaries
            config: Django Config object

        Returns:
            Dict with:
                - 'threats': List of detected threats
                - 'summary': Analysis summary text (for embedding)
                - 'duration_seconds': Time taken
                - 'model_used': LLM model name
        """
        start_time = datetime.now()

        try:
            # Build LLM prompt with raw logs + RAG context
            prompt = self._build_prompt_with_context(raw_logs, rag_context)

            # Estimate token count
            estimated_tokens = len(prompt.split()) * 1.3
            logger.info(f"Analyzing {len(raw_logs)} raw logs with RAG context. Estimated tokens: {int(estimated_tokens)}")

            # Call LLM
            response = self.llm_client.generate(
                model=config.llm_model,
                prompt=prompt,
                system=SYSTEM_PROMPT,
                temperature=self.temperature
            )

            # Parse threats
            llm_output = response.get('response', '')
            threats_data = self._parse_llm_response(llm_output)

            # Generate analysis summary for embedding
            summary = self._generate_analysis_summary(raw_logs, threats_data['threats'])

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Analysis complete in {duration:.2f}s. Found {len(threats_data['threats'])} threats.")

            return {
                'threats': threats_data['threats'],
                'summary': summary,  # For embedding
                'llm_summary': threats_data['summary'],  # Original LLM summary
                'duration_seconds': duration,
                'model_used': config.llm_model,
                'estimated_tokens': int(estimated_tokens),
                'logs_analyzed': len(raw_logs)
            }

        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            return {
                'threats': [],
                'summary': f'Analysis failed: {str(e)}',
                'duration_seconds': (datetime.now() - start_time).total_seconds(),
                'model_used': config.llm_model,
                'error': str(e)
            }

    def _build_prompt_with_context(self, raw_logs: List, rag_context: Dict[str, List[str]]) -> str:
        """
        Build LLM prompt with raw logs and RAG-retrieved context.

        Args:
            raw_logs: List of ParsedLogEntry objects
            rag_context: Retrieved context from vector DB

        Returns:
            Complete prompt string
        """
        sections = []

        # Section 1: Recent individual logs (for pattern reference)
        if rag_context.get('individual_logs'):
            sections.append("## Recent Individual Logs (last 30 minutes)\n")
            sections.append("These are recent individual log entries for context:\n")
            sections.append("\n---\n".join(rag_context['individual_logs'][:10]))

        # Section 2: Recent grouped summaries (for trend reference)
        if rag_context.get('grouped_summaries'):
            sections.append("\n\n## Recent Group Summaries (last 30 minutes)\n")
            sections.append("These are summaries of recent grouped activity:\n")
            sections.append("\n---\n".join(rag_context['grouped_summaries'][:5]))

        # Section 3: Previous analysis summaries (for context continuity)
        if rag_context.get('analysis_summaries'):
            sections.append("\n\n## Previous Analysis Results\n")
            sections.append("Recent security analysis summaries:\n")
            sections.append("\n---\n".join(rag_context['analysis_summaries'][:3]))

        # Section 4: Current raw logs to analyze (main focus)
        sections.append(f"\n\n## Current Logs to Analyze ({len(raw_logs)} logs)\n")
        sections.append("Analyze these logs for security threats:\n")
        sections.append("\n".join([log.raw_line for log in raw_logs]))

        prompt = f"""
You are a cybersecurity analyst. Analyze the web server logs below for security threats.

{chr(10).join(sections)}

## CRITICAL ANALYSIS RULES:

**IP Address Analysis (MOST IMPORTANT):**
1. Count UNIQUE IP addresses in the logs
2. If you see MANY DIFFERENT IPs → This is NORMAL TRAFFIC, NOT an attack
3. If you see the SAME IP repeated MANY times (10+ requests) → Potential attack
4. ONLY flag as DDoS if ONE IP has excessive requests, not if many different IPs are present

**Examples:**
✅ ATTACK: IP 192.168.1.100 appears 50 times in 1 minute → DDoS
✅ ATTACK: IP 10.0.0.5 has 20 failed login attempts → Brute force
❌ NOT AN ATTACK: 15 different IPs each make 1 request → Normal traffic
❌ NOT AN ATTACK: Different users hitting /nodeviewcount, /analytics, /api/tracking → Legitimate app

**Legitimate Application Endpoints (DO NOT FLAG):**
- /nodeviewcount, /updateCounter, /analytics, /api/tracking, /api/metrics
- Multiple different IPs hitting these = normal application behavior

**Real Threats to Identify:**
- **Brute force attacks**: SAME IP with repeated 401/403 responses on /login, /admin
- **DDoS/DoS patterns**: ONE IP with 20+ requests in short time (not distributed IPs!)
- **SQL injection**: SQL patterns in URLs (UNION, SELECT, DROP, etc.)
- **Path traversal**: Directory traversal attempts (../, /etc/passwd, ../../../../)
- **Reconnaissance**: SAME IP probing /admin, /.git, /.env, /phpinfo.php
- **Suspicious bot activity**: SAME IP with bot-like patterns (rapid scanning)

For EACH real threat detected, provide:
- type: brute_force | ddos | sql_injection | path_traversal | reconnaissance | bot_activity
- severity: critical | high | medium | low
- confidence: 0.0-1.0 (how confident you are this is a REAL threat)
- description: Brief explanation with IP count evidence
- evidence: List of specific log line numbers or content
- recommendation: Specific action to take
- source_ips: List of ALL attacking IP addresses (must be SAME IP repeated, not different IPs)
- target_paths: List of URLs/paths targeted

**BEFORE FLAGGING A THREAT:**
1. Count how many unique IPs are involved
2. If >5 different IPs → Probably NOT an attack (normal traffic)
3. If 1-2 IPs repeated many times → Investigate further
4. Check if path is legitimate app endpoint (/nodeviewcount, /analytics)

Respond ONLY with valid JSON in this exact format:
{{
  "threats": [
    {{
      "type": "ddos",
      "severity": "critical",
      "confidence": 0.95,
      "description": "IP 192.168.1.100 sent 47 requests in 60 seconds to /api/submit",
      "evidence": ["Request 1 from 192.168.1.100", "Request 2 from 192.168.1.100", "...47 total from same IP"],
      "recommendation": "Block IP 192.168.1.100 immediately",
      "source_ips": ["192.168.1.100"],
      "target_paths": ["/api/submit"]
    }}
  ],
  "summary": "Overall assessment of log analysis"
}}

If NO threats detected (normal traffic), respond:
{{
  "threats": [],
  "summary": "Normal traffic patterns observed. Multiple different IPs accessing legitimate endpoints."
}}
"""
        return prompt

    def _generate_analysis_summary(self, logs: List, threats: List[Dict]) -> str:
        """
        Generate concise summary for embedding in analysis_summaries collection.

        This summary captures the essence of the analysis for cross-batch correlation.

        Args:
            logs: List of ParsedLogEntry objects analyzed
            threats: List of detected threats

        Returns:
            Multiline key-value summary text
        """
        from collections import Counter

        if not logs:
            return "Empty analysis batch"

        # Gather statistics
        ip_counts = Counter(log.client_ip for log in logs)
        status_counts = Counter(log.status_code for log in logs if log.status_code)
        path_counts = Counter(log.path for log in logs if log.path)

        lines = []
        lines.append(f"Analysis Summary")
        lines.append(f"Batch Size: {len(logs)} logs")
        lines.append(f"Time Range: {logs[0].timestamp.isoformat()} to {logs[-1].timestamp.isoformat()}")
        lines.append(f"Unique IPs: {len(ip_counts)}")

        # Top IPs
        top_ips = ip_counts.most_common(5)
        ip_str = ", ".join([f"{ip} ({count})" for ip, count in top_ips])
        lines.append(f"Top IPs: {ip_str}")

        # Status code distribution
        status_str = ", ".join([f"{status} ({count})" for status, count in status_counts.most_common(5)])
        lines.append(f"Status Codes: {status_str}")

        # Top paths
        top_paths = path_counts.most_common(5)
        path_str = ", ".join([f"{path} ({count})" for path, count in top_paths])
        lines.append(f"Top Paths: {path_str}")

        # Threats section
        if threats:
            lines.append(f"\nThreats Detected: {len(threats)}")

            # Group by type
            threat_types = Counter(t.get('type', 'unknown') for t in threats)
            type_str = ", ".join([f"{ttype} ({count})" for ttype, count in threat_types.items()])
            lines.append(f"Threat Types: {type_str}")

            # Extract suspicious IPs
            suspicious_ips = set()
            for threat in threats:
                if 'source_ips' in threat and threat['source_ips']:
                    suspicious_ips.update(threat['source_ips'])

            if suspicious_ips:
                lines.append(f"Suspicious IPs: {', '.join(list(suspicious_ips)[:10])}")

            # Brief threat descriptions
            for i, threat in enumerate(threats[:3], 1):
                desc = threat.get('description', '')[:100]
                lines.append(f"Threat {i}: {threat.get('type', 'unknown')} - {desc}")
        else:
            lines.append(f"\nThreats Detected: 0")
            lines.append("Assessment: Normal traffic patterns, no suspicious activity")

        return "\n".join(lines)

    def quick_scan(self) -> Dict[str, Any]:
        """
        Quick scan of recent logs (last 15 minutes).
        Useful for testing or frequent checks.
        """
        return self.analyze(time_window_hours=0.25, max_logs=50)

    def deep_scan(self) -> Dict[str, Any]:
        """
        Deep scan of logs (last 24 hours).
        More comprehensive but slower.
        """
        return self.analyze(time_window_hours=24, max_logs=200)

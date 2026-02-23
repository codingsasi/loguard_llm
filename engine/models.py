from django.db import models
from django.utils import timezone


class Config(models.Model):
    """
    System configuration for LoguardLLM.
    Single row configuration (singleton pattern).
    """
    # Analysis Settings
    analysis_interval_seconds = models.IntegerField(
        default=60,
        help_text="How often to run threat analysis (in seconds)"
    )
    max_logs_per_analysis = models.IntegerField(
        default=1000,
        help_text="Maximum number of log chunks to retrieve per analysis"
    )

    # Log Source
    log_file_path = models.CharField(
        max_length=500,
        default='/var/log/nginx/access.log',
        help_text="Path to the log file to monitor"
    )
    log_format = models.CharField(
        max_length=50,
        default='clf',
        choices=[
            ('clf', 'Common Log Format'),
            ('combined', 'NCSA Combined/Extended'),
        ],
        help_text="Log format type"
    )
    filter_static_assets = models.BooleanField(
        default=True,
        help_text="Exclude static assets (CSS, JS, images) from analysis"
    )
    excluded_extensions = models.TextField(
        default='.css,.js,.jpg,.jpeg,.png,.gif,.webp,.svg,.ico,.woff,.woff2,.ttf,.eot,.otf,.map,.json,.xml,.mp4,.webm,.mp3,.wav,.zip,.pdf,.doc,.docx',
        help_text="Comma-separated list of file extensions to exclude (e.g., .css,.js,.png)"
    )
    excluded_user_agents = models.TextField(
        default='googlebot,bingbot,msnbot,slurp,duckduckbot,baiduspider,yandexbot,facebookexternalhit,twitterbot,linkedinbot,whatsapp,telegrambot',
        blank=True,
        help_text="Comma-separated list of user agent substrings to exclude (case-insensitive, e.g., googlebot,bingbot). Leave empty to disable."
    )
    excluded_status_codes = models.TextField(
        default='',
        blank=True,
        help_text="Comma-separated list of status codes to exclude (e.g., 200,301,304 to focus on errors). Leave empty to include all."
    )
    excluded_methods = models.TextField(
        default='',
        blank=True,
        help_text="Comma-separated list of HTTP methods to exclude (e.g., HEAD,OPTIONS). Leave empty to include all methods."
    )
    included_methods_override = models.TextField(
        default='POST,PUT,DELETE,PATCH',
        blank=True,
        help_text="HTTP methods to ALWAYS include, even if their status code is excluded (e.g., POST to catch spam submissions with 200 OK). Overrides status code filtering."
    )
    excluded_paths = models.TextField(
        default='/nodeviewcount,/analytics,/api/tracking,/api/metrics,/heartbeat,/health,/ping',
        blank=True,
        help_text="Comma-separated list of path substrings to exclude (e.g., /nodeviewcount,/api/tracking). Matches if path CONTAINS any of these. Use for legitimate app endpoints."
    )

    # LLM Configuration
    llm_model = models.CharField(
        max_length=100,
        default='qwen2.5:14b-instruct',
        choices=[
            ('mistral:7b-instruct', 'Mistral 7B Instruct (8K context) - 4.4GB ✓'),
            ('qwen2.5:7b-instruct', 'Qwen 2.5 7B Instruct (32K context) - 4.7GB ✓'),
            ('llama3.1:8b', 'Llama 3.1 8B Base (128K context) - 4.9GB ✓'),
            ('qwen2.5:14b-instruct', 'Qwen 2.5 14B Instruct (32K context) - 9.0GB ⭐ ✓'),
            ('llama3.1:70b-instruct-q4_K_M', 'Llama 3.1 70B Instruct Q4 (128K context) - 42GB ✓'),
        ],
        help_text="Ollama model name for threat analysis (✓ = pulled and ready)"
    )

    # Two-Tier Embedding Configuration
    fast_embedding_model = models.CharField(
        max_length=100,
        default='mxbai-embed-large',
        choices=[
            ('mxbai-embed-large', 'Mxbai Embed Large (1024 dims, fast) - 669MB ⭐ ✓'),
            ('nomic-embed-text', 'Nomic Embed Text (768 dims) - 274MB ✓'),
            ('snowflake-arctic-embed:335m', 'Snowflake Arctic (1024 dims) - 669MB ✓'),
        ],
        help_text="Fast model for individual logs (✓ = pulled). Use mxbai for best speed."
    )
    context_embedding_model = models.CharField(
        max_length=100,
        default='bge-m3',
        choices=[
            ('bge-m3', 'BGE M3 (1024 dims, 8K context) - 1.2GB ⭐ ✓'),
            ('nomic-embed-text', 'Nomic Embed Text (768 dims, 2K context) - 274MB ✓'),
            ('snowflake-arctic-embed2:568m', 'Snowflake Arctic 2 (1024 dims) - 1.2GB ✓'),
        ],
        help_text="Context model for groups/summaries (✓ = pulled). Use bge-m3 for best quality."
    )

    # Buffer Configuration
    buffer_size = models.IntegerField(
        default=50,
        help_text="Number of logs to accumulate before analysis (hardcoded intelligent grouping)"
    )

    # RAG Configuration
    rag_time_window_minutes = models.IntegerField(
        default=30,
        choices=[
            (15, '15 minutes'),
            (30, '30 minutes'),
            (60, '1 hour'),
            (120, '2 hours'),
        ],
        help_text="Time window for RAG context retrieval"
    )

    # Vector DB Retention
    vectordb_retention_minutes = models.IntegerField(
        default=60,
        help_text="TTL for embeddings in ChromaDB (minutes). Old embeddings are auto-deleted."
    )

    # Analysis Behavior
    enabled = models.BooleanField(
        default=True,
        help_text="Enable/disable automatic analysis"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuration"
        verbose_name_plural = "Configuration"

    def __str__(self):
        return f"LoguardLLM Config (Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M')})"

    def save(self, *args, **kwargs):
        # Ensure only one config exists (singleton)
        if not self.pk and Config.objects.exists():
            raise ValueError("Only one Config instance allowed. Update the existing one.")
        return super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        """Get or create the singleton config instance."""
        config, created = cls.objects.get_or_create(pk=1)
        return config


class AnalysisRun(models.Model):
    """
    Record of each analysis run.
    Tracks performance and results.
    """
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    # Input
    logs_analyzed = models.IntegerField(
        help_text="Number of log chunks analyzed"
    )
    time_window_start = models.DateTimeField(
        null=True, blank=True,
        help_text="Start of log time window analyzed"
    )
    time_window_end = models.DateTimeField(
        null=True, blank=True,
        help_text="End of log time window analyzed"
    )

    # Output
    threats_found = models.IntegerField(
        default=0,
        help_text="Number of threats detected"
    )

    # Performance
    duration_seconds = models.FloatField(
        help_text="Time taken for analysis"
    )
    tokens_used = models.IntegerField(
        null=True, blank=True,
        help_text="Approximate tokens sent to LLM"
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=[
            ('success', 'Success'),
            ('error', 'Error'),
            ('partial', 'Partial Success'),
        ],
        default='success'
    )
    error_message = models.TextField(
        blank=True,
        help_text="Error details if status is error"
    )

    # Configuration snapshot
    llm_model_used = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Analysis Run"
        verbose_name_plural = "Analysis Runs"

    def __str__(self):
        return f"Analysis {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {self.threats_found} threats"


class ThreatAlert(models.Model):
    """
    Detected security threat.
    Linked to the analysis run that found it.
    """
    analysis_run = models.ForeignKey(
        AnalysisRun,
        on_delete=models.CASCADE,
        related_name='threats'
    )

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    # Threat Classification
    threat_type = models.CharField(
        max_length=50,
        choices=[
            ('brute_force', 'Brute Force Attack'),
            ('ddos', 'DDoS/DoS Attack'),
            ('sql_injection', 'SQL Injection'),
            ('path_traversal', 'Path Traversal'),
            ('reconnaissance', 'Reconnaissance/Scanning'),
            ('bot', 'Malicious Bot Activity'),
            ('other', 'Other Threat'),
        ],
        db_index=True
    )

    severity = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('info', 'Informational'),
        ],
        default='medium',
        db_index=True
    )

    confidence = models.FloatField(
        help_text="LLM confidence score (0.0-1.0)"
    )

    # Threat Details
    description = models.TextField(
        help_text="LLM-generated description of the threat"
    )

    evidence = models.JSONField(
        help_text="Log entries that triggered the alert"
    )

    recommendation = models.TextField(
        help_text="Suggested remediation action"
    )

    # Extracted Indicators
    source_ips = models.JSONField(
        default=list,
        help_text="List of source IP addresses involved"
    )
    target_paths = models.JSONField(
        default=list,
        help_text="List of targeted paths/endpoints"
    )

    # Alert Management
    acknowledged = models.BooleanField(
        default=False,
        help_text="Has this alert been reviewed?"
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.CharField(max_length=100, blank=True)

    notes = models.TextField(
        blank=True,
        help_text="Analyst notes"
    )

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Threat Alert"
        verbose_name_plural = "Threat Alerts"

    def __str__(self):
        return f"{self.get_threat_type_display()} - {self.get_severity_display()} ({self.timestamp.strftime('%Y-%m-%d %H:%M')})"

    def acknowledge(self, user=None):
        """Mark threat as acknowledged."""
        self.acknowledged = True
        self.acknowledged_at = timezone.now()
        if user:
            self.acknowledged_by = str(user)
        self.save()

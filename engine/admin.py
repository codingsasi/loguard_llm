from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
import json
from .models import Config, AnalysisRun, ThreatAlert


@admin.register(Config)
class ConfigAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'enabled', 'analysis_interval_seconds', 'llm_model', 'updated_at']
    fieldsets = (
        ('Analysis Settings', {
            'fields': ('enabled', 'analysis_interval_seconds', 'max_logs_per_analysis')
        }),
        ('Log Source', {
            'fields': ('log_file_path', 'log_format'),
            'description': 'Configure log source location and format.'
        }),
        ('Filtering Options', {
            'fields': (
                'filter_static_assets',
                'excluded_extensions',
                'excluded_paths',
                'excluded_user_agents',
                'excluded_status_codes',
                'excluded_methods',
                'included_methods_override'
            ),
            'description': 'Filter out noise: static assets (CSS/JS/images), legitimate app endpoints (/nodeviewcount, /analytics), '
                          'legitimate bots (Googlebot), status codes, and HTTP methods. '
                          'Use method override to always include certain methods (e.g., POST) even if their status code is excluded - '
                          'useful for catching spam submissions with 200 OK responses.'
        }),
        ('LLM Configuration', {
            'fields': ('llm_model',),
            'description': 'Select LLM model for threat detection analysis.'
        }),
        ('Embedding Models (Two-Tier System)', {
            'fields': ('fast_embedding_model', 'context_embedding_model'),
            'description': 'Fast model embeds individual logs immediately (mxbai recommended). Context model embeds groups and summaries with larger context (bge-m3 recommended).'
        }),
        ('Buffer & RAG Settings', {
            'fields': ('buffer_size', 'rag_time_window_minutes', 'vectordb_retention_minutes'),
            'description': 'Buffer accumulates logs until threshold (default 50). RAG retrieves recent context. Old embeddings are auto-deleted after retention period. Intelligent grouping by status codes & IPs is hardcoded.'
        }),
    )

    def has_add_permission(self, request):
        # Only allow one config instance
        try:
            return not Config.objects.exists()
        except Exception:
            # Table doesn't exist yet (migrations not run)
            return True

    def has_delete_permission(self, request, obj=None):
        # Don't allow deleting the config
        return False


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'status_badge', 'logs_analyzed', 'threats_found', 'duration_seconds', 'llm_model_used']
    list_filter = ['status', 'timestamp']
    search_fields = ['error_message']
    readonly_fields = ['timestamp', 'logs_analyzed', 'threats_found', 'duration_seconds',
                      'tokens_used', 'status', 'error_message', 'llm_model_used',
                      'time_window_start', 'time_window_end']

    fieldsets = (
        ('Run Information', {
            'fields': ('timestamp', 'status', 'llm_model_used')
        }),
        ('Input', {
            'fields': ('logs_analyzed', 'time_window_start', 'time_window_end')
        }),
        ('Results', {
            'fields': ('threats_found', 'duration_seconds', 'tokens_used')
        }),
        ('Errors', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'success': 'green',
            'error': 'red',
            'partial': 'orange',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def has_add_permission(self, request):
        # Analysis runs are created automatically
        return False


@admin.register(ThreatAlert)
class ThreatAlertAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'threat_type_badge', 'severity_badge', 'confidence',
                   'acknowledged_badge', 'analysis_run']
    list_filter = ['threat_type', 'severity', 'acknowledged', 'timestamp']
    search_fields = ['description', 'recommendation', 'source_ips', 'target_paths']
    readonly_fields = ['analysis_run', 'timestamp', 'threat_type', 'severity', 'confidence',
                      'description', 'evidence_display', 'recommendation', 'source_ips', 'target_paths']

    fieldsets = (
        ('Alert Information', {
            'fields': ('analysis_run', 'timestamp', 'threat_type', 'severity', 'confidence')
        }),
        ('Threat Details', {
            'fields': ('description', 'recommendation')
        }),
        ('Evidence', {
            'fields': ('evidence_display', 'source_ips', 'target_paths'),
        }),
        ('Alert Management', {
            'fields': ('acknowledged', 'acknowledged_at', 'acknowledged_by', 'notes')
        }),
    )

    actions = ['mark_acknowledged']

    def threat_type_badge(self, obj):
        return format_html(
            '<span style="background-color: #007bff; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            obj.get_threat_type_display()
        )
    threat_type_badge.short_description = 'Threat Type'

    def severity_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px; font-weight: bold;">{}</span>',
            colors.get(obj.severity, 'gray'),
            obj.get_severity_display().upper()
        )
    severity_badge.short_description = 'Severity'

    def acknowledged_badge(self, obj):
        if obj.acknowledged:
            return format_html(
                '<span style="color: green;">✓ Acknowledged</span>'
            )
        return format_html(
            '<span style="color: orange;">⚠ Pending</span>'
        )
    acknowledged_badge.short_description = 'Status'

    def evidence_display(self, obj):
        """Format evidence field for better display."""
        if not obj.evidence:
            return "No evidence available"

        html = []

        # Handle dict format (new format with LLM evidence + sample logs)
        if isinstance(obj.evidence, dict):
            # LLM Evidence
            llm_evidence = obj.evidence.get('llm_evidence', [])
            if llm_evidence:
                html.append('<div style="margin-bottom: 15px;">')
                html.append('<strong style="color: #007bff;">LLM Analysis:</strong>')
                html.append('<ul style="margin: 5px 0;">')
                for item in llm_evidence:
                    html.append(f'<li>{item}</li>')
                html.append('</ul>')
                html.append('</div>')

            # Sample Logs
            sample_logs = obj.evidence.get('sample_logs', [])
            if sample_logs:
                html.append('<div>')
                html.append(f'<strong style="color: #28a745;">Sample Logs ({len(sample_logs)}):</strong>')

                # Summary table
                html.append('<table style="width: 100%; margin-top: 10px; border-collapse: collapse; font-family: monospace; font-size: 12px;">')
                html.append('<thead><tr style="background-color: #f8f9fa;">')
                html.append('<th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Time</th>')
                html.append('<th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">IP</th>')
                html.append('<th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Method</th>')
                html.append('<th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Path</th>')
                html.append('<th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Status</th>')
                html.append('</tr></thead><tbody>')

                for log in sample_logs:
                    status_color = '#28a745' if str(log.get('status', '')).startswith('2') else '#dc3545'
                    html.append('<tr>')
                    html.append(f'<td style="border: 1px solid #dee2e6; padding: 8px;">{log.get("timestamp", "")}</td>')
                    html.append(f'<td style="border: 1px solid #dee2e6; padding: 8px;">{log.get("ip", "")}</td>')
                    html.append(f'<td style="border: 1px solid #dee2e6; padding: 8px;">{log.get("method", "")}</td>')
                    html.append(f'<td style="border: 1px solid #dee2e6; padding: 8px; word-break: break-all;">{log.get("path", "")}</td>')
                    html.append(f'<td style="border: 1px solid #dee2e6; padding: 8px; color: {status_color}; font-weight: bold;">{log.get("status", "")}</td>')
                    html.append('</tr>')

                html.append('</tbody></table>')

                # Raw log lines (collapsible)
                html.append('<details style="margin-top: 15px;">')
                html.append('<summary style="cursor: pointer; font-weight: bold; color: #6c757d; margin-bottom: 5px;">📜 View Raw Log Lines</summary>')
                html.append('<div style="background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 5px;">')
                for i, log in enumerate(sample_logs, 1):
                    raw_line = log.get('raw_line', '')
                    if raw_line:
                        html.append(f'<div style="font-family: monospace; font-size: 11px; padding: 5px; margin-bottom: 5px; background-color: white; border-left: 3px solid #007bff;">')
                        html.append(f'<strong>{i}.</strong> {raw_line}')
                        html.append('</div>')
                    else:
                        # Fallback: reconstruct from fields if no raw_line
                        reconstructed = f'{log.get("ip", "N/A")} - - [{log.get("timestamp", "N/A")}] "{log.get("method", "N/A")} {log.get("path", "N/A")} HTTP/1.1" {log.get("status", "N/A")}'
                        html.append(f'<div style="font-family: monospace; font-size: 11px; padding: 5px; margin-bottom: 5px; background-color: white; border-left: 3px solid #ffc107;">')
                        html.append(f'<strong>{i}.</strong> {reconstructed}')
                        html.append('</div>')
                html.append('</div>')
                html.append('</details>')

                html.append('</div>')

        # Handle list format (old format - just LLM evidence)
        elif isinstance(obj.evidence, list):
            html.append('<div>')
            html.append('<strong>Evidence:</strong>')
            html.append('<ul style="margin: 5px 0;">')
            for item in obj.evidence:
                html.append(f'<li>{item}</li>')
            html.append('</ul>')
            html.append('</div>')

        return mark_safe(''.join(html)) if html else "No evidence available"

    evidence_display.short_description = 'Evidence & Sample Logs'

    def mark_acknowledged(self, request, queryset):
        for threat in queryset:
            threat.acknowledge(user=request.user)
        self.message_user(request, f"{queryset.count()} threat(s) marked as acknowledged.")
    mark_acknowledged.short_description = "Mark selected threats as acknowledged"

    def has_add_permission(self, request):
        # Threats are created automatically
        return False

"""
Django management command to run the LoguardLLM analyzer.
Real-time mode only: watches log file, buffers, groups, embeds, and analyzes with LLM + RAG.
Usage: python manage.py run_analyzer
"""
import time
import logging
from django.core.management.base import BaseCommand
from rich.console import Console
from rich.panel import Panel

from engine.models import Config, AnalysisRun, ThreatAlert
from engine.collector.watcher import LogCollector
from engine.collector.parsers.clf import CLFParser

logger = logging.getLogger(__name__)
console = Console()


class Command(BaseCommand):
    help = 'Run LoguardLLM threat analyzer (real-time monitoring only)'

    def add_arguments(self, parser):
        pass  # Real-time only; no mode flags

    def handle(self, *args, **options):
        """Main command handler."""
        console.print(Panel.fit(
            "[bold cyan]LoguardLLM Threat Analyzer[/bold cyan]\n"
            "RAG-Powered Log Security Analysis",
            border_style="cyan"
        ))

        # Load configuration
        config = Config.get_config()

        # Display configuration
        console.print("\n[bold]Configuration:[/bold]")
        console.print(f"  Log file: [cyan]{config.log_file_path}[/cyan]")
        console.print(f"  Log format: [cyan]{config.get_log_format_display()}[/cyan]")

        # Display filtering configuration
        filters_active = []
        if config.filter_static_assets:
            ext_count = len(config.excluded_extensions.split(','))
            filters_active.append(f"{ext_count} extensions")
        if config.excluded_user_agents:
            ua_list = [ua.strip() for ua in config.excluded_user_agents.split(',') if ua.strip()]
            if ua_list:
                filters_active.append(f"{len(ua_list)} user agents")
                console.print(f"  Excluded user agents: [dim]{', '.join(ua_list[:3])}{', ...' if len(ua_list) > 3 else ''}[/dim]")
        if config.excluded_status_codes:
            sc_list = [sc.strip() for sc in config.excluded_status_codes.split(',') if sc.strip()]
            if sc_list:
                filters_active.append(f"{len(sc_list)} status codes")
                console.print(f"  Excluded status codes: [dim]{', '.join(sc_list)}[/dim]")
        if config.excluded_methods:
            method_list = [m.strip().upper() for m in config.excluded_methods.split(',') if m.strip()]
            if method_list:
                filters_active.append(f"{len(method_list)} methods")
                console.print(f"  Excluded methods: [dim]{', '.join(method_list)}[/dim]")

        # Show method override configuration
        if config.included_methods_override:
            override_list = [m.strip().upper() for m in config.included_methods_override.split(',') if m.strip()]
            if override_list:
                console.print(f"  Always include methods: [green]{', '.join(override_list)}[/green] [dim](overrides status code filter)[/dim]")

        if filters_active:
            console.print(f"  Active filters: [cyan]{' + '.join(filters_active)}[/cyan]")
        else:
            console.print(f"  Active filters: [yellow]None (analyzing all traffic)[/yellow]")
        console.print(f"  LLM model: [cyan]{config.llm_model}[/cyan]")
        console.print(f"  Fast embedding: [cyan]{config.fast_embedding_model}[/cyan] (individual logs)")
        console.print(f"  Context embedding: [cyan]{config.context_embedding_model}[/cyan] (groups/summaries)")
        console.print(f"  Buffer size: [cyan]{config.buffer_size} logs[/cyan] (intelligent grouping)")
        console.print(f"  RAG window: [cyan]{config.rag_time_window_minutes} min[/cyan]")
        console.print(f"  VectorDB retention: [cyan]{config.vectordb_retention_minutes} min[/cyan]")
        console.print(f"  Status: [{'green' if config.enabled else 'yellow'}]{'Enabled' if config.enabled else 'Disabled'}[/{'green' if config.enabled else 'yellow'}]")

        if not config.enabled:
            console.print("\n[yellow]⚠ Analysis is disabled in configuration[/yellow]")
            return

        # Initialize components
        console.print("\n[bold]Initializing components...[/bold]")

        try:
            # Parser
            parser = CLFParser()
            console.print("✓ Log parser initialized")

            # Collector
            collector = LogCollector(
                config.log_file_path,
                parser,
                filter_static=config.filter_static_assets,
                excluded_extensions=config.excluded_extensions if config.filter_static_assets else None,
                excluded_user_agents=config.excluded_user_agents,
                excluded_status_codes=config.excluded_status_codes,
                excluded_methods=config.excluded_methods,
                included_methods_override=config.included_methods_override,
                excluded_paths=config.excluded_paths
            )

            # Build filter status message
            filter_parts = []
            if config.filter_static_assets:
                ext_count = len(config.excluded_extensions.split(','))
                filter_parts.append(f"{ext_count} extensions")
            if config.excluded_user_agents:
                ua_count = len([ua for ua in config.excluded_user_agents.split(',') if ua.strip()])
                filter_parts.append(f"{ua_count} user agents")
            if config.excluded_status_codes:
                sc_count = len([sc for sc in config.excluded_status_codes.split(',') if sc.strip()])
                filter_parts.append(f"{sc_count} status codes")
            if config.excluded_methods:
                method_count = len([m for m in config.excluded_methods.split(',') if m.strip()])
                filter_parts.append(f"{method_count} methods")

            filter_status = f"filtering {', '.join(filter_parts)}" if filter_parts else "no filtering"
            if config.included_methods_override:
                override_methods = [m.strip() for m in config.included_methods_override.split(',') if m.strip()]
                filter_status += f" [always include: {', '.join(override_methods)}]"
            console.print(f"✓ Log collector watching: {config.log_file_path} ({filter_status})")

        except Exception as e:
            console.print(f"[bold red]✗ Initialization failed: {e}[/bold red]")
            logger.error(f"Initialization error: {e}", exc_info=True)
            return

        # Real-time mode only
        self._run_realtime_mode(collector, config)

    def _run_realtime_mode(self, collector, config):
        """
        NEW real-time processing mode with two-tier embeddings.

        This mode:
        1. Watches log file continuously (tail -f behavior)
        2. Immediately embeds each log with fast model (mxbai)
        3. Buffers logs until reaching 50
        4. Groups and embeds summaries with context model (bge-m3)
        5. Analyzes with LLM + RAG context
        6. Embeds analysis summary for next iteration
        """
        from engine.indexer.buffer import LogBuffer
        from engine.indexer.sentencify import sentencify_log
        from engine.indexer.embedder import FastLogEmbedder, ContextEmbedder
        from engine.indexer.indexer import LogIndexer
        from engine.indexer.retriever import LogRetriever
        from engine.analyzer.detector import ThreatDetector
        from engine.indexer.cleanup import VectorDBCleaner

        console.print("\n[bold cyan]Starting real-time monitoring mode...[/bold cyan]")
        console.print("[dim]Two-tier embeddings: mxbai (individual) + bge-m3 (groups/summaries)[/dim]")
        console.print(f"[dim]Buffer size: {config.buffer_size} logs | RAG window: {config.rag_time_window_minutes} min | Retention: {config.vectordb_retention_minutes} min[/dim]")
        console.print("Press Ctrl+C to stop\n")

        try:
            # Initialize real-time components
            console.print("[bold]Initializing real-time components...[/bold]")

            buffer = LogBuffer(max_size=config.buffer_size)
            console.print(f"✓ Buffer initialized (max: {config.buffer_size} logs)")

            fast_embedder = FastLogEmbedder(model=config.fast_embedding_model)
            console.print(f"✓ Fast embedder initialized ({config.fast_embedding_model})")

            context_embedder = ContextEmbedder(model=config.context_embedding_model)
            console.print(f"✓ Context embedder initialized ({config.context_embedding_model})")

            indexer = LogIndexer()
            console.print(f"✓ Multi-collection indexer initialized")

            # Show collection counts
            counts = indexer.count_all()
            console.print(f"  [dim]Collections: individual={counts['individual_logs']}, groups={counts['log_chunks']}, summaries={counts['analysis_summaries']}[/dim]")

            retriever = LogRetriever(indexer, context_embedder)
            console.print("✓ RAG retriever initialized")

            detector = ThreatDetector(retriever, llm_model=config.llm_model)
            console.print(f"✓ Threat detector initialized ({config.llm_model})")

            # Start TTL cleanup thread
            cleaner = VectorDBCleaner(
                indexer=indexer,
                retention_seconds=config.vectordb_retention_minutes * 60
            )
            cleaner.start()
            console.print(f"✓ Cleanup thread started (TTL: {config.vectordb_retention_minutes} min)")

            # Start file watching
            collector.start()
            console.print(f"[green]✓ Watching log file: {config.log_file_path}[/green]\n")

            logs_processed = 0
            batches_analyzed = 0

            try:
                while True:
                    # Get new log entries (non-blocking)
                    new_logs = collector.collect_new_entries()

                    for log in new_logs:
                        # 1. Sentencify log
                        sentencified = sentencify_log(log)

                        # 2. Embed with fast model
                        embedding = fast_embedder.embed(sentencified)

                        # 3. Index individual log immediately
                        log_id = f"log_{log.line_number}_{int(time.time() * 1000)}"
                        indexer.index_individual_log(
                            log_id=log_id,
                            embedding=embedding,
                            sentencified_text=sentencified,
                            metadata={
                                'line_number': log.line_number,
                                'client_ip': log.client_ip,
                                'status_code': log.status_code,
                                'path': log.path,
                                'method': log.method
                            }
                        )

                        logs_processed += 1

                        # 4. Add to buffer
                        buffer.add_log(log)

                        # 5. Check if buffer ready for analysis
                        if buffer.should_flush():
                            batches_analyzed += 1
                            console.print(f"\n[bold yellow]Buffer full ({buffer.current_size()} logs) - starting batch analysis #{batches_analyzed}...[/bold yellow]")
                            self._process_buffer(buffer, context_embedder, indexer, retriever, detector, config)
                            console.print(f"[dim]Total processed: {logs_processed} logs, {batches_analyzed} batches[/dim]\n")

                    # Sleep briefly to avoid busy loop
                    time.sleep(1)

            except KeyboardInterrupt:
                console.print("\n[yellow]Stopping real-time analyzer...[/yellow]")
            finally:
                cleaner.stop()
                collector.stop()
                console.print(f"[green]✓ Analyzer stopped. Processed {logs_processed} logs in {batches_analyzed} batches.[/green]")

        except Exception as e:
            console.print(f"[bold red]✗ Real-time mode failed: {e}[/bold red]")
            logger.error(f"Real-time error: {e}", exc_info=True)

    def _process_buffer(self, buffer, context_embedder, indexer, retriever, detector, config):
        """
        Process buffered logs when threshold reached.

        This performs:
        1. Flush buffer and get raw logs + grouped summaries
        2. Embed grouped summaries with large context model
        3. Index grouped summaries
        4. Retrieve RAG context (individual logs + groups + previous summaries)
        5. Analyze with LLM
        6. Embed and index analysis summary
        7. Save threats to database
        """
        try:
            # 1. Flush buffer
            raw_logs, grouped_summaries = buffer.flush()

            if not raw_logs:
                console.print("[dim]Buffer empty, skipping analysis[/dim]")
                return

            console.print(f"[dim]  Flushed {len(raw_logs)} logs, created {len(grouped_summaries)} group summaries[/dim]")

            # 2. Embed grouped summaries with large model
            summary_embeddings = {}
            if grouped_summaries:
                for group_id, summary_text in grouped_summaries.items():
                    summary_embeddings[group_id] = context_embedder.embed(summary_text)
                console.print(f"[dim]  Generated {len(summary_embeddings)} group embeddings[/dim]")

            # 3. Index grouped summaries
            batch_id = f"batch_{int(time.time())}"
            if grouped_summaries:
                indexer.index_group_summaries(grouped_summaries, summary_embeddings, batch_id)

            # 4. Retrieve RAG context
            semantic_queries = [
                "failed authentication brute force",
                "SQL injection attack",
                "high volume requests DDoS",
                "scanning reconnaissance probing"
            ]
            rag_context = retriever.retrieve_recent_context(
                semantic_queries=semantic_queries,
                time_window_minutes=config.rag_time_window_minutes,
                max_individual=20,
                max_groups=10
            )
            console.print(f"[dim]  Retrieved RAG context: {len(rag_context['individual_logs'])} individual, "
                         f"{len(rag_context['grouped_summaries'])} groups, {len(rag_context['analysis_summaries'])} summaries[/dim]")

            # 5. Analyze with LLM
            console.print("[cyan]  Running LLM analysis...[/cyan]")
            results = detector.analyze_with_context(
                raw_logs=raw_logs,
                rag_context=rag_context,
                config=config
            )

            # 6. Embed and index analysis summary
            if 'summary' in results:
                summary_embedding = context_embedder.embed(results['summary'])
                indexer.index_analysis_summary(
                    summary_id=f"analysis_{batch_id}",
                    embedding=summary_embedding,
                    summary_text=results['summary'],
                    metadata={
                        'threats_found': len(results['threats']),
                        'batch_id': batch_id
                    }
                )

            # 7. Save threats to database
            if results['threats']:
                analysis_run = AnalysisRun.objects.create(
                    logs_analyzed=len(raw_logs),
                    threats_found=len(results['threats']),
                    duration_seconds=results['duration_seconds'],
                    tokens_used=results.get('estimated_tokens', 0),
                    status='success',
                    llm_model_used=results['model_used'],
                )

                for threat in results['threats']:
                    # Build evidence with actual log samples matching the threat
                    evidence = self._build_realtime_evidence(threat, raw_logs)

                    ThreatAlert.objects.create(
                        analysis_run=analysis_run,
                        threat_type=threat.get('type', 'other'),
                        severity=threat.get('severity', 'medium'),
                        confidence=threat.get('confidence', 0.5),
                        description=threat.get('description', ''),
                        evidence=evidence,
                        recommendation=threat.get('recommendation', ''),
                        source_ips=threat.get('source_ips', []),
                        target_paths=threat.get('target_paths', []),
                    )

                console.print(f"[bold red]  ⚠ {len(results['threats'])} threats detected![/bold red]")

                # Show brief threat summary
                for threat in results['threats']:
                    severity_icon = {'critical': '🔴', 'high': '🔴', 'medium': '🟡', 'low': '🔵'}.get(threat['severity'], '⚪')
                    console.print(f"    {severity_icon} {threat['type']}: {threat['description'][:60]}...")
            else:
                console.print("[green]  ✓ No threats detected[/green]")

        except Exception as e:
            console.print(f"[red]  Error processing buffer: {e}[/red]")
            logger.error(f"Buffer processing error: {e}", exc_info=True)

    def _build_realtime_evidence(self, threat: dict, raw_logs: list) -> dict:
        """
        Build evidence dictionary for real-time mode with actual log samples.

        Args:
            threat: Threat dictionary from LLM
            raw_logs: List of ParsedLogEntry objects from the buffer

        Returns:
            Dict with llm_evidence and sample_logs
        """
        evidence = {
            'llm_evidence': threat.get('evidence', []),
            'sample_logs': []
        }

        # Extract source IPs and target paths for filtering
        source_ips = set(threat.get('source_ips', []))
        target_paths = set(threat.get('target_paths', []))

        # Find relevant logs
        max_samples = 15  # Show up to 15 sample logs per threat
        sample_count = 0

        for log in raw_logs:
            if sample_count >= max_samples:
                break

            # Check if log is relevant to this threat
            is_relevant = False

            # Match by IP
            if source_ips and log.client_ip in source_ips:
                is_relevant = True

            # Match by path
            if target_paths:
                log_path = log.path or ''
                for target_path in target_paths:
                    if target_path in log_path:
                        is_relevant = True
                        break

            # If no IPs or paths specified, include all logs
            if not source_ips and not target_paths:
                is_relevant = True

            if is_relevant:
                # Format log entry for display - include full raw line
                evidence['sample_logs'].append({
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'ip': log.client_ip,
                    'method': log.method,
                    'path': log.path,
                    'status': log.status_code,
                    'user_agent': (log.user_agent or '')[:100],  # Truncate long UAs
                    'referer': log.referer or '',
                    'raw_line': log.raw_line  # Include full raw log line
                })
                sample_count += 1

        return evidence

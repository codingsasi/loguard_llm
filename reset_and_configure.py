#!/usr/bin/env python
"""
Reset LoguardLLM data only (no config changes).

This script:
1. Deletes all threat alerts and analysis runs (unless --chroma-only)
2. Clears all ChromaDB embeddings (individual_logs, log_chunks, analysis_summaries)

Use --chroma-only to clear only ChromaDB (keeps threats and analysis runs).
Use --force to delete the ChromaDB data directory and reinitialize (if normal clear
leaves stale data, e.g. old /nodeviewcount in RAG context).

Configuration (Config) is left unchanged. Edit filters/LLM in Django admin if needed.
"""
import argparse
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'loguard.settings')
django.setup()

from engine.models import ThreatAlert, AnalysisRun
from engine.indexer.indexer import LogIndexer

def main():
    p = argparse.ArgumentParser(description="Reset LoguardLLM data (runs, threats, ChromaDB). Config unchanged.")
    p.add_argument("--chroma-only", action="store_true", help="Clear only ChromaDB; do not delete threats or analysis runs")
    p.add_argument("--force", action="store_true", help="Delete ChromaDB data directory and reinit (nuclear clear)")
    args = p.parse_args()

    print("\n" + "="*60)
    if args.chroma_only:
        print("CHROMADB ONLY CLEAR")
    else:
        print("LOGUARDLLM DATA RESET (runs, threats, ChromaDB)")
    print("="*60)

    if not args.chroma_only:
        threat_count = ThreatAlert.objects.count()
        run_count = AnalysisRun.objects.count()
        ThreatAlert.objects.all().delete()
        AnalysisRun.objects.all().delete()
        print(f"\n✓ Deleted {threat_count} threat alerts and {run_count} analysis runs")
    else:
        print("\n(Skipping threats and analysis runs; clearing ChromaDB only)")

    indexer = LogIndexer()
    if args.force:
        wiped = indexer.clear_all_force()
        if wiped:
            print("✓ Cleared ChromaDB (force: wiped data directory and reinitialized)")
        else:
            print("✓ Cleared ChromaDB collections (directory was in use, could not wipe files)")
            print("  To fully wipe old RAG data: stop the analyzer, then run:")
            print("    docker exec loguard_app rm -rf /app/chroma_data")
            print("  Then start the analyzer again.")
    else:
        indexer.clear_all()
        print("✓ Cleared ChromaDB (individual_logs, log_chunks, analysis_summaries)")

    print("\n✓ Config was NOT changed. Edit settings in Django admin if needed.")
    print("="*60)
    print("\nRun the analyzer: docker exec -it loguard_app python manage.py run_analyzer")
    if not args.force:
        print("If RAG still shows old paths, run: python reset_and_configure.py --force")
    print()

if __name__ == "__main__":
    main()

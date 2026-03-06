"""
Inspect ChromaDB contents: counts and sample documents.

Use this to verify what is stored (e.g. after clear, or to see if old
/nodeviewcount or /analytics content is still in RAG context).
"""
from django.core.management.base import BaseCommand
from engine.indexer.indexer import LogIndexer


# Substrings that should NOT appear if excluded_paths are applied (noise check)
EXCLUDED_PATH_HINTS = ('nodeviewcount', 'updateCounter', 'analytics', 'api/tracking', 'api/metrics')


class Command(BaseCommand):
    help = "Inspect ChromaDB: show counts and sample documents from each collection."

    def add_arguments(self, parser):
        parser.add_argument(
            '--samples', type=int, default=5,
            help='Max sample documents to print per collection (default: 5)',
        )
        parser.add_argument(
            '--check-excluded', action='store_true',
            help='Flag samples that contain common excluded path strings',
        )

    def handle(self, *args, **options):
        samples = max(0, options['samples'])
        check_excluded = options['check_excluded']

        # Ensure telemetry is disabled before any Chroma use (inspect runs in its own process)
        import os
        os.environ["ANONYMIZED_TELEMETRY"] = "False"

        indexer = LogIndexer()
        counts = indexer.count_all()

        self.stdout.write("")
        self.stdout.write("=" * 60)
        self.stdout.write("CHROMADB CONTENTS")
        self.stdout.write("=" * 60)
        self.stdout.write("")
        self.stdout.write(f"  individual_logs:   {counts['individual_logs']} documents")
        self.stdout.write(f"  log_chunks:         {counts['log_chunks']} documents (group summaries)")
        self.stdout.write(f"  analysis_summaries: {counts['analysis_summaries']} documents")
        self.stdout.write(f"  log_chunks_legacy:  {counts['legacy']} documents")
        self.stdout.write("")

        for coll_name, attr in [
            ("individual_logs", "individual_logs"),
            ("log_chunks", "log_chunks"),
            ("analysis_summaries", "analysis_summaries"),
        ]:
            coll = getattr(indexer, attr, None)
            if not coll:
                continue
            n = counts.get(coll_name, coll.count())
            self.stdout.write(f"--- {coll_name} (total: {n}) ---")
            if n == 0:
                self.stdout.write("  (empty)")
                self.stdout.write("")
                continue
            try:
                result = coll.get(limit=min(samples, n), include=["documents", "metadatas"])
                # Chroma returns lists; for get() without ids, documents is a flat list
                docs = result.get("documents") if result.get("documents") is not None else []
                if docs and isinstance(docs[0], list):
                    docs = docs[0]
                metas = result.get("metadatas") or []
                if metas and isinstance(metas[0], list):
                    metas = metas[0]
                for i, (doc, meta) in enumerate(zip(docs, metas)):
                    preview = (doc or "")[:400]
                    if len(doc or "") > 400:
                        preview += "..."
                    self.stdout.write(f"  [{i+1}] {preview}")
                    if meta:
                        self.stdout.write(f"      metadata: {meta}")
                    if check_excluded and doc:
                        lower = doc.lower()
                        found = [h for h in EXCLUDED_PATH_HINTS if h.lower() in lower]
                        if found:
                            self.stdout.write(self.style.WARNING(f"      ^ contains excluded-path hints: {found}"))
                    self.stdout.write("")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
            self.stdout.write("")

        self.stdout.write("=" * 60)
        if any(counts[k] > 0 for k in ("individual_logs", "log_chunks", "analysis_summaries")):
            self.stdout.write("To clear all ChromaDB data and start fresh, run:")
            self.stdout.write("  python reset_and_configure.py")
            if check_excluded and (counts.get("analysis_summaries") or 0) > 0:
                self.stdout.write("")
                self.stdout.write(self.style.WARNING(
                    "If analysis_summaries above contain excluded-path hints (e.g. nodeviewcount), "
                    "RAG will keep feeding that text to the LLM. Use a force clear to remove all stored data:"
                ))
                self.stdout.write("  python reset_and_configure.py --force")
            self.stdout.write("  (or from project root: python loguard_llm/reset_and_configure.py)")
        self.stdout.write("=" * 60)
        self.stdout.write("")

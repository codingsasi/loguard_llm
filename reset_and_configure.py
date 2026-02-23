#!/usr/bin/env python
"""
Reset LoguardLLM and configure with improved filters and LLM prompt.

This script:
1. Clears old threat alerts and analysis runs
2. Clears old embeddings
3. Configures smart filtering rules
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'loguard.settings')
django.setup()

from engine.models import ThreatAlert, AnalysisRun, Config
from engine.indexer.indexer import LogIndexer

print("\n" + "="*80)
print("LOGUARDLLM RESET & CONFIGURATION")
print("="*80)

# Step 1: Clear old data
print("\n[1/3] Clearing old data...")
threat_count = ThreatAlert.objects.count()
run_count = AnalysisRun.objects.count()
ThreatAlert.objects.all().delete()
AnalysisRun.objects.all().delete()
print(f"  ✓ Deleted {threat_count} threats and {run_count} analysis runs")

# Clear embeddings
indexer = LogIndexer()
indexer.clear_all()
print("  ✓ Cleared all embeddings")

# Step 2: Configure filters
print("\n[2/3] Configuring smart filters...")
config = Config.objects.first()

# Exclude successful status codes (focus on errors)
config.excluded_status_codes = '200,201,301,302,304'
print("  ✓ Excluding status codes: 200, 201, 301, 302, 304 (successful responses)")

# Exclude legitimate application endpoints
config.excluded_paths = '/nodeviewcount,/updateCounter,/analytics,/api/tracking,/api/metrics,/heartbeat,/health,/ping'
print("  ✓ Excluding legitimate app paths: /nodeviewcount, /analytics, /api/tracking, etc.")

# Keep POST/PUT/DELETE/PATCH override (but paths are filtered first)
config.included_methods_override = 'POST,PUT,DELETE,PATCH'
print("  ✓ Always including methods: POST, PUT, DELETE, PATCH (for spam/abuse detection)")
print("    → But legitimate app endpoints (like /nodeviewcount) are filtered BEFORE this")

# Keep user agent filtering
print("  ✓ Keeping user agent filtering (bots excluded)")

# Don't exclude any methods by default
config.excluded_methods = ''

config.save()

# Step 3: Summary
print("\n[3/3] Configuration summary:")
print("="*80)
print("\n✅ FILTERING RULES CONFIGURED:")
print("  1. Static assets excluded (CSS, JS, images)")
print("  2. Legitimate app endpoints excluded (/nodeviewcount, /analytics)")
print("  3. Legitimate bots excluded (Googlebot, Bingbot, etc.)")
print("  4. Successful status codes excluded (200, 301, 302, 304)")
print("  5. BUT: POST/PUT/DELETE/PATCH to non-excluded paths always analyzed")
print()
print("✅ LLM PROMPT IMPROVED:")
print("  • Now counts unique IPs before flagging attacks")
print("  • Understands that different IPs = normal traffic")
print("  • Only flags as attack if SAME IP repeats many times")
print("  • Won't flag legitimate app endpoints")
print()
print("="*80)
print("\n🚀 READY TO ANALYZE!")
print("="*80)
print()
print("Start the analyzer:")
print("  docker exec -it loguard_app python manage.py run_analyzer --realtime")
print()
print("View threats:")
print("  docker exec loguard_app python view_threats.py")
print()
print("What to expect:")
print("  ✅ Legitimate traffic (different IPs to /nodeviewcount) → IGNORED")
print("  ✅ Spam submissions (POST to /contact, /submit) → ANALYZED")
print("  ✅ Brute force (same IP, many 401s) → FLAGGED")
print("  ✅ DDoS (same IP, 20+ requests) → FLAGGED")
print("  ❌ False positives on normal traffic → SHOULD BE GONE")
print()

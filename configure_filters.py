#!/usr/bin/env python
"""
Configure LoguardLLM filters to focus on security threats.

Recommended configuration:
- Exclude 200 OK status codes (successful requests)
- Exclude 301/302 redirects
- Exclude 304 Not Modified
- BUT: Always include POST/PUT/DELETE/PATCH requests (even with 200 OK) to catch spam/abuse
- Exclude legitimate bots (Googlebot, Bingbot, etc.)
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'loguard.settings')
django.setup()

from engine.models import Config

config = Config.objects.first()

print("\n" + "="*80)
print("CURRENT FILTER CONFIGURATION")
print("="*80)
print(f"Excluded status codes: {config.excluded_status_codes or '(none)'}")
print(f"Excluded methods: {config.excluded_methods or '(none)'}")
print(f"Included methods override: {config.included_methods_override or '(none)'}")
print(f"Excluded user agents: {config.excluded_user_agents[:100]}..." if len(config.excluded_user_agents) > 100 else f"Excluded user agents: {config.excluded_user_agents}")

print("\n" + "="*80)
print("APPLYING RECOMMENDED CONFIGURATION")
print("="*80)

# Exclude successful status codes (focus on errors and interesting activity)
config.excluded_status_codes = '200,301,302,304'
print("✓ Excluding status codes: 200 (OK), 301/302 (redirects), 304 (not modified)")

# Don't exclude any methods by default
config.excluded_methods = ''
print("✓ Not excluding any methods")

# Always include POST/PUT/DELETE/PATCH (even with 200 OK) - catches spam, abuse, API attacks
config.included_methods_override = 'POST,PUT,DELETE,PATCH'
print("✓ Always including: POST, PUT, DELETE, PATCH (overrides status code filter)")
print("  → This means POST requests with 200 OK will be analyzed (catches spam submissions)")

# Keep user agent filtering
print("✓ Keeping user agent filtering (bots excluded)")

config.save()

print("\n" + "="*80)
print("CONFIGURATION APPLIED!")
print("="*80)
print("\nWhat this does:")
print("  ✓ GET requests with 200 OK → EXCLUDED (normal browsing)")
print("  ✓ GET requests with 404 → INCLUDED (potential scanning)")
print("  ✓ POST requests with 200 OK → INCLUDED (potential spam/abuse)")
print("  ✓ POST requests with 500 → INCLUDED (application errors)")
print("  ✓ Googlebot with 200 OK → EXCLUDED (legitimate bot)")
print("\nRun the analyzer now:")
print("  docker exec -it loguard_app python manage.py run_analyzer --realtime")
print()

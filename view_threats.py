#!/usr/bin/env python
"""
View and analyze threat alerts from LoguardLLM database.
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'loguard.settings')
django.setup()

from engine.models import ThreatAlert
import json

threats = ThreatAlert.objects.all().order_by('-timestamp')[:5]

if not threats:
    print("\n❌ No threats found in database\n")
else:
    print(f"\n📊 Found {ThreatAlert.objects.count()} total threats. Showing latest 5:\n")
    
    for i, threat in enumerate(threats, 1):
        print(f"\n{'='*80}")
        print(f"🔴 THREAT #{i} - {threat.get_threat_type_display()} (Severity: {threat.get_severity_display()})")
        print(f"{'='*80}")
        print(f"Detected: {threat.timestamp}")
        print(f"Confidence: {threat.confidence:.2%}")
        print(f"Acknowledged: {'✓ Yes' if threat.acknowledged else '✗ No'}")
        
        if threat.source_ips:
            ips = threat.source_ips if isinstance(threat.source_ips, list) else []
            if ips:
                print(f"Source IPs: {', '.join(ips[:5])}{' ...' if len(ips) > 5 else ''}")
        
        if threat.target_paths:
            paths = threat.target_paths if isinstance(threat.target_paths, list) else []
            if paths:
                print(f"Target Paths: {', '.join(paths[:3])}{' ...' if len(paths) > 3 else ''}")
        
        print(f"\n📝 Description:")
        print(f"  {threat.description or 'N/A'}")
        
        print(f"\n💡 Recommendation:")
        print(f"  {threat.recommendation or 'N/A'}")
        
        # Display evidence with proper formatting
        if threat.evidence:
            evidence = threat.evidence
            
            # Show LLM evidence references
            if isinstance(evidence, dict):
                llm_evidence = evidence.get('llm_evidence', [])
                if llm_evidence and llm_evidence != ['No evidence provided']:
                    print(f"\n🔍 LLM Evidence References:")
                    for ref in llm_evidence[:3]:
                        print(f"  • {ref}")
                
                # Show actual sample logs
                sample_logs = evidence.get('sample_logs', [])
                if sample_logs:
                    print(f"\n📜 Sample Logs ({len(sample_logs)} entries):")
                    for j, log in enumerate(sample_logs[:5], 1):
                        # Check if it has raw_line (new format) or formatted display (old format)
                        if 'raw_line' in log:
                            print(f"  {j}. {log['raw_line'][:150]}")
                        else:
                            # Old format - reconstruct from fields
                            log_str = f"{log.get('timestamp', 'N/A')} | {log.get('ip', 'N/A')} | {log.get('method', 'N/A')} {log.get('path', 'N/A')} | Status: {log.get('status', 'N/A')}"
                            print(f"  {j}. {log_str}")
                    
                    if len(sample_logs) > 5:
                        print(f"  ... and {len(sample_logs) - 5} more")
            
            elif isinstance(evidence, list):
                # Old format - just a list of strings
                print(f"\n🔍 Evidence ({len(evidence)} entries):")
                for j, item in enumerate(evidence[:5], 1):
                    item_str = item if isinstance(item, str) else str(item)
                    print(f"  {j}. {item_str[:150]}")
                if len(evidence) > 5:
                    print(f"  ... and {len(evidence) - 5} more")
        
        if threat.notes:
            print(f"\n📌 Notes: {threat.notes}")

print(f"\n{'='*80}\n")
print("💡 To acknowledge a threat:")
print("   docker exec loguard_app python manage.py shell")
print("   >>> from engine.models import ThreatAlert")
print("   >>> threat = ThreatAlert.objects.get(id=1)")
print("   >>> threat.acknowledge(user='admin')")
print()

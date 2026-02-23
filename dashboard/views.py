from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from engine.models import ThreatAlert, AnalysisRun, Config


@login_required
def home(request):
    """Dashboard home page with overview metrics."""
    
    # Get recent stats
    last_24h = timezone.now() - timedelta(hours=24)
    
    total_threats = ThreatAlert.objects.count()
    recent_threats = ThreatAlert.objects.filter(timestamp__gte=last_24h).count()
    unacknowledged = ThreatAlert.objects.filter(acknowledged=False).count()
    
    # Severity breakdown
    severity_stats = ThreatAlert.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Threat type breakdown
    type_stats = ThreatAlert.objects.values('threat_type').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Recent analysis runs
    recent_runs = AnalysisRun.objects.all()[:10]
    
    # Latest threats
    latest_threats = ThreatAlert.objects.select_related('analysis_run').all()[:10]
    
    # System status
    config = Config.get_config()
    
    context = {
        'total_threats': total_threats,
        'recent_threats': recent_threats,
        'unacknowledged': unacknowledged,
        'severity_stats': severity_stats,
        'type_stats': type_stats,
        'recent_runs': recent_runs,
        'latest_threats': latest_threats,
        'config': config,
    }
    
    return render(request, 'dashboard/home.html', context)


@login_required
def threats(request):
    """List all threats with filtering."""
    
    # Get filter parameters
    severity_filter = request.GET.get('severity')
    type_filter = request.GET.get('type')
    acknowledged_filter = request.GET.get('acknowledged')
    
    # Build queryset
    threats = ThreatAlert.objects.select_related('analysis_run').all()
    
    if severity_filter:
        threats = threats.filter(severity=severity_filter)
    
    if type_filter:
        threats = threats.filter(threat_type=type_filter)
    
    if acknowledged_filter == 'yes':
        threats = threats.filter(acknowledged=True)
    elif acknowledged_filter == 'no':
        threats = threats.filter(acknowledged=False)
    
    # Get filter options
    severity_choices = ThreatAlert._meta.get_field('severity').choices
    type_choices = ThreatAlert._meta.get_field('threat_type').choices
    
    context = {
        'threats': threats,
        'severity_filter': severity_filter,
        'type_filter': type_filter,
        'acknowledged_filter': acknowledged_filter,
        'severity_choices': severity_choices,
        'type_choices': type_choices,
    }
    
    return render(request, 'dashboard/threats.html', context)


@login_required
def threat_detail(request, threat_id):
    """Detailed view of a single threat."""
    
    threat = ThreatAlert.objects.select_related('analysis_run').get(id=threat_id)
    
    context = {
        'threat': threat,
    }
    
    return render(request, 'dashboard/threat_detail.html', context)


@login_required
def analysis_runs(request):
    """List all analysis runs."""
    
    runs = AnalysisRun.objects.all()
    
    # Stats
    total_runs = runs.count()
    successful_runs = runs.filter(status='success').count()
    failed_runs = runs.filter(status='error').count()
    
    context = {
        'runs': runs,
        'total_runs': total_runs,
        'successful_runs': successful_runs,
        'failed_runs': failed_runs,
    }
    
    return render(request, 'dashboard/analysis_runs.html', context)

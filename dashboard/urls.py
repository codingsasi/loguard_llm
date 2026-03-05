from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='home'),
    path('threats/', views.threats, name='threats'),
    path('threats/<int:threat_id>/', views.threat_detail, name='threat_detail'),
    path('runs/', views.analysis_runs, name='analysis_runs'),
]

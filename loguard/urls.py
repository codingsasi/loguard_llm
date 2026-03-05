from django.contrib import admin
from django.urls import path
from django.shortcuts import redirect, render


def root_redirect(request):
    """Redirect the site root to the Django admin."""
    return redirect('admin:index')


def custom_404(request, path=''):
    """Show custom 404 page (used even when DEBUG=True via catch-all)."""
    return render(request, '404.html', status=404)


urlpatterns = [
    path('', root_redirect, name='root'),
    path('admin/', admin.site.urls),
    path('<path:path>', custom_404),
]

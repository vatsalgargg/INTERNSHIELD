from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('gmail/', views.scan_gmail, name='scan_gmail'),
    path('gmail/auth/', views.gmail_auth, name='gmail_auth'),
    path('gmail/callback/', views.gmail_callback, name='gmail_callback'),
    path('offer/', views.analyze_offer, name='analyze_offer'),
    path('paste/', views.paste_email, name='paste_email'),
    path('domain/', views.check_domain, name='check_domain'),
]

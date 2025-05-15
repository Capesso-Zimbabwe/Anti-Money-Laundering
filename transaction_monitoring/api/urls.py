"""
Main URL patterns for the API.
"""

from django.urls import path, include
 
urlpatterns = [
    path('v1/', include('transaction_monitoring.api.v1.urls')),
] 
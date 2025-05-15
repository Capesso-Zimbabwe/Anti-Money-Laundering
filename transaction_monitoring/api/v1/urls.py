"""
URL patterns for the API v1 endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'transactions', views.TransactionViewSet)
router.register(r'alerts', views.AlertViewSet)
router.register(r'reports', views.SARViewSet)
router.register(r'rules', views.RuleViewSet)
router.register(r'transaction-types', views.TransactionTypeViewSet)
router.register(r'transaction-groups', views.TransactionTypeGroupViewSet)

# The API URLs are determined automatically by the router
urlpatterns = [
    path('', include(router.urls)),
    path('stats/engine/', views.engine_statistics, name='engine_statistics'),
    path('stats/engine/reset/', views.reset_engine_statistics, name='reset_engine_statistics'),
    # Rule configuration endpoints
    path('rules/<str:rule_code>/config/', views.RuleConfigUpdateAPIView.as_view(), name='rule-update-config'),
    path('rules/<str:rule_code>/scoring/', views.RuleScoringUpdateAPIView.as_view(), name='rule-update-scoring'),
] 
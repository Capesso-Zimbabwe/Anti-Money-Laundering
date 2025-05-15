from django.contrib import admin
from django.urls import include, path
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from aml_app.functions_view import (
    AMLConfigurationAPIView, 
    AMLConfigurationView,
    suspicious_activity_report_view, 
    suspicious_activity_report_detail, 
    update_suspicious_activity_report
)
from aml_app.transaction_monitor import process_all_unchecked_transactions
from aml_app.transaction_view import suspicious_transaction_report
from aml_app.views import (
    AMLLoginView, 
    AMLLogoutView, 
    CustomPasswordResetConfirmView, 
    CustomPasswordResetView,
    alert_detail,
    aml_settings_view,
    dashboard,
    generate_aml_report,
    generate_aml_report_pdf,
    hello,
    list_alerts,
    open_alert,
    risk_definitions,
    risk_scoring,
    run_aml_screening,
    run_aml_screening_ajax
)
from aml_project import settings

urlpatterns = [
    # Admin URLs
    path('admin/', admin.site.urls),
    
    # Authentication URLs
    path('login/', AMLLoginView.as_view(), name='login'),
    path('logout/', AMLLogoutView.as_view(), name='logout'),
    path('password-reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    # Include kyc_app URLs with namespace
    path('', include('kyc_app.urls', namespace='kyc_app')),
    path('', include('transaction_monitoring.urls', namespace='transaction_monitoring')),

    # Development URLs
    path("__reload__/", include("django_browser_reload.urls")),

    # AML Screening URLs
    path('run_aml_screening_ajax/', run_aml_screening_ajax, name='run_aml_screening_ajax'),
    path('run_aml_screening/', run_aml_screening, name='run_aml_screening'),
    path('aml-settings/', aml_settings_view, name='aml-settings'),
    
    # Dashboard and Risk URLs
    path('dashboard/', dashboard, name='dashboard'),
    path('risk_scoring/', risk_scoring, name='risk_scoring'),
    path('risk_definitions/', risk_definitions, name='risk_definitions'),

    # Reports URLs
    path('aml-report/', generate_aml_report, name='aml_report'),
    path('aml-report/pdf/', generate_aml_report_pdf, name='aml_report_pdf'),

    # Alerts URLs
    path('alerts/', list_alerts, name='list_alerts'),
    path('alerts/<int:alert_id>/open/', open_alert, name='open_alert'),
    path('alerts/<int:alert_id>/detail/', alert_detail, name='alert_detail'),

    # Transaction URLs
    path('aml/configuration/', AMLConfigurationView.as_view(), name='aml_configuration'),
    path('api/aml/configuration/', AMLConfigurationAPIView.as_view(), name='aml_configuration_api'),
    path('report/', suspicious_transaction_report, name='suspicious_transaction_report'),

    # Suspicious Activity Reports
    path('suspicious-activity-reports/', suspicious_activity_report_view, name='suspicious_activity_report_view'),
    path('suspicious-activity-reports/<str:report_id>/', suspicious_activity_report_detail, name='suspicious_activity_report_detail'),
    path('suspicious-activity-reports/<str:report_id>/update/', update_suspicious_activity_report, name='update_suspicious_activity_report'),

    # Testing URLs
    path('test-monitor/', process_all_unchecked_transactions, name='test_transaction_monitor'),
    path('hello/', hello, name='hello'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


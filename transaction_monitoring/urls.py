from django.urls import path, include
from . import views
from .api.v1 import urls as api_urls

app_name = "transaction_monitoring"

urlpatterns = [
    # Dashboard
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Transaction processing views
    path('process/', views.process_transactions_view, name='process_transactions'),
    path('analyze/<str:transaction_id>/', views.analyze_transaction_view, name='analyze_transaction'),
    
    # Alerts and Reports
    path('alerts/', views.alerts_list_view, name='alerts_list'),
    path('alerts/<str:alert_id>/', views.alert_detail_view, name='alert_detail'),
    path('reports/', views.sar_reports_list_view, name='reports_list'),
    path('reports/<str:report_id>/', views.sar_report_detail_view, name='report_detail'),
    
    # Rule Management - New Professional Structure
    path('management/', views.management_dashboard_view, name='management_dashboard'),
    
    # Rule Listing and Basic Management
    path('management/rules/', views.rules_list_view, name='rules_list'),
    path('management/rules/create/', views.rule_create_view, name='rule_create'),
    path('management/rules/<str:rule_id>/', views.rule_detail_view, name='rule_detail'),
    path('management/rules/<str:rule_id>/update/', views.rule_update_view, name='rule_update'),
    
    # Rule Configuration - Professional Path
    path('management/rules/<str:rule_id>/configuration/', views.RuleConfigView.as_view(), name='rule-config'),
    
    # Maintain backward compatibility with old URLs
    path('rules/', views.rules_list_view, name='old_rules_list'),
    path('rules/add/', views.rule_create_view, name='old_rule_create'),
    path('rules/<str:rule_id>/', views.rule_detail_view, name='old_rule_detail'),
    path('rules/<str:rule_id>/update/', views.rule_update_view, name='old_rule_update'),
    path('rules/<str:rule_id>/config/', views.RuleConfigView.as_view(), name='old_rule_config'),

    # API endpoints
    path('api/', include('transaction_monitoring.api.urls')),

    # Class-based views
    path('rules_new/', views.RuleListView.as_view(), name='rules'),
    path('alerts_new/', views.AlertListView.as_view(), name='alerts'),
    path('transactions/', views.TransactionListView.as_view(), name='transactions'),
    path('customers/', views.CustomerListView.as_view(), name='customers'),
    path('reports_new/', views.ReportView.as_view(), name='reports'),
    path('settings/', views.SettingsView.as_view(), name='settings'),
    path('api/v1/', include((api_urls, 'api'), namespace='api:v1')),

    # Transaction Type Management URLs
    path('transaction-types/', views.TransactionTypeListView.as_view(), name='transaction_type_list'),
    path('transaction-types/create/', views.TransactionTypeCreateView.as_view(), name='transaction_type_create'),
    path('transaction-types/edit/<str:code>/', views.TransactionTypeEditView.as_view(), name='transaction_type_edit'),
    path('transaction-types/delete/<str:code>/', views.TransactionTypeDeleteView.as_view(), name='transaction_type_delete'),
    path('transaction-types/import/', views.TransactionTypeCsvImportView.as_view(), name='transaction_type_csv_import'),
    
    # Transaction Type Group Management URLs
    path('transaction-type-groups/', views.TransactionTypeGroupListView.as_view(), name='transaction_type_group_list'),
    path('transaction-type-groups/create/', views.TransactionTypeGroupCreateView.as_view(), name='transaction_type_group_create'),
    path('transaction-type-groups/edit/<str:code>/', views.TransactionTypeGroupEditView.as_view(), name='transaction_type_group_edit'),
    path('transaction-type-groups/delete/<str:code>/', views.TransactionTypeGroupDeleteView.as_view(), name='transaction_type_group_delete'),

    # Add a URL for processing all transactions with the dormant account algorithm
    path('run-dormant-all-transactions/', views.run_dormant_all_transactions, name='run_dormant_all_transactions'),
]

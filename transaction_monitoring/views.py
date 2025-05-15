from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from django.utils import timezone
from django.contrib import messages
from django.views import View
import json

from .model.transaction import Transactions
from .model.alert import SuspiciousTransactions, SuspiciousActivityReports
from .model.rule_settings import AMLRules, TransactionTypeGroup, TransactionType, ScoringThreshold
from .monitoring.monitor_service import TransactionMonitoringService
from .monitoring.config.rule_registry import rule_registry

# Initialize the transaction monitoring service
monitoring_service = TransactionMonitoringService()

@csrf_exempt
def process_transactions_view(request):
    """View to process all unchecked transactions."""
    if request.method == 'POST':
        batch_size = int(request.POST.get('batch_size', 100))
        result = monitoring_service.process_unprocessed_transactions(batch_size)
        return JsonResponse(result)
    else:
        return JsonResponse({'status': 'error', 'message': 'Only POST method is allowed'})

@csrf_exempt
def analyze_transaction_view(request, transaction_id):
    """View to analyze a specific transaction."""
    transaction = get_object_or_404(Transactions, transaction_id=transaction_id)
    
    if request.method == 'POST':
        alerts = monitoring_service.create_alerts_from_transaction(transaction)
        return JsonResponse({
            'status': 'success',
            'message': f'Transaction {transaction_id} analyzed',
            'alerts_count': len(alerts),
            'alert_ids': [alert.report_id for alert in alerts]
        })
    else:
        return JsonResponse({'status': 'error', 'message': 'Only POST method is allowed'})

@login_required
def alerts_list_view(request):
    """View to list all suspicious transactions."""
    alerts = SuspiciousTransactions.objects.all().order_by('-created_at')
    return render(request, 'monitoring/alerts_list.html', {'alerts': alerts})

@login_required
def alert_detail_view(request, alert_id):
    """View to show details of a suspicious transaction."""
    alert = get_object_or_404(SuspiciousTransactions, report_id=alert_id)
    return render(request, 'monitoring/alert_detail.html', {'alert': alert})

@login_required
def sar_reports_list_view(request):
    """View to list all SAR reports."""
    reports = SuspiciousActivityReports.objects.all().order_by('-created_at')
    return render(request, 'monitoring/reports_list.html', {'reports': reports})

@login_required
def sar_report_detail_view(request, report_id):
    """View to show details of a SAR report."""
    report = get_object_or_404(SuspiciousActivityReports, report_id=report_id)
    return render(request, 'monitoring/report_detail.html', {'report': report})

@login_required
def rules_list_view(request):
    """View to list all rules."""
    rules = AMLRules.objects.all().order_by('rule_code')
    return render(request, 'monitoring/rules_list.html', {'rules': rules})

@login_required
def rule_create_view(request):
    """View to create a new rule."""
    if request.method == 'POST':
        # Extract rule data from the form
        rule_code = request.POST.get('rule_code')
        rule_name = request.POST.get('rule_name')
        description = request.POST.get('description')
        alert_level = request.POST.get('alert_level')
        enabled = request.POST.get('enabled') == 'on'
        transaction_types = request.POST.get('transaction_types', '')
        scoring_algorithm = request.POST.get('scoring_algorithm', 'MAX')
        min_alert_score = int(request.POST.get('min_alert_score', 50))
        
        # Create a new rule
        rule = AMLRules(
            rule_code=rule_code,
            rule_name=rule_name,
            description=description,
            alert_level=alert_level,
            enabled=enabled,
            transaction_types=transaction_types,
            scoring_algorithm=scoring_algorithm,
            min_alert_score=min_alert_score
        )
        rule.save()
        
        messages.success(request, f"Rule '{rule_name}' created successfully.")
        return redirect('transaction_monitoring:rules_list')
    
    # For GET requests, render the create rule form
    transaction_type_groups = TransactionTypeGroup.objects.all()
    transaction_types = TransactionType.objects.all()
    
    # Get transaction type codes from transaction_types for fallback
    transaction_type_codes = list(transaction_types.values_list('transaction_code', flat=True))
    
    # If no transaction types in DB, get them from the registry as fallback
    if not transaction_type_codes:
        # Get codes from transaction type registry
        from transaction_monitoring.monitoring.config.transaction_types import TransactionTypeRegistry
        registry = TransactionTypeRegistry()
        all_codes = set()
        for group in registry.transaction_groups.values():
            codes = group['included_codes']
            if '*' not in codes:  # Skip wildcard
                all_codes.update(codes)
        transaction_type_codes = list(all_codes)
    
    return render(request, 'monitoring/rule_create.html', {
        'transaction_type_groups': transaction_type_groups,
        'transaction_types': transaction_types,
        'transaction_type_codes': transaction_type_codes
    })

@login_required
def rule_detail_view(request, rule_id):
    """View to show details of a rule."""
    rule = get_object_or_404(AMLRules, rule_code=rule_id)
    
    # Get scoring thresholds
    activity_value_thresholds = ScoringThreshold.objects.filter(
        rule=rule, 
        factor_type='ACTIVITY_VALUE'
    ).order_by('threshold_value')
    
    recurrence_thresholds = ScoringThreshold.objects.filter(
        rule=rule, 
        factor_type='RECURRENCE'
    ).order_by('threshold_value')
    
    return render(request, 'monitoring/rule_detail.html', {
        'rule': rule,
        'activity_value_thresholds': activity_value_thresholds,
        'recurrence_thresholds': recurrence_thresholds
    })

@login_required
def rule_update_view(request, rule_id):
    """View to update a rule."""
    rule = get_object_or_404(AMLRules, rule_code=rule_id)
    
    if request.method == 'POST':
        # Get parameters from POST data
        rule.rule_name = request.POST.get('rule_name', rule.rule_name)
        rule.description = request.POST.get('description', rule.description)
        rule.alert_level = request.POST.get('alert_level', rule.alert_level)
        rule.enabled = request.POST.get('enabled') == 'on'
        rule.transaction_types = request.POST.get('transaction_types', rule.transaction_types)
        rule.scoring_algorithm = request.POST.get('scoring_algorithm', rule.scoring_algorithm)
        rule.min_alert_score = int(request.POST.get('min_alert_score', rule.min_alert_score))
        
        # If there are JSON fields, update them
        if 'thresholds' in request.POST:
            rule.set_thresholds(json.loads(request.POST.get('thresholds', '{}')))
        
        if 'recurrence_settings' in request.POST:
            rule.set_recurrence_settings(json.loads(request.POST.get('recurrence_settings', '{}')))
        
        rule.save()
        
        messages.success(request, f"Rule '{rule.rule_name}' updated successfully.")
        return redirect('transaction_monitoring:rule_detail', rule_id=rule_id)
    
    # For GET requests, render the update form
    transaction_type_groups = TransactionTypeGroup.objects.all()
    return render(request, 'monitoring/rule_update.html', {
        'rule': rule,
        'transaction_type_groups': transaction_type_groups
    })

@login_required
def dashboard_view(request):
    """Dashboard view with monitoring statistics and visualizations."""
    # Get current date and time
    now = timezone.now()
    
    # Get statistics for alerts
    total_alerts = SuspiciousTransactions.objects.count()
    pending_alerts = SuspiciousTransactions.objects.filter(review_status='Pending').count()
    high_risk_alerts = SuspiciousTransactions.objects.filter(risk_level='HIGH').count()
    medium_risk_alerts = SuspiciousTransactions.objects.filter(risk_level='MEDIUM').count()
    low_risk_alerts = SuspiciousTransactions.objects.filter(risk_level='LOW').count()
    
    # Get statistics for SARs
    total_sars = SuspiciousActivityReports.objects.count()
    draft_sars = SuspiciousActivityReports.objects.filter(report_status='DRAFT').count()
    submitted_sars = SuspiciousActivityReports.objects.filter(report_status='SUBMITTED').count()
    
    # Get rule statistics
    total_rules = AMLRules.objects.count()
    enabled_rules = AMLRules.objects.filter(enabled=True).count()
    
    # Get recent alerts (last 10)
    recent_alerts = SuspiciousTransactions.objects.all().order_by('-created_at')[:10]
    
    # Get top triggering rules
    top_rules = SuspiciousTransactions.objects.values('flagged_reason').annotate(
        count=Count('flagged_reason')
    ).order_by('-count')[:5]
    
    # Get total suspicious amount
    total_suspicious_amount = SuspiciousTransactions.objects.aggregate(
        total=Sum('amount')
    )['total'] or 0
    
    # Prepare context for template
    context = {
        'statistics': {
            'total_alerts': total_alerts,
            'pending_alerts': pending_alerts,
            'high_risk_alerts': high_risk_alerts,
            'medium_risk_alerts': medium_risk_alerts,
            'low_risk_alerts': low_risk_alerts,
            'total_sars': total_sars,
            'draft_sars': draft_sars,
            'submitted_sars': submitted_sars,
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'total_suspicious_amount': total_suspicious_amount
        },
        'recent_alerts': recent_alerts,
        'top_rules': top_rules
    }
    
    return render(request, 'monitoring/dashboard.html', context)

class DashboardView(View):
    def get(self, request):
        context = {
            'active_rules': AMLRules.objects.filter(enabled=True).count(),
            'total_rules': AMLRules.objects.count(),
            'high_alerts': 15,  # Placeholder values
            'medium_alerts': 23,
            'low_alerts': 47
        }
        return render(request, 'monitoring/dashboard.html', context)

class RuleListView(View):
    def get(self, request):
        rules = AMLRules.objects.all()
        context = {
            'rules': rules
        }
        return render(request, 'monitoring/rules.html', context)

class RuleConfigView(View):
    def get(self, request, rule_code=None, rule_id=None):
        # Allow retrieving by either rule_code or rule_id
        if rule_id:
            rule_code = rule_id
            
        rule = get_object_or_404(AMLRules, rule_code=rule_code)
        
        # Get scoring thresholds
        activity_value_thresholds = ScoringThreshold.objects.filter(
            rule=rule, 
            factor_type='ACTIVITY_VALUE'
        ).order_by('threshold_value')
        
        recurrence_thresholds = ScoringThreshold.objects.filter(
            rule=rule, 
            factor_type='RECURRENCE'
        ).order_by('threshold_value')
        
        # Get transaction type groups
        transaction_type_groups = TransactionTypeGroup.objects.all()
        
        # Get transaction types
        transaction_types = TransactionType.objects.all()
        
        # Get transaction type codes from transaction_types for fallback
        transaction_type_codes = list(transaction_types.values_list('transaction_code', flat=True))
        
        # If no transaction types in DB, get them from the registry as fallback
        if not transaction_type_codes:
            # Get codes from transaction type registry
            from transaction_monitoring.monitoring.config.transaction_types import TransactionTypeRegistry
            registry = TransactionTypeRegistry()
            all_codes = set()
            for group in registry.transaction_groups.values():
                codes = group['included_codes']
                if '*' not in codes:  # Skip wildcard
                    all_codes.update(codes)
            transaction_type_codes = list(all_codes)
        
        # Get rule types from registry
        rule_types = rule_registry.get_all_rule_types()
        
        # Determine the current rule type (if any)
        current_rule_type = None
        if rule.rule_code.startswith('LCT'):
            current_rule_type = 'large_cash'
        elif rule.rule_code.startswith('ADR'):
            current_rule_type = 'dormant_account'
            
        # Get specific parameters for the current rule type
        rule_type_params = []
        if current_rule_type:
            rule_type_info = rule_registry.get_rule_type(current_rule_type)
            rule_type_params = rule_type_info.get('configurable_params', [])
        
        context = {
            'rule': rule,
            'activity_value_thresholds': activity_value_thresholds,
            'recurrence_thresholds': recurrence_thresholds,
            'transaction_type_groups': transaction_type_groups,
            'transaction_types': transaction_types,
            'transaction_type_codes': transaction_type_codes,
            'rule_types': rule_types,
            'current_rule_type': current_rule_type,
            'rule_type_params': rule_type_params
        }
        
        return render(request, 'monitoring/rule_config.html', context)
    
    def post(self, request, rule_code=None, rule_id=None):
        # Allow retrieving by either rule_code or rule_id
        if rule_id:
            rule_code = rule_id
            
        rule = get_object_or_404(AMLRules, rule_code=rule_code)
        
        # Update rule basic information
        if 'description' in request.POST:
            rule.description = request.POST.get('description')
        
        if 'alert_level' in request.POST:
            rule.alert_level = request.POST.get('alert_level')
        
        if 'min_alert_score' in request.POST:
            rule.min_alert_score = int(request.POST.get('min_alert_score'))
        
        if 'scoring_algorithm' in request.POST:
            rule.scoring_algorithm = request.POST.get('scoring_algorithm')
        
        # Handle enabled status (checkbox)
        rule.enabled = 'enabled' in request.POST
        
        # Handle transaction types
        if 'transaction_types[]' in request.POST:
            rule.transaction_types = ' '.join(request.POST.getlist('transaction_types[]'))
        
        # Handle rule type specific parameters
        rule_type = request.POST.get('rule_type')
        if rule_type:
            rule_type_info = rule_registry.get_rule_type(rule_type)
            if rule_type_info:
                # Store rule type in custom_parameters
                if not hasattr(rule, 'custom_parameters') or not rule.custom_parameters:
                    rule.custom_parameters = {}
                
                rule.custom_parameters['rule_type'] = rule_type
                
                # Store rule specific parameters
                for param in rule_type_info.get('configurable_params', []):
                    param_name = param['name']
                    if param_name in request.POST:
                        param_value = request.POST.get(param_name)
                        
                        # Convert value based on type
                        if param['type'] == 'integer':
                            param_value = int(param_value)
                        elif param['type'] == 'float':
                            param_value = float(param_value)
                        elif param['type'] == 'boolean':
                            param_value = param_value.lower() == 'true'
                        
                        rule.custom_parameters[param_name] = param_value
        
        rule.updated_at = timezone.now()
        rule.save()
        
        # Update rule configuration in monitoring service
        if rule_type:
            rule_config = {
                'rule_id': f'AML-{rule.rule_code}',  # Add AML- prefix only for monitoring service
                'rule_name': rule.rule_name,
                'description': rule.description,
                'alert_level': rule.alert_level,
                'scoring_algorithm': rule.scoring_algorithm,
                'transaction_types': rule.transaction_types.split(),
                'thresholds': rule.custom_parameters
            }
            
            # Update in monitoring service if it's a recognized rule type
            if rule_type == 'dormant_account':
                monitoring_service.update_rule_config('AML-ADR-ALL-ALL-A-M06-AIN', rule_config)
            elif rule_type == 'large_cash':
                monitoring_service.update_rule_config('AML-LCT-CCE-INN-A-D01-LCT', rule_config)
        
        messages.success(request, f"Rule '{rule.rule_name}' has been updated successfully.")
        # Redirect to the management dashboard instead of back to the config page
        return redirect('transaction_monitoring:management_dashboard')

class AlertListView(View):
    def get(self, request):
        return render(request, 'monitoring/alerts.html')

class TransactionListView(View):
    def get(self, request):
        return render(request, 'monitoring/transactions.html')

class CustomerListView(View):
    def get(self, request):
        return render(request, 'monitoring/customers.html')

class ReportView(View):
    def get(self, request):
        return render(request, 'monitoring/reports.html')

class SettingsView(View):
    def get(self, request):
        return render(request, 'monitoring/settings.html')

@login_required
def management_dashboard_view(request):
    """Management dashboard view with rule management centralized interface."""
    # Get rule statistics
    total_rules = AMLRules.objects.count()
    enabled_rules = AMLRules.objects.filter(enabled=True).count()
    disabled_rules = total_rules - enabled_rules
    
    # Get rules by alert level
    high_rules = AMLRules.objects.filter(alert_level='HIGH').count()
    medium_rules = AMLRules.objects.filter(alert_level='MEDIUM').count()
    low_rules = AMLRules.objects.filter(alert_level='LOW').count()
    
    # Get recently modified rules
    recent_rules = AMLRules.objects.all().order_by('-updated_at')[:5]
    
    # Get rule type statistics
    rule_types = rule_registry.get_all_rule_types()
    
    # Organize rules by type
    rules_by_type = {}
    for rule_type in rule_types:
        # This is a simplified approach - you would need a way to identify rule types in your data model
        # For now, we'll use rule codes as a proxy
        type_rules = []
        if rule_type['id'] == 'dormant_account':
            type_rules = AMLRules.objects.filter(rule_code__startswith='ADR')
        elif rule_type['id'] == 'large_cash':
            type_rules = AMLRules.objects.filter(rule_code__startswith='LCT')
        
        rules_by_type[rule_type['name']] = {
            'count': type_rules.count(),
            'rules': type_rules[:3],  # Just the first few
            'type_id': rule_type['id']
        }
    
    context = {
        'total_rules': total_rules,
        'enabled_rules': enabled_rules,
        'disabled_rules': disabled_rules,
        'high_rules': high_rules,
        'medium_rules': medium_rules,
        'low_rules': low_rules,
        'recent_rules': recent_rules,
        'rule_types': rule_types,
        'rules_by_type': rules_by_type
    }
    
    return render(request, 'monitoring/management_dashboard.html', context)

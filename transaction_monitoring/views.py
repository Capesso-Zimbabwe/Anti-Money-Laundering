from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from django.utils import timezone
from django.contrib import messages
from django.views import View
import json
import io
import logging
import sys
from contextlib import redirect_stdout
import os
from django.conf import settings
from datetime import date, datetime
from decimal import Decimal

from .model.transaction import Transactions
from .model.alert import Alert, SuspiciousActivityReport
from .model.rule_settings import (
    AMLRules, DormantAccountRule as DormantAccountRuleSettings, LargeCashRule, TransactionTypeGroup, TransactionType, ScoringThreshold,
    RuleType, RuleTypeConfig, 
    StructuredTransactionConfig, HighRiskCountryConfig, RecurrenceConfig
)
from .model.account import Account
# Import the rule processor with a clear alias
from .monitoring.rules.dormant_account import DormantAccountRule as DormantAccountRuleProcessor
from .monitoring.monitor_service import TransactionMonitoringService
from .monitoring.config.rule_registry import rule_registry

# Initialize the transaction monitoring service
monitoring_service = TransactionMonitoringService()

# Define a custom JSON encoder to handle date objects and Decimal
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)  # Convert Decimal to float for JSON serialization
        return super().default(obj)

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
            'alert_ids': [alert.alert_id for alert in alerts]
        })
    else:
        return JsonResponse({'status': 'error', 'message': 'Only POST method is allowed'})

@login_required
def alerts_list_view(request):
    """View to list all suspicious transactions."""
    alerts = Alert.objects.all().order_by('-created_at')
    return render(request, 'monitoring/alerts_list.html', {'alerts': alerts})

@login_required
def alert_detail_view(request, alert_id):
    """View to show details of a suspicious transaction."""
    alert = get_object_or_404(Alert, alert_id=alert_id)
    return render(request, 'monitoring/alert_detail.html', {'alert': alert})

@login_required
def sar_reports_list_view(request):
    """View to list all SAR reports."""
    reports = SuspiciousActivityReport.objects.all().order_by('-created_at')
    return render(request, 'monitoring/reports_list.html', {'reports': reports})

@login_required
def sar_report_detail_view(request, report_id):
    """View to show details of a SAR report."""
    report = get_object_or_404(SuspiciousActivityReport, sar_id=report_id)
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
    total_alerts = Alert.objects.count()
    pending_alerts = Alert.objects.filter(status='NEW').count()
    high_risk_alerts = Alert.objects.filter(alert_level='HIGH').count()
    medium_risk_alerts = Alert.objects.filter(alert_level='MEDIUM').count()
    low_risk_alerts = Alert.objects.filter(alert_level='LOW').count()
    
    # Get statistics for SARs
    total_sars = SuspiciousActivityReport.objects.count()
    draft_sars = SuspiciousActivityReport.objects.filter(status='DRAFT').count()
    submitted_sars = SuspiciousActivityReport.objects.filter(status='FILED').count()
    
    # Get rule statistics
    total_rules = AMLRules.objects.count()
    enabled_rules = AMLRules.objects.filter(enabled=True).count()
    
    # Get recent alerts (last 10)
    recent_alerts = Alert.objects.all().order_by('-created_at')[:10]
    
    # Get top triggering rules
    top_rules = Alert.objects.values('rule_type').annotate(
        count=Count('rule_type')
    ).order_by('-count')[:5]
    
    # Get total suspicious amount
    total_suspicious_amount = Alert.objects.aggregate(
        total=Sum('total_amount')
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
        
        # First check the rule_type field
        if rule.rule_type == 'DORMANT_ACCOUNT':
            current_rule_type = 'dormant_account'
        elif rule.rule_type == 'LARGE_CASH':
            current_rule_type = 'large_cash'
        # Fallback to checking custom_parameters
        elif rule.custom_parameters and 'rule_type' in rule.custom_parameters:
            current_rule_type = rule.custom_parameters['rule_type']
        # Legacy fallback
        elif hasattr(rule, 'dormant_account_activity') and rule.dormant_account_activity:
            current_rule_type = 'dormant_account'
        elif hasattr(rule, 'large_cash_deposits') and rule.large_cash_deposits:
            current_rule_type = 'large_cash'
            
        # Get specific parameters for the current rule type
        rule_type_params = []
        if current_rule_type:
            rule_type_info = rule_registry.get_rule_type(current_rule_type)
            rule_type_params = rule_type_info.get('configurable_params', [])
        
        # Get rule specific configurations
        dormant_account_config = None
        large_cash_config = None
        
        if current_rule_type == 'dormant_account':
            # Try to get the dormant account configuration
            try:
                dormant_account_config = DormantAccountRuleSettings.objects.get(rule=rule)
            except DormantAccountRuleSettings.DoesNotExist:
                # Create a new configuration if it doesn't exist
                dormant_account_config = DormantAccountRuleSettings(rule=rule)
                # If there are custom parameters, use them to initialize the config
                if rule.custom_parameters:
                    if 'account_age_days' in rule.custom_parameters:
                        dormant_account_config.account_age_days = rule.custom_parameters['account_age_days']
                    if 'inactive_period_months' in rule.custom_parameters:
                        dormant_account_config.inactive_period_months = rule.custom_parameters['inactive_period_months']
                    if 'activity_amount_threshold' in rule.custom_parameters:
                        dormant_account_config.activity_amount_threshold = rule.custom_parameters['activity_amount_threshold']
                    if 'max_prior_activity' in rule.custom_parameters:
                        dormant_account_config.max_prior_activity = rule.custom_parameters['max_prior_activity']
                # Save the new configuration
                dormant_account_config.save()
        elif current_rule_type == 'large_cash':
            # Try to get the large cash configuration
            try:
                large_cash_config = LargeCashRule.objects.get(rule=rule)
            except LargeCashRule.DoesNotExist: 
                # Create a new configuration if it doesn't exist
                large_cash_config = LargeCashRule(rule=rule)
                # If there are custom parameters, use them to initialize the config
                if rule.custom_parameters:
                    if 'threshold_amount' in rule.custom_parameters:
                        large_cash_config.threshold_amount = rule.custom_parameters['threshold_amount']
                    if 'aggregate_period_days' in rule.custom_parameters:
                        large_cash_config.aggregate_period_days = rule.custom_parameters['aggregate_period_days']
                    if 'include_foreign_currency' in rule.custom_parameters:
                        large_cash_config.include_foreign_currency = rule.custom_parameters['include_foreign_currency']
                    if 'monitor_deposits' in rule.custom_parameters:
                        large_cash_config.monitor_deposits = rule.custom_parameters['monitor_deposits']
                    if 'monitor_withdrawals' in rule.custom_parameters:
                        large_cash_config.monitor_withdrawals = rule.custom_parameters['monitor_withdrawals']
                # Save the new configuration
                large_cash_config.save()
        
        context = {
            'rule': rule,
            'activity_value_thresholds': activity_value_thresholds,
            'recurrence_thresholds': recurrence_thresholds,
            'transaction_type_groups': transaction_type_groups,
            'transaction_types': transaction_types,
            'transaction_type_codes': transaction_type_codes,
            'rule_types': rule_types,
            'current_rule_type': current_rule_type,
            'rule_type_params': rule_type_params,
            'dormant_account_config': dormant_account_config,
            'large_cash_config': large_cash_config
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
            # Set the rule type in the main rule record
            if rule_type == 'dormant_account':
                rule.rule_type = 'DORMANT_ACCOUNT'
            elif rule_type == 'large_cash':
                rule.rule_type = 'LARGE_CASH'
            else:
                rule.rule_type = rule_type.upper()
            
            # For backward compatibility
            if not hasattr(rule, 'custom_parameters') or not rule.custom_parameters:
                rule.custom_parameters = {}
            rule.custom_parameters['rule_type'] = rule_type
            
            # Process specific rule types with their parameters using proper models
            if rule_type == 'dormant_account':
                # Get or create the dormant account rule configuration
                dormant_rule, created = DormantAccountRuleSettings.objects.get_or_create(rule=rule)
                
                # Update the configuration from form data
                if 'account_age_days' in request.POST and request.POST['account_age_days']:
                    try:
                        dormant_rule.account_age_days = int(request.POST['account_age_days'])
                        rule.custom_parameters['account_age_days'] = dormant_rule.account_age_days
                    except (ValueError, TypeError):
                        pass
                
                if 'inactive_period_months' in request.POST and request.POST['inactive_period_months']:
                    try:
                        dormant_rule.inactive_period_months = int(request.POST['inactive_period_months'])
                        rule.custom_parameters['inactive_period_months'] = dormant_rule.inactive_period_months
                    except (ValueError, TypeError):
                        pass
                
                if 'activity_amount_threshold' in request.POST and request.POST['activity_amount_threshold']:
                    try:
                        dormant_rule.activity_amount_threshold = float(request.POST['activity_amount_threshold'])
                        rule.custom_parameters['activity_amount_threshold'] = float(dormant_rule.activity_amount_threshold)
                    except (ValueError, TypeError):
                        pass
                
                if 'max_prior_activity' in request.POST and request.POST['max_prior_activity']:
                    try:
                        dormant_rule.max_prior_activity = float(request.POST['max_prior_activity'])
                        rule.custom_parameters['max_prior_activity'] = float(dormant_rule.max_prior_activity)
                    except (ValueError, TypeError):
                        pass
                
                # Save the dormant account rule configuration
                dormant_rule.save()
                
            elif rule_type == 'large_cash':
                # Get or create the large cash rule configuration
                large_cash_rule, created = LargeCashRule.objects.get_or_create(rule=rule)
                
                # Update the configuration from form data
                if 'threshold_amount' in request.POST and request.POST['threshold_amount']:
                    try:
                        large_cash_rule.threshold_amount = float(request.POST['threshold_amount'])
                        rule.custom_parameters['threshold_amount'] = float(large_cash_rule.threshold_amount)
                    except (ValueError, TypeError):
                        pass
                
                if 'aggregate_period_days' in request.POST and request.POST['aggregate_period_days']:
                    try:
                        large_cash_rule.aggregate_period_days = int(request.POST['aggregate_period_days'])
                        rule.custom_parameters['aggregate_period_days'] = large_cash_rule.aggregate_period_days
                    except (ValueError, TypeError):
                        pass
                
                if 'include_foreign_currency' in request.POST:
                    large_cash_rule.include_foreign_currency = request.POST['include_foreign_currency'] == 'true'
                    rule.custom_parameters['include_foreign_currency'] = large_cash_rule.include_foreign_currency
                
                if 'monitor_deposits' in request.POST:
                    large_cash_rule.monitor_deposits = request.POST['monitor_deposits'] == 'true'
                    rule.custom_parameters['monitor_deposits'] = large_cash_rule.monitor_deposits
                
                if 'monitor_withdrawals' in request.POST:
                    large_cash_rule.monitor_withdrawals = request.POST['monitor_withdrawals'] == 'true'
                    rule.custom_parameters['monitor_withdrawals'] = large_cash_rule.monitor_withdrawals
                
                # Save the large cash rule configuration
                large_cash_rule.save()
            
            # Generic parameter handling for any rule type
            rule_type_info = rule_registry.get_rule_type(rule_type)
            if rule_type_info:
                # Process all parameters from the rule registry configuration
                for param in rule_type_info.get('configurable_params', []):
                    param_name = param['name']
                    if param_name in request.POST and request.POST[param_name]:
                        param_value = request.POST[param_name]
                        
                        # Convert value based on type
                        try:
                            if param['type'] == 'integer':
                                param_value = int(param_value)
                            elif param['type'] == 'float':
                                param_value = float(param_value)
                            elif param['type'] == 'boolean':
                                param_value = param_value.lower() == 'true'
                        except (ValueError, TypeError):
                            # Keep as string if conversion fails
                            pass
                        
                        rule.custom_parameters[param_name] = param_value
        
        # Process activity threshold data
        if 'activity_thresholds_json' in request.POST and request.POST.get('activity_thresholds_json'):
            activity_thresholds = json.loads(request.POST.get('activity_thresholds_json'))
            
            # Also store in custom_parameters for backup
            rule.custom_parameters['activity_thresholds'] = activity_thresholds
            
            # First, remove existing activity thresholds
            ScoringThreshold.objects.filter(rule=rule, factor_type='ACTIVITY_VALUE').delete()
            
            # Create new thresholds from the submitted data
            for threshold in activity_thresholds:
                ScoringThreshold.objects.create(
                    rule=rule,
                    factor_type='ACTIVITY_VALUE',
                    threshold_value=threshold['threshold_value'],
                    score=threshold['score'],
                    description=threshold['description']
                )
        
        # Process recurrence threshold data
        if 'recurrence_thresholds_json' in request.POST and request.POST.get('recurrence_thresholds_json'):
            recurrence_thresholds = json.loads(request.POST.get('recurrence_thresholds_json'))
            
            # Also store in custom_parameters for backup
            rule.custom_parameters['recurrence_thresholds'] = recurrence_thresholds
            
            # First, remove existing recurrence thresholds
            ScoringThreshold.objects.filter(rule=rule, factor_type='RECURRENCE').delete()
            
            # Create new thresholds from the submitted data
            for threshold in recurrence_thresholds:
                ScoringThreshold.objects.create(
                    rule=rule,
                    factor_type='RECURRENCE',
                    threshold_value=threshold['threshold_value'],
                    score=threshold['score'],
                    description=threshold['description'],
                    lookback_days=threshold.get('lookback_days', 30)  # Default to 30 if not provided
                )
        
        # Print debug information to console
        print(f"Rule configuration saved: {rule.rule_type}")
        
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
                'transaction_types': rule.transaction_types.split() if rule.transaction_types else [],
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

# Transaction Type Management Views
class TransactionTypeListView(View):
    def get(self, request):
        """View to list all transaction types."""
        transaction_types = TransactionType.objects.all().order_by('transaction_code')
        return render(request, 'monitoring/transaction_types/list.html', {
            'transaction_types': transaction_types
        })

class TransactionTypeCreateView(View):
    def get(self, request):
        """View to display form for creating a transaction type."""
        groups = TransactionTypeGroup.objects.all().order_by('group_code')
        return render(request, 'monitoring/transaction_types/create.html', {
            'groups': groups
        })
    
    def post(self, request):
        """Process the transaction type creation form."""
        transaction_code = request.POST.get('transaction_code')
        description = request.POST.get('description')
        jurisdiction = request.POST.get('jurisdiction')
        group_ids = request.POST.getlist('groups')
        
        # Validate that transaction code is unique
        if TransactionType.objects.filter(transaction_code=transaction_code).exists():
            messages.error(request, f"Transaction code '{transaction_code}' already exists.")
            return redirect('transaction_monitoring:transaction_type_create')
        
        # Create the transaction type
        transaction_type = TransactionType.objects.create(
            transaction_code=transaction_code,
            description=description,
            jurisdiction=jurisdiction
        )
        
        # Add to groups
        for group_id in group_ids:
            try:
                group = TransactionTypeGroup.objects.get(group_code=group_id)
                transaction_type.groups.add(group)
            except TransactionTypeGroup.DoesNotExist:
                pass
        
        messages.success(request, f"Transaction type '{transaction_code}' created successfully.")
        return redirect('transaction_monitoring:transaction_type_list')

class TransactionTypeEditView(View):
    def get(self, request, code):
        """View to display form for editing a transaction type."""
        transaction_type = get_object_or_404(TransactionType, transaction_code=code)
        groups = TransactionTypeGroup.objects.all().order_by('group_code')
        selected_groups = transaction_type.groups.all()
        
        return render(request, 'monitoring/transaction_types/edit.html', {
            'transaction_type': transaction_type,
            'groups': groups,
            'selected_groups': selected_groups
        })
    
    def post(self, request, code):
        """Process the transaction type edit form."""
        transaction_type = get_object_or_404(TransactionType, transaction_code=code)
        
        # Update fields
        transaction_type.description = request.POST.get('description')
        transaction_type.jurisdiction = request.POST.get('jurisdiction')
        
        # Update group associations
        group_ids = request.POST.getlist('groups')
        transaction_type.groups.clear()
        
        for group_id in group_ids:
            try:
                group = TransactionTypeGroup.objects.get(group_code=group_id)
                transaction_type.groups.add(group)
            except TransactionTypeGroup.DoesNotExist:
                pass
        
        transaction_type.save()
        
        messages.success(request, f"Transaction type '{code}' updated successfully.")
        return redirect('transaction_monitoring:transaction_type_list')

class TransactionTypeDeleteView(View):
    def post(self, request, code):
        """Delete a transaction type."""
        transaction_type = get_object_or_404(TransactionType, transaction_code=code)
        code = transaction_type.transaction_code
        transaction_type.delete()
        
        messages.success(request, f"Transaction type '{code}' deleted successfully.")
        return redirect('transaction_monitoring:transaction_type_list')

# Transaction Type Group Management Views
class TransactionTypeGroupListView(View):
    def get(self, request):
        """View to list all transaction type groups."""
        groups = TransactionTypeGroup.objects.all().order_by('group_code')
        return render(request, 'monitoring/transaction_type_groups/list.html', {
            'groups': groups
        })

class TransactionTypeGroupCreateView(View):
    def get(self, request):
        """View to display form for creating a transaction type group."""
        parent_groups = TransactionTypeGroup.objects.all().order_by('group_code')
        return render(request, 'monitoring/transaction_type_groups/create.html', {
            'parent_groups': parent_groups
        })
    
    def post(self, request):
        """Process the transaction type group creation form."""
        group_code = request.POST.get('group_code')
        description = request.POST.get('description')
        parent_group_id = request.POST.get('parent_group')
        
        # Validate that group code is unique
        if TransactionTypeGroup.objects.filter(group_code=group_code).exists():
            messages.error(request, f"Group code '{group_code}' already exists.")
            return redirect('transaction_monitoring:transaction_type_group_create')
        
        # Create the transaction type group
        parent_group = None
        if parent_group_id:
            try:
                parent_group = TransactionTypeGroup.objects.get(group_code=parent_group_id)
            except TransactionTypeGroup.DoesNotExist:
                pass
        
        TransactionTypeGroup.objects.create(
            group_code=group_code,
            description=description,
            parent_group=parent_group
        )
        
        messages.success(request, f"Transaction type group '{group_code}' created successfully.")
        return redirect('transaction_monitoring:transaction_type_group_list')

class TransactionTypeGroupEditView(View):
    def get(self, request, code):
        """View to display form for editing a transaction type group."""
        group = get_object_or_404(TransactionTypeGroup, group_code=code)
        parent_groups = TransactionTypeGroup.objects.exclude(group_code=code).order_by('group_code')
        
        return render(request, 'monitoring/transaction_type_groups/edit.html', {
            'group': group,
            'parent_groups': parent_groups
        })
    
    def post(self, request, code):
        """Process the transaction type group edit form."""
        group = get_object_or_404(TransactionTypeGroup, group_code=code)
        
        # Update fields
        group.description = request.POST.get('description')
        
        # Update parent group
        parent_group_id = request.POST.get('parent_group')
        if parent_group_id and parent_group_id != code:  # Prevent circular reference
            try:
                parent_group = TransactionTypeGroup.objects.get(group_code=parent_group_id)
                group.parent_group = parent_group
            except TransactionTypeGroup.DoesNotExist:
                group.parent_group = None
                
        else:
            group.parent_group = None
        
            group.save()
        
            messages.success(request, f"Transaction type group '{code}' updated successfully.")
        return redirect('transaction_monitoring:transaction_type_group_list')

class TransactionTypeGroupDeleteView(View):
    def post(self, request, code):
        """Delete a transaction type group."""
        group = get_object_or_404(TransactionTypeGroup, group_code=code)
        
        # Check if the group has any transaction types or children groups
        if group.transaction_types.exists():
            messages.error(request, f"Cannot delete group '{code}' as it has transaction types associated with it.")
            return redirect('transaction_monitoring:transaction_type_group_list')
        
        if TransactionTypeGroup.objects.filter(parent_group=group).exists():
            messages.error(request, f"Cannot delete group '{code}' as it has child groups.")
            return redirect('transaction_monitoring:transaction_type_group_list')
        
        code = group.group_code
        group.delete()
        
        messages.success(request, f"Transaction type group '{code}' deleted successfully.")
        return redirect('transaction_monitoring:transaction_type_group_list')

class TransactionTypeCsvImportView(View):
    def get(self, request):
        """Display form for importing transaction types from CSV."""
        return render(request, 'monitoring/transaction_types/import.html')
    
    def post(self, request):
        """Process the CSV import."""
        if 'csv_file' not in request.FILES:
            messages.error(request, "No CSV file uploaded.")
            return redirect('transaction_monitoring:transaction_type_csv_import')
        
        csv_file = request.FILES['csv_file']
        if not csv_file.name.endswith('.csv'):
            messages.error(request, "File is not a CSV file.")
            return redirect('transaction_monitoring:transaction_type_csv_import')
        
        # Process the CSV file
        imported_count = 0
        skipped_count = 0
        try:
            import csv
            decoded_file = csv_file.read().decode('utf-8').splitlines()
            reader = csv.DictReader(decoded_file)
            
            for row in reader:
                # Skip if required fields are missing
                if 'transaction_code' not in row or 'description' not in row:
                    skipped_count += 1
                    continue
                
                # Create or update transaction type
                transaction_type, created = TransactionType.objects.update_or_create(
                    transaction_code=row['transaction_code'],
                    defaults={
                        'description': row['description'],
                        'jurisdiction': row.get('jurisdiction', '')
                    }
                )
                
                # Add to groups if specified
                if 'groups' in row and row['groups']:
                    group_codes = [g.strip() for g in row['groups'].split(',')]
                    for group_code in group_codes:
                        group, created = TransactionTypeGroup.objects.get_or_create(
                            group_code=group_code,
                            defaults={'description': f"Auto-created group: {group_code}"}
                        )
                        transaction_type.groups.add(group)
                
                imported_count += 1
                
            messages.success(request, f"Successfully imported {imported_count} transaction types. Skipped {skipped_count}.")
        except Exception as e:
            messages.error(request, f"Error processing CSV: {str(e)}")
        
        return redirect('transaction_monitoring:transaction_type_list')

@login_required
def run_dormant_all_transactions(request):
    """
    Process all transactions in the database with the dormant account algorithm.
    No input is required - this view automatically processes everything.
    
    Returns:
        HttpResponse with algorithm execution results for all transactions
    """
    from django.http import HttpResponse
    import io
    from contextlib import redirect_stdout
    import time
    
    # Set the maximum number of transactions to process
    limit = int(request.GET.get('limit', 20))  # Default to 20 to avoid too much processing
    
    # Get all transactions, ordered by most recent first
    transactions = Transactions.objects.all().order_by('-transaction_date')[:limit]
    
    # Start building the HTML response
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dormant Account Algorithm - All Transactions</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-size: 12px; overflow-x: auto; max-height: 300px; overflow-y: auto; }
            .transaction { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .alert { color: #721c24; background-color: #f8d7da; padding: 10px; border-radius: 3px; }
            .success { color: #155724; background-color: #d4edda; padding: 10px; border-radius: 3px; }
            .transaction-header { display: flex; justify-content: space-between; }
            .summary { margin-top: 20px; padding: 15px; background-color: #e9ecef; border-radius: 5px; }
            .triggered { border-left: 5px solid #28a745; }
            .not-triggered { border-left: 5px solid #dc3545; }
            .collapsible { cursor: pointer; padding: 10px; background-color: #f1f1f1; }
            .content { display: none; overflow: hidden; }
            h3 { margin-top: 0; }
        </style>
        <script>
        function toggleContent(id) {
            var content = document.getElementById(id);
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        }
        </script>
    </head>
    <body>
    """
    
    # Add the header with transaction count
    html_content += f"""
        <h1>Dormant Account Algorithm - Processing All Transactions</h1>
        <p>Processing {len(transactions)} transactions (limit: {limit})</p>
        
        <div class="summary" id="summary">
            <h2>Processing Summary</h2>
            <p>Total transactions: <span id="total-count">0</span></p>
            <p>Alerts triggered: <span id="triggered-count">0</span></p>
        </div>
        
        <hr>
        <div id="results">
    """
    
    # Import and initialize the rule processor
    from transaction_monitoring.monitoring.rules.dormant_account import DormantAccountRule
    rule_processor = DormantAccountRule()
    
    # Set up context for rule evaluation
    context = {
        'test_mode': True
    }
    
    # Keep track of statistics
    total_count = 0
    triggered_count = 0
    
    # Process each transaction
    start_time = time.time()
    
    for transaction in transactions:
        total_count += 1
        
        # Create output buffer to capture algorithm prints
        output_buffer = io.StringIO()
        
        # Transaction header info
        transaction_html = f"""
        <div class="transaction" id="transaction-{transaction.transaction_id}">
            <div class="transaction-header">
                <h3>Transaction: {transaction.transaction_id}</h3>
                <div>Amount: {transaction.amount} {transaction.currency_code}</div>
            </div>
            <p>Date: {transaction.transaction_date}</p>
            <p>Source Account: {transaction.source_account_number}</p>
            <p>Destination: {getattr(transaction, 'destination_account_number', 'N/A')}</p>
        """
        
        try:
            # Execute the rule algorithm with stdout redirected to capture prints
            with redirect_stdout(output_buffer):
                triggered, details = rule_processor.evaluate(transaction, context)
            
            # Get algorithm output
            algorithm_output = output_buffer.getvalue()
            
            # Add a collapsible section for the algorithm output
            transaction_html += f"""
            <div class="collapsible" onclick="toggleContent('output-{transaction.transaction_id}')">
                Click to show/hide algorithm output
            </div>
            <div class="content" id="output-{transaction.transaction_id}">
                <pre>{algorithm_output}</pre>
            </div>
            """
            
            # Add result information
            if triggered:
                triggered_count += 1
                transaction_html += f"""
                <div class="success">
                    <strong>✅ RULE TRIGGERED</strong> | Score: {details.get('score', 0)}
                </div>
                """
                # Add triggered class to the transaction div
                transaction_html = transaction_html.replace('class="transaction"', 'class="transaction triggered"')
            else:
                transaction_html += f"""
                <div class="alert">
                    <strong>❌ RULE NOT TRIGGERED</strong> | Reason: {details.get('reason', 'No reason provided')}
                </div>
                """
                # Add not-triggered class to the transaction div
                transaction_html = transaction_html.replace('class="transaction"', 'class="transaction not-triggered"')
            
            # Add collapsible details
            transaction_html += f"""
            <div class="collapsible" onclick="toggleContent('details-{transaction.transaction_id}')">
                Click to show/hide rule details
            </div>
            <div class="content" id="details-{transaction.transaction_id}">
                <pre>{json.dumps(details, indent=2, cls=CustomJSONEncoder)}</pre>
            </div>
            """
            
        except Exception as e:
            # Handle exceptions for this transaction
            import traceback
            transaction_html += f"""
            <div class="alert">
                <strong>⚠️ ERROR Processing Transaction</strong>
                <pre>{str(e)}\n{traceback.format_exc()}</pre>
            </div>
            """
        
        # Close the transaction div
        transaction_html += "</div>"
        
        # Add this transaction's HTML to the main content
        html_content += transaction_html
    
    # Calculate processing time
    processing_time = time.time() - start_time
    
    # Complete the HTML content
    html_content += f"""
        </div>
        
        <div class="summary">
            <h2>Processing Complete</h2>
            <p>Total processing time: {processing_time:.2f} seconds</p>
            <p>Total transactions processed: {total_count}</p>
            <p>Alerts triggered: {triggered_count}</p>
        </div>
        
        <script>
            // Update the summary
            document.getElementById('total-count').textContent = '{total_count}';
            document.getElementById('triggered-count').textContent = '{triggered_count}';
        </script>
    </body>
    </html>
    """
    
    return HttpResponse(html_content)

from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import json

from .model.transaction import Transactions
from .model.alert import SuspiciousTransactions, SuspiciousActivityReports
from .model.rule_settings import AMLRules
from .monitoring.monitor_service import TransactionMonitoringService

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
def rule_detail_view(request, rule_id):
    """View to show details of a rule."""
    rule = get_object_or_404(AMLRules, rule_code=rule_id.split('-', 1)[1] if '-' in rule_id else rule_id)
    return render(request, 'monitoring/rule_detail.html', {'rule': rule})

@login_required
def rule_update_view(request, rule_id):
    """View to update a rule."""
    rule = get_object_or_404(AMLRules, rule_code=rule_id.split('-', 1)[1] if '-' in rule_id else rule_id)
    
    if request.method == 'POST':
        # Get parameters from POST data
        enabled = request.POST.get('enabled') == 'on'
        thresholds = json.loads(request.POST.get('thresholds', '{}'))
        recurrence_settings = json.loads(request.POST.get('recurrence_settings', '{}'))
        
        # Update rule settings
        rule.enabled = enabled
        rule.set_thresholds(thresholds)
        rule.set_recurrence_settings(recurrence_settings)
        rule.save()
        
        # Update rule in the monitoring service
        full_rule_id = f"AML-{rule.rule_code}"
        config = {
            'rule_id': full_rule_id,
            'rule_name': rule.rule_name,
            'description': rule.description,
            'alert_level': rule.alert_level,
            'evaluation_trigger': rule.evaluation_trigger,
            'scoring_algorithm': rule.scoring_algorithm,
            'transaction_types': rule.transaction_types.split(',') if rule.transaction_types else ['ALL-ALL'],
            'thresholds': thresholds,
            'recurrence': recurrence_settings,
            'enabled': enabled,
            'version': '1.0'
        }
        
        monitoring_service.update_rule_config(full_rule_id, config)
        
        return redirect('rule_detail', rule_id=rule_id)
    else:
        return render(request, 'monitoring/rule_update.html', {'rule': rule})

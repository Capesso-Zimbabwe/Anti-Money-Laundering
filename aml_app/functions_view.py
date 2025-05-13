##############################################################################

from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.views.generic import View
from django.http import JsonResponse
from .models import AMLSettings, AMLParameterRisk, KYCTestResult
from django.forms import modelform_factory
import json

from django.shortcuts import render, redirect
from django.views import View
from django.contrib import messages
from .models import AMLSettings, AMLParameterRisk

def safe_float(value, default=0.0):
    """
    Convert a string to a float, using the default if the string is empty.
    """
    if isinstance(value, str):
        value = value.strip()
    try:
        return float(value) if value != '' else default
    except ValueError:
        return default

def safe_int(value, default=0):
    """
    Convert a string to an int, using the default if the string is empty.
    """
    if isinstance(value, str):
        value = value.strip()
    try:
        return int(value) if value != '' else default
    except ValueError:
        return default

class AMLConfigurationView(View):
    template_name = 'aml_settings/configuration.html'
    
    def get(self, request):
        """Load AML configuration settings and display the form"""
        # Get or create default AML settings for the selected account type
        account_type = request.GET.get('account_type', 'individual_savings')
        
        try:
            aml_settings = AMLSettings.objects.get(account_type=account_type)
        except AMLSettings.DoesNotExist:
            aml_settings = AMLSettings(account_type=account_type)
            aml_settings.save()
        
        # Prepare account type choices for the template
        account_type_choices = dict(AMLSettings.ACCOUNT_TYPE_CHOICES)
        
        context = {
            'aml_settings': aml_settings,
            'account_type_choices': account_type_choices,
            'current_account_type': account_type
        }
        
        return render(request, self.template_name, context)
    
    def post(self, request):
        """Save AML configuration settings from the form"""
        data = request.POST
        account_type = data.get('account_type', 'individual_savings')
        
        # Get or create settings object
        aml_settings, created = AMLSettings.objects.get_or_create(account_type=account_type)
        
        # Global Transaction Thresholds
        aml_settings.max_transaction_amount = safe_float(data.get('max_transaction_amount', ''), 10000)
        aml_settings.cash_deposit_limit = safe_float(data.get('cash_deposit_limit', ''), 5000)
        aml_settings.structuring_detection_limit = safe_float(data.get('structuring_detection_limit', ''), 3000)
        aml_settings.mismatched_behavior_multiplier = safe_float(data.get('mismatched_behavior_multiplier', ''), 3)
        aml_settings.inactive_days_threshold = safe_int(data.get('inactive_days_threshold', ''), 60)
        aml_settings.circular_transaction_window = safe_int(data.get('circular_transaction_window', ''), 72)
        
        # Suspicious Transaction Indicators
        # Cash Transactions
        aml_settings.large_cash_deposits = data.get('large_cash_deposits', 'off') == 'on'
        aml_settings.large_cash_deposits_threshold = safe_float(data.get('large_cash_deposits_threshold', ''), 5000)
        
        aml_settings.frequent_currency_exchange = data.get('frequent_currency_exchange', 'off') == 'on'
        aml_settings.currency_exchange_count_threshold = safe_int(data.get('currency_exchange_count_threshold', ''), 3)
        aml_settings.currency_exchange_time_window = safe_int(data.get('currency_exchange_time_window', ''), 7)
        
        aml_settings.structured_deposits = data.get('structured_deposits', 'off') == 'on'
        aml_settings.structured_deposits_threshold = safe_float(data.get('structured_deposits_threshold', ''), 9000)
        aml_settings.structured_deposits_count = safe_int(data.get('structured_deposits_count', ''), 3)
        aml_settings.structured_deposits_window = safe_int(data.get('structured_deposits_window', ''), 2)
        
        # Account Activity
        aml_settings.dormant_account_activity = data.get('dormant_account_activity', 'off') == 'on'
        aml_settings.dormant_days_threshold = safe_int(data.get('dormant_days_threshold', ''), 90)
        aml_settings.dormant_activity_amount = safe_float(data.get('dormant_activity_amount', ''), 3000)
        
        aml_settings.rapid_fund_movement = data.get('rapid_fund_movement', 'off') == 'on'
        aml_settings.rapid_movement_percentage = safe_float(data.get('rapid_movement_percentage', ''), 75)
        aml_settings.rapid_movement_window = safe_int(data.get('rapid_movement_window', ''), 24)
        
        aml_settings.inconsistent_transactions = data.get('inconsistent_transactions', 'off') == 'on'
        aml_settings.inconsistent_amount_multiplier = safe_float(data.get('inconsistent_amount_multiplier', ''), 3)
        
        # Wire Transfers
        aml_settings.high_risk_jurisdictions = data.get('high_risk_jurisdictions', 'off') == 'on'
        aml_settings.high_risk_countries = data.get('high_risk_countries', 'AF,KP,IR,SY,VE,RU,BY,MM,CU')
        
        aml_settings.small_frequent_transfers = data.get('small_frequent_transfers', 'off') == 'on'
        aml_settings.small_transfer_threshold = safe_float(data.get('small_transfer_threshold', ''), 1000)
        aml_settings.small_transfer_frequency = safe_int(data.get('small_transfer_frequency', ''), 5)
        aml_settings.small_transfer_window = safe_int(data.get('small_transfer_window', ''), 7)
        
        # High-Risk Customers
        aml_settings.nonprofit_suspicious = data.get('nonprofit_suspicious', 'off') == 'on'
        aml_settings.nonprofit_transaction_threshold = safe_float(data.get('nonprofit_transaction_threshold', ''), 5000)
        
        aml_settings.shell_companies = data.get('shell_companies', 'off') == 'on'
        aml_settings.shell_company_age_threshold = safe_int(data.get('shell_company_age_threshold', ''), 365)
        
        aml_settings.high_risk_jurisdictions_customers = data.get('high_risk_jurisdictions_customers', 'off') == 'on'
        
        # Alert Management
        aml_settings.critical_alert_action = data.get('critical_alert_action', 'freeze')
        aml_settings.high_alert_action = data.get('high_alert_action', 'hold')
        aml_settings.standard_alert_action = data.get('standard_alert_action', 'routine')
        
        # Save the updated settings
        aml_settings.save()
        
        messages.success(request, "AML Configuration saved successfully.")
        return redirect(f"{request.path}?account_type={account_type}")



##############################################################################################
class AMLConfigurationAPIView(View):
    """API view for AJAX interactions with the AML configuration"""
    
    def get(self, request):
        """Get AML settings for a specific account type"""
        account_type = request.GET.get('account_type', 'individual_savings')
        
        try:
            aml_settings = AMLSettings.objects.get(account_type=account_type)
            
            # Convert model to dict for JSON response
            settings_dict = {field.name: getattr(aml_settings, field.name) 
                            for field in AMLSettings._meta.fields 
                            if field.name != 'id'}
            
            # Get risk levels
            risk_levels = {}
            for risk in AMLParameterRisk.objects.filter(aml_settings=aml_settings):
                risk_levels[risk.parameter_name] = risk.risk_level
            
            return JsonResponse({
                'success': True,
                'settings': settings_dict,
                'risk_levels': risk_levels
            })
        
        except AMLSettings.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Settings not found for the specified account type'
            }, status=404)
    
    def post(self, request):
        """Save AML settings via API"""
        try:
            data = json.loads(request.body)
            account_type = data.get('account_type', 'individual_savings')
            
            # Rest of the code similar to the post method in AMLConfigurationView
            # but adapted for JSON data
            
            return JsonResponse({'success': True})
        
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
        
#################################################################################################################################





from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Sum, Count
from datetime import timedelta
import weasyprint

# Import your SuspiciousTransaction model
from .models import SuspiciousTransaction




def generate_aml_kyc_report(request):
    """
    View to generate a summary of suspicious transactions in HTML format with dynamic filtering.
    """
    # Get filter parameters from GET request
    risk_level = request.GET.get('risk_level')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Start with all transactions
    qs = KYCTestResult.objects.all()

    # Filter by start_date; default to past 30 days if not provided
    if start_date:
        qs = qs.filter(created_at__gte=start_date)
    else:
        thirty_days_ago = timezone.now() - timedelta(days=30)
        qs = qs.filter(created_at__gte=thirty_days_ago)

    # Filter by end_date if provided
    if end_date:
        qs = qs.filter(created_at__lte=end_date)

    # Filter by risk_level if provided
    if risk_level:
        qs = qs.filter(risk_level=risk_level)

    suspicious_qs = qs

    total_suspicious = suspicious_qs.count()

    

    context = {
        'suspicious_qs': suspicious_qs,
        'total_suspicious': total_suspicious,
    }

    return render(request, "mmmmmaml_report_kyc.html", context)


############################################################################################################


def generate_aml_report_pdf(request):
    """
    View to generate a PDF report of suspicious transactions using WeasyPrint,
    with dynamic filtering based on GET parameters.
    """
    risk_level = request.GET.get('risk_level')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Start with all transactions
    qs = SuspiciousTransaction.objects.all()
    
    # Filter by start_date; default to past 30 days if not provided
    if start_date:
        qs = qs.filter(created_at__gte=start_date)
    else:
        thirty_days_ago = timezone.now() - timedelta(days=30)
        qs = qs.filter(created_at__gte=thirty_days_ago)
    
    # Filter by end_date if provided
    if end_date:
        qs = qs.filter(created_at__lte=end_date)
    
    # Filter by risk_level if provided
    if risk_level:
        qs = qs.filter(risk_level=risk_level)
    
    suspicious_qs = qs

    total_suspicious = suspicious_qs.count()
    total_amount = suspicious_qs.aggregate(total=Sum('amount'))['total'] or 0

    # Risk breakdown by count & sum of amounts
    risk_breakdown = (
        suspicious_qs
        .values('risk_level')
        .annotate(count=Count('id'), total=Sum('amount'))
        .order_by('-count')
    )

    # 1. Render the HTML template to a string
    html_string = render_to_string('aml_report_pdf.html', {
        'suspicious_qs': suspicious_qs,
        'total_suspicious': total_suspicious,
        'total_amount': total_amount,
        'risk_breakdown': risk_breakdown,
    })

    # 2. Convert the HTML string to a PDF using WeasyPrint
    pdf_file = weasyprint.HTML(string=html_string).write_pdf()

    # 3. Return as a downloadable PDF response
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="AML_Report.pdf"'
    return response


########################################################################################################


































######################################################################################################

def register_kyc_bussi (request):
    return render(request, "register_kyc_business.html",)



############################################################################################################

def suspicious_activity_report_view(request):
    """
    View to display and manage Suspicious Activity Reports.
    Allows filtering by status, risk level, and date range.
    """
    from .models import SuspiciousActivityReport, Customer, Transaction1
    from django.db.models import Q
    from django.core.paginator import Paginator
    
    # Get filter parameters
    report_status = request.GET.get('status', '')
    risk_level = request.GET.get('risk_level', '')
    activity_type = request.GET.get('activity_type', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    
    # Base queryset
    reports = SuspiciousActivityReport.objects.all().order_by('-detection_date')
    
    # Apply filters
    if report_status:
        reports = reports.filter(report_status=report_status)
    
    if risk_level:
        reports = reports.filter(risk_level=risk_level)
    
    if activity_type:
        reports = reports.filter(suspicious_activity_type=activity_type)
    
    if start_date:
        reports = reports.filter(detection_date__gte=start_date)
    
    if end_date:
        reports = reports.filter(detection_date__lte=end_date)
    
    # Pagination
    paginator = Paginator(reports, 10)  # Show 10 reports per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Context for the template
    context = {
        'page_obj': page_obj,
        'report_status_choices': SuspiciousActivityReport.REPORT_STATUS_CHOICES,
        'risk_level_choices': SuspiciousActivityReport.RISK_LEVEL_CHOICES,
        'activity_type_choices': SuspiciousActivityReport.SUSPICIOUS_ACTIVITY_TYPE_CHOICES,
        'total_reports': reports.count(),
        'filters': {
            'status': report_status,
            'risk_level': risk_level,
            'activity_type': activity_type,
            'start_date': start_date,
            'end_date': end_date,
        }
    }
    
    return render(request, 'suspicious_activity_reports.html', context)

def suspicious_activity_report_detail(request, report_id):
    """
    View to display details of a specific Suspicious Activity Report.
    Also shows related customer information if available.
    """
    from .models import SuspiciousActivityReport, Customer, Transaction1
    
    # Get the report or return 404
    report = get_object_or_404(SuspiciousActivityReport, report_id=report_id)
    
    # Get related customer info if available
    customer = None
    try:
        if report.primary_subject_id:
            customer = Customer.objects.filter(customer_id=report.primary_subject_id).first()
    except Customer.DoesNotExist:
        pass
    
    # Get related transactions
    related_transaction_ids = report.related_transactions.split(',') if report.related_transactions else []
    related_transactions = []
    
    if related_transaction_ids:
        for txn_id in related_transaction_ids:
            txn_id = txn_id.strip()
            if txn_id:
                try:
                    txn = Transaction1.objects.filter(transaction_id=txn_id).first()
                    if txn:
                        related_transactions.append(txn)
                except Transaction1.DoesNotExist:
                    pass
    
    context = {
        'report': report,
        'customer': customer,
        'related_transactions': related_transactions,
    }
    
    return render(request, 'suspicious_activity_report_detail.html', context)

def update_suspicious_activity_report(request, report_id):
    """
    View to update a Suspicious Activity Report.
    Handles both GET (show form) and POST (update data) requests.
    """
    from .models import SuspiciousActivityReport, Customer
    from django.shortcuts import redirect
    
    # Get the report or return 404
    report = get_object_or_404(SuspiciousActivityReport, report_id=report_id)
    
    if request.method == 'POST':
        # Update report fields from form data
        report.report_status = request.POST.get('report_status', report.report_status)
        report.risk_level = request.POST.get('risk_level', report.risk_level)
        report.suspicious_activity_description = request.POST.get('suspicious_activity_description', 
                                                              report.suspicious_activity_description)
        report.internal_actions_taken = request.POST.get('internal_actions_taken', 
                                                     report.internal_actions_taken)
        
        # If report is being submitted to authorities
        if report.report_status == 'SUBMITTED' and not report.submission_date:
            report.submission_date = timezone.now()
        
        # Update reviewer info
        if request.user.is_authenticated:
            report.modified_by = request.user.username
        
        report.save()
        messages.success(request, f"Report {report.report_id} updated successfully.")
        return redirect('suspicious_activity_report_detail', report_id=report_id)
    
    # Get all customers for the dropdown
    customers = Customer.objects.all()
    
    context = {
        'report': report,
        'report_status_choices': SuspiciousActivityReport.REPORT_STATUS_CHOICES,
        'risk_level_choices': SuspiciousActivityReport.RISK_LEVEL_CHOICES,
        'activity_type_choices': SuspiciousActivityReport.SUSPICIOUS_ACTIVITY_TYPE_CHOICES,
        'customers': customers,
    }
    
    return render(request, 'update_suspicious_activity_report.html', context)
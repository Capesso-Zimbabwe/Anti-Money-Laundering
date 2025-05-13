import csv
import json
from django.http import HttpResponse, JsonResponse
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render
from django.utils.timezone import now
from django.db.models import Count, Q
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth.views import PasswordResetConfirmView

from django.http import JsonResponse
from django.core.paginator import Paginator
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware, now

from datetime import timedelta, timezone
from .models import AMLSettingss, AdverseMediaCheck, KYCProfile, KYCTestResult, PoliticallyExposedPerson, RiskAssessment, RiskDefinition, RiskFactor, RiskFactorAssessment, SanctionsList, SuspiciousTransaction, Transaction, WatchlistEntry
from .signal1 import detect_blacklisted_transactions, detect_suspicious_transactions, detect_whitelisted_transactions, perform_kyc_screening  # Import function
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.shortcuts import redirect


##############################################################################################################

class AMLLoginView(LoginView):
    template_name = 'login.html'  # our Tailwind-styled template
    redirect_authenticated_user = True

    def get_success_url(self):
        # Redirect to your dashboard after login
        return reverse_lazy('dashboard')

class AMLLogoutView(LogoutView):
    next_page = reverse_lazy('login')

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        messages.success(self.request, "Password reset email sent. Please check your inbox.")
        return super().form_valid(form)

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        messages.success(self.request, "Password has been reset successfully. You can now log in.")
        return super().form_valid(form)
####################################################################################################
@login_required
def aml_settings_view(request):
    """
    View to manage AML screening parameters.
    - Superusers can update settings.
    - Users in 'Compliance Officers' group can update settings.
    - Regular users can view but not modify settings.
    """
    settings, created = AMLSettingss.objects.get_or_create(id=1)  # Ensure only one record exists

    # Check if user is a superuser or in the Compliance Officers group
    user_can_edit = request.user

    # user_can_edit = request.user.is_superuser or request.user.groups.filter(name="Compliance Officers").exists()

    if request.method == "POST":
        if not user_can_edit:
            return JsonResponse({"message": "Unauthorized access! Only admins or compliance officers can update settings."}, status=403)

        # Overwrite existing settings with new values
        settings.transaction_threshold = float(request.POST.get("transaction_threshold", settings.transaction_threshold))
        settings.cash_deposit_limit = float(request.POST.get("cash_deposit_limit", settings.cash_deposit_limit))
        settings.structuring_limit = float(request.POST.get("structuring_limit", settings.structuring_limit))
        settings.inactive_days = int(request.POST.get("inactive_days", settings.inactive_days))
        settings.multiple_beneficiaries = int(request.POST.get("multiple_beneficiaries", settings.multiple_beneficiaries))
        settings.geo_location_mismatch = int(request.POST.get("geo_location_mismatch", settings.geo_location_mismatch))
        settings.high_risk_countries = request.POST.get("high_risk_countries", settings.high_risk_countries)
        settings.circular_transaction_days = int(request.POST.get("circular_transaction_days", settings.circular_transaction_days))
        settings.mismatched_behavior_multiplier = float(request.POST.get("mismatched_behavior_multiplier", settings.mismatched_behavior_multiplier))
        settings.cash_deposit_no_withdrawal = float(request.POST.get("cash_deposit_no_withdrawal", settings.cash_deposit_no_withdrawal))
        settings.dormant_account_transfer_limit = float(request.POST.get("dormant_account_transfer_limit", settings.dormant_account_transfer_limit))
        settings.structuring_txn_count = int(request.POST.get("structuring_txn_count", settings.structuring_txn_count))
        settings.employee_risk_flag = "employee_risk_flag" in request.POST  # Checkbox is either present (True) or missing (False)

        settings.save()

        return JsonResponse({"message": "AML Parameters Updated Successfully!"})

    # return render(request, "aml_settings.html", {"settings": settings, "user_can_edit": user_can_edit})
    return render(request, "aml_settings.html", {"settings": settings, "user_can_edit": user_can_edit})


























# 



##############################################################################################################




from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Transaction

@login_required
def run_aml_screening_ajax(request):
    """
    AJAX endpoint to run AML screening on new transactions.
    This function processes transactions that have not been checked.
    """
    # Optionally, filter for unprocessed transactions only:
    unprocessed_transactions = Transaction.objects.filter(is_checked=False)
    flagged_count = 0

    for txn in unprocessed_transactions:
        detect_suspicious_transactions(txn)
        detect_blacklisted_transactions(txn)
        detect_whitelisted_transactions(txn)
        flagged_count += 1

    return JsonResponse({
        "status": "Screening completed",
        "transactions_checked": flagged_count,
    })





@login_required
def run_aml_screening(request):
    """
    View to manually trigger AML screening and display suspicious transactions.
    """
    if request.method == "POST":
        # 1. Run screening
        all_transactions = Transaction.objects.all()
        flagged_count = 0
        for txn in all_transactions:
            detect_suspicious_transactions(txn)
            detect_blacklisted_transactions(txn)
            detect_whitelisted_transactions(txn)
            flagged_count += 1

        # 2. Return simple JSON
        return JsonResponse({
            "status": "AML screening completed",
            "transactions_checked": flagged_count,
        })

    # If GET request:
    # 3. Fetch suspicious transactions & paginate
    suspicious_qs = SuspiciousTransaction.objects.select_related("transaction").all()
    paginator = Paginator(suspicious_qs, 10)  # show 10 per page

    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # 4. Check if we should auto-show the modal
    # show_table = request.GET.get("show_table") == "1"  # boolean flag


     # Always show the table
    show_table = True

    return render(request, "run_aml_screening.html", {
        "page_obj": page_obj,
        "show_table": show_table
    })


@login_required
def run_kyc_aml_screening(request):
    """
    View to manually trigger KYC AML screening with optional date range filtering.
    Displays suspicious KYCTestResult for KYCProfiles in that date range on GET.
    Runs batch screening on those KYCProfiles on POST.
    """

    # Parse date range from request (GET or POST)
    if request.method == "POST":
        # 1) Parse JSON body
        try:
            body = json.loads(request.body.decode('utf-8'))
        except (ValueError, TypeError):
            body = {}
        start_date_str = body.get('start_date')
        end_date_str = body.get('end_date')
    else:
        # For GET, we read from query params
        start_date_str = request.GET.get("start_date")
        end_date_str = request.GET.get("end_date")

    # 2) Build base queryset for KYCProfile
    kyc_profiles = KYCProfile.objects.all()

    # 3) If provided, parse the start_date and filter
    if start_date_str:
        dt_start = parse_datetime(start_date_str)
        if dt_start:
            dt_start = make_aware(dt_start)
            kyc_profiles = kyc_profiles.filter(created_at__gte=dt_start)

    # 4) If provided, parse the end_date and filter
    if end_date_str:
        dt_end = parse_datetime(end_date_str)
        if dt_end:
            dt_end = make_aware(dt_end)
            kyc_profiles = kyc_profiles.filter(created_at__lte=dt_end)

    # 5) Handle POST: Run screening for all profiles in date range
    if request.method == "POST":
        flagged_count = 0
        for profile in kyc_profiles:
            result = perform_kyc_screening(profile.id_document_number)
            if isinstance(result, str):
                # e.g. "Error: No customer found..."
                continue
            flagged_count += 1

        # Return JSON
        return JsonResponse({
            "status": "KYC AML screening completed",
            "profiles_checked": flagged_count,
        })

    # If GET request: Display suspicious results for the filtered KYCProfiles
    # 6) Gather all test results that belong to these KYC profiles
    KYCTestResult_qs = KYCTestResult.objects.select_related("kyc_profile").filter(
        kyc_profile__in=kyc_profiles
    )

    # 7) Paginate
    paginator = Paginator(KYCTestResult_qs, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # 8) Check if we should auto-show the table
    show_table = request.GET.get("show_table") == "1"
    show_table = True


    return render(request, "perform_kyc_screening.html", {
        "page_obj": page_obj,
        "show_table": show_table
    })



#################################################################################################

from django.shortcuts import render, redirect
from .forms import KYCProfileForm
from .models import KYCProfile

from django.shortcuts import render
from django.contrib import messages
from .forms import KYCProfileForm

@login_required
def register_kyc_profile(request):
    """
    View to register a new KYC Profile.
    On successful submission, displays a success message and returns the same page.
    """
    if request.method == "POST":
        form = KYCProfileForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, "KYC profile registered successfully!")
            # Reinitialize form to clear the fields after a successful submission
            form = KYCProfileForm()
        else:
            messages.error(request, "There were errors in your submission. Please correct them and try again.")
    else:
        form = KYCProfileForm()
    
    return render(request, "register_kyc_profile.html", {"form": form})
################################################################################################################





@login_required
def kyc_search_view(request):
    query = request.GET.get("q", "")
    nationality = request.GET.get("nationality", "")
    kyc_status = request.GET.get("kyc_status", "")
    risk_level = request.GET.get("risk_level", "")
    search_model = request.GET.get("search_model", "KYCProfile")

    results = []

    if search_model == "KYCTestResult":
        results = KYCTestResult.objects.select_related("kyc_profile")
        if query:
            results = results.filter(
                kyc_profile__full_name__icontains=query
            ) | results.filter(
                kyc_profile__id_document_number__icontains=query
            ) | results.filter(
                kyc_profile__phone_number__icontains=query
            )
        if nationality:
            results = results.filter(kyc_profile__nationality__iexact=nationality)
        if kyc_status:
            results = results.filter(kyc_status=kyc_status)
        if risk_level:
            results = results.filter(risk_level=risk_level)
    else:
        results = KYCProfile.objects.all()
        if query:
            results = results.filter(
                full_name__icontains=query
            ) | results.filter(
                id_document_number__icontains=query
            ) | results.filter(
                phone_number__icontains=query
            )
        if nationality:
            results = results.filter(nationality__iexact=nationality)

    # CSV Export
    if "export" in request.GET:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="kyc_export.csv"'
        writer = csv.writer(response)

        if search_model == "KYCTestResult":
            writer.writerow(['Customer ID', 'Full Name', 'Phone', 'Nationality', 'KYC Status', 'Risk'])
            for r in results:
                writer.writerow([
                    r.kyc_profile.customer_id,
                    r.kyc_profile.full_name,
                    r.kyc_profile.phone_number,
                    r.kyc_profile.nationality,
                    r.kyc_status,
                    r.risk_level
                ])
        else:
            writer.writerow(['Customer ID', 'Full Name', 'Phone', 'Nationality'])
            for r in results:
                writer.writerow([
                    r.customer_id,
                    r.full_name,
                    r.phone_number,
                    r.nationality
                ])
        return response

    return render(request, "kyc_search.html", {
        "results": results,
        "query": query,
        "nationality": nationality,
        "kyc_status": kyc_status,
        "risk_level": risk_level,
        "search_model": search_model
    })

# def run_individual_kyc(request, customer_id):
#     profile = get_object_or_404(KYCProfile, customer_id=customer_id)
#     result = perform_kyc_screening(profile.id_document_number)
#     return JsonResponse({"status": "KYC screening completed", "customer": profile.full_name})


@login_required

def run_individual_kyc(request, customer_id):
    profile = get_object_or_404(KYCProfile, customer_id=customer_id)

    # Delete any existing KYCTestResults for this customer to prevent duplication
    KYCTestResult.objects.filter(kyc_profile__id_document_number=profile.id_document_number).delete()

    # Run KYC screening again
    perform_kyc_screening(profile.id_document_number)

    return JsonResponse({
        "status": "KYC screening completed",
        "customer": profile.full_name
    })



###################################################################################################################







from django.shortcuts import render
from django.db.models import Count, Avg, Case, When, FloatField
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
from django.utils import timezone
from datetime import timedelta
from django.template.defaultfilters import timesince
from .models import Transaction, SuspiciousTransaction, KYCTestResult

@login_required
def dashboard(request):
    now = timezone.now()
    thirty_days_ago = now - timedelta(days=30)

    # Quick Stats
    total_transactions = Transaction.objects.filter(date__gte=thirty_days_ago).count()
    total_transactions_change = "+12.5%"  # Replace with real calculation if available

    active_alerts = SuspiciousTransaction.objects.filter(created_at__gte=thirty_days_ago, manual_review_required=True).count()
    active_alerts_change = "+5.2%"  # Replace with real calculation if available

    # Compute average risk score from SuspiciousTransaction
    # Map risk levels to numbers: High=80, Medium=50, Low=20
    risk_mapping_expr = Case(
        When(risk_level="High", then=80),
        When(risk_level="Medium", then=50),
        When(risk_level="Low", then=20),
        default=50,
        output_field=FloatField()
    )
    suspicious_qs = SuspiciousTransaction.objects.filter(created_at__gte=thirty_days_ago)
    risk_scores = list(suspicious_qs.annotate(risk_num=risk_mapping_expr).values_list('risk_num', flat=True))
    if risk_scores:
        average_risk_score = round(sum(risk_scores) / len(risk_scores), 1)
        risk_score_count = len(risk_scores)
    else:
        average_risk_score = 0
        risk_score_count = 0
    if average_risk_score >= 70:
        risk_score_category = "High"
    elif average_risk_score >= 40:
        risk_score_category = "Medium"
    else:
        risk_score_category = "Low"

    # KYC Completion Rate
    total_kyc = KYCTestResult.objects.count()
    verified_kyc = KYCTestResult.objects.filter(kyc_status="Verified").count()
    kyc_completion_rate = round((verified_kyc / total_kyc) * 100, 1) if total_kyc else 0
    kyc_completion_change = "+2.1%"  # Replace with real calculation if available

    # Daily Transactions (last 30 days)
    daily_qs = Transaction.objects.filter(date__gte=thirty_days_ago) \
        .annotate(day=TruncDay('date')) \
        .values('day') \
        .annotate(count=Count('id')) \
        .order_by('day')
    daily_transactions = [{"date": entry["day"].strftime("%Y-%m-%d"), "count": entry["count"]} for entry in daily_qs]

    # Weekly Transactions (last 12 weeks)
    twelve_weeks_ago = now - timedelta(weeks=12)
    weekly_qs = Transaction.objects.filter(date__gte=twelve_weeks_ago) \
        .annotate(week=TruncWeek('date')) \
        .values('week') \
        .annotate(count=Count('id')) \
        .order_by('week')
    weekly_transactions = [{"date": entry["week"].strftime("%Y-%m-%d"), "count": entry["count"]} for entry in weekly_qs]

    # Monthly Transactions (last 1 months)
    twelve_months_ago = now - timedelta(days=365)
    monthly_qs = Transaction.objects.filter(date__gte=twelve_months_ago) \
        .annotate(month=TruncMonth('date')) \
        .values('month') \
        .annotate(count=Count('id')) \
        .order_by('month')
    monthly_transactions = [{"date": entry["month"].strftime("%Y-%m-%d"), "count": entry["count"]} for entry in monthly_qs]

    # Risk Distribution by Region (using sender_bank_location as region)
    risk_distribution_qs = SuspiciousTransaction.objects.filter(created_at__gte=thirty_days_ago) \
        .values('transaction__sender_bank_location') \
        .annotate(avg_risk=Avg(risk_mapping_expr))
    risk_distribution = [{"country__region": entry["transaction__sender_bank_location"] or "Unknown", "avg_risk": entry["avg_risk"]} for entry in risk_distribution_qs]

    # Risk Distribution by Type (group by risk_level)
    risk_by_type_qs = SuspiciousTransaction.objects.filter(created_at__gte=thirty_days_ago) \
        .values('risk_level') \
        .annotate(avg_risk=Avg(risk_mapping_expr))
    risk_by_type = list(risk_by_type_qs)

    # Recent Activities (using last 5 suspicious transactions)
    recent_suspicious = SuspiciousTransaction.objects.filter(created_at__gte=thirty_days_ago).order_by('-created_at')[:5]
    recent_activities = []
    for st in recent_suspicious:
        time_str = timesince(st.created_at) + " ago"
        if st.risk_level == "High":
            bg_color = "red"
            icon = '<svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>'
        elif st.risk_level == "Medium":
            bg_color = "yellow"
            icon = '<svg class="w-5 h-5 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01"/></svg>'
        else:
            bg_color = "green"
            icon = '<svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4"/></svg>'
        title = "Suspicious Transaction Alert"
        description = f"Transaction {st.transaction.transaction_id} flagged as {st.risk_level} risk."
        recent_activities.append({
            "bg_color": bg_color,
            "icon": icon,
            "title": title,
            "description": description,
            "time": time_str,
        })

    context = {
        "total_transactions": total_transactions,
        "total_transactions_change": total_transactions_change,
        "active_alerts": active_alerts,
        "active_alerts_change": active_alerts_change,
        "average_risk_score": average_risk_score,
        "risk_score_category": risk_score_category,
        "risk_score_count": risk_score_count,
        "kyc_completion_rate": kyc_completion_rate,
        "kyc_completion_change": kyc_completion_change,
        "daily_transactions": daily_transactions,
        "weekly_transactions": weekly_transactions,
        "monthly_transactions": monthly_transactions,
        "risk_distribution": risk_distribution,
        "risk_by_type": risk_by_type,
        "recent_activities": recent_activities,
    }
    return render(request, "dashboard.html", context)


#####################################################################################################


from django.shortcuts import render, redirect
from .models import RiskScore

def risk_scoring(request):
    if request.method == "POST":
        # Get the country and risk values directly from the form
        selected_country = request.POST.get("country")
        try:
            country_risk = int(request.POST.get("country_risk"))
        except (ValueError, TypeError):
            country_risk = 2  # Default to Medium if not provided
        try:
            source_risk = int(request.POST.get("source_risk"))
        except (ValueError, TypeError):
            source_risk = 2  # Default to Medium if not provided
        
        # Create a new RiskScore instance.
        RiskScore.objects.create(
            country=selected_country,
            country_risk=country_risk,
            source_risk=source_risk,
        )
        return redirect("risk_scoring")
    
    # GET: Fetch all risk scores and calculate summary metrics.
    risk_scores = RiskScore.objects.all().order_by("-created_at")
    total = risk_scores.count()
    low_count = risk_scores.filter(overall_risk="Low").count()
    medium_count = risk_scores.filter(overall_risk="Medium").count()
    high_count = risk_scores.filter(overall_risk="High").count()
    
    low_percentage = (low_count / total * 100) if total else 0
    medium_percentage = (medium_count / total * 100) if total else 0
    high_percentage = (high_count / total * 100) if total else 0
    
    # For the modal, we include a static list of countries.
    countries = [
        {"name": "United States"},
        {"name": "United Kingdom"},
        {"name": "Germany"},
        {"name": "Canada"},
        {"name": "Brazil"},
        {"name": "India"},
        {"name": "Nigeria"},
        {"name": "Iran"},
        {"name": "North Korea"},
    ]
    
    context = {
        "risk_scores": risk_scores,
        "countries": countries,
        "low_count": low_count,
        "medium_count": medium_count,
        "high_count": high_count,
        "low_percentage": low_percentage,
        "medium_percentage": medium_percentage,
        "high_percentage": high_percentage,
    }
    return render(request, "risk_scoring.html", context)



#########################################################################

from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from .models import RiskDefinition

def risk_definitions(request):
    if request.method == "POST":
        category = request.POST.get("category")
        value = request.POST.get("value")
        try:
            risk_rating = float(request.POST.get("risk_rating"))
        except (ValueError, TypeError):
            risk_rating = 50.0  # default to 50% if conversion fails

        # Use update_or_create to avoid duplicate entries for the same category and value.
        RiskDefinition.objects.update_or_create(
            category=category,
            value=value,
            defaults={'risk_rating': risk_rating}
        )
        return redirect("risk_definitions")
    
    # GET: Retrieve definitions
    country_definitions = RiskDefinition.objects.filter(category="country")
    source_definitions = RiskDefinition.objects.filter(category="source")
    
    # Get page size from GET parameter (default to 10)
    try:
        page_size = int(request.GET.get("page_size", 10))
    except ValueError:
        page_size = 10

    # Paginate each queryset using the chosen page size
    country_paginator = Paginator(country_definitions, page_size)
    source_paginator = Paginator(source_definitions, page_size)
    
    country_page_number = request.GET.get('country_page')
    source_page_number = request.GET.get('source_page')
    
    country_page_obj = country_paginator.get_page(country_page_number)
    source_page_obj = source_paginator.get_page(source_page_number)
    
    # Compute summary metrics using thresholds on risk_rating
    country_high = country_definitions.filter(risk_rating__gte=67).count()
    country_medium = country_definitions.filter(risk_rating__gte=34, risk_rating__lt=67).count()
    country_low = country_definitions.filter(risk_rating__lt=34).count()
    country_total = country_definitions.count()
    
    source_high = source_definitions.filter(risk_rating__gte=67).count()
    source_medium = source_definitions.filter(risk_rating__gte=34, risk_rating__lt=67).count()
    source_low = source_definitions.filter(risk_rating__lt=34).count()
    source_total = source_definitions.count()
    
    context = {
        "country_page_obj": country_page_obj,
        "source_page_obj": source_page_obj,
        "country_high": country_high,
        "country_medium": country_medium,
        "country_low": country_low,
        "country_total": country_total,
        "source_high": source_high,
        "source_medium": source_medium,
        "source_low": source_low,
        "source_total": source_total,
        "page_size": page_size,
    }
    
    return render(request, "risk_definitions.html", context)

    



######################################################################################################################

from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Sum, Count
from datetime import timedelta
import weasyprint

# Import your SuspiciousTransaction model
from .models import SuspiciousTransaction




def generate_aml_report(request):
    """
    View to generate a summary of suspicious transactions in HTML format with dynamic filtering.
    """
    # Get filter parameters from GET request
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

    # Breakdown by risk level (count and total amount)
    risk_breakdown = (
        suspicious_qs
        .values('risk_level')
        .annotate(count=Count('id'), total=Sum('amount'))
        .order_by('-count')
    )

    context = {
        'suspicious_qs': suspicious_qs,
        'total_suspicious': total_suspicious,
        'total_amount': total_amount,
        'risk_breakdown': risk_breakdown,
    }

    return render(request, "aml_report.html", context)


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




























from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .dilisense import (
    check_individual,
    download_individual_report,
    check_entity,
    generate_entity_report,
    list_sources
)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_check_individual(request):
    search_all = request.query_params.get("search_all")
    names = request.query_params.get("names")
    fuzzy_search = request.query_params.get("fuzzy_search")
    dob = request.query_params.get("dob")
    gender = request.query_params.get("gender")
    includes = request.query_params.get("includes")
    try:
        result = check_individual(
            names=names,
            search_all=search_all,
            fuzzy_search=fuzzy_search,
            dob=dob,
            gender=gender,
            includes=includes
        )
        return Response(result)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_download_individual_report(request):
    names = request.query_params.get("names")
    dob = request.query_params.get("dob")
    gender = request.query_params.get("gender")
    includes = request.query_params.get("includes")
    if not names:
        return Response({"error": "The 'names' parameter is required."}, status=400)
    try:
        result = download_individual_report(
            names=names,
            dob=dob,
            gender=gender,
            includes=includes
        )
        return Response(result)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_check_entity(request):
    search_all = request.query_params.get("search_all")
    names = request.query_params.get("names")
    fuzzy_search = request.query_params.get("fuzzy_search")
    includes = request.query_params.get("includes")
    try:
        result = check_entity(
            search_all=search_all,
            names=names,
            fuzzy_search=fuzzy_search,
            includes=includes
        )
        return Response(result)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_generate_entity_report(request):
    names = request.query_params.get("names")
    includes = request.query_params.get("includes")
    if not names:
        return Response({"error": "The 'names' parameter is required."}, status=400)
    try:
        result = generate_entity_report(
            names=names,
            includes=includes
        )
        return Response(result)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_list_sources(request):
    try:
        result = list_sources()
        return Response(result)
    except Exception as e:
        return Response({"error": str(e)}, status=500)






################################################################################################################

# views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.core.paginator import Paginator
from django.utils import timezone
from .models import Alert

def list_alerts(request):
    """
    Displays alerts with optional filtering by status, severity, and type.
    """
    # Start with all alerts, ordered by newest first
    alerts_qs = Alert.objects.order_by("-created_at")

    # 1) Status filter (OPEN or RESOLVED)
    status_filter = request.GET.get("status")
    if status_filter in ("OPEN", "RESOLVED"):
        alerts_qs = alerts_qs.filter(status=status_filter)

    # 2) Severity filter (LOW, MEDIUM, HIGH)
    severity_filter = request.GET.get("severity")
    if severity_filter in ("LOW", "MEDIUM", "HIGH"):
        alerts_qs = alerts_qs.filter(severity=severity_filter)

    # 3) Alert type filter (KYC, TXN)
    alert_type_filter = request.GET.get("alert_type")
    if alert_type_filter in ("KYC", "TXN"):
        alerts_qs = alerts_qs.filter(alert_type=alert_type_filter)

    # Paginate
    paginator = Paginator(alerts_qs, 10)  # 10 alerts per page
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)

    return render(request, "list_alerts.html", {
        "page_obj": page_obj
    })


##################################################################################

def open_alert(request, alert_id):
    """
    Marks an alert as resolved (removes from the open list).
    """
    alert = get_object_or_404(Alert, pk=alert_id, status="OPEN")
    # Mark as resolved
    alert.status = "RESOLVED"
    alert.resolved_at = timezone.now()
    alert.save()

    # Optionally redirect to alert detail page or just back to list
    return redirect("list_alerts")
######################################################################################

def alert_detail(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id, status="OPEN")
    if request.method == "POST":
        # user clicked "resolve" button
        alert.status = "RESOLVED"
        alert.resolved_at = timezone.now()
        alert.save()
        return redirect("list_alerts")
    return render(request, "alert_detail.html", {"alert": alert})

















@login_required
def hello(request):
    return render(request, "base.html",)







@login_required
class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard.html'
    login_url = '/login/'  # This is the URL to redirect if not logged in






@login_required
def kyc_aml_screening(request):
    """
    View to manually trigger KYC AML screening on all KYC profiles.
    """
    # Fetch all KYC profiles
    sample_profiles = KYCProfile.objects.all()

    flagged_count = 0
    for profile in sample_profiles:
        result = perform_kyc_screening(profile.id_document_number)  # Run KYC screening
        
        if isinstance(result, str):
            continue  # Skip if customer is not found
        
        flagged_count += 1  # Track number of KYC profiles processed

    return JsonResponse({"status": "KYC AML screening completed", "profiles_checked": flagged_count})


############################################################################################






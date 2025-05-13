import csv
import json
from datetime import timedelta, timezone
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from kyc_app import perform_kyc_screening
from kyc_app.models import KYCProfile, KYCTestResult
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware, now
from django.utils import timezone




###################################################################################################
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
##################################################################################################

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



###########################################################################################

from django.shortcuts import render, redirect
from .forms import KYCBusiForm, KYCProfileForm
from .models import KYCBusiness, KYCProfile

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

def register_kyc_bussi (request):
    return render(request, "register_kyc_business_reg.html",)

############################################################################################
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
###############################################################################################


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

    return render(request, "aml_report_kyc.html", context)


############################################################################################################



@login_required
def register_kyc_Busi(request):
    """
    View to register a new KYC Business with support for multi-step form and drafts.
    Ensures documents are stored in the correct path structure:
    businesses/business_{business_id}/{doc_type}/{filename}
    """
    if request.method == "POST":
        # Check if this is a draft or final submission
        is_draft = request.POST.get('is_draft') == 'true'
        current_step = int(request.POST.get('current_step', 1))
        
        # Process the form
        form = KYCBusiForm(request.POST, request.FILES)
        
        # Handle beneficial owners data from the hidden field
        beneficial_owners_json = request.POST.get('beneficial_owners', '[]')
        try:
            beneficial_owners = json.loads(beneficial_owners_json)
            # Validate that it's actually a list
            if not isinstance(beneficial_owners, list):
                beneficial_owners = []
        except json.JSONDecodeError:
            beneficial_owners = []
            
        if form.is_valid():
            # Save the profile but don't commit yet
            business_profile = form.save(commit=False)
            business_profile.is_draft = is_draft
            
            # Set the beneficial owners
            business_profile.beneficial_owners = beneficial_owners
            
            # Save the business profile first to generate an ID if it's a new record
            business_profile.save()
            
            # Now handle the documents - don't modify file names directly, let Django handle it
            # The business_document_path function in models.py will take care of the path structure
            if 'registration_document' in request.FILES:
                # The file is already correctly configured to use business_document_path
                # Don't modify the name, just let it be saved normally
                pass
                
            if 'tax_document' in request.FILES:
                # The file is already correctly configured to use business_document_path
                # Don't modify the name, just let it be saved normally
                pass
            
            # Save the business profile again to ensure files are properly saved
            business_profile.save()
            
            # If this is a final submission, update the workflow state
            if not is_draft:
                try:
                    # Transition to SUBMITTED state
                    workflow_state = business_profile.workflow_state
                    workflow_state.transition_to(
                        'SUBMITTED',
                        user=request.user.username if request.user.is_authenticated else 'Anonymous',
                        notes='Submitted via KYC registration form'
                    )
                    
                    # Import documents to Document model
                    try:
                        from kyc_app.views import import_id_document
                        if business_profile.registration_document or business_profile.tax_document:
                            import_id_document(business=business_profile)
                    except Exception as e:
                        messages.warning(request, f"Business profile saved but document import failed: {str(e)}")
                        
                except Exception as e:
                    messages.warning(request, f"Profile saved but workflow state update failed: {str(e)}")
            
            # Set success message based on draft status
            if is_draft:
                messages.success(request, "KYC business profile saved as draft. You can complete it later.")
            else:
                messages.success(request, "KYC business profile submitted successfully!")
            
            # Reinitialize form to clear the fields after a successful submission
            form = KYCBusiForm()
        else:
            # Show form errors
            messages.error(request, "There were errors in your submission. Please correct them and try again.")
    else:
        # For GET requests, check if we are resuming a draft
        draft_id = request.GET.get('resume_draft')
        if draft_id:
            try:
                # Try to find the draft profile
                draft_profile = KYCBusiness.objects.get(id=draft_id, is_draft=True)
                # Initialize form with the draft data
                form = KYCBusiForm(instance=draft_profile)
                messages.info(request, "You're editing a draft KYC profile. Complete and submit when ready.")
            except KYCBusiness.DoesNotExist:
                messages.error(request, "Draft profile not found.")
                form = KYCBusiForm()
        else:
            # Regular new form
            form = KYCBusiForm()
    
    # Get user's draft profiles for the dropdown
    if request.user.is_authenticated:
        # In a real app, you'd filter by the current user
        draft_profiles = KYCBusiness.objects.filter(is_draft=True)
    else:
        draft_profiles = []
    
    # Determine initial step based on form errors
    initial_step = 1
    if form.errors:
        if any(field in form.errors for field in ['business_id', 'business_name', 'registration_date', 'business_type', 'industry_sector']):
            initial_step = 1
        elif any(field in form.errors for field in ['registration_number', 'tax_id_number', 'registration_country', 'license_expiry_date']):
            initial_step = 2
        elif any(field in form.errors for field in ['business_email', 'business_phone', 'business_address', 'business_city', 'business_country']):
            initial_step = 3
        elif any(field in form.errors for field in ['ownership_structure', 'annual_revenue', 'source_of_funds', 'business_purpose', 'transaction_volume', 'beneficial_owners']):
            initial_step = 4
        elif any(field in form.errors for field in ['bank_name', 'account_number', 'account_type', 'swift_code']):
            initial_step = 5
    
    context = {
        "form": form,
        "draft_profiles": draft_profiles,
        "initial_step": initial_step
    }
    
    # Choose template based on preference - standard or multi-step
    template_name = 'register_kyc_dump.html'  # For the multi-step form
    
    return render(request, template_name, context)



############################################################

@login_required
def kyc_profile_drafts(request):
    """
    View to list all draft KYC profiles.
    """
    # In a real app, you'd filter by the current user
    draft_profiles = KYCProfile.objects.filter(is_draft=True)
    
    return render(request, "kyc_profile_drafts.html", {
        "draft_profiles": draft_profiles
    })

@login_required
def delete_kyc_draft(request, profile_id):
    """
    View to delete a draft KYC profile.
    """
    profile = get_object_or_404(KYCProfile, id=profile_id, is_draft=True)
    
    if request.method == "POST":
        profile.delete()
        messages.success(request, "Draft profile deleted successfully.")
        return redirect('kyc_app:kyc_profile_drafts')
    
    return render(request, "confirm_delete_draft.html", {
        "profile": profile
    })

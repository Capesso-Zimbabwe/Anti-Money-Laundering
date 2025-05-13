from datetime import datetime
import requests
from .models import DilisenseConfig

def get_dilisense_config():
    config = DilisenseConfig.objects.first()
    if not config:
        raise Exception("Capesso configuration not found. Please set up your API key in the admin.")
    return config
###########################################################################################################

# views.py
import requests
from django.http import HttpResponse, JsonResponse
from .models import DilisenseConfig

import requests
from django.http import JsonResponse
from django.shortcuts import render
from .models import DilisenseConfig

import requests
from django.shortcuts import render
from .models import DilisenseConfig

def check_individual(request):
    """
    View to handle searching individuals via DILISense checkIndividual endpoint.
    Filters results by source_type if specified (ALL, SANCTION, PEP, CRIMINAL).
    """
    # 1) Read query parameters from the GET request
    query = request.GET.get('query', '')  # e.g. "John Doe"
    source_type = request.GET.get('source_type', 'ALL')  # e.g. "PEP", "SANCTION", etc.
    
    # If no search term is provided, render the template without results
    if not query:
        return render(request, 'check_individual.html', {
            'error': "No search term provided."
        })
    
    # 2) Make sure we have a DilisenseConfig with an API key
    config = DilisenseConfig.objects.first()
    if not config:
        return render(request, 'check_individual.html', {
            'error': "Capesso API key not configured. Please set up CapessoConfig in admin."
        })
    
    # 3) Prepare DILISense request (names= query)
    url = "https://api.dilisense.com/v1/checkIndividual"
    params = {
        "names": query,  # searching only the name fields
        # We do NOT add includes= source_type here, because we plan to filter afterwards
    }
    headers = {
        "x-api-key": config.api_key,
        "Content-Type": "application/json"
    }
    
    try:
        # 4) Call DILISense
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        results = response.json()  # e.g. { 'total_hits': X, 'found_records': [...] }

        # 5) If there's an error or no 'found_records' in the data, handle it
        if 'found_records' not in results:
            return render(request, 'check_individual.html', {
                'error': "Invalid response from Capesso.",
                'results': None
            })
        
        # 6) Post-filter by source_type (if not 'ALL')
        if source_type != 'ALL':
            filtered = []
            for record in results['found_records']:
                # record['source_type'] might be "SANCTION", "PEP", "CRIMINAL", etc.
                if record.get('source_type', '').upper() == source_type.upper():
                    filtered.append(record)
            results['found_records'] = filtered
            # Update total_hits to reflect filtered records
            results['total_hits'] = len(filtered)



            # Save these results in the session for the PDF
        request.session['last_results'] = results
        request.session['last_query'] = query
        request.session['last_source_type'] = source_type

        
        
        # 7) Render results
        # If no matches remain after filtering, we can pass an error or let the template handle
        if results['total_hits'] == 0:
            return render(request, 'check_individual.html', {
                'error': "No records found for your search.",
                'results': results
            })
        
        
        
        return render(request, 'check_individual.html', {
            'results': results,
            'query': query,
            'source_type': source_type,
        })
    
    except requests.RequestException as e:
        # Handle network/HTTP errors
        return render(request, 'check_individual.html', {
            'error': f"Error communicating with Capesso: {str(e)}"
        })


###########################################################################################################
from django.template.loader import render_to_string
from weasyprint import HTML
from django.utils import timezone


def download_individual_report(request):
    """
    Generates a PDF from the last search results stored in session
    and returns it as a file download.
    """
    results = request.session.get('last_results')
    query = request.session.get('last_query', 'Unknown')
    source_type = request.session.get('last_source_type', 'ALL')

    if not results:
        # There's no stored data
        return HttpResponse("No data available for PDF.", status=400)

    # Optionally add a timestamp or any other info
    screening_time = timezone.now().strftime("%Y-%m-%d %H:%M:%S")

    # Render the PDF template to HTML
    html_string = render_to_string('pdf_template.html', {
        'results': results,
        'query': query,
        'source_type': source_type,
        'screening_time': screening_time,
    })

    # Convert HTML to PDF
    pdf_file = HTML(string=html_string).write_pdf()

    # Return as downloadable file
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="Capesso_AML_report.pdf"'
    return response







##########################################################################################################

def check_entity(search_all=None, names=None, fuzzy_search=None, includes=None):
    """
    Calls the DILISense checkEntity endpoint.
    """
    config = get_dilisense_config()
    url = "https://api.dilisense.com/v1/checkEntity"
    params = {}
    if search_all:
        params["search_all"] = search_all
    elif names:
        params["names"] = names
    if fuzzy_search:
        params["fuzzy_search"] = fuzzy_search
    if includes:
        params["includes"] = includes

    headers = {
        "x-api-key": config.api_key,
        "Content-Type": "application/json"
    }
    response = requests.get(url, params=params, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()

def generate_entity_report(names, includes=None):
    """
    Calls the DILISense generateEntityReport endpoint.
    Returns a Base64 encoded PDF report.
    """
    config = get_dilisense_config()
    url = "https://api.dilisense.com/v1/generateEntityReport"
    params = {"names": names}
    if includes:
        params["includes"] = includes

    headers = {
        "x-api-key": config.api_key,
        "Content-Type": "application/json"
    }
    response = requests.get(url, params=params, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()

def list_sources():
    """
    Calls the DILISense listSources endpoint.
    Returns the available sources as JSON.
    """
    config = get_dilisense_config()
    url = "https://api.dilisense.com/v1/listSources"
    headers = {
        "x-api-key": config.api_key,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()

# views.py
from django.shortcuts import render

def suspicious_transaction_report(request):
    # Sample data to populate the form
    report_data = {
        'reporting_date': '2025-04-08',
        'reporting_entity': 'First National Bank - Downtown Branch',
        'reporting_person': 'Jane Smith, Compliance Officer (555-123-4567)',
        
        # Individual details
        'individual': {
            'surname': 'Johnson',
            'full_name': 'Robert Allen Johnson',
            'nationality': 'Canadian',
            'account_numbers': 'AC-78932145, SA-45678912',
            'identity_number': 'Passport: P123456789',
        },
        
        # Company details
        'company': {
            'name': 'Global Trading Partners Ltd.',
            'registration_number': 'BN-12345678',
            'directors': 'Michael Wong, Sarah Edwards',
            'directors_contact': 'mwong@gtpl.com, sedwards@gtpl.com',
            'directors_address': '123 Business Park, Suite 400, Vancouver BC V6C 3E8',
            'company_account': 'AC-89654321',
            'directors_accounts': 'AC-12378945, AC-65498732',
            'business_type': 'Import/Export Trading',
            'address': '456 Harbor Avenue, Suite 500, Vancouver BC V6C 2T4',
        },
        
        # Transaction details
        'suspicious_date': '2025-04-01',
        'amount': '$475,000.00 USD',
        'transaction_types': ['electronic_funds_transfer', 'trust_account'],
        'transaction_comment': 'Multiple rapid transfers through various accounts',
        
        # Entity on whose behalf transaction was conducted
        'behalf_entity': {
            'name': 'Seaside Investments Inc.',
            'directors': 'Victor Strand, Maria Lopez',
            'business_type': 'Property Investment',
            'account_number': 'AC-36925814',
            'address': '789 Ocean Drive, Miami FL 33139, USA',
        },
        
        # Description of suspicious activity
        'suspicious_description': '''
        Client deposited $475,000 USD via wire transfer from an offshore account in the Cayman Islands. 
        Funds were immediately split into multiple smaller transactions (each below $10,000) and transferred to 5 different accounts across 3 different financial institutions within 24 hours.
        
        When questioned about the source of funds, client provided vague explanations and inconsistent documentation. Account history shows minimal activity for 8 months prior to this large transaction.
        
        Unusual pattern observed: funds ultimately consolidated back to a single account after passing through multiple entities.
        
        Attached bank statements show unusual pattern of deposits precisely below reporting thresholds.
        ''',
        
        # Action taken
        'action_description': '''
        1. Transaction temporarily held pending further review
        2. Enhanced due diligence initiated on all related accounts
        3. Notified bank's senior compliance team on April 2, 2025
        4. Contact made with FinCEN on April 3, 2025 (Reference #FIN-2025-78945)
        5. All related accounts placed under enhanced monitoring
        ''',
    }
    
    return render(request, 'transactions/suspicious_transaction_report.html', {'report': report_data})
from django import forms
from .models import KYCProfile, KYCBusiness

class KYCProfileForm(forms.ModelForm):
    """
    Form to register a new KYC Profile.
    """

    class Meta:
        model = KYCProfile
        exclude = ['created_at', 'updated_at', 'is_draft', 'completion_percentage']
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'YYYY-MM-DD'}),
            'id_expiry_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'YYYY-MM-DD'}),
            'address': forms.Textarea(attrs={'rows': 3, 'class': 'form-control', 'placeholder': 'Enter full address'}),
            'annual_income': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'E.g. 50000'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional for draft saving
        optional_fields = [
            'gender', 'id_document_file', 'id_expiry_date', 
            'occupation', 'employer_name', 'annual_income', 'source_of_funds'
        ]
        
        for field_name in optional_fields:
            self.fields[field_name].required = False
            
        # Add helpful placeholders and classes
        field_placeholders = {
            'customer_id': 'Enter unique customer ID',
            'full_name': 'Enter full legal name',
            'nationality': 'Select nationality',
            'id_document_number': 'Enter ID number (e.g. passport number)',
            'email': 'Enter email address',
            'phone_number': 'Enter phone number',
            'city': 'Enter city',
            'occupation': 'Enter current occupation',
            'employer_name': 'Enter employer name',
            'account_number': 'Enter account number',
        }
        
        for field_name, placeholder in field_placeholders.items():
            if field_name in self.fields:
                self.fields[field_name].widget.attrs.update({
                    'placeholder': placeholder,
                    'class': 'form-control'
                })

############################################################################################################
class KYCBusiForm(forms.ModelForm):
    """
    Form to register a new KYC ProBusiness file.
    """

    class Meta:
        model = KYCBusiness
        exclude = ['created_at', 'updated_at', 'is_draft', 'completion_percentage']
        widgets = {
            'registration_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'YYYY-MM-DD'}),
            'license_expiry_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'YYYY-MM-DD'}),
            'business_address': forms.Textarea(attrs={'rows': 3, 'class': 'form-control', 'placeholder': 'Enter full address'}),
            'annual_revenue': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'E.g. 50000'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional for draft saving
        optional_fields = [
            # 'gender', 'id_document_file', 'id_expiry_date', 
            # 'occupation', 'employer_name', 'annual_income', 'source_of_funds'
        ]
        
        for field_name in optional_fields:
            self.fields[field_name].required = False
            
        # Add helpful placeholders and classes
        field_placeholders = {
            'business_id': 'Enter unique Business ID',
            'business_name': 'Enter full legal Business Name',
            'business_type': 'Select busines type',
            'industry_sector': 'Select industry sector',
            'business_email': 'Enter email address',
            'business_phone': 'Enter phone number',
            'business_city': 'Enter city',
            'registration_number': 'Enter Registration Number',
            'business_country': 'Enter Business Country',
            'tax_id_number': 'Enter tax_id_number',
            'business_website': 'Enter Business Website',
            'business_country': 'Enter Business Country',
            
        }
        
        for field_name, placeholder in field_placeholders.items():
            if field_name in self.fields:
                self.fields[field_name].widget.attrs.update({
                    'placeholder': placeholder,
                    'class': 'form-control'
                })


############################################################################################################
class KYCBusinessForm(forms.ModelForm):
    """
    Form for registering a new business KYC profile.
    """
    class Meta:
        model = KYCBusiness
        fields = ['business_id', 'business_name', 'registration_date', 'business_type',
                  'industry_sector', 'business_website', 'business_email', 'business_phone',
                  'business_address', 'business_city', 'business_country', 'registration_number',
                  'registration_country', 'tax_id_number', 'license_expiry_date', 'registration_document', 
                  'tax_document', 'annual_revenue', 'source_of_funds', 'business_purpose', 
                  'high_risk_jurisdiction', 'sanctions_history', 'aml_policy', 'transaction_volume',
                  'bank_name', 'account_number', 'account_type', 'swift_code', 'compliance_officer']
        
        widgets = {
            'registration_date': forms.DateInput(attrs={'type': 'date'}),
            'license_expiry_date': forms.DateInput(attrs={'type': 'date'}),
            'business_purpose': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add helpful titles/labels to fields
        field_labels = {
            'business_id': 'Business ID',
            'business_name': 'Business Name',
            'registration_date': 'Registration Date',
            'business_type': 'Business Type',
            'industry_sector': 'Industry Sector',
            'business_website': 'Business Website',
            'business_email': 'Business Email',
            'business_phone': 'Business Phone Number',
            'business_address': 'Business Address',
            'business_city': 'City',
            'business_country': 'Country',
            'registration_number': 'Registration Number',
            'registration_country': 'Country of Registration',
            'tax_id_number': 'Tax ID Number',
            'license_expiry_date': 'License Expiry Date',
            'annual_revenue': 'Annual Revenue',
            'source_of_funds': 'Source of Funds',
            'business_purpose': 'Business Purpose',
            'transaction_volume': 'Transaction Volume',
            'bank_name': 'Bank Name',
            'account_number': 'Account Number',
            'account_type': 'Account Type',
            'swift_code': 'SWIFT/BIC Code',
            'compliance_officer': 'Compliance Officer Name'
        }
        
        for field_name, label in field_labels.items():
            if field_name in self.fields:
                self.fields[field_name].label = label
                
        # Add max_length validation message to help fields
        fifty_char_fields = [
            'business_id', 'business_type', 'industry_sector', 
            'ownership_structure', 'annual_revenue', 'source_of_funds',
            'transaction_volume', 'account_number', 'account_type', 'swift_code'
        ]
        
        for field_name in fifty_char_fields:
            if field_name in self.fields:
                self.fields[field_name].help_text = f"Maximum 50 characters"
    
    # Field-specific clean methods for validation
    def clean_business_id(self):
        value = self.cleaned_data.get('business_id')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Business ID must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_business_type(self):
        value = self.cleaned_data.get('business_type')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Business Type must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_industry_sector(self):
        value = self.cleaned_data.get('industry_sector')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Industry Sector must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_ownership_structure(self):
        value = self.cleaned_data.get('beneficial_owners')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Ownership Structure must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_annual_revenue(self):
        value = self.cleaned_data.get('annual_revenue')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Annual Revenue must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_source_of_funds(self):
        value = self.cleaned_data.get('source_of_funds')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Source of Funds must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_transaction_volume(self):
        value = self.cleaned_data.get('transaction_volume')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Transaction Volume must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_account_number(self):
        value = self.cleaned_data.get('account_number')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Account Number must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_account_type(self):
        value = self.cleaned_data.get('account_type')
        if value and len(value) > 50:
            raise forms.ValidationError(f"Account Type must be 50 characters or less. Current length: {len(value)}")
        return value
        
    def clean_swift_code(self):
        value = self.cleaned_data.get('swift_code')
        if value and len(value) > 50:
            raise forms.ValidationError(f"SWIFT/BIC Code must be 50 characters or less. Current length: {len(value)}")
        return value
    
    def clean(self):
        """Validate form data before saving to database"""
        cleaned_data = super().clean()
        
        # Additional cross-field validation if needed
        
        return cleaned_data

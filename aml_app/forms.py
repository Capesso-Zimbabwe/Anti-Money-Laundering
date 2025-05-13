from django import forms
from .models import KYCProfile

class KYCProfileForm(forms.ModelForm):
    """
    Form to register a new KYC Profile.
    """

    class Meta:
        model = KYCProfile

        fields = "__all__"  # Include all fields from the model except metadata fields

        widgets = {
            "date_of_birth": forms.DateInput(attrs={"type": "date"}),
            "id_expiry_date": forms.DateInput(attrs={"type": "date"}),
            "annual_income": forms.NumberInput(attrs={"step": "0.01"}),
 }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add a rounded class to the customer_id widget
        self.fields['customer_id'].widget.attrs.update({
            'class': 'rounded-full border border-gray-300 p-2'
        })
       

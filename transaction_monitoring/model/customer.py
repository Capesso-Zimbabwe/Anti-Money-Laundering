from django.db import models
from django.utils import timezone
import uuid


class Customer(models.Model):
    """
    Model representing a banking customer in a core banking system.
    Contains customer identification information, demographics, and risk indicators.
    """
    customer_id = models.CharField(max_length=64, primary_key=True)
    customer_number = models.CharField(max_length=64, unique=True, db_index=True)
    
    # Personal Identification
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)
    
    # KYC Data
    kyc_status = models.CharField(
        max_length=20,
        choices=[
            ('COMPLETE', 'Complete'),
            ('PENDING', 'Pending'),
            ('EXPIRED', 'Expired'),
            ('REJECTED', 'Rejected'),
        ],
        default='PENDING'
    )
    kyc_last_verified = models.DateField(null=True, blank=True)
    kyc_next_review = models.DateField(null=True, blank=True)
    
    # Contact Information
    email = models.EmailField(null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address_line1 = models.CharField(max_length=255, null=True, blank=True)
    address_line2 = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state_province = models.CharField(max_length=100, null=True, blank=True)
    postal_code = models.CharField(max_length=20, null=True, blank=True)
    country_code = models.CharField(max_length=10, null=True, blank=True)
    country_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Risk and Compliance
    risk_rating = models.CharField(
        max_length=20, 
        choices=[
            ('LOW', 'Low Risk'),
            ('MEDIUM', 'Medium Risk'),
            ('HIGH', 'High Risk'),
            ('EXTREME', 'Extreme Risk'),
        ],
        default='MEDIUM'
    )
    risk_score = models.IntegerField(default=50)
    pep_status = models.BooleanField(default=False, help_text="Politically Exposed Person status")
    sanctions_screening_status = models.CharField(
        max_length=20,
        choices=[
            ('CLEAR', 'Clear'),
            ('REVIEW', 'Under Review'),
            ('MATCH', 'Potential Match'),
            ('CONFIRMED', 'Confirmed Match'),
        ],
        default='CLEAR'
    )
    
    # Business Information
    customer_type = models.CharField(
        max_length=20,
        choices=[
            ('INDIVIDUAL', 'Individual'),
            ('BUSINESS', 'Business'),
            ('TRUST', 'Trust'),
            ('GOVERNMENT', 'Government'),
            ('NGO', 'Non-profit Organization'),
            ('OTHER', 'Other'),
        ],
        default='INDIVIDUAL'
    )
    business_name = models.CharField(max_length=255, null=True, blank=True)
    industry_code = models.CharField(max_length=20, null=True, blank=True)
    tax_id = models.CharField(max_length=50, null=True, blank=True)
    
    # Relationship Information
    customer_since = models.DateField(default=timezone.now)
    relationship_manager_id = models.CharField(max_length=64, null=True, blank=True)
    
    # Temporal Information 
    is_active = models.BooleanField(default=True)
    last_activity_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tm_customers'
        indexes = [
            models.Index(fields=['customer_type']),
            models.Index(fields=['risk_rating']),
            models.Index(fields=['kyc_status']),
            models.Index(fields=['is_active']),
            models.Index(fields=['last_activity_date']),
        ]
    
    def __str__(self):
        if self.customer_type == 'INDIVIDUAL':
            return f"{self.customer_number} - {self.first_name} {self.last_name}"
        else:
            return f"{self.customer_number} - {self.business_name}"
    
    def save(self, *args, **kwargs):
        if not self.customer_id:
            self.customer_id = str(uuid.uuid4())
        super().save(*args, **kwargs)
        
    def get_full_name(self):
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
        
    def get_address(self):
        address_parts = [part for part in [
            self.address_line1,
            self.address_line2,
            self.city,
            self.state_province,
            self.postal_code,
            self.country_name
        ] if part]
        return ", ".join(address_parts)


class CustomerIdentification(models.Model):
    """
    Model for storing customer identification documents.
    """
    id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='identifications')
    
    document_type = models.CharField(
        max_length=50,
        choices=[
            ('PASSPORT', 'Passport'),
            ('DRIVERS_LICENSE', 'Driver\'s License'),
            ('NATIONAL_ID', 'National ID'),
            ('TAX_ID', 'Tax Identification'),
            ('BUSINESS_LICENSE', 'Business License'),
            ('CERTIFICATE_OF_INCORPORATION', 'Certificate of Incorporation'),
            ('OTHER', 'Other'),
        ]
    )
    document_number = models.CharField(max_length=100)
    issuing_country = models.CharField(max_length=100)
    issue_date = models.DateField()
    expiry_date = models.DateField()
    document_verification_status = models.CharField(
        max_length=20,
        choices=[
            ('VERIFIED', 'Verified'),
            ('PENDING', 'Pending Verification'),
            ('EXPIRED', 'Expired'),
            ('REJECTED', 'Rejected'),
        ],
        default='PENDING'
    )
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tm_customer_identifications'
        unique_together = ('customer', 'document_type', 'document_number')
    
    def __str__(self):
        return f"{self.customer.customer_number} - {self.document_type} ({self.document_number})" 
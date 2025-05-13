from django.db import models
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid

def customer_document_path(instance, filename):
    """
    File path function to organize uploaded documents by customer ID and document type.
    
    This creates a structure like:
    customer_123456/PASSPORT/passport.pdf
    customer_123456/ID_CARD/id_card.jpg
    customer_789012/UTILITY_BILL/bill.pdf
    
    Args:
        instance: The Document instance being saved
        filename: Original filename
        
    Returns:
        String: Path where file should be stored
    """
    # Get customer ID from the profile
    customer_id = instance.profile.customer_id
    # Get document type
    doc_type = instance.document_type
    # Return the path
    return f'customers/customer_{customer_id}/{doc_type}/{filename}'

def profile_document_path(instance, filename):
    """
    File path function for KYCProfile documents.
    Organizes ID documents in a customer-specific folder.
    
    Args:
        instance: The KYCProfile instance
        filename: Original filename
        
    Returns:
        String: Path where file should be stored
    """
    return f'customers/customer_{instance.customer_id}/id_documents/{filename}'

def business_document_path(instance, filename):
    """
    File path function for KYCBusiness documents.
    Organizes business documents in a business-specific folder.
    
    Args:
        instance: The KYCBusiness instance
        filename: Original filename
        
    Returns:
        String: Path where file should be stored
    """
    # Determine document type from filename or field name
    if 'registration' in filename.lower():
        doc_type = 'registration_docs'
    elif 'tax' in filename.lower():
        doc_type = 'tax_docs'
    else:
        doc_type = 'other_docs'
        
    return f'businesses/business_{instance.business_id}/{doc_type}/{filename}'

##########################################################################################################3

class KYCWorkflowState(models.Model):
    """
    Tracks the workflow state of a KYC profile or business through its lifecycle.
    Enables a formal state machine for KYC processing.
    """
    STATE_CHOICES = [
        ('DRAFT', 'Draft - Initial Information Entered'),
        ('SUBMITTED', 'Submitted - Pending Initial Review'),
        ('DOC_REVIEW', 'Document Review - Validating Documents'),
        ('SCREENING', 'Screening - Running Checks'),
        ('INVESTIGATION', 'Investigation - Enhanced Due Diligence'),
        ('APPROVAL_PENDING', 'Approval Pending - Awaiting Final Decision'),
        ('APPROVED', 'Approved - KYC Complete'),
        ('REJECTED', 'Rejected - KYC Failed'),
        ('EXPIRED', 'Expired - Renewal Required'),
    ]
    
    # Allow linking to either an individual KYC profile or a business KYC profile
    kyc_profile = models.OneToOneField('KYCProfile', on_delete=models.CASCADE, 
                                      related_name='workflow_state', null=True, blank=True)
    business_kyc = models.OneToOneField('KYCBusiness', on_delete=models.CASCADE,
                                       related_name='workflow_state', null=True, blank=True)
    current_state = models.CharField(max_length=20, choices=STATE_CHOICES, default='DRAFT')
    
    # Workflow tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.CharField(max_length=100, null=True, blank=True)
    last_modified_by = models.CharField(max_length=100, null=True, blank=True)
    
    # Decision tracking
    approved_by = models.CharField(max_length=100, null=True, blank=True)
    approval_date = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    
    # Time tracking
    days_in_current_state = models.IntegerField(default=0)
    screening_date = models.DateTimeField(null=True, blank=True)
    next_review_date = models.DateField(null=True, blank=True)
    
    # Comments and notes
    reviewer_notes = models.TextField(null=True, blank=True)
    history = models.JSONField(default=list, help_text="List of previous states with timestamps")
    
    class Meta:
        verbose_name = "KYC Workflow State"
        verbose_name_plural = "KYC Workflow States"
        constraints = [
            models.CheckConstraint(
                check=models.Q(kyc_profile__isnull=False) | models.Q(business_kyc__isnull=False),
                name="either_profile_or_business_required"
            )
        ]
    
    def __str__(self):
        if self.kyc_profile:
            return f"Individual: {self.kyc_profile.full_name} - {self.get_current_state_display()}"
        elif self.business_kyc:
            return f"Business: {self.business_kyc.business_name} - {self.get_current_state_display()}"
        return f"Unknown KYC - {self.get_current_state_display()}"
    
    def get_subject_name(self):
        """Returns the name of the profile or business this workflow belongs to"""
        if self.kyc_profile:
            return self.kyc_profile.full_name
        elif self.business_kyc:
            return self.business_kyc.business_name
        return "Unknown"
    
    def get_subject_id(self):
        """Returns the ID of the profile or business this workflow belongs to"""
        if self.kyc_profile:
            return self.kyc_profile.customer_id
        elif self.business_kyc:
            return self.business_kyc.business_id
        return "Unknown"
    
    def transition_to(self, new_state, user=None, notes=None):
        """
        Transition the KYC profile to a new state, recording the history
        """
        if new_state not in [choice[0] for choice in self.STATE_CHOICES]:
            raise ValueError(f"Invalid state: {new_state}")
            
        # Record the current state in history before changing
        state_history = {
            'from_state': self.current_state,
            'to_state': new_state,
            'timestamp': timezone.now().isoformat(),
            'by_user': user,
            'notes': notes
        }
        
        # Get the current history and append the new entry
        history_list = self.history
        history_list.append(state_history)
        self.history = history_list
        
        # Update the current state
        self.current_state = new_state
        self.updated_at = timezone.now()
        if user:
            self.last_modified_by = user
        if notes:
            self.reviewer_notes = notes
        
        # Reset days counter when state changes
        self.days_in_current_state = 0
        
        # If transitioning to approved or rejected, record approver and date
        if new_state == 'APPROVED':
            self.approved_by = user
            self.approval_date = timezone.now()
            
            # Set next review date (1 year from approval by default)
            self.next_review_date = (timezone.now() + timezone.timedelta(days=365)).date()
        
        # If transitioning to screening, record screening date
        if new_state == 'SCREENING':
            self.screening_date = timezone.now()
        
        self.save()
        return True

class KYCProfile(models.Model):
    """
    KYC (Know Your Customer) profile model for AML compliance.
    Stores customer identification details and banking information.
    """

    # Basic Customer Details
    customer_id = models.CharField(max_length=50, unique=True)  # Unique customer ID
    full_name = models.CharField(max_length=255)  # Full name as per ID
    date_of_birth = models.DateField(null=True, blank=True)  # Date of birth
    nationality = models.CharField(max_length=100)  # Nationality
    gender = models.CharField(
        max_length=10,
        choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')],
        null=True, blank=True
    )

    # Identification Documents
    id_document_type = models.CharField(
        max_length=50,
        choices=[
            ('Passport', 'Passport'),
            ('National ID', 'National ID'),
            ('Driver License', 'Driver License'),
            ('Other', 'Other')
        ]
    )
    id_document_number = models.CharField(max_length=100, unique=True)  # Document number
    # New field for uploading the ID document file
    id_document_file = models.FileField(upload_to=profile_document_path, null=True, blank=True)

    id_issued_country = models.CharField(max_length=100)  # Country of issuance
    id_expiry_date = models.DateField(null=True, blank=True)  # Expiry date of document

    # Contact Information
    email = models.EmailField(unique=True)  # Email address
    phone_number = models.CharField(max_length=20, unique=True)  # Primary phone number
    address = models.TextField()  # Full residential address
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)  # Country of residence

    # Financial & Employment Details
    occupation = models.CharField(max_length=150, null=True, blank=True)  # Customer's occupation
    employer_name = models.CharField(max_length=255, null=True, blank=True)  # Employer
    annual_income = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)  # Income for risk profiling
    source_of_funds = models.CharField(
        max_length=100,
        choices=[
            ('Salary-Informal', 'Salary Informal '),
            ('Salary-Formal', 'Salary Formal '),
            ('Business Income (Cooperate)', 'Business Income (Cooperate)'),
            ('Business Income (Small Fames)', 'Business Income (Small Fames)'),
            ('Pension', 'Pension'),
            ('Investments', 'Investments'),
            ('Inheritance', 'Inheritance'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )

    # Account & Banking Information
    account_number = models.CharField(max_length=50, unique=True)  # Bank account number
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('Savings', 'Savings'),
            ('Current', 'Current'),
            ('Business', 'Business'),
            ('Other', 'Other')
        ]
    )
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('Active', 'Active'),
            ('Suspended', 'Suspended'),
            ('Closed', 'Closed'),
            ('Blacklisted', 'Blacklisted')
        ]
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)  # KYC profile creation timestamp
    updated_at = models.DateTimeField(auto_now=True)  # Auto-updates on modification
    
    # Draft mode - allows saving incomplete profiles
    is_draft = models.BooleanField(default=True)
    
    # Completion tracking
    completion_percentage = models.IntegerField(default=0)

    def create_document_folders(self):
        """
        Create document folders for this profile.
        This is called after a profile is created to set up the folders structure.
        """
        # This is just a helper method that doesn't actually create folders.
        # The folders are created automatically when files are uploaded.
        return f"customers/customer_{self.customer_id}/"

    def __str__(self):
        return f"{self.full_name} ({self.customer_id})"
    
    def save(self, *args, **kwargs):
        # Calculate completion percentage
        self._calculate_completion_percentage()
        
        # Create workflow state if it doesn't exist
        is_new = self.pk is None
        
        # Save the profile
        super().save(*args, **kwargs)
        
        if is_new:
            # Create workflow state for new profiles
            KYCWorkflowState.objects.create(kyc_profile=self)
    
    def _calculate_completion_percentage(self):
        """Calculate the completion percentage of the KYC profile"""
        required_fields = ['full_name', 'date_of_birth', 'nationality', 
                          'id_document_type', 'id_document_number', 'id_issued_country',
                          'email', 'phone_number', 'address', 'city', 'country',
                          'account_number', 'account_type']
        
        completed = 0
        for field in required_fields:
            if getattr(self, field):
                completed += 1
        
        self.completion_percentage = int((completed / len(required_fields)) * 100)
        return self.completion_percentage


###############################################################################################################
class KYCTestResult(models.Model):
    """
    KYC Test Results for AML Screening & Risk Profiling.
    Each KYC Profile has one or more test results.
    """

    kyc_profile = models.ForeignKey(KYCProfile, on_delete=models.CASCADE, related_name="kyc_tests")

# ✅ Essential Customer Details from KYCProfile
    full_name = models.CharField(max_length=255)  # Full name of the checked person
    customer_id = models.CharField(max_length=50, null=True, blank=True)  # Unique customer ID
    id_document_number = models.CharField(max_length=100, null=True, blank=True)  # Document number

    # Risk Assessment
    risk_level = models.CharField(
        max_length=10,
        choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')],
        default='Low'
    )
    politically_exposed_person = models.BooleanField(default=False)  # PEP flag
    sanctions_list_check = models.BooleanField(default=False)  # Flag for matching with OFAC, UN, etc.
    watchlist_check = models.BooleanField(default=False)  # Check against internal/external watchlists
    adverse_media_check = models.BooleanField(default=False)  # Flag if customer appears in negative news
    suspicious_activity_flag = models.BooleanField(default=False)  # If customer has suspicious activity reports
    financial_crime_check = models.BooleanField(default=False)  # Additional financial crime screening
    fraud_check = models.BooleanField(default=False)  # Fraud screening flag

    # Verification & Compliance
    kyc_status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Verified', 'Verified'), ('Rejected', 'Rejected')],
        default='Pending'
    )
    verification_notes = models.TextField(null=True, blank=True)  # Notes on verification status
    reviewer = models.CharField(max_length=255, null=True, blank=True)  # Compliance officer who reviewed KYC
    review_date = models.DateTimeField(null=True, blank=True)  # Date of last review
    audit_trail = models.TextField(null=True, blank=True)  # Log of verification steps taken

    # Additional Flags
    enhanced_due_diligence_required = models.BooleanField(default=False)  # If further review is needed
    transaction_monitoring_required = models.BooleanField(default=False)  # If transactions should be flagged
    high_risk_country = models.BooleanField(default=False)  # If customer is from a high-risk country

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)  # KYC test result timestamp
    updated_at = models.DateTimeField(auto_now=True)  # Auto-updates on modification

    def __str__(self):
        return f"KYC Test for {self.kyc_profile.full_name} - Risk: {self.risk_level}"


########################################################################################################################

class DilisenseConfig(models.Model):
    """
    Model to store DILISense API configuration settings.
    It stores the API key securely in the database.
    """
    api_key = models.CharField(
        max_length=255,
        help_text="Private API key for accessing the DILISense API"
    )
    # Optionally, add other configuration fields as needed.
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table='API Configurations'

    ##############################################################################



class KYCBusiness(models.Model):
    """
    KYC Business profile model for business entities.
    """
    # Business Information
    business_id = models.CharField(max_length=100, unique=True)
    business_name = models.CharField(max_length=255)
    registration_date = models.DateField()
    business_type = models.CharField(
        max_length=100,
        choices=[
            ('sole_proprietorship', 'Sole Proprietorship'),
            ('partnership', 'Partnership'),
            ('llc', 'Limited Liability Company (LLC)'),
            ('corporation', 'Corporation'),
            ('nonprofit', 'Non-Profit Organization'),
            ('trust', 'Trust'),
            ('other', 'Other')
        ]
    )
    industry_sector = models.CharField(
        max_length=100,
        choices=[
            ('agriculture', 'Agriculture'),
            ('manufacturing', 'Manufacturing'),
            ('retail', 'Retail'),
            ('technology', 'Technology'),
            ('healthcare', 'Healthcare'),
            ('finance', 'Finance & Insurance'),
            ('construction', 'Construction'),
            ('transportation', 'Transportation'),
            ('hospitality', 'Hospitality'),
            ('education', 'Education'),
            ('other', 'Other')
        ]
    )

    # Registration Documents
    registration_number = models.CharField(max_length=100)
    tax_id_number = models.CharField(max_length=100)
    registration_country = models.CharField(max_length=100)
    license_expiry_date = models.DateField(null=True, blank=True)
    registration_document = models.FileField(upload_to=business_document_path, null=True, blank=True)

    tax_document = models.FileField(upload_to=business_document_path, null=True, blank=True)


    # Contact Information
    business_email = models.EmailField(unique=True)
    business_phone = models.CharField(max_length=20)
    business_address = models.TextField()
    business_city = models.CharField(max_length=100)
    business_country = models.CharField(max_length=100)
    business_website = models.URLField(null=True, blank=True)

    # Ownership Structure
    ownership_structure = models.CharField(
        max_length=100,
        choices=[
            ('single_owner', 'Single Owner'),
            ('multiple_partners', 'Multiple Partners'),
            ('public_company', 'Public Company'),
            ('private_company', 'Private Company'),
            ('government_owned', 'Government Owned'),
            ('other', 'Other')
        ]
    )

    # Beneficial Owners Information
    beneficial_owners = models.JSONField(default=list, help_text="List of beneficial owners with their details")

    # Financial Information
    annual_revenue = models.CharField(
        max_length=100,
        choices=[
            ('less_than_100k', 'Less than $100,000'),
            ('100k_500k', '$100,000 - $500,000'),
            ('500k_1m', '$500,000 - $1,000,000'),
            ('1m_5m', '$1,000,000 - $5,000,000'),
            ('5m_10m', '$5,000,000 - $10,000,000'),
            ('more_than_10m', 'More than $10,000,000')
        ]
    )
    source_of_funds = models.CharField(
        max_length=100,
        choices=[
            ('business_revenue', 'Business Revenue'),
            ('investments', 'Investments'),
            ('loans', 'Loans/Credit'),
            ('personal_capital', 'Personal Capital'),
            ('grants', 'Grants/Subsidies'),
            ('other', 'Other')
        ]
    )
    business_purpose = models.TextField()
    transaction_volume = models.CharField(
        max_length=100,
        choices=[
            ('less_than_10k', 'Less than $10,000'),
            ('10k_50k', '$10,000 - $50,000'),
            ('50k_100k', '$50,000 - $100,000'),
            ('100k_500k', '$100,000 - $500,000'),
            ('more_than_500k', 'More than $500,000')
        ]
    )

    # Banking Information
    bank_name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=100)
    account_type = models.CharField(
        max_length=100,
        choices=[
            ('checking', 'Business Checking'),
            ('savings', 'Business Savings'),
            ('investment', 'Investment Account'),
            ('other', 'Other')
        ]
    )
    swift_code = models.CharField(max_length=100)

    # Risk Assessment
    high_risk_jurisdiction = models.BooleanField(default=False)
    sanctions_history = models.BooleanField(default=False)
    aml_policy = models.BooleanField(default=False)
    compliance_officer = models.CharField(max_length=255, null=True, blank=True)

    # Declaration
    declaration_accepted = models.BooleanField(default=False)
    consent_accepted = models.BooleanField(default=False)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Draft mode flag - similar to KYCProfile
    is_draft = models.BooleanField(default=True)

    def create_document_folders(self):
        """
        Create document folders for this business.
        This is called after a business is created to set up the folders structure.
        """
        # This is just a helper method that doesn't actually create folders.
        # The folders are created automatically when files are uploaded.
        return f"businesses/business_{self.business_id}/"
        
    def __str__(self):
        return f"{self.business_name} ({self.business_id})"

    def add_beneficial_owner(self, owner_data):
        """
        Add a beneficial owner to the business.
        """
        if not self.beneficial_owners:
            self.beneficial_owners = []
        
        self.beneficial_owners.append({
            'full_name': owner_data.get('full_name'),
            'nationality': owner_data.get('nationality'),
            'id_document_type': owner_data.get('id_document_type'),
            'id_document_number': owner_data.get('id_document_number'),
            'ownership_percentage': owner_data.get('ownership_percentage'),
            'pep_status': owner_data.get('pep_status', 'no')
        })
        self.save()

    def remove_beneficial_owner(self, owner_index):
        """
        Remove a beneficial owner from the business.
        """
        if self.beneficial_owners and 0 <= owner_index < len(self.beneficial_owners):
            self.beneficial_owners.pop(owner_index)
            self.save()

    def get_beneficial_owners(self):
        """
        Get all beneficial owners of the business.
        """
        return self.beneficial_owners or []
        
    def save(self, *args, **kwargs):
        # Check if this is a new record
        is_new = self.pk is None
        
        # Save the business profile
        super().save(*args, **kwargs)
        
        if is_new:
            # Create workflow state for new business profiles
            from .models import KYCWorkflowState
            KYCWorkflowState.objects.create(business_kyc=self)

class KYCReport(models.Model):
    """
    Model to store KYC reports generated after workflow completion.
    These reports provide a complete audit trail of the KYC process.
    """
    # Report Identification
    report_id = models.CharField(max_length=50, unique=True)
    report_type = models.CharField(
        max_length=20,
        choices=[
            ('INDIVIDUAL', 'Individual KYC Report'),
            ('BUSINESS', 'Business KYC Report'),
        ]
    )
    
    # Subject of the Report
    kyc_profile = models.ForeignKey('KYCProfile', on_delete=models.CASCADE, null=True, blank=True,
                                   related_name='kyc_reports')
    business_kyc = models.ForeignKey('KYCBusiness', on_delete=models.CASCADE, null=True, blank=True,
                                    related_name='kyc_reports')
    
    # Report Content
    summary = models.TextField(help_text="Executive summary of the KYC report")
    risk_assessment = models.TextField(help_text="Details of risk assessment")
    decision = models.CharField(
        max_length=20,
        choices=[
            ('APPROVED', 'Approved'),
            ('REJECTED', 'Rejected')
        ]
    )
    decision_reason = models.TextField(help_text="Reason for approval or rejection")
    
    # Report Metadata
    generated_by = models.CharField(max_length=100, help_text="User who generated the report")
    generated_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pdf_report = models.FileField(upload_to='kyc_reports/', null=True, blank=True)
    
    # AML Screening Results
    screening_result = models.JSONField(default=dict, help_text="Raw screening results from third-party services")
    sanctions_check = models.BooleanField(default=False)
    pep_check = models.BooleanField(default=False)
    adverse_media_check = models.BooleanField(default=False)
    
    # Enhanced Due Diligence
    edd_performed = models.BooleanField(default=False, help_text="Whether Enhanced Due Diligence was performed")
    edd_details = models.TextField(null=True, blank=True)
    
    class Meta:
        verbose_name = "KYC Report"
        verbose_name_plural = "KYC Reports"
        ordering = ['-generated_at']
        constraints = [
            models.CheckConstraint(
                check=models.Q(kyc_profile__isnull=False) | models.Q(business_kyc__isnull=False),
                name="either_individual_or_business_report_required"
            )
        ]
    
    def __str__(self):
        if self.kyc_profile:
            subject_name = self.kyc_profile.full_name
            subject_id = self.kyc_profile.customer_id
        else:
            subject_name = self.business_kyc.business_name
            subject_id = self.business_kyc.business_id
        
        return f"Report #{self.report_id} - {subject_name} ({subject_id})"
    
    def generate_report_id(self):
        """Generate a unique report ID"""
        if not self.report_id:
            import uuid
            prefix = "IND" if self.kyc_profile else "BUS"
            self.report_id = f"{prefix}-{str(uuid.uuid4())[:8]}"
        return self.report_id
    
    def save(self, *args, **kwargs):
        self.generate_report_id()
        super().save(*args, **kwargs)
    
    def get_absolute_url(self):
        """Get the URL to view this report"""
        return reverse('kyc_app:view_kyc_report', kwargs={'report_id': self.report_id})

class Document(models.Model):
    """
    Model to store customer documents that need verification.
    Linked to KYC profiles for identity verification purposes.
    """
    DOCUMENT_TYPE_CHOICES = [
        ('PASSPORT', 'Passport'),
        ('ID_CARD', 'National ID Card'),
        ('DRIVERS_LICENSE', 'Driver\'s License'),
        ('RESIDENCE_PERMIT', 'Residence Permit'),
        ('UTILITY_BILL', 'Utility Bill'),
        ('BANK_STATEMENT', 'Bank Statement'),
        ('REGISTRATION_CERT', 'Business Registration Certificate'),
        ('TAX_CERT', 'Tax Certificate'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending Verification'),
        ('VERIFIED', 'Verified'),
        ('REJECTED', 'Rejected'),
    ]
    
    # Document metadata
    profile = models.ForeignKey('KYCProfile', on_delete=models.CASCADE, related_name='documents', null=True, blank=True)
    business = models.ForeignKey('KYCBusiness', on_delete=models.CASCADE, related_name='documents', null=True, blank=True)
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPE_CHOICES)
    document_file = models.FileField(upload_to=customer_document_path)
    upload_date = models.DateTimeField(auto_now_add=True)
    
    # Verification status
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    verification_date = models.DateTimeField(null=True, blank=True)
    verified_by = models.CharField(max_length=100, null=True, blank=True)
    verification_notes = models.TextField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    
    # Document details
    document_number = models.CharField(max_length=100, null=True, blank=True)
    issue_date = models.DateField(null=True, blank=True)
    expiry_date = models.DateField(null=True, blank=True)
    issuing_authority = models.CharField(max_length=100, null=True, blank=True)
    issuing_country = models.CharField(max_length=100, null=True, blank=True)
    
    class Meta:
        verbose_name = "Document"
        verbose_name_plural = "Documents"
        ordering = ['-upload_date']
    
    def __str__(self):
        if self.profile:
            return f"{self.get_document_type_display()} - {self.profile.full_name} ({self.profile.customer_id})"
        elif self.business:
            return f"{self.get_document_type_display()} - {self.business.business_name} ({self.business.business_id})"
        return f"{self.get_document_type_display()} - {self.id}"
    
    def verify(self, verified_by, notes=None):
        """
        Mark document as verified.
        """
        self.status = 'VERIFIED'
        self.verification_date = timezone.now()
        self.verified_by = verified_by
        if notes:
            self.verification_notes = notes
        self.save()
    
    def reject(self, verified_by, reason):
        """
        Mark document as rejected with a reason.
        """
        self.status = 'REJECTED'
        self.verification_date = timezone.now()
        self.verified_by = verified_by
        self.rejection_reason = reason
        self.save()
    
    @property
    def is_expired(self):
        """
        Check if document is expired based on expiry date.
        """
        if not self.expiry_date:
            return False
        return self.expiry_date < timezone.now().date()
    
    @property
    def days_until_expiry(self):
        """
        Calculate days until document expires.
        """
        if not self.expiry_date:
            return None
        if self.is_expired:
            return 0
        delta = self.expiry_date - timezone.now().date()
        return delta.days
        
    @property
    def document_path(self):
        """
        Get the organized path for the document
        """
        if self.profile and self.document_file:
            return f"customer_{self.profile.customer_id}/{self.document_type}/{self.document_file.name.split('/')[-1]}"
        return None


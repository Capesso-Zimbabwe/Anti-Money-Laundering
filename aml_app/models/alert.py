from django.db import models
from django.utils import timezone
from .transaction import Transaction1

class SuspiciousTransaction1(models.Model):
    """
    Model representing a suspicious transaction that has been flagged by the AML system.
    """
    id = models.AutoField(primary_key=True)
    transaction = models.ForeignKey(Transaction1, on_delete=models.PROTECT, related_name='suspicious_flags')
    
    report_id = models.CharField(max_length=100, unique=True)
    risk_level = models.CharField(max_length=20, choices=[
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low')
    ])
    
    flagged_reason = models.TextField()
    suspicious_date = models.DateField()
    suspicious_description = models.TextField()
    manual_review_required = models.BooleanField(default=True)
    
    # Transaction details
    sender_account = models.CharField(max_length=64, db_index=True)
    receiver_account = models.CharField(max_length=64, null=True, blank=True)
    beneficiary_account = models.CharField(max_length=64, null=True, blank=True)
    beneficiary_name = models.CharField(max_length=255, null=True, blank=True)
    beneficiary_address = models.TextField(null=True, blank=True)
    beneficiary_relationship = models.CharField(max_length=100, null=True, blank=True)
    
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    
    # Customer details
    customer_id = models.CharField(max_length=64, null=True, blank=True)
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    customer_address = models.TextField(null=True, blank=True)
    customer_occupation = models.CharField(max_length=100, null=True, blank=True)
    id_document_type = models.CharField(max_length=50, null=True, blank=True)
    
    # Individual details
    is_entity = models.BooleanField(default=False)
    individual_surname = models.CharField(max_length=100, null=True, blank=True)
    individual_full_name = models.CharField(max_length=255, null=True, blank=True)
    individual_nationality = models.CharField(max_length=50, null=True, blank=True)
    individual_identity_number = models.CharField(max_length=100, null=True, blank=True)
    individual_account_numbers = models.TextField(null=True, blank=True)
    
    # Company details
    company_name = models.CharField(max_length=255, null=True, blank=True)
    company_registration_number = models.CharField(max_length=100, null=True, blank=True)
    company_directors = models.TextField(null=True, blank=True)
    company_business_type = models.CharField(max_length=100, null=True, blank=True)
    company_address = models.TextField(null=True, blank=True)
    company_account = models.CharField(max_length=64, null=True, blank=True)
    
    # Account details
    account_number = models.CharField(max_length=64, null=True, blank=True)
    account_type = models.CharField(max_length=50, null=True, blank=True)
    account_status = models.CharField(max_length=50, null=True, blank=True)
    
    # Branch details
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Review status
    review_status = models.CharField(max_length=50, default='Pending')
    reviewed_by = models.CharField(max_length=100, null=True, blank=True)
    review_date = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'suspicious_transactions'
        indexes = [
            models.Index(fields=['risk_level']),
            models.Index(fields=['suspicious_date']),
            models.Index(fields=['review_status']),
        ]
    
    def __str__(self):
        return f"{self.report_id} - {self.risk_level} - {self.transaction.transaction_id}"
    
    def mark_as_reviewed(self, reviewer, notes=None):
        """Mark the suspicious transaction as reviewed"""
        self.review_status = 'Reviewed'
        self.reviewed_by = reviewer
        self.review_date = timezone.now()
        if notes:
            self.review_notes = notes
        self.save()


class SuspiciousActivityReport(models.Model):
    """
    Model representing a Suspicious Activity Report (SAR).
    """
    id = models.AutoField(primary_key=True)
    report_id = models.CharField(max_length=100, unique=True)
    report_reference_number = models.CharField(max_length=100, unique=True)
    report_type = models.CharField(max_length=20, default='SAR')
    report_status = models.CharField(max_length=20, default='DRAFT')
    
    # Activity details
    suspicious_activity_type = models.CharField(max_length=100)
    secondary_activity_types = models.CharField(max_length=255, null=True, blank=True)
    detection_date = models.DateTimeField()
    activity_start_date = models.DateField()
    activity_end_date = models.DateField()
    total_suspicious_amount = models.DecimalField(max_digits=20, decimal_places=2)
    currency_code = models.CharField(max_length=10)
    related_transactions = models.TextField(null=True, blank=True)
    
    # Subject details
    primary_subject_name = models.CharField(max_length=255)
    primary_subject_id = models.CharField(max_length=64, null=True, blank=True)
    primary_subject_id_type = models.CharField(max_length=50, null=True, blank=True)
    primary_subject_nationality = models.CharField(max_length=50, null=True, blank=True)
    primary_subject_address = models.TextField(null=True, blank=True)
    primary_account_number = models.CharField(max_length=64, null=True, blank=True)
    
    # Other fields
    risk_level = models.CharField(max_length=20, choices=[
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low')
    ])
    suspicious_activity_description = models.TextField()
    red_flags_identified = models.TextField()
    internal_actions_taken = models.TextField(null=True, blank=True)
    
    # Filing details
    filing_institution_name = models.CharField(max_length=255)
    filing_institution_id = models.CharField(max_length=100)
    preparer_name = models.CharField(max_length=255)
    preparer_position = models.CharField(max_length=100)
    preparer_contact = models.CharField(max_length=100, null=True, blank=True)
    approver_name = models.CharField(max_length=255, null=True, blank=True)
    approver_position = models.CharField(max_length=100, null=True, blank=True)
    reporting_date = models.DateField(null=True, blank=True)
    
    # Individual details
    individual_surname = models.CharField(max_length=100, null=True, blank=True)
    individual_full_name = models.CharField(max_length=255, null=True, blank=True)
    individual_nationality = models.CharField(max_length=50, null=True, blank=True)
    individual_identity_number = models.CharField(max_length=100, null=True, blank=True)
    individual_account_numbers = models.TextField(null=True, blank=True)
    
    # Company details
    is_entity = models.BooleanField(default=False)
    company_name = models.CharField(max_length=255, null=True, blank=True)
    company_registration_number = models.CharField(max_length=100, null=True, blank=True)
    company_directors = models.TextField(null=True, blank=True)
    company_business_type = models.CharField(max_length=100, null=True, blank=True)
    company_address = models.TextField(null=True, blank=True)
    company_account = models.CharField(max_length=64, null=True, blank=True)
    
    # Customer details
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    customer_address = models.TextField(null=True, blank=True)
    customer_occupation = models.CharField(max_length=100, null=True, blank=True)
    id_document_type = models.CharField(max_length=50, null=True, blank=True)
    
    # Transaction details
    suspicious_date = models.DateField(null=True, blank=True)
    amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    sender_account = models.CharField(max_length=64, null=True, blank=True)
    receiver_account = models.CharField(max_length=64, null=True, blank=True)
    transaction_comment = models.TextField(null=True, blank=True)
    transaction_types = models.JSONField(null=True, blank=True)
    
    # Beneficiary information
    beneficiary_name = models.CharField(max_length=255, null=True, blank=True)
    beneficiary_account = models.CharField(max_length=64, null=True, blank=True)
    beneficiary_relationship = models.CharField(max_length=100, null=True, blank=True)
    beneficiary_address = models.TextField(null=True, blank=True)
    
    # Account information
    account_number = models.CharField(max_length=64, null=True, blank=True)
    account_type = models.CharField(max_length=50, null=True, blank=True)
    account_status = models.CharField(max_length=50, null=True, blank=True)
    
    # Law enforcement information
    law_enforcement_contacted = models.BooleanField(default=False)
    law_enforcement_details = models.TextField(null=True, blank=True)
    
    # Review status
    manual_review_required = models.BooleanField(default=True)
    review_status = models.CharField(max_length=50, default='Pending')
    review_notes = models.TextField(null=True, blank=True)
    flagged_reason = models.TextField(null=True, blank=True)
    
    # Branch details
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Audit fields
    created_by = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'suspicious_activity_reports'
        indexes = [
            models.Index(fields=['report_status']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['reporting_date']),
        ]
    
    def __str__(self):
        return f"{self.report_reference_number} - {self.primary_subject_name} - {self.risk_level}"
    
    def mark_as_approved(self, approver_name, approver_position, notes=None):
        """Mark the SAR as approved"""
        self.report_status = 'APPROVED'
        self.approver_name = approver_name
        self.approver_position = approver_position
        self.reporting_date = timezone.now().date()
        if notes:
            self.review_notes = notes
        self.save()

from decimal import Decimal
from django.db import models


class Transaction(models.Model):
    transaction_id = models.CharField(max_length=100, unique=True)
    time = models.TimeField()
    date = models.DateField()
    account_number = models.CharField(max_length=50, null=True, blank=True)
    sender_account = models.CharField(max_length=50)
    receiver_account = models.CharField(max_length=50)
    customer_id = models.CharField(max_length=50, null=True, blank=True)  # or a ForeignKey to a Customer model

    amount = models.DecimalField(max_digits=15, decimal_places=2)
    payment_currency = models.CharField(max_length=10)
    received_currency = models.CharField(max_length=10)

    sender_bank_location = models.CharField(max_length=100)
    receiver_bank_location = models.CharField(max_length=100)

    payment_type = models.CharField(
        max_length=50,
        choices=[
            ('Wire Transfer', 'Wire Transfer'),
            ('Cash Deposit', 'Cash Deposit'),
            ('Online Payment', 'Online Payment'),
            ('Other', 'Other')
        ]
    )

    old_balance_sender = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    new_balance_sender = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    old_balance_receiver = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    new_balance_receiver = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)

    transaction_status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Completed', 'Completed'),
            ('Flagged', 'Flagged')
        ],
        default='Pending'
    )
    is_checked = models.BooleanField(default=False)


    def __str__(self):
        return f"{self.transaction_id} | {self.sender_account} → {self.receiver_account} | {self.amount} {self.payment_currency}"


from django.db import models
from django.utils import timezone

class Transaction1(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAW', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
        ('PAYMENT', 'Payment'),
        ('REFUND', 'Refund'),
        # Add more as needed
    ]

    TRANSACTION_STATUS_CHOICES = [
        ('PEND', 'Pending'),
        ('COMP', 'Completed'),
        ('FAIL', 'Failed'),
        ('RJCT', 'Rejected'),
        ('CANC', 'Cancelled'),
    ]

    CHANNEL_CHOICES = [
        ('ATM', 'ATM'),
        ('OLB', 'Online Banking'),
        ('MOB', 'Mobile Banking'),
        ('BRN', 'Branch'),
        ('POS', 'Point of Sale'),
    ]
    
    SANCTION_SCREENING_RESULT_CHOICES = [
        ('PASS', 'Passed'),
        ('FAIL', 'Failed'),
        ('MREV', 'Manual Review'),
    ]

    # Primary fields
    transaction_id = models.CharField(max_length=20, primary_key=True)
    customer_id = models.CharField(max_length=20)
    transaction_date = models.DateField(null=False)
    transaction_time = models.TimeField(null=True, blank=True)
    transaction_timestamp = models.DateTimeField(null=True, blank=True)
    amount = models.DecimalField(max_digits=19, decimal_places=4, null=False)
    currency_code = models.CharField(max_length=3, null=False)
    transaction_type_code = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES, null=False)
    transaction_status_code = models.CharField(max_length=5, choices=TRANSACTION_STATUS_CHOICES, null=False)
    description = models.CharField(max_length=255, null=True, blank=True)
    narrative = models.TextField(null=True, blank=True)
    reference_number = models.CharField(max_length=50, null=True, blank=True)
    purpose_code = models.CharField(max_length=10, null=True, blank=True)
    reason_code = models.CharField(max_length=10, null=True, blank=True)

    # Source account information
    source_account_number = models.CharField(max_length=30, null=False)
    source_account_type_code = models.CharField(max_length=5, null=True, blank=True)
    source_account_holder_id = models.CharField(max_length=20, null=True, blank=True)
    source_customer_name = models.CharField(max_length=100, null=True, blank=True)
    source_branch_code = models.CharField(max_length=10, null=True, blank=True)
    
    # Destination account information
    destination_account_number = models.CharField(max_length=30, null=True, blank=True)
    destination_account_type_code = models.CharField(max_length=5, null=True, blank=True)
    destination_account_holder_id = models.CharField(max_length=20, null=True, blank=True)
    destination_customer_name = models.CharField(max_length=100, null=True, blank=True)
    destination_branch_code = models.CharField(max_length=10, null=True, blank=True)
    
    # Transaction channel information
    channel_code = models.CharField(max_length=5, choices=CHANNEL_CHOICES, null=False)
    location_code = models.CharField(max_length=10, null=True, blank=True)
    terminal_id = models.CharField(max_length=20, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_id = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    geo_location = models.CharField(max_length=100, null=True, blank=True)
    
    # Country information
    source_country_code = models.CharField(max_length=2, null=True, blank=True)
    source_country_name = models.CharField(max_length=50, null=True, blank=True)
    destination_country_code = models.CharField(max_length=2, null=True, blank=True)
    destination_country_name = models.CharField(max_length=50, null=True, blank=True)
    
    # Financial details
    transaction_fee = models.DecimalField(max_digits=19, decimal_places=4, null=True, blank=True)
    balance_after = models.DecimalField(max_digits=19, decimal_places=4, null=True, blank=True)
    exchange_rate = models.DecimalField(max_digits=10, decimal_places=6, null=True, blank=True)
    
    # Processing information
    batch_number = models.CharField(max_length=20, null=True, blank=True)
    teller_id = models.CharField(max_length=20, null=True, blank=True)
    approver_id = models.CharField(max_length=20, null=True, blank=True)
    
    # AML specific
    aml_alert_reason_code = models.CharField(max_length=10, null=True, blank=True)
    
    # International payment information
    correspondent_bank_code = models.CharField(max_length=20, null=True, blank=True)
    swift_code = models.CharField(max_length=11, null=True, blank=True)
    bic_code = models.CharField(max_length=11, null=True, blank=True)
    routing_number = models.CharField(max_length=20, null=True, blank=True)
    beneficiary_bank_code = models.CharField(max_length=20, null=True, blank=True)
    intermediary_bank_code = models.CharField(max_length=20, null=True, blank=True)
    
    # Document and reference information
    document_reference_number = models.CharField(max_length=50, null=True, blank=True)
    source_of_funds_code = models.CharField(max_length=5, null=True, blank=True)
    obi_information = models.TextField(null=True, blank=True)  # Originator to Beneficiary Information
    sanction_screening_result_code = models.CharField(
        max_length=5,
        choices=SANCTION_SCREENING_RESULT_CHOICES,
        null=True,
        blank=True
    )
    wire_message_reference = models.CharField(max_length=50, null=True, blank=True)
    
    # Audit fields
    created_by = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    modified_by = models.CharField(max_length=50, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    is_checked = models.BooleanField(default=False)

    # New Branch Details
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)

    
    class Meta:
        db_table = 'transactions'
        indexes = [
            models.Index(fields=['transaction_date']),
            models.Index(fields=['source_account_number']),
            models.Index(fields=['destination_account_number']),
            models.Index(fields=['source_country_code']),
            models.Index(fields=['destination_country_code']),
            models.Index(fields=['transaction_type_code']),
            models.Index(fields=['amount']),
        ]
    
    def __str__(self):
        return f"{self.transaction_id} - {self.amount} {self.currency_code} ({self.transaction_type_code})"

class WatchlistEntry(models.Model):
    full_name = models.CharField(max_length=100)
    id_document_number = models.CharField(max_length=100, unique=True)  # Document number
    id_number = models.CharField(max_length=50, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)  # Country associated with the individual/entity
    watchlist_type = models.CharField(
        max_length=100,
        choices=[
            ('Bank Internal', 'Bank Internal'),
            ('Law Enforcement', 'Law Enforcement'),
            ('Regulatory', 'Regulatory'),
            ('Third Party Data', 'Third Party Data'),
            ('Other', 'Other')
        ]
    )  # Type of watchlist
    reason = models.TextField()
    risk_level = models.CharField(
        max_length=10,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')],
        default='Medium'
    )  # Risk assessment level
    date_flagged = models.DateField(null=True, blank=True)  # Date when the entry was added to the watchlist
    status = models.CharField(
        max_length=50,
        choices=[('Active', 'Active'), ('Cleared', 'Cleared')],
        default='Active'
    )  # Current status of the entry
    added_on = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(null=True, blank=True)  # Additional comments or case notes


    def __str__(self):
        return self.full_name



#############################################################################################################3
class SuspiciousTransaction(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE)
    risk_level = models.CharField(
        max_length=10,
        choices=[
            ('High', 'High'),
            ('Medium', 'Medium'),
            ('Low', 'Low')
        ]
    )
    flagged_reason = models.TextField()
    manual_review_required = models.BooleanField(default=True)
    reviewed_by = models.CharField(max_length=100, null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # New Identifiers for Suspicious Account Holder
    customer_id = models.CharField(max_length=50, null=True, blank=True)
    customer_name = models.CharField(max_length=100, null=True, blank=True)
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    id_document_type = models.CharField(
        max_length=50,
        choices=[
            ('Passport', 'Passport'),
            ('National ID', 'National ID'),
            ('Driver License', 'Driver License'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    id_document_number = models.CharField(max_length=50, null=True, blank=True)

    # Account Details
    account_number = models.CharField(max_length=50, null=True, blank=True)
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('Savings', 'Savings'),
            ('Current', 'Current'),
            ('Business', 'Business'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('Active', 'Active'),
            ('Suspended', 'Suspended'),
            ('Blacklisted', 'Blacklisted')
        ],
        null=True, blank=True
    )

    # Transaction Risk Details
    sender_account = models.CharField(max_length=50)
    receiver_account = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    


    def __str__(self):
        return f"Suspicious: {self.transaction.transaction_id}"


#############################################################3


###############################################################
from django.db import models
from aml_app.models import Transaction1  # Ensure this import points to your Transaction1 model

class SuspiciousTransaction1(models.Model):
   # Optional link to Transaction model if needed
    transaction = models.ForeignKey('Transaction1', on_delete=models.CASCADE, null=True, blank=True)
    
    # Part A - Information about where the transaction took place
    report_id = models.CharField(max_length=20, primary_key=True)
    reporting_date = models.DateField()
    reporting_entity = models.CharField(max_length=255)
    reporting_person = models.TextField()
    
    # Branch details
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Risk assessment and review status
    risk_level = models.CharField(
        max_length=10,
        choices=[
            ('High', 'High'),
            ('Medium', 'Medium'),
            ('Low', 'Low')
        ],
        null=True, blank=True
    )
    flagged_reason = models.TextField(null=True, blank=True)
    manual_review_required = models.BooleanField(default=True)
    review_status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Under Review', 'Under Review'),
            ('Resolved', 'Resolved')
        ],
        default='Pending'
    )
    reviewed_by = models.CharField(max_length=100, null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    
    # Part B - Suspicious Activity Information - Individual Information
    individual_surname = models.CharField(max_length=255, blank=True, null=True)
    individual_full_name = models.CharField(max_length=255, blank=True, null=True)
    individual_nationality = models.CharField(max_length=100, blank=True, null=True)
    individual_account_numbers = models.TextField(blank=True, null=True)
    individual_identity_number = models.CharField(max_length=100, blank=True, null=True)
    
    # Additional customer information from the second model
    customer_id = models.CharField(max_length=50, null=True, blank=True)
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    id_document_type = models.CharField(
        max_length=50,
        choices=[
            ('Passport', 'Passport'),
            ('National ID', 'National ID'),
            ('Driver License', 'Driver License'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    customer_address = models.TextField(null=True, blank=True)
    customer_occupation = models.CharField(max_length=100, null=True, blank=True)
    
    # Account Details
    account_number = models.CharField(max_length=50, null=True, blank=True)
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('Savings', 'Savings'),
            ('Current', 'Current'),
            ('Business', 'Business'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('Active', 'Active'),
            ('Suspended', 'Suspended'),
            ('Blacklisted', 'Blacklisted')
        ],
        null=True, blank=True
    )
    
    # Company/Entity Information
    is_entity = models.BooleanField(default=False, null=True, blank=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    company_registration_number = models.CharField(max_length=100, blank=True, null=True)
    company_directors = models.TextField(blank=True, null=True)
    company_directors_contact = models.TextField(blank=True, null=True)
    company_directors_address = models.TextField(blank=True, null=True)
    company_account = models.CharField(max_length=100, blank=True, null=True)
    company_directors_accounts = models.TextField(blank=True, null=True)
    company_business_type = models.CharField(max_length=255, blank=True, null=True)
    company_address = models.TextField(blank=True, null=True)
    
    # Transaction Information
    suspicious_date = models.DateField()
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    sender_account = models.CharField(max_length=50, null=True, blank=True)
    receiver_account = models.CharField(max_length=50, null=True, blank=True)
    
    # Transaction Types
    TRANSACTION_TYPE_CHOICES = [
        ('accountant', 'Accountant'),
        ('bank_cash', 'Bank Cash'),
        ('bank_cheques', 'Bank Cheques'),
        ('electronic_funds_transfer', 'Electronic Funds Transfer'),
        ('casino', 'Casino'),
        ('life_insurance_broker', 'Life Insurance Broker or Agent'),
        ('life_insurance_company', 'Life Insurance Company'),
        ('money_transfer', 'Money Transfer Business'),
        ('real_estate', 'Real Estate Broker'),
        ('securities_dealer', 'Securities Dealer'),
        ('foreign_exchange', 'Foreign Exchange'),
        ('travelers_cheques', 'Traveler\'s Cheques'),
        ('trust_account', 'Trust Account'),
        ('lawyer', 'Lawyer'),
        ('other', 'Other'),
    ]
    transaction_types = models.JSONField(default=list)  # Store as a list of selected types
    transaction_comment = models.TextField(blank=True, null=True)
    
    # Information about entity on whose behalf the transaction was conducted
    behalf_entity_name = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_directors = models.TextField(blank=True, null=True)
    behalf_entity_business_type = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_account_number = models.CharField(max_length=100, blank=True, null=True)
    behalf_entity_address = models.TextField(blank=True, null=True)
    
    # Beneficiary information
    beneficiary_name = models.CharField(max_length=200, null=True, blank=True)
    beneficiary_account = models.CharField(max_length=50, null=True, blank=True)
    beneficiary_relationship = models.CharField(max_length=100, null=True, blank=True)
    beneficiary_address = models.TextField(null=True, blank=True)
    
    # Part C - Description of suspicious activity
    suspicious_description = models.TextField()
    
    # Part D - Description of action taken
    action_description = models.TextField(blank=True, null=True)
    action_taken = models.TextField(null=True, blank=True)
    law_enforcement_contacted = models.BooleanField(default=False)
    law_enforcement_details = models.TextField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    def __str__(self):
        return f"Suspicious: {self.transaction.transaction_id}"

###########################################################################################################
from django.db import models

class SuspiciousTransactionReport(models.Model):
    # Optional link to Transaction model if needed
    transaction = models.ForeignKey('Transaction1', on_delete=models.CASCADE, null=True, blank=True)
    
    # Part A - Information about where the transaction took place
    report_id = models.CharField(max_length=20, primary_key=True)
    reporting_date = models.DateField()
    reporting_entity = models.CharField(max_length=255)
    reporting_person = models.TextField()
    
    # Branch details
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Risk assessment and review status
    risk_level = models.CharField(
        max_length=10,
        choices=[
            ('High', 'High'),
            ('Medium', 'Medium'),
            ('Low', 'Low')
        ],
        null=True, blank=True
    )
    flagged_reason = models.TextField(null=True, blank=True)
    manual_review_required = models.BooleanField(default=True)
    review_status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Under Review', 'Under Review'),
            ('Resolved', 'Resolved')
        ],
        default='Pending'
    )
    reviewed_by = models.CharField(max_length=100, null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    
    # Part B - Suspicious Activity Information - Individual Information
    individual_surname = models.CharField(max_length=255, blank=True, null=True)
    individual_full_name = models.CharField(max_length=255, blank=True, null=True)
    individual_nationality = models.CharField(max_length=100, blank=True, null=True)
    individual_account_numbers = models.TextField(blank=True, null=True)
    individual_identity_number = models.CharField(max_length=100, blank=True, null=True)
    
    # Additional customer information from the second model
    customer_id = models.CharField(max_length=50, null=True, blank=True)
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    id_document_type = models.CharField(
        max_length=50,
        choices=[
            ('Passport', 'Passport'),
            ('National ID', 'National ID'),
            ('Driver License', 'Driver License'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    customer_address = models.TextField(null=True, blank=True)
    customer_occupation = models.CharField(max_length=100, null=True, blank=True)
    
    # Account Details
    account_number = models.CharField(max_length=50, null=True, blank=True)
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('Savings', 'Savings'),
            ('Current', 'Current'),
            ('Business', 'Business'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('Active', 'Active'),
            ('Suspended', 'Suspended'),
            ('Blacklisted', 'Blacklisted')
        ],
        null=True, blank=True
    )
    
    # Company/Entity Information
    is_entity = models.BooleanField(default=False, null=True, blank=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    company_registration_number = models.CharField(max_length=100, blank=True, null=True)
    company_directors = models.TextField(blank=True, null=True)
    company_directors_contact = models.TextField(blank=True, null=True)
    company_directors_address = models.TextField(blank=True, null=True)
    company_account = models.CharField(max_length=100, blank=True, null=True)
    company_directors_accounts = models.TextField(blank=True, null=True)
    company_business_type = models.CharField(max_length=255, blank=True, null=True)
    company_address = models.TextField(blank=True, null=True)
    
    # Transaction Information
    suspicious_date = models.DateField()
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    sender_account = models.CharField(max_length=50, null=True, blank=True)
    receiver_account = models.CharField(max_length=50, null=True, blank=True)
    
    # Transaction Types
    TRANSACTION_TYPE_CHOICES = [
        ('accountant', 'Accountant'),
        ('bank_cash', 'Bank Cash'),
        ('bank_cheques', 'Bank Cheques'),
        ('electronic_funds_transfer', 'Electronic Funds Transfer'),
        ('casino', 'Casino'),
        ('life_insurance_broker', 'Life Insurance Broker or Agent'),
        ('life_insurance_company', 'Life Insurance Company'),
        ('money_transfer', 'Money Transfer Business'),
        ('real_estate', 'Real Estate Broker'),
        ('securities_dealer', 'Securities Dealer'),
        ('foreign_exchange', 'Foreign Exchange'),
        ('travelers_cheques', 'Traveler\'s Cheques'),
        ('trust_account', 'Trust Account'),
        ('lawyer', 'Lawyer'),
        ('other', 'Other'),
    ]
    transaction_types = models.JSONField(default=list)  # Store as a list of selected types
    transaction_comment = models.TextField(blank=True, null=True)
    
    # Information about entity on whose behalf the transaction was conducted
    behalf_entity_name = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_directors = models.TextField(blank=True, null=True)
    behalf_entity_business_type = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_account_number = models.CharField(max_length=100, blank=True, null=True)
    behalf_entity_address = models.TextField(blank=True, null=True)
    
    # Beneficiary information
    beneficiary_name = models.CharField(max_length=200, null=True, blank=True)
    beneficiary_account = models.CharField(max_length=50, null=True, blank=True)
    beneficiary_relationship = models.CharField(max_length=100, null=True, blank=True)
    beneficiary_address = models.TextField(null=True, blank=True)
    
    # Part C - Description of suspicious activity
    suspicious_description = models.TextField()
    
    # Part D - Description of action taken
    action_description = models.TextField(blank=True, null=True)
    action_taken = models.TextField(null=True, blank=True)
    law_enforcement_contacted = models.BooleanField(default=False)
    law_enforcement_details = models.TextField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        if hasattr(self, 'transaction') and self.transaction:
            return f"STR #{self.id} - {self.transaction.transaction_id}"
        return f"STR #{self.id} - {self.reporting_date}"
    
    class Meta:
        verbose_name = "Suspicious Transaction "
######################################################################################################

from django.db import models
from django.utils import timezone

class SuspiciousActivityReport(models.Model):
    REPORT_STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('PENDING', 'Pending Review'),
        ('SUBMITTED', 'Submitted to Authorities'),
        ('CLOSED', 'Closed'),
        ('UNDER_INVESTIGATION', 'Under Investigation'),
    ]
    
    RISK_LEVEL_CHOICES = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk'),
    ]
    
    REPORT_TYPE_CHOICES = [
        ('STR', 'Suspicious Transaction Report'),
        ('CTR', 'Currency Transaction Report'),
        ('SAR', 'Suspicious Activity Report'),
    ]
    
    SUSPICIOUS_ACTIVITY_TYPE_CHOICES = [
        ('STRUCTURING', 'Structuring'),
        ('MONEY_LAUNDERING', 'Money Laundering'),
        ('TERRORIST_FINANCING', 'Terrorist Financing'),
        ('FRAUD', 'Fraud'),
        ('IDENTITY_THEFT', 'Identity Theft'),
        ('UNUSUAL_ACTIVITY', 'Unusual Account Activity'),
        ('TAX_EVASION', 'Tax Evasion'),
        ('INSIDER_TRADING', 'Insider Trading'),
        ('SANCTIONS_VIOLATION', 'Sanctions Violation'),
        ('HUMAN_TRAFFICKING', 'Human Trafficking'),
        ('DRUG_TRAFFICKING', 'Drug Trafficking'),
        ('CORRUPTION', 'Corruption/Bribery'),
        ('OTHER', 'Other'),
    ]
    
    TRANSACTION_TYPE_CHOICES = [
        ('accountant', 'Accountant'),
        ('bank_cash', 'Bank Cash'),
        ('bank_cheques', 'Bank Cheques'),
        ('electronic_funds_transfer', 'Electronic Funds Transfer'),
        ('casino', 'Casino'),
        ('life_insurance_broker', 'Life Insurance Broker or Agent'),
        ('life_insurance_company', 'Life Insurance Company'),
        ('money_transfer', 'Money Transfer Business'),
        ('real_estate', 'Real Estate Broker'),
        ('securities_dealer', 'Securities Dealer'),
        ('foreign_exchange', 'Foreign Exchange'),
        ('travelers_cheques', 'Traveler\'s Cheques'),
        ('trust_account', 'Trust Account'),
        ('lawyer', 'Lawyer'),
        ('other', 'Other'),
    ]
    
    # Added fields from SuspiciousTransaction1 model
    transaction = models.ForeignKey('Transaction1', on_delete=models.CASCADE, null=True, blank=True)
    
    # Primary fields
    report_id = models.CharField(max_length=20, primary_key=True)
    report_reference_number = models.CharField(max_length=50, unique=True)
    report_type = models.CharField(max_length=10, choices=REPORT_TYPE_CHOICES)
    report_status = models.CharField(max_length=20, choices=REPORT_STATUS_CHOICES, default='DRAFT')
    suspicious_activity_type = models.CharField(max_length=30, choices=SUSPICIOUS_ACTIVITY_TYPE_CHOICES)
    secondary_activity_types = models.TextField(null=True, blank=True, help_text="Comma-separated list of secondary suspicious activity types")
    
    # Branch details from SuspiciousTransaction1
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Additional review fields from SuspiciousTransaction1
    manual_review_required = models.BooleanField(default=True)
    review_status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Under Review', 'Under Review'),
            ('Resolved', 'Resolved')
        ],
        default='Pending'
    )
    reviewed_by = models.CharField(max_length=100, null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    flagged_reason = models.TextField(null=True, blank=True)
    
    # Date fields
    detection_date = models.DateTimeField(help_text="When the suspicious activity was detected")
    report_date = models.DateTimeField(default=timezone.now, help_text="When the report was created")
    submission_date = models.DateTimeField(null=True, blank=True, help_text="When the report was submitted to authorities")
    activity_start_date = models.DateField(help_text="When the suspicious activity began")
    activity_end_date = models.DateField(help_text="When the suspicious activity ended")
    # Added from SuspiciousTransaction1
    reporting_date = models.DateField()
    suspicious_date = models.DateField()
    
    # Financial information
    total_suspicious_amount = models.DecimalField(max_digits=19, decimal_places=4, help_text="Total amount involved in suspicious activity")
    currency_code = models.CharField(max_length=3, help_text="Currency of suspicious amount")
    # Added from SuspiciousTransaction1
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    sender_account = models.CharField(max_length=50, null=True, blank=True)
    receiver_account = models.CharField(max_length=50, null=True, blank=True)
    
    # Related transactions
    related_transactions = models.TextField(help_text="Comma-separated list of transaction IDs involved")
    
    # Involved parties (individuals/entities)
    primary_subject_name = models.CharField(max_length=100, help_text="Name of primary subject")
    primary_subject_id = models.CharField(max_length=50, help_text="Customer ID or identification number")
    primary_subject_id_type = models.CharField(max_length=20, help_text="Type of ID (passport, national ID, etc.)")
    primary_subject_address = models.TextField(help_text="Address of primary subject")
    primary_subject_dob = models.DateField(null=True, blank=True, help_text="Date of birth if individual")
    primary_subject_nationality = models.CharField(max_length=50, null=True, blank=True)
    primary_subject_occupation = models.CharField(max_length=100, null=True, blank=True)
    
    # Additional subject fields from SuspiciousTransaction1
    individual_surname = models.CharField(max_length=255, blank=True, null=True)
    individual_full_name = models.CharField(max_length=255, blank=True, null=True)
    individual_nationality = models.CharField(max_length=100, blank=True, null=True)
    individual_account_numbers = models.TextField(blank=True, null=True)
    individual_identity_number = models.CharField(max_length=100, blank=True, null=True)
    
    # Added customer fields from SuspiciousTransaction1
    customer_id = models.CharField(max_length=50, null=True, blank=True)
    customer_email = models.EmailField(null=True, blank=True)
    customer_phone = models.CharField(max_length=20, null=True, blank=True)
    id_document_type = models.CharField(
        max_length=50,
        choices=[
            ('Passport', 'Passport'),
            ('National ID', 'National ID'),
            ('Driver License', 'Driver License'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    customer_address = models.TextField(null=True, blank=True)
    customer_occupation = models.CharField(max_length=100, null=True, blank=True)
    
    # Additional subjects (stored as JSON or in a related table in production)
    additional_subjects = models.TextField(null=True, blank=True, help_text="JSON format of additional subjects involved")
    
    # Account information from SuspiciousTransaction1
    account_number = models.CharField(max_length=50, null=True, blank=True)
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('Savings', 'Savings'),
            ('Current', 'Current'),
            ('Business', 'Business'),
            ('Other', 'Other')
        ],
        null=True, blank=True
    )
    account_status = models.CharField(
        max_length=50,
        choices=[
            ('Active', 'Active'),
            ('Suspended', 'Suspended'),
            ('Blacklisted', 'Blacklisted')
        ],
        null=True, blank=True
    )
    
    # Account information
    primary_account_number = models.CharField(max_length=30, help_text="Primary account involved")
    additional_accounts = models.TextField(null=True, blank=True, help_text="Comma-separated list of additional accounts involved")
    
    # Company details from SuspiciousTransaction1
    is_entity = models.BooleanField(default=False, null=True, blank=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    company_registration_number = models.CharField(max_length=100, blank=True, null=True)
    company_directors = models.TextField(blank=True, null=True)
    company_directors_contact = models.TextField(blank=True, null=True)
    company_directors_address = models.TextField(blank=True, null=True)
    company_account = models.CharField(max_length=100, blank=True, null=True)
    company_directors_accounts = models.TextField(blank=True, null=True)
    company_business_type = models.CharField(max_length=255, blank=True, null=True)
    company_address = models.TextField(blank=True, null=True)
    
    # Suspicious activity details
    risk_level = models.CharField(max_length=10, choices=RISK_LEVEL_CHOICES, help_text="Risk assessment level of the suspicious activity")
    suspicious_activity_description = models.TextField(help_text="Detailed narrative of suspicious activity")
    red_flags_identified = models.TextField(help_text="Description of red flags that triggered detection")
    unusual_behavior_patterns = models.TextField(null=True, blank=True, help_text="Patterns of behavior that deviated from normal")
    supporting_evidence = models.TextField(null=True, blank=True, help_text="Description of evidence supporting suspicion")
    
    # Beneficiary information from SuspiciousTransaction1
    beneficiary_name = models.CharField(max_length=200, null=True, blank=True)
    beneficiary_account = models.CharField(max_length=50, null=True, blank=True)
    beneficiary_relationship = models.CharField(max_length=100, null=True, blank=True)
    beneficiary_address = models.TextField(null=True, blank=True)
    
    # Actions taken
    internal_actions_taken = models.TextField(help_text="Actions taken by the financial institution")
    account_action = models.CharField(max_length=50, null=True, blank=True, help_text="Action taken on accounts (e.g., frozen, closed)")
    relationship_action = models.CharField(max_length=50, null=True, blank=True, help_text="Action taken on customer relationship")
    
    # Law enforcement information
    law_enforcement_agency = models.CharField(max_length=100, null=True, blank=True, help_text="Agency report was submitted to")
    law_enforcement_contact = models.CharField(max_length=100, null=True, blank=True, help_text="Contact person at law enforcement")
    case_reference_number = models.CharField(max_length=50, null=True, blank=True, help_text="Law enforcement case reference")
    law_enforcement_contacted = models.BooleanField(default=False)
    law_enforcement_details = models.TextField(null=True, blank=True)
    
    # Filing information
    filing_institution_name = models.CharField(max_length=100, help_text="Name of filing institution")
    filing_institution_id = models.CharField(max_length=50, help_text="ID/License of filing institution")
    preparer_name = models.CharField(max_length=100, help_text="Name of report preparer")
    preparer_position = models.CharField(max_length=50, help_text="Position of report preparer")
    preparer_contact = models.CharField(max_length=100, help_text="Contact info of report preparer")
    approver_name = models.CharField(max_length=100, help_text="Name of report approver (e.g., MLRO)")
    approver_position = models.CharField(max_length=50, help_text="Position of report approver")
    
    # Attachments and documentation
    supporting_documents = models.TextField(null=True, blank=True, help_text="List of attached supporting documents")
    
    # Enhanced SAR reporting fields based on the template
    reporting_entity = models.CharField(max_length=100, null=True, blank=True, help_text="Reporting entity's branch or division")
    reporting_person = models.CharField(max_length=200, null=True, blank=True, help_text="Reporting person and contact details")
    
    # Individual details section
    individual = models.JSONField(null=True, blank=True, help_text="JSON object containing individual details (surname, full_name, nationality, account_numbers, identity_number)")
    
    # Company details section
    company = models.JSONField(null=True, blank=True, help_text="JSON object containing company details (name, registration_number, directors, directors_contact, directors_address, company_account, directors_accounts, business_type, address)")
    
    # Transaction type information
    transaction_types = models.JSONField(null=True, blank=True, help_text="JSON array of transaction types involved")
    transaction_comment = models.TextField(null=True, blank=True, help_text="Comment about transaction types")
    
    # On behalf entity information from SuspiciousTransaction1
    behalf_entity_name = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_directors = models.TextField(blank=True, null=True)
    behalf_entity_business_type = models.CharField(max_length=255, blank=True, null=True)
    behalf_entity_account_number = models.CharField(max_length=100, blank=True, null=True)
    behalf_entity_address = models.TextField(blank=True, null=True)
    
    # JSON-based behalf entity information
    behalf_entity = models.JSONField(null=True, blank=True, help_text="JSON object containing information about entity/person on whose behalf the transaction was conducted")
    
    # Additional fields for action description
    action_description = models.TextField(null=True, blank=True, help_text="Description of action taken as a result of the transaction")
    action_taken = models.TextField(null=True, blank=True)
    
    # Audit fields
    created_by = models.CharField(max_length=50)
    created_at = models.DateTimeField(default=timezone.now)
    modified_by = models.CharField(max_length=50, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'suspicious_activity_reports'
        indexes = [
            models.Index(fields=['report_date']),
            models.Index(fields=['report_status']),
            models.Index(fields=['suspicious_activity_type']),
            models.Index(fields=['primary_subject_id']),
            models.Index(fields=['primary_account_number']),
            models.Index(fields=['risk_level']),
        ]
        
    def __str__(self):
        return f"{self.report_id} - {self.suspicious_activity_type} ({self.report_status})"

#######################################################################################################################

class BlacklistEntry(models.Model):
    full_name = models.CharField(max_length=100)
    id_number = models.CharField(max_length=50, null=True, blank=True)
    id_document_number = models.CharField(max_length=100, unique=True)  # Document number
    reason = models.TextField()
    date_blacklisted = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        # If you intended to store an account number here, rename the field above to 'account_number'
        return self.full_name
    


#############################################################################################################

class SanctionsList(models.Model):
    """
    Stores information about individuals or entities that are sanctioned or blacklisted.
    """
    full_name = models.CharField(max_length=255)  # Full name of the sanctioned individual or entity
    id_document_number = models.CharField(max_length=100, unique=True)  # Document number
    id_number = models.CharField(max_length=100, null=True, blank=True, unique=True)  # National ID, passport, or corporate registration
    country = models.CharField(max_length=100, null=True, blank=True)  # Country associated with the individual/entity
    sanctions_source = models.CharField(
        max_length=100,
        choices=[
            ('OFAC', 'OFAC'),
            ('UN', 'UN'),
            ('EU', 'EU'),
            ('FATF', 'FATF'),
            ('Other', 'Other')
        ]
    )  # Source of the sanction
    reason = models.TextField()  # Reason for being sanctioned (e.g., Money Laundering, Terrorism)
    risk_level = models.CharField(
        max_length=10,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')],
        default='High'
    )  # Risk assessment level
    sanction_start_date = models.DateField(null=True, blank=True)  # Date when sanction was imposed
    sanction_end_date = models.DateField(null=True, blank=True)  # If temporary sanction, expiration date
    status = models.CharField(
        max_length=50,
        choices=[('Active', 'Active'), ('Removed', 'Removed')],
        default='Active'
    )  # Sanction status
    date_blacklisted = models.DateTimeField(null=True, blank=True)  # Date this entry was added to the system
    notes = models.TextField(null=True, blank=True)  # Additional comments or notes

    def __str__(self):
        return f"{self.full_name} - {self.sanctions_source} ({self.risk_level})"


###############################################################################################################

class AdverseMediaCheck(models.Model):
    """
    Stores information about customers flagged in negative news reports.
    """
    full_name = models.CharField(max_length=255)  # Full name of the individual or entity
    id_document_number = models.CharField(max_length=100, unique=True)  # Document number
    id_number = models.CharField(max_length=100, null=True, blank=True, unique=True)  # ID document number
    country = models.CharField(max_length=100, null=True, blank=True)  # Country of the individual/entity
    media_source = models.CharField(max_length=255)  # Name of the news outlet/source
    headline = models.CharField(max_length=500)  # News article headline
    article_url = models.URLField(null=True, blank=True)  # Link to the news article
    date_published = models.DateField()  # Date when the news article was published
    risk_assessment = models.CharField(
        max_length=10,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')],
        default='Medium'
    )  # Risk level determined based on the news content
    category = models.CharField(
        max_length=100,
        choices=[
            ('Fraud', 'Fraud'),
            ('Money Laundering', 'Money Laundering'),
            ('Terrorism Financing', 'Terrorism Financing'),
            ('Corruption', 'Corruption'),
            ('Other', 'Other')
        ]
    )  # Type of adverse news
    flagged_date = models.DateTimeField(auto_now_add=True)  # Date this record was added
    notes = models.TextField(null=True, blank=True)  # Additional comments

    def __str__(self):
        return f"{self.full_name} - {self.category} ({self.risk_assessment})"

#############################################################################################################################
class SARReport(models.Model):
    report_id = models.CharField(max_length=100, unique=True)
    generated_on = models.DateTimeField(auto_now_add=True)
    transactions = models.ManyToManyField(SuspiciousTransaction)
    report_file = models.FileField(upload_to='sar_reports/')

    def __str__(self):
        return f"SAR Report {self.report_id} generated on {self.generated_on.date()}"

###############################################################################################################

from django.db import models
from django.utils import timezone

class Customer(models.Model):
    CUSTOMER_TYPE_CHOICES = [
        ('INDIVIDUAL', 'Individual'),
        ('ENTITY', 'Entity/Organization'),
    ]
    
    CUSTOMER_STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('SUSPENDED', 'Suspended'),
        ('CLOSED', 'Closed'),
        ('DECEASED', 'Deceased'),
        ('WATCH', 'Watch List'),
    ]
    
    RISK_RATING_CHOICES = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk'),
    ]
    
    KYC_STATUS_CHOICES = [
        ('VERIFIED', 'Fully Verified'),
        ('PARTIAL', 'Partially Verified'),
        ('PENDING', 'Verification Pending'),
        ('FAILED', 'Verification Failed'),
        ('EXPIRED', 'Verification Expired'),
    ]
    
    PEP_STATUS_CHOICES = [
        ('NOT_PEP', 'Not a PEP'),
        ('DIRECT_PEP', 'Direct PEP'),
        ('RELATIVE_PEP', 'PEP Relative'),
        ('ASSOCIATE_PEP', 'PEP Associate'),
        ('FORMER_PEP', 'Former PEP'),
    ]
    
    # Primary identification
    customer_id = models.CharField(max_length=20, primary_key=True)
    customer_type = models.CharField(max_length=20, choices=CUSTOMER_TYPE_CHOICES)
    customer_status = models.CharField(max_length=20, choices=CUSTOMER_STATUS_CHOICES, default='ACTIVE')
    account_type = models.CharField(  max_length=20,default='INDIVIDUAL')

    # Basic information
    first_name = models.CharField(max_length=100, null=True, blank=True)
    middle_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    entity_name = models.CharField(max_length=200, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    date_of_incorporation = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    
    # Contact information
    primary_email = models.EmailField(null=True, blank=True)
    secondary_email = models.EmailField(null=True, blank=True)
    primary_phone = models.CharField(max_length=20, null=True, blank=True)
    secondary_phone = models.CharField(max_length=20, null=True, blank=True)
    
    # Address information
    residential_address = models.TextField(null=True, blank=True)
    residential_city = models.CharField(max_length=100, null=True, blank=True)
    residential_state = models.CharField(max_length=100, null=True, blank=True)
    residential_country = models.CharField(max_length=100, null=True, blank=True)
    residential_postal_code = models.CharField(max_length=20, null=True, blank=True)
    mailing_address = models.TextField(null=True, blank=True)
    
    # Identification documents
    primary_id_type = models.CharField(max_length=50, null=True, blank=True)
    primary_id_number = models.CharField(max_length=50, null=True, blank=True)
    primary_id_issue_date = models.DateField(null=True, blank=True)
    primary_id_expiry_date = models.DateField(null=True, blank=True)
    primary_id_issuing_country = models.CharField(max_length=100, null=True, blank=True)
    secondary_id_type = models.CharField(max_length=50, null=True, blank=True)
    secondary_id_number = models.CharField(max_length=50, null=True, blank=True)
    
    # Nationality and tax information
    nationality = models.CharField(max_length=100, null=True, blank=True)
    citizenship = models.CharField(max_length=100, null=True, blank=True)
    additional_nationalities = models.TextField(null=True, blank=True, help_text="Comma-separated list of additional nationalities")
    tax_id_number = models.CharField(max_length=50, null=True, blank=True)
    tax_residence_country = models.CharField(max_length=100, null=True, blank=True)
    
    # KYC/CDD information
    kyc_status = models.CharField(max_length=20, choices=KYC_STATUS_CHOICES, default='PENDING')
    kyc_last_verified_date = models.DateField(null=True, blank=True)
    kyc_next_review_date = models.DateField(null=True, blank=True)
    enhanced_due_diligence = models.BooleanField(default=False)
    edd_reason = models.TextField(null=True, blank=True)
    
    # Beneficial ownership (for entities)
    beneficial_owners = models.TextField(null=True, blank=True, help_text="JSON format of beneficial owners with 25%+ ownership")
    ownership_structure = models.TextField(null=True, blank=True, help_text="Description of ownership structure")
    company_registration_number = models.CharField(max_length=50, null=True, blank=True)
    
    # Business information (for entities)
    industry_code = models.CharField(max_length=20, null=True, blank=True)
    industry_description = models.CharField(max_length=200, null=True, blank=True)
    annual_turnover = models.DecimalField(max_digits=19, decimal_places=2, null=True, blank=True)
    employee_count = models.IntegerField(null=True, blank=True)
    
    # Employment information (for individuals)
    occupation = models.CharField(max_length=100, null=True, blank=True)
    employer_name = models.CharField(max_length=200, null=True, blank=True)
    employment_status = models.CharField(max_length=50, null=True, blank=True)
    income_range = models.CharField(max_length=50, null=True, blank=True)
    
    # Risk assessment
    risk_rating = models.CharField(max_length=10, choices=RISK_RATING_CHOICES, default='MEDIUM')
    risk_score = models.IntegerField(null=True, blank=True)
    risk_factors = models.TextField(null=True, blank=True, help_text="Factors contributing to risk score")
    risk_last_assessment_date = models.DateField(null=True, blank=True)
    risk_next_assessment_date = models.DateField(null=True, blank=True)
    
    # PEP information
    pep_status = models.CharField(max_length=20, choices=PEP_STATUS_CHOICES, default='NOT_PEP')
    pep_position = models.CharField(max_length=200, null=True, blank=True)
    pep_country = models.CharField(max_length=100, null=True, blank=True)
    pep_start_date = models.DateField(null=True, blank=True)
    pep_end_date = models.DateField(null=True, blank=True)
    pep_associated_entity = models.CharField(max_length=200, null=True, blank=True)
    
    # Sanctions and watch list
    is_sanctioned = models.BooleanField(default=False)
    sanction_list_name = models.CharField(max_length=100, null=True, blank=True)
    sanction_list_reference = models.CharField(max_length=100, null=True, blank=True)
    sanction_date = models.DateField(null=True, blank=True)
    negative_media = models.BooleanField(default=False)
    negative_media_details = models.TextField(null=True, blank=True)
    
    # Account behavior
    expected_transaction_types = models.TextField(null=True, blank=True)
    expected_transaction_volumes = models.TextField(null=True, blank=True)
    expected_countries = models.TextField(null=True, blank=True, help_text="Expected countries for transactions")
    
    # Relationship information
    onboarding_date = models.DateField(null=True, blank=True)
    relationship_manager_id = models.CharField(max_length=20, null=True, blank=True)
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    customer_segment = models.CharField(max_length=50, null=True, blank=True)
    
    # Audit fields
    created_by = models.CharField(max_length=50 ,null=True,blank=True)
    created_at = models.DateTimeField(default=timezone.now,null=True, blank=True)
    modified_by = models.CharField(max_length=50, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'customers'
        indexes = [
            models.Index(fields=['customer_status']),
            models.Index(fields=['last_name', 'first_name']),
            models.Index(fields=['entity_name']),
            models.Index(fields=['primary_id_number']),
            models.Index(fields=['risk_rating']),
            models.Index(fields=['pep_status']),
            models.Index(fields=['is_sanctioned']),
            models.Index(fields=['kyc_status']),
        ]
    
    def __str__(self):
        if self.customer_type == 'INDIVIDUAL':
            name = f"{self.last_name}, {self.first_name}"
            return f"{self.customer_id} - {name}"
        else:
            return f"{self.customer_id} - {self.entity_name}"

    

############################################################################################################
class AMLSettingss(models.Model):
    transaction_threshold = models.FloatField(default=10000, help_text="Max transaction amount before flagging.")
    cash_deposit_limit = models.FloatField(default=5000, help_text="Max cash deposit amount before flagging.")
    structuring_limit = models.FloatField(default=9500, help_text="Threshold for structuring transactions.")
    inactive_days = models.IntegerField(default=365, help_text="Days an account must be inactive before considered dormant.")
    multiple_beneficiaries = models.IntegerField(default=5, help_text="Max different beneficiaries in 48hrs before flagging.")
    geo_location_mismatch = models.IntegerField(default=2, help_text="Max distinct locations in 48hrs before flagging.")
    high_risk_countries = models.TextField(default="North Korea,Iran,Syria,Sudan,Cuba", help_text="Comma-separated list of high-risk countries.")
    employee_risk_flag = models.BooleanField(default=True, help_text="Flag transactions involving employees.")
    circular_transaction_days = models.IntegerField(default=1, help_text="Days within which circular transactions are flagged.")
    mismatched_behavior_multiplier = models.FloatField(default=5, help_text="Multiplier for mismatched customer behavior (compared to average transaction).")
    cash_deposit_no_withdrawal = models.FloatField(default=50000, help_text="Flag high cash deposits with no withdrawals.")
    dormant_account_transfer_limit = models.FloatField(default=5000, help_text="Amount for flagging large transfers from dormant accounts.")
    structuring_txn_count = models.IntegerField(default=3, help_text="Count of structuring transactions before flagging.")
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "AML Screening Parameters"
    



###############################################################################################################################
class AMLSettingsVersion(models.Model):
    """Model to track versions of AML settings"""
    version_number = models.CharField(max_length=20, unique=True)
    description = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=False)
    effective_from = models.DateTimeField()
    effective_to = models.DateTimeField(null=True, blank=True)
    approved_by = models.CharField(max_length=100)
    approval_date = models.DateTimeField()
    created_by = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"AML Settings v{self.version_number} ({'Active' if self.is_active else 'Inactive'})"
    
    class Meta:
        verbose_name = "AML Settings Version"
        verbose_name_plural = "AML Settings Versions"



from django.db import models
from django.utils import timezone

class AMLSettings(models.Model):
    # Account Type Configuration
    ACCOUNT_TYPE_CHOICES = [
        ('INDIVIDUAL', 'Individual Account'),
        ('BUSINESS', 'Business Account'),
        ('TRUST', 'Trust Account'),
        ('WEALTH', 'Wealth Management'),
        ('NONPROFIT', 'Non-Profit Organization'),
    ]
    account_type = models.CharField(
        max_length=20,
        choices=ACCOUNT_TYPE_CHOICES,
        default='INDIVIDUAL'
    )

    # Transaction Thresholds
    large_transaction_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=10000.00,
        help_text="Threshold for large transaction reporting"
    )
    cash_transaction_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=5000.00,
        help_text="Threshold for cash transaction reporting"
    )
    
    # New fields for transaction monitoring
    large_withdrawals = models.BooleanField(
        default=True,
        help_text="Flag unusually large withdrawals inconsistent with customer profile"
    )
    large_withdrawals_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=5000.00,
        help_text="Amount threshold for flagging large withdrawals"
    )
    
    large_transfers = models.BooleanField(
        default=True,
        help_text="Flag unusually large transfers inconsistent with customer profile"
    )
    large_transfers_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=7500.00,
        help_text="Amount threshold for flagging large transfers"
    )
    
    large_payments = models.BooleanField(
        default=True,
        help_text="Flag unusually large payments inconsistent with customer profile"
    )
    large_payments_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=10000.00,
        help_text="Amount threshold for flagging large payments"
    )
    
    # Structuring Detection
    structuring_detection_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=3000.00,
        help_text="Threshold for potential structuring activity"
    )
    structuring_transaction_count = models.IntegerField(
        default=3,
        help_text="Minimum number of transactions to trigger structuring alert"
    )
    structuring_time_window_hours = models.IntegerField(
        default=48,
        help_text="Time window in hours for structuring detection"
    )
    
    # Velocity Rules
    velocity_amount_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=15000.00,
        help_text="Total amount threshold for velocity checks"
    )
    velocity_count_threshold = models.IntegerField(
        default=5,
        help_text="Number of transactions threshold for velocity"
    )
    velocity_time_window_hours = models.IntegerField(
        default=24,
        help_text="Time window in hours for velocity checks"
    )
    
    # Pattern Detection
    rapid_withdrawal_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=90.00,
        help_text="Percentage of deposit withdrawn rapidly"
    )
    rapid_withdrawal_window_hours = models.IntegerField(
        default=24,
        help_text="Time window in hours for rapid withdrawal detection"
    )
    dormant_activation_days = models.IntegerField(
        default=90,
        help_text="Days of inactivity to consider account dormant"
    )
    circular_transaction_hours = models.IntegerField(
        default=72,
        help_text="Time window in hours for circular transaction detection"
    )
    
    # Risk Factor Weights
    amount_risk_weight = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=30.00,
        help_text="Weight for transaction amount in risk score calculation"
    )
    country_risk_weight = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=25.00,
        help_text="Weight for country risk in risk score calculation"
    )
    customer_risk_weight = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=25.00,
        help_text="Weight for customer risk in risk score calculation"
    )
    pattern_risk_weight = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=20.00,
        help_text="Weight for transaction pattern in risk score calculation"
    )
    
    # High-Risk Countries
    high_risk_countries = models.TextField(
        default="AF,KP,IR,SY,VE,RU,BY,MM,CU",
        help_text="Comma-separated ISO country codes"
    )
    medium_risk_countries = models.TextField(
        default="AE,SA,NG,KE,PA,VN,KH",
        help_text="Comma-separated ISO country codes"
    )
    
    # PEP Settings
    pep_enhanced_due_diligence = models.BooleanField(
        default=True,
        help_text="Apply enhanced due diligence for PEPs"
    )
    pep_transaction_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=1000.00,
        help_text="Lower threshold for PEP transaction monitoring"
    )
    
    # Alert Configuration
    RISK_LEVEL_MAPPING = [
        ('SCORE_90_100', 'Critical Risk (90-100)'),
        ('SCORE_75_89', 'High Risk (75-89)'),
        ('SCORE_50_74', 'Medium Risk (50-74)'),
        ('SCORE_0_49', 'Low Risk (0-49)'),
    ]
    risk_level_critical = models.IntegerField(
        default=90,
        help_text="Minimum score for Critical risk classification"
    )
    risk_level_high = models.IntegerField(
        default=75,
        help_text="Minimum score for High risk classification"
    )
    risk_level_medium = models.IntegerField(
        default=50,
        help_text="Minimum score for Medium risk classification"
    )
    
    # Screening Settings
    SCREENING_FREQUENCY_CHOICES = [
        ('REALTIME', 'Real-time'),
        ('HOURLY', 'Hourly batch'),
        ('DAILY', 'Daily batch'),
    ]
    sanctions_screening_frequency = models.CharField(
        max_length=10,
        choices=SCREENING_FREQUENCY_CHOICES,
        default='REALTIME'
    )
    watchlist_screening_frequency = models.CharField(
        max_length=10,
        choices=SCREENING_FREQUENCY_CHOICES,
        default='REALTIME'
    )
    
    # Response Actions
    ACTION_CHOICES = [
        ('BLOCK', 'Block transaction'),
        ('HOLD', 'Hold for review'),
        ('FLAG', 'Flag but process'),
        ('MONITOR', 'Process with enhanced monitoring'),
    ]
    critical_risk_action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default='BLOCK'
    )
    high_risk_action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default='HOLD'
    )
    medium_risk_action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default='FLAG'
    )
    low_risk_action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default='MONITOR'
    )
    
    # Suspicious Transaction Indicators
    # Cash Transactions
    large_cash_deposits = models.BooleanField(
        default=True,
        help_text="Flag unusually large cash deposits inconsistent with customer profile"
    )
    large_cash_deposits_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=5000.00,
        help_text="Amount threshold for flagging large cash deposits"
    )
    
    frequent_currency_exchange = models.BooleanField(
        default=True,
        help_text="Flag frequent exchange of cash into other currencies"
    )
    currency_exchange_count_threshold = models.IntegerField(
        default=3,
        help_text="Number of currency exchanges within time window to trigger flag"
    )
    currency_exchange_time_window = models.IntegerField(
        default=7,
        help_text="Time window in days for currency exchange frequency"
    )
    
    structured_deposits = models.BooleanField(
        default=True,
        help_text="Flag structuring deposits to avoid reporting thresholds"
    )
    structured_deposits_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=9000.00,
        help_text="Total amount of structured deposits to trigger flag"
    )
    structured_deposits_count = models.IntegerField(
        default=3,
        help_text="Minimum number of deposits that could indicate structuring"
    )
    structured_deposits_window = models.IntegerField(
        default=2,
        help_text="Time window in days to check for structuring"
    )
    
    # Account Activity
    dormant_account_activity = models.BooleanField(
        default=True,
        help_text="Flag dormant accounts suddenly receiving large deposits"
    )
    dormant_days_threshold = models.IntegerField(
        default=90,
        help_text="Days of inactivity to consider an account dormant"
    )
    dormant_activity_amount = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=3000.00,
        help_text="Amount threshold for flagging activity on dormant accounts"
    )
    
    rapid_fund_movement = models.BooleanField(
        default=True,
        help_text="Flag rapid movement of funds in and out of accounts"
    )
    rapid_movement_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=75.00,
        help_text="Percentage of funds moved quickly to trigger flag"
    )
    rapid_movement_window = models.IntegerField(
        default=24,
        help_text="Time window in hours for rapid movement detection"
    )
    
    inconsistent_transactions = models.BooleanField(
        default=True,
        help_text="Flag transactions inconsistent with customer's known business activities"
    )
    inconsistent_amount_multiplier = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=3.00,
        help_text="Multiplier of average transaction size to trigger inconsistency flag"
    )
    
    # Wire Transfers
    high_risk_jurisdictions = models.BooleanField(
        default=True,
        help_text="Flag transfers to/from high-risk jurisdictions"
    )
    high_risk_countries = models.TextField(
        default="AF,KP,IR,SY,VE,RU,BY,MM,CU",
        help_text="Comma-separated ISO country codes of high-risk jurisdictions"
    )
    
    small_frequent_transfers = models.BooleanField(
        default=True,
        help_text="Flag frequent small transfers that may indicate avoidance of detection"
    )
    small_transfer_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=1000.00,
        help_text="Amount threshold for what constitutes a 'small' transfer"
    )
    small_transfer_frequency = models.IntegerField(
        default=5,
        help_text="Number of small transfers within window to trigger flag"
    )
    small_transfer_window = models.IntegerField(
        default=7,
        help_text="Time window in days for small transfer frequency"
    )
    
    # High-Risk Customers
    nonprofit_suspicious = models.BooleanField(
        default=True,
        help_text="Flag non-profit organizations with unexplained transactions"
    )
    nonprofit_transaction_threshold = models.DecimalField(
        max_digits=19, 
        decimal_places=4, 
        default=5000.00,
        help_text="Amount threshold for flagging non-profit transactions"
    )
    
    shell_companies = models.BooleanField(
        default=True,
        help_text="Flag trusts or shell companies with no clear business purpose"
    )
    shell_company_age_threshold = models.IntegerField(
        default=365,
        help_text="Age threshold in days for new shell company monitoring"
    )
    
    high_risk_jurisdictions_customers = models.BooleanField(
        default=True,
        help_text="Flag customers linked to high-risk jurisdictions"
    )
    
    # Fields to support UI configuration
    max_transaction_amount = models.FloatField(default=10000.0)  # For UI consistency
    cash_deposit_limit = models.FloatField(default=5000.0)  # For UI consistency
    structuring_detection_limit = models.FloatField(default=3000.0)  # For UI consistency
    mismatched_behavior_multiplier = models.FloatField(default=3.0)  # For UI consistency
    inactive_days_threshold = models.IntegerField(default=60)  # For UI consistency
    circular_transaction_window = models.IntegerField(default=72)  # For UI consistency
    geo_mismatch_locations = models.IntegerField(default=3)  # For UI consistency
    geo_mismatch_hours = models.IntegerField(default=24)  # For UI consistency
    critical_alert_action = models.CharField(max_length=20, default='freeze')  # For UI consistency
    high_alert_action = models.CharField(max_length=20, default='hold')  # For UI consistency
    standard_alert_action = models.CharField(max_length=20, default='routine')  # For UI consistency
    
    # Audit fields
    created_by = models.CharField(max_length=50)
    created_at = models.DateTimeField(default=timezone.now)
    modified_by = models.CharField(max_length=50, null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"AML Settings - {self.account_type}"

    class Meta:
        verbose_name = "AML Configuration"
        verbose_name_plural = "AML Configurations"
######################################################################################################

from django.db import models

#######################################################################################################

class AMLParameterRisk(models.Model):
    RISK_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    aml_settings = models.ForeignKey(AMLSettings, on_delete=models.CASCADE, related_name='parameter_risks')
    parameter_name = models.CharField(max_length=50)
    risk_level = models.CharField(max_length=6, choices=RISK_LEVEL_CHOICES, default='medium')
    
    class Meta:
        unique_together = ['aml_settings', 'parameter_name']
        verbose_name = "AML Parameter Risk"
        verbose_name_plural = "AML Parameter Risks"
    
    def __str__(self):
        return f"{self.parameter_name} - {self.get_risk_level_display()}"



###############################################################################################################


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
    id_document_file = models.FileField(upload_to="id_documents/", null=True, blank=True)

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

    def __str__(self):
        return f"{self.full_name} ({self.customer_id})"



class PoliticallyExposedPerson(models.Model):
    """
    Stores information about Politically Exposed Persons (PEPs) for AML screening.
    """

    kyc_profile = models.ForeignKey(KYCProfile, on_delete=models.CASCADE, related_name="pep_status", null=True, blank=True)
    full_name = models.CharField(max_length=255)  # Full name of the PEP
    customer_id = models.CharField(max_length=50, null=True, blank=True)  # Customer ID from KYCProfile
    id_document_number = models.CharField(max_length=100, unique=True)  # National ID, passport, or corporate registration
    country = models.CharField(max_length=100)  # Country associated with the individual
    position = models.CharField(max_length=255)  # Official position held
    pep_category = models.CharField(
        max_length=50,
        choices=[
            ('Government Official', 'Government Official'),
            ('Military', 'Military'),
            ('Judiciary', 'Judiciary'),
            ('Business Leader', 'Business Leader'),
            ('Other', 'Other')
        ]
    )  # Type of PEP
    status = models.CharField(
        max_length=20,
        choices=[('Active', 'Active'), ('Former', 'Former')],
        default='Active'
    )  # Current or Former PEP
    relationship_to_power = models.CharField(
        max_length=100,
        choices=[
            ('Self', 'Self'),
            ('Family Member', 'Family Member'),
            ('Close Associate', 'Close Associate')
        ]
    )  # Relationship to political power
    risk_level = models.CharField(
        max_length=10,
        choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')],
        default='High'
    )  # Risk assessment level
    date_listed = models.DateField()  # Date the PEP was listed
    date_removed = models.DateField(null=True, blank=True)  # If applicable, date they were removed from the PEP list
    reason_flagged = models.TextField()  # Reason for being listed as a PEP
    enhanced_due_diligence_required = models.BooleanField(default=True)  # If extra scrutiny is needed
    notes = models.TextField(null=True, blank=True)  # Additional comments

    def __str__(self):
        return f"{self.full_name} - {self.position} ({self.risk_level})"

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

################################################################################################################


from django.db import models

RISK_CHOICES = (
    (1, "Low"),
    (2, "Medium"),
    (3, "High"),
)

class RiskFactor(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class RiskAssessment(models.Model):
    # For simplicity, we store the country as a CharField.
    country = models.CharField(max_length=100)
    notes = models.TextField(blank=True)
    overall_risk = models.CharField(max_length=10, blank=True)  # e.g., LOW, MEDIUM, HIGH
    risk_score = models.DecimalField(max_digits=5, decimal_places=1, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)

    def calculate_overall_risk(self):
        """
        Calculate an overall risk percentage based on the associated risk factor assessments.
        Here we assume that each risk factor is scored 1 (Low), 2 (Medium) or 3 (High).
        The percentage is the sum of scores divided by the maximum possible score.
        """
        factor_assessments = self.riskfactorassessment_set.all()
        if not factor_assessments.exists():
            return
        total_score = sum([assessment.score for assessment in factor_assessments])
        max_score = 3 * factor_assessments.count()  # if all factors were rated High (3)
        percentage = (total_score / max_score) * 100
        self.risk_score = round(percentage, 1)
        if percentage >= 66:
            self.overall_risk = "HIGH"
        elif percentage >= 33:
            self.overall_risk = "MEDIUM"
        else:
            self.overall_risk = "LOW"

    def save(self, *args, **kwargs):
        self.calculate_overall_risk()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.country} - {self.overall_risk}"

class RiskFactorAssessment(models.Model):
    risk_assessment = models.ForeignKey(RiskAssessment, on_delete=models.CASCADE)
    risk_factor = models.ForeignKey(RiskFactor, on_delete=models.CASCADE)
    score = models.PositiveSmallIntegerField(choices=RISK_CHOICES)

    def __str__(self):
        return f"{self.risk_factor.name}: {self.score}"



from django.db import models

class RiskScore(models.Model):
    RISK_CHOICES = (
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
    )
    # Store the country for which the risk is assessed
    country = models.CharField(max_length=100, blank=True, help_text="Country selected for risk assessment")
    # Risk ratings (1=Low, 2=Medium, 3=High)
    country_risk = models.PositiveSmallIntegerField(choices=RISK_CHOICES, help_text="Risk rating based on country")
    source_risk = models.PositiveSmallIntegerField(choices=RISK_CHOICES, help_text="Risk rating based on source of funds")
    overall_risk = models.CharField(max_length=50, blank=True, help_text="Overall risk category (Low, Medium, High)")
    calculated_score = models.PositiveSmallIntegerField(blank=True, null=True, help_text="Total numerical score")
    created_at = models.DateTimeField(auto_now_add=True)

    def calculate_score(self):
        total = self.country_risk + self.source_risk
        self.calculated_score = total
        if total <= 2:
            self.overall_risk = "Low"
        elif total <= 4:
            self.overall_risk = "Medium"
        else:
            self.overall_risk = "High"
        return total

    def save(self, *args, **kwargs):
        self.calculate_score()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.country} - {self.overall_risk} ({self.calculated_score})"



#######################################################################################

from django.db import models

RISK_CHOICES = (
    (1, 'Low'),
    (2, 'Medium'),
    (3, 'High'),
)

CATEGORY_CHOICES = (
    ('country', 'Country'),
    ('source', 'Source of Funds'),
)

class RiskDefinition(models.Model):
    """
    This model acts as a reference table.
    - category: distinguishes whether the risk definition applies to a country or a source of funds.
    - value: the specific country name or source of funds type.
    - risk_rating: the predefined risk score (1=Low, 2=Medium, 3=High).
    """
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    value = models.CharField(max_length=100, help_text="Country name or Source of Funds type")
    risk_rating = models.DecimalField(
            max_digits=5,
            decimal_places=2,
            default=Decimal('50.00'),
            help_text="Risk rating as a percentage (0-100)"
        )
    
    risk_category = models.CharField(max_length=10, blank=True, editable=False)

    def save(self, *args, **kwargs):
        # Classify based on risk_rating thresholds
        rating = float(self.risk_rating)
        if rating < 34:
            self.risk_category = "Low"
        elif rating < 67:
            self.risk_category = "Medium"
        else:
            self.risk_category = "High"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.get_category_display()} – {self.value}: {self.risk_rating}% ({self.risk_category})"


###############################################################################################################

from django.db import models

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
        db_table='API Conf'

    ##############################################################################


    # models.py
from django.db import models
from django.utils import timezone

class Alert(models.Model):
    """
    Represents an alert in the system.
    Alerts can come from suspicious KYC or suspicious transactions.
    """
    ALERT_TYPE_CHOICES = [
        ("KYC", "KYC Screening"),
        ("TXN", "Transaction Monitoring")
    ]
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High")
    ]
    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("RESOLVED", "Resolved")
    ]

    alert_type = models.CharField(max_length=3, choices=ALERT_TYPE_CHOICES, default="KYC")
    severity = models.CharField(max_length=6, choices=SEVERITY_CHOICES, default="LOW")
    status = models.CharField(max_length=8, choices=STATUS_CHOICES, default="OPEN")

    # Optional references to KYC or transaction
    kyc_test = models.ForeignKey('KYCTestResult', null=True, blank=True, on_delete=models.SET_NULL)
    suspicious_txn = models.ForeignKey('SuspiciousTransaction', null=True, blank=True, on_delete=models.SET_NULL)

    title = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.get_alert_type_display()} Alert - {self.severity} - {self.status}"

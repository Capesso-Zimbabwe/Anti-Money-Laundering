from django.db import models
from django.utils import timezone
import uuid
from transaction_monitoring.model.account import Account
from transaction_monitoring.model.customer import Customer


class Transactions(models.Model):
    """
    Model representing a financial transaction.
    Enhanced to better support dormant account activity monitoring.
    """
    transaction_id = models.CharField(max_length=64, primary_key=True)
    transaction_date = models.DateField()
    transaction_timestamp = models.DateTimeField(default=timezone.now)
    currency_code = models.CharField(max_length=10)
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    transaction_type_code = models.CharField(max_length=20)
    
    # Source account information - now with references to Account model
    source_account_number = models.CharField(max_length=64, db_index=True)
    source_account = models.ForeignKey(
        Account,
        on_delete=models.SET_NULL,
        null=True,
        related_name='outgoing_transactions',
        db_constraint=False,  # For performance on high-volume transaction tables
        db_index=True
    )
    source_account_holder_id = models.CharField(max_length=64, null=True, blank=True)
    source_customer = models.ForeignKey(
        Customer,
        on_delete=models.SET_NULL,
        null=True,
        related_name='outgoing_transactions',
        db_constraint=False,  # For performance on high-volume transaction tables
        db_index=True
    )
    source_customer_name = models.CharField(max_length=255, null=True, blank=True)
    source_account_type_code = models.CharField(max_length=20, null=True, blank=True)
    source_country_code = models.CharField(max_length=10, null=True, blank=True)
    source_country_name = models.CharField(max_length=64, null=True, blank=True)
    source_branch_code = models.CharField(max_length=20, null=True, blank=True)
    
    # Destination account information - now with references to Account model
    destination_account_number = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    destination_account = models.ForeignKey(
        Account,
        on_delete=models.SET_NULL,
        null=True,
        related_name='incoming_transactions',
        db_constraint=False,  # For performance on high-volume transaction tables
        db_index=True
    )
    destination_account_holder_id = models.CharField(max_length=64, null=True, blank=True)
    destination_customer = models.ForeignKey(
        Customer,
        on_delete=models.SET_NULL,
        null=True,
        related_name='incoming_transactions',
        db_constraint=False,  # For performance on high-volume transaction tables
        db_index=True
    )
    destination_customer_name = models.CharField(max_length=255, null=True, blank=True)
    destination_account_type_code = models.CharField(max_length=20, null=True, blank=True)
    destination_country_code = models.CharField(max_length=10, null=True, blank=True)
    destination_country_name = models.CharField(max_length=64, null=True, blank=True)
    
    # Transaction channel and location information
    channel_code = models.CharField(max_length=20, null=True, blank=True)
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    terminal_id = models.CharField(max_length=64, null=True, blank=True)
    geo_location = models.CharField(max_length=255, null=True, blank=True)
    
    # Transaction purpose and reference information
    purpose_code = models.CharField(max_length=20, null=True, blank=True)
    correspondent_bank_code = models.CharField(max_length=20, null=True, blank=True)
    beneficiary_bank_code = models.CharField(max_length=20, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    narrative = models.TextField(null=True, blank=True)
    
    # Currency conversion information
    destination_currency_code = models.CharField(max_length=10, null=True, blank=True)
    exchange_rate = models.DecimalField(max_digits=20, decimal_places=6, null=True, blank=True)
    
    # AML specific fields
    is_checked = models.BooleanField(default=False)
    check_timestamp = models.DateTimeField(null=True, blank=True)
    check_rule_count = models.IntegerField(default=0)
    alert_generated = models.BooleanField(default=False)
    
    # Flags for special transaction types
    is_cash_transaction = models.BooleanField(default=False, db_index=True)
    is_international = models.BooleanField(default=False, db_index=True)
    is_dormant_account_activity = models.BooleanField(default=False, db_index=True)
    is_high_risk = models.BooleanField(default=False)
    
    # Book-keeping
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tm_transactions'
        indexes = [
            models.Index(fields=['transaction_date']),
            models.Index(fields=['is_checked']),
            models.Index(fields=['source_account_number', 'transaction_timestamp']),
            models.Index(fields=['destination_account_number', 'transaction_timestamp']),
            models.Index(fields=['is_dormant_account_activity']),
            models.Index(fields=['transaction_type_code']),
            models.Index(fields=['alert_generated']),
        ]
    
    def __str__(self):
        return f"{self.transaction_id} - {self.amount} {self.currency_code} - {self.transaction_type_code}"
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4())
            
        # Update account's last_transaction_date
        if self.source_account and self.source_account.last_transaction_date is None or self.transaction_date > self.source_account.last_transaction_date:
            self.source_account.last_transaction_date = self.transaction_date
            self.source_account.save(update_fields=['last_transaction_date', 'last_activity_date', 'updated_at'])
            
        if self.destination_account and self.destination_account.last_transaction_date is None or self.transaction_date > self.destination_account.last_transaction_date:
            self.destination_account.last_transaction_date = self.transaction_date
            self.destination_account.save(update_fields=['last_transaction_date', 'last_activity_date', 'updated_at'])
        
        # Set dormant account activity flag
        if (self.source_account and self.source_account.is_dormant) or (self.destination_account and self.destination_account.is_dormant):
            self.is_dormant_account_activity = True
            
        super().save(*args, **kwargs)
    
    def get_transaction_direction(self):
        """Return whether this is an incoming, outgoing, or internal transaction"""
        has_source = bool(self.source_account_number)
        has_destination = bool(self.destination_account_number)
        
        if has_source and has_destination:
            return "INTERNAL"
        elif has_source:
            return "OUTGOING"
        elif has_destination:
            return "INCOMING"
        else:
            return "UNKNOWN"
            
    def get_transaction_risk_score(self):
        """Calculate a basic risk score for this transaction"""
        base_score = 10  # Starting point
        
        # Add points for various risk factors
        if self.is_international:
            base_score += 20
        
        if self.is_cash_transaction:
            base_score += 15
            
        if self.is_dormant_account_activity:
            base_score += 30
            
        if self.is_high_risk:
            base_score += 25
            
        # Add points based on amount tiers
        amount_value = float(self.amount)
        if amount_value > 10000:
            base_score += 15
        elif amount_value > 5000:
            base_score += 10
        elif amount_value > 1000:
            base_score += 5
            
        # Cap the score at 100
        return min(base_score, 100)


class TransactionDetail(models.Model):
    """
    Model for storing additional transaction details
    that aren't needed in the main transaction record.
    """
    id = models.AutoField(primary_key=True)
    transaction = models.OneToOneField(Transactions, on_delete=models.CASCADE, related_name='details')
    
    # Approval information
    is_approved = models.BooleanField(default=True)
    approver_id = models.CharField(max_length=64, null=True, blank=True)
    approval_timestamp = models.DateTimeField(null=True, blank=True)
    approval_notes = models.TextField(null=True, blank=True)
    
    # Additional party information
    ultimate_beneficiary = models.TextField(null=True, blank=True)
    ultimate_originator = models.TextField(null=True, blank=True)
    intermediary_parties = models.TextField(null=True, blank=True)
    
    # Additional transaction context
    is_recurring = models.BooleanField(default=False)
    recurring_reference = models.CharField(max_length=100, null=True, blank=True)
    parent_transaction_id = models.CharField(max_length=64, null=True, blank=True)
    is_reversal = models.BooleanField(default=False)
    reversed_transaction_id = models.CharField(max_length=64, null=True, blank=True)
    
    # Document references
    documentation_provided = models.BooleanField(default=False)
    document_references = models.TextField(null=True, blank=True)
    
    # Extended compliance information
    source_of_funds = models.CharField(max_length=255, null=True, blank=True)
    purpose_of_transaction = models.TextField(null=True, blank=True)
    compliance_notes = models.TextField(null=True, blank=True)
    
    # Book-keeping
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tm_transaction_details'
    
    def __str__(self):
        return f"Details for {self.transaction.transaction_id}"

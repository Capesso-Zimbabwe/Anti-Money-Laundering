from django.db import models
from django.utils import timezone
import uuid
from transaction_monitoring.model.customer import Customer


class Account(models.Model):
    """
    Model representing a bank account in a core banking system.
    Contains account details, status, balance information, and links to customer.
    Critical for dormant account monitoring.
    """
    account_id = models.CharField(max_length=64, primary_key=True)
    account_number = models.CharField(max_length=64, unique=True, db_index=True)
    
    # Account Classification
    account_type = models.CharField(
        max_length=50,
        choices=[
            ('SAVINGS', 'Savings Account'),
            ('CHECKING', 'Checking Account'),
            ('LOAN', 'Loan Account'),
            ('TERM_DEPOSIT', 'Term Deposit'),
            ('CREDIT_CARD', 'Credit Card'),
            ('CORPORATE', 'Corporate Account'),
            ('INVESTMENT', 'Investment Account'),
            ('FOREIGN_CURRENCY', 'Foreign Currency Account'),
            ('OTHER', 'Other Account Type'),
        ],
        db_index=True
    )
    account_subtype = models.CharField(max_length=50, null=True, blank=True)
    
    # Ownership Information
    primary_customer = models.ForeignKey(
        Customer,
        on_delete=models.SET_NULL,
        null=True,
        related_name='primary_accounts'
    )
    is_joint_account = models.BooleanField(default=False)
    
    # Status Information (critical for dormant account monitoring)
    status = models.CharField(
        max_length=50,
        choices=[
            ('ACTIVE', 'Active'),
            ('INACTIVE', 'Inactive'),
            ('DORMANT', 'Dormant'),
            ('FROZEN', 'Frozen'),
            ('CLOSED', 'Closed'),
            ('PENDING', 'Pending Activation'),
        ],
        default='ACTIVE',
        db_index=True
    )
    
    # Dormancy tracking fields
    is_dormant = models.BooleanField(default=False, db_index=True)
    dormancy_start_date = models.DateField(null=True, blank=True, db_index=True)
    dormancy_reason = models.CharField(max_length=255, null=True, blank=True)
    reactivation_date = models.DateField(null=True, blank=True)
    
    # Activity tracking
    opening_date = models.DateField()
    closing_date = models.DateField(null=True, blank=True)
    last_transaction_date = models.DateField(null=True, blank=True, db_index=True)
    last_activity_date = models.DateField(null=True, blank=True, db_index=True)
    last_statement_date = models.DateField(null=True, blank=True)
    
    # Financial information
    currency_code = models.CharField(max_length=10)
    current_balance = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    available_balance = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    blocked_amount = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    overdraft_limit = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    minimum_balance = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    interest_rate = models.DecimalField(max_digits=10, decimal_places=4, default=0.00)
    accrued_interest = models.DecimalField(max_digits=22, decimal_places=2, default=0.00)
    
    # Branch and product information
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    product_code = models.CharField(max_length=50, null=True, blank=True)
    product_name = models.CharField(max_length=100, null=True, blank=True)
    
    # Risk and compliance
    risk_score = models.IntegerField(default=0)
    risk_category = models.CharField(
        max_length=20,
        choices=[
            ('LOW', 'Low Risk'),
            ('MEDIUM', 'Medium Risk'),
            ('HIGH', 'High Risk'),
        ],
        default='MEDIUM'
    )
    kyc_status = models.CharField(
        max_length=20,
        choices=[
            ('COMPLETE', 'Complete'),
            ('PENDING', 'Pending'),
            ('EXPIRED', 'Expired'),
            ('EXEMPTED', 'Exempted'),
        ],
        default='PENDING'
    )
    
    # Monitoring fields
    monitoring_notes = models.TextField(null=True, blank=True)
    is_special_case = models.BooleanField(default=False)
    special_case_reason = models.CharField(max_length=255, null=True, blank=True)
    
    # Book-keeping
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'accounts'
        indexes = [
            models.Index(fields=['account_type']),
            models.Index(fields=['status']),
            models.Index(fields=['is_dormant']),
            models.Index(fields=['dormancy_start_date']),
            models.Index(fields=['last_transaction_date']),
            models.Index(fields=['opening_date']),
            models.Index(fields=['risk_category']),
        ]
    
    def __str__(self):
        return f"{self.account_number} - {self.get_account_type_display()} ({self.get_status_display()})"
    
    def save(self, *args, **kwargs):
        # Generate UUID if not provided
        if not self.account_id:
            self.account_id = str(uuid.uuid4())
        
        # Set last_activity_date to the latest of transaction or other activity
        if self.last_transaction_date:
            if not self.last_activity_date or self.last_transaction_date > self.last_activity_date:
                self.last_activity_date = self.last_transaction_date
        
        super().save(*args, **kwargs)
    
    def is_eligible_for_dormancy_check(self):
        """Check if this account should be evaluated for dormancy"""
        if self.status == 'CLOSED':
            return False
        
        if not self.last_activity_date:
            # No activity recorded yet, use opening date for comparison
            return (timezone.now().date() - self.opening_date).days > 180
        
        # Otherwise check based on last activity
        return True


class AccountHolder(models.Model):
    """
    Model representing account holders, allowing for joint account structures.
    """
    id = models.AutoField(primary_key=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='account_holders')
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='accounts_held')
    
    holder_type = models.CharField(
        max_length=20,
        choices=[
            ('PRIMARY', 'Primary Holder'),
            ('JOINT', 'Joint Holder'),
            ('GUARDIAN', 'Guardian/Trustee'),
            ('AUTHORIZED', 'Authorized Signatory'),
            ('POWER_OF_ATTORNEY', 'Power of Attorney'),
            ('BENEFICIAL_OWNER', 'Beneficial Owner'),
        ],
        default='JOINT'
    )
    
    # Permissions
    can_withdraw = models.BooleanField(default=True)
    can_deposit = models.BooleanField(default=True)
    can_close = models.BooleanField(default=False)
    can_modify = models.BooleanField(default=False)
    can_view_statements = models.BooleanField(default=True)
    
    # Book-keeping
    start_date = models.DateField(default=timezone.now)
    end_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'account_holders'
        unique_together = ('account', 'customer')
    
    def __str__(self):
        return f"{self.account.account_number} - {self.customer.customer_number} ({self.get_holder_type_display()})"


class AccountStatusHistory(models.Model):
    """
    Model to track changes in account status over time.
    Critical for auditing dormancy transitions.
    """
    id = models.AutoField(primary_key=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='status_history')
    
    previous_status = models.CharField(
        max_length=50,
        choices=Account._meta.get_field('status').choices
    )
    new_status = models.CharField(
        max_length=50,
        choices=Account._meta.get_field('status').choices
    )
    
    change_date = models.DateTimeField(default=timezone.now)
    change_reason = models.CharField(max_length=255, null=True, blank=True)
    changed_by = models.CharField(max_length=100, null=True, blank=True)
    notes = models.TextField(null=True, blank=True)
    
    class Meta:
        db_table = 'account_status_history'
        ordering = ['-change_date']
    
    def __str__(self):
        return f"{self.account.account_number} - {self.previous_status} to {self.new_status} on {self.change_date}"


class AccountParameter(models.Model):
    """
    Model for account parameters including dormancy thresholds by account type.
    Used to configure when accounts should be considered dormant.
    """
    id = models.AutoField(primary_key=True)
    account_type = models.CharField(
        max_length=50,
        choices=Account._meta.get_field('account_type').choices,
        unique=True
    )
    
    # Dormancy rules
    dormancy_threshold_days = models.IntegerField(
        default=365,
        help_text="Number of days of inactivity before account is considered dormant"
    )
    dormancy_warning_threshold_days = models.IntegerField(
        default=300,
        help_text="Number of days of inactivity before warning is issued"
    )
    dormancy_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        help_text="Fee charged when account becomes dormant"
    )
    abandoned_property_threshold_days = models.IntegerField(
        default=1825,  # 5 years
        help_text="Days after which account considered abandoned property"
    )
    
    # Transaction monitoring thresholds
    minimum_balance_required = models.DecimalField(max_digits=20, decimal_places=2, default=0.00)
    daily_withdrawal_limit = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    daily_deposit_limit = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    monthly_transaction_limit_count = models.IntegerField(null=True, blank=True)
    
    # Book-keeping
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'account_parameters'
    
    def __str__(self):
        return f"{self.get_account_type_display()} - Dormancy: {self.dormancy_threshold_days} days" 
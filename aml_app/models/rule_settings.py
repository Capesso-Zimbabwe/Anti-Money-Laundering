from django.db import models
from django.utils import timezone
import json

class AMLSettings(models.Model):
    """
    Model for AML monitoring rule settings.
    """
    id = models.AutoField(primary_key=True)
    rule_code = models.CharField(max_length=100, unique=True)
    account_type = models.CharField(max_length=50, default='INDIVIDUAL')
    rule_name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    
    # General rule settings
    enabled = models.BooleanField(default=True)
    transaction_types = models.CharField(max_length=255, null=True, blank=True)
    alert_level = models.CharField(max_length=50, default='Account')
    evaluation_trigger = models.CharField(max_length=50, default='Transaction')
    scoring_algorithm = models.CharField(max_length=20, default='MAX')
    
    # Thresholds and settings (stored as JSON)
    thresholds = models.TextField(null=True, blank=True)
    recurrence_settings = models.TextField(null=True, blank=True)
    
    # Large cash deposits
    large_cash_deposits = models.BooleanField(default=True)
    large_cash_deposits_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=10000.00)
    
    # Large withdrawals
    large_withdrawals = models.BooleanField(default=True)
    large_withdrawals_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=10000.00)
    
    # Large transfers
    large_transfers = models.BooleanField(default=True)
    large_transfers_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=10000.00)
    
    # Large payments
    large_payments = models.BooleanField(default=True)
    large_payments_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=10000.00)
    
    # Dormant account
    dormant_account_activity = models.BooleanField(default=True)
    dormant_days_threshold = models.IntegerField(default=180)
    dormant_activity_amount = models.DecimalField(max_digits=20, decimal_places=2, default=5000.00)
    
    # Structured deposits
    structured_deposits = models.BooleanField(default=True)
    structured_deposits_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=9000.00)
    structured_deposits_window = models.IntegerField(default=30)
    structured_deposits_count = models.IntegerField(default=3)
    
    # Currency exchange
    frequent_currency_exchange = models.BooleanField(default=True)
    currency_exchange_count_threshold = models.IntegerField(default=3)
    currency_exchange_time_window = models.IntegerField(default=30)
    
    # Fund movement
    rapid_fund_movement = models.BooleanField(default=True)
    rapid_movement_window = models.IntegerField(default=48)
    rapid_movement_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=80.00)
    
    # Inconsistent transactions
    inconsistent_transactions = models.BooleanField(default=True)
    inconsistent_amount_multiplier = models.DecimalField(max_digits=5, decimal_places=2, default=5.00)
    
    # High risk jurisdictions
    high_risk_jurisdictions = models.BooleanField(default=True)
    high_risk_countries = models.TextField(default='AF,IR,KP,RU,MM')
    
    # Small transfers
    small_frequent_transfers = models.BooleanField(default=True)
    small_transfer_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=3000.00)
    small_transfer_frequency = models.IntegerField(default=3)
    small_transfer_window = models.IntegerField(default=7)
    
    # Non-profit organizations
    nonprofit_suspicious = models.BooleanField(default=True)
    nonprofit_transaction_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=5000.00)
    
    # Shell companies
    shell_companies = models.BooleanField(default=True)
    shell_company_age_threshold = models.IntegerField(default=90)
    
    # Customer risks
    high_risk_jurisdictions_customers = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'aml_settings'
        indexes = [
            models.Index(fields=['account_type']),
            models.Index(fields=['enabled']),
        ]
    
    def __str__(self):
        return f"{self.rule_code} - {self.rule_name} - {self.account_type}"
    
    def get_thresholds(self):
        """Get thresholds as dictionary"""
        if self.thresholds:
            return json.loads(self.thresholds)
        return {}
    
    def set_thresholds(self, thresholds_dict):
        """Set thresholds from dictionary"""
        self.thresholds = json.dumps(thresholds_dict)
    
    def get_recurrence_settings(self):
        """Get recurrence settings as dictionary"""
        if self.recurrence_settings:
            return json.loads(self.recurrence_settings)
        return {}
    
    def set_recurrence_settings(self, recurrence_dict):
        """Set recurrence settings from dictionary"""
        self.recurrence_settings = json.dumps(recurrence_dict)

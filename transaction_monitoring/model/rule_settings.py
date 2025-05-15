from django.db import models
from django.utils import timezone
import json
import jsonfield

class AMLRules(models.Model):
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
    alert_level = models.CharField(
        max_length=20, 
        choices=[
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High')
        ], 
        default='MEDIUM'
    )
    evaluation_trigger = models.CharField(max_length=50, default='Transaction')
    scoring_algorithm = models.CharField(
        max_length=20,
        choices=[
            ('MAX', 'Maximum Factor Score'),
            ('AVG', 'Average of Factor Scores'),
            ('SUM', 'Sum of Factor Scores'),
            ('WEIGHTED', 'Weighted Factors')
        ],
        default='MAX'
    )
    min_alert_score = models.IntegerField(default=50)
    
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
    
    # Custom parameters
    custom_parameters = jsonfield.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'aml_rules'
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

class ScoringThreshold(models.Model):
    """
    Model representing a scoring threshold for a rule and factor type.
    """
    rule = models.ForeignKey(AMLRules, on_delete=models.CASCADE, related_name='scoring_thresholds')
    factor_type = models.CharField(max_length=50, choices=[
        ('ACTIVITY_VALUE', 'Activity Value'),
        ('RECURRENCE', 'Recurrence'),
        ('COUNTRY_RISK', 'Country Risk'),
        ('PARTY_RISK', 'Party Risk'),
        ('ACCOUNT_AGE', 'Account Age'),
    ])
    threshold_value = models.DecimalField(max_digits=20, decimal_places=2)
    score = models.IntegerField()
    description = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        db_table = 'scoring_thresholds'
        unique_together = ('rule', 'factor_type', 'threshold_value')
        ordering = ['rule', 'factor_type', 'threshold_value']
    
    def __str__(self):
        return f"{self.rule.rule_code} - {self.factor_type} - {self.threshold_value}"

class TransactionTypeGroup(models.Model):
    """
    Model representing transaction type groupings.
    """
    group_code = models.CharField(max_length=50, primary_key=True)
    description = models.CharField(max_length=255)
    parent_group = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='children')
    
    class Meta:
        db_table = 'transaction_type_groups'
        ordering = ['group_code']
    
    def __str__(self):
        return f"{self.group_code} - {self.description}"

class TransactionType(models.Model):
    """
    Model representing transaction types and their mappings to groups.
    """
    transaction_code = models.CharField(max_length=50, primary_key=True)
    description = models.CharField(max_length=255)
    groups = models.ManyToManyField(TransactionTypeGroup, related_name='transaction_types')
    jurisdiction = models.CharField(max_length=3, null=True, blank=True)  # Country code
    
    class Meta:
        db_table = 'transaction_types'
        ordering = ['transaction_code']
    
    def __str__(self):
        return f"{self.transaction_code} - {self.description}"

class RuleExecution(models.Model):
    """
    Model to track rule execution history and performance.
    """
    rule = models.ForeignKey(AMLRules, on_delete=models.CASCADE, related_name='executions')
    execution_date = models.DateTimeField(auto_now_add=True)
    execution_time_ms = models.FloatField()
    transactions_evaluated = models.IntegerField()
    alerts_generated = models.IntegerField()
    
    class Meta:
        db_table = 'rule_executions'
        ordering = ['-execution_date']
    
    def __str__(self):
        return f"{self.rule.rule_code} - {self.execution_date}"

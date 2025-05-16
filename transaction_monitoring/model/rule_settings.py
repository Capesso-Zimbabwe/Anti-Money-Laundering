from django.db import models
from django.utils import timezone
import json
import jsonfield

class AMLRules(models.Model):
    """
    Model for AML monitoring rule settings.
    This is the base model for all rule types.
    """
    id = models.AutoField(primary_key=True)
    rule_code = models.CharField(max_length=100, unique=True)
    account_type = models.CharField(max_length=50, null=True, blank=True)
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
    
    # Rule type indicator
    rule_type = models.CharField(
        max_length=50,
        choices=[
            ('DORMANT_ACCOUNT', 'Dormant Account Activity'),
            ('LARGE_CASH', 'Large Cash Transactions'),
        ],
        null=True,
        blank=True
    )
    
    # For backwards compatibility
    custom_parameters = jsonfield.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'aml_rules'
        indexes = [
            models.Index(fields=['account_type']),
            models.Index(fields=['enabled']),
            models.Index(fields=['rule_type']),
        ]
    
    def __str__(self):
        return f"{self.rule_code} - {self.rule_name}"

class DormantAccountRule(models.Model):
    """
    Configuration for dormant account monitoring rules.
    Detects when previously inactive accounts suddenly show activity.
    """
    rule = models.OneToOneField(AMLRules, on_delete=models.CASCADE, related_name='dormant_account_config')
    account_age_days = models.IntegerField(
        default=90, 
        help_text="Minimum age of account in days to be considered for dormancy checks"
    )
    inactive_period_months = models.IntegerField(
        default=3, 
        help_text="Number of months with minimal activity to consider account dormant"
    )
    activity_amount_threshold = models.DecimalField(
        max_digits=20, 
        decimal_places=2, 
        default=5000.00,
        help_text="Minimum amount to trigger alert when activity occurs in dormant account"
    )
    max_prior_activity = models.DecimalField(
        max_digits=20, 
        decimal_places=2, 
        default=1000.00,
        help_text="Maximum allowed activity amount during dormancy period"
    )
    
    class Meta:
        db_table = 'dormant_account_rules'
    
    def __str__(self):
        return f"Dormant Account Config - {self.rule.rule_code}"

class LargeCashRule(models.Model):
    """
    Configuration for large cash transaction monitoring rules.
    Detects large cash deposits, withdrawals, and aggregated cash activity.
    """
    rule = models.OneToOneField(AMLRules, on_delete=models.CASCADE, related_name='large_cash_config')
    threshold_amount = models.DecimalField(
        max_digits=20, 
        decimal_places=2, 
        default=10000.00,
        help_text="Threshold amount to trigger the rule"
    )
    aggregate_period_days = models.IntegerField(
        default=30,
        help_text="Period in days over which to aggregate transactions"
    )
    include_foreign_currency = models.BooleanField(
        default=True,
        help_text="Whether to include foreign currency transactions in the detection"
    )
    monitor_deposits = models.BooleanField(
        default=True,
        help_text="Monitor cash deposits"
    )
    monitor_withdrawals = models.BooleanField(
        default=True,
        help_text="Monitor cash withdrawals"
    )
    
    class Meta:
        db_table = 'large_cash_rules'
    
    def __str__(self):
        return f"Large Cash Config - {self.rule.rule_code}"

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
    lookback_days = models.IntegerField(null=True, blank=True)
    
    class Meta:
        db_table = 'scoring_thresholds'
        unique_together = ('rule', 'factor_type', 'threshold_value')
        ordering = ['rule', 'factor_type', 'threshold_value']
    
    def __str__(self):
        return f"{self.rule.rule_code} - {self.factor_type} - {self.threshold_value}"

class RuleType(models.Model):
    """
    Model for storing available rule types and their configurations.
    """
    type_id = models.CharField(max_length=100, primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    
    class Meta:
        db_table = 'rule_types'
        ordering = ['type_id']
    
    def __str__(self):
        return f"{self.type_id} - {self.name}"

class RuleTypeConfig(models.Model):
    """
    Configuration for a specific rule's rule type.
    This replaces storing rule type configurations in the custom_parameters JSON field.
    """
    rule = models.ForeignKey(AMLRules, on_delete=models.CASCADE, related_name='rule_type_configs')
    rule_type = models.ForeignKey(RuleType, on_delete=models.CASCADE, related_name='rule_configs')
    
    # Common configurable parameters across rule types
    # Specific parameter fields for each rule type
    amount_threshold = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    count_threshold = models.IntegerField(null=True, blank=True)
    time_window_days = models.IntegerField(null=True, blank=True)
    percentage_threshold = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    lookback_period_days = models.IntegerField(null=True, blank=True)
    
    # JSON field for any additional parameters not covered by standard fields
    additional_parameters = jsonfield.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'rule_type_configs'
        unique_together = ('rule', 'rule_type')
    
    def __str__(self):
        return f"{self.rule.rule_code} - {self.rule_type.type_id}"

class StructuredTransactionConfig(models.Model):
    """
    Configuration for structured transaction monitoring rules.
    """
    rule = models.OneToOneField(AMLRules, on_delete=models.CASCADE, related_name='structured_transaction_config')
    total_amount_threshold = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    transaction_count_threshold = models.IntegerField(null=True, blank=True)
    time_window_days = models.IntegerField(null=True, blank=True)
    
    class Meta:
        db_table = 'structured_transaction_configs'
    
    def __str__(self):
        return f"Structured Transaction Config - {self.rule.rule_code}"

class HighRiskCountryConfig(models.Model):
    """
    Configuration for high-risk country monitoring.
    """
    rule = models.OneToOneField(AMLRules, on_delete=models.CASCADE, related_name='high_risk_country_config')
    country_codes = models.TextField(null=True, blank=True)  # Comma-separated country codes
    amount_threshold = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    
    class Meta:
        db_table = 'high_risk_country_configs'
    
    def __str__(self):
        return f"High Risk Country Config - {self.rule.rule_code}"

class RecurrenceConfig(models.Model):
    """
    Configuration for recurrence pattern monitoring.
    """
    rule = models.OneToOneField(AMLRules, on_delete=models.CASCADE, related_name='recurrence_config')
    occurrences_threshold = models.IntegerField(null=True, blank=True)
    lookback_period_days = models.IntegerField(null=True, blank=True)
    
    class Meta:
        db_table = 'recurrence_configs'
    
    def __str__(self):
        return f"Recurrence Config - {self.rule.rule_code}"

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

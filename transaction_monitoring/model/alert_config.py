from django.db import models
from django.utils import timezone


class AlertConfiguration(models.Model):
    """
    Model for configuring alert thresholds and parameters.
    Base class for all alert configurations.
    """
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    alert_type = models.CharField(
        max_length=50,
        choices=[
            ('DORMANT_ACCOUNT', 'Dormant Account Activity'),
            ('LARGE_CASH', 'Large Cash Transaction'),
            ('STRUCTURING', 'Transaction Structuring'),
            ('HIGH_RISK_COUNTRY', 'High Risk Country'),
            ('RAPID_MOVEMENT', 'Rapid Movement of Funds'),
            ('UNUSUAL_ACTIVITY', 'Unusual Account Activity'),
            ('AML_PATTERN', 'AML Pattern Detection'),
        ]
    )
    
    min_customer_risk_level = models.CharField(
        max_length=20,
        choices=[
            ('ALL', 'All Risk Levels'),
            ('LOW', 'Low Risk and Above'),
            ('MEDIUM', 'Medium Risk and Above'),
            ('HIGH', 'High Risk Only'),
        ],
        default='ALL'
    )
    
    min_alert_score = models.IntegerField(default=50)
    applies_to_account_types = models.CharField(max_length=255, null=True, blank=True)
    
    # Notification settings
    generate_email_notification = models.BooleanField(default=True)
    notification_recipients = models.TextField(null=True, blank=True)
    
    # Book-keeping
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=100, null=True, blank=True)
    last_updated_by = models.CharField(max_length=100, null=True, blank=True)
    
    class Meta:
        db_table = 'alert_configurations'
    
    def __str__(self):
        return f"{self.name} ({self.get_alert_type_display()})"


class DormantAccountAlertConfig(models.Model):
    """
    Configuration specific to dormant account activity alerts.
    """
    alert_config = models.OneToOneField(
        AlertConfiguration, 
        on_delete=models.CASCADE,
        related_name='dormant_account_config'
    )
    
    # Dormancy parameters
    dormancy_definition_days = models.IntegerField(
        default=180,
        help_text="Number of days without activity to consider account dormant"
    )
    
    # Amount thresholds
    min_transaction_amount = models.DecimalField(
        max_digits=20,
        decimal_places=2,
        default=1000.00,
        help_text="Minimum transaction amount to trigger alert"
    )
    
    high_amount_threshold = models.DecimalField(
        max_digits=20,
        decimal_places=2,
        default=5000.00,
        help_text="Amount considered high risk for dormant accounts"
    )
    
    # Activity patterns
    check_for_previous_activity_pattern = models.BooleanField(
        default=True,
        help_text="Check if previous activity exists before dormancy"
    )
    
    alert_on_multiple_transactions = models.BooleanField(
        default=True,
        help_text="Generate alert if multiple transactions occur within monitoring period"
    )
    
    consider_all_transactions = models.BooleanField(
        default=True,
        help_text="Consider all transaction types, not just deposits/credits"
    )
    
    monitoring_window_days = models.IntegerField(
        default=7,
        help_text="Days to monitor for subsequent activity after first transaction"
    )
    
    # Risk scoring weights
    amount_factor_weight = models.IntegerField(default=30, help_text="Weight for transaction amount")
    customer_risk_factor_weight = models.IntegerField(default=20, help_text="Weight for customer risk rating")
    dormancy_duration_factor_weight = models.IntegerField(default=15, help_text="Weight for length of dormancy")
    multiple_transactions_factor_weight = models.IntegerField(default=25, help_text="Weight for multiple transactions")
    international_factor_weight = models.IntegerField(default=10, help_text="Weight for international transactions")
    
    class Meta:
        db_table = 'dormant_account_alert_configs'
    
    def __str__(self):
        return f"Dormant Account Config for {self.alert_config.name}"


class AlertThreshold(models.Model):
    """
    Model for defining alert thresholds for different factors.
    """
    id = models.AutoField(primary_key=True)
    alert_config = models.ForeignKey(
        AlertConfiguration,
        on_delete=models.CASCADE,
        related_name='thresholds'
    )
    
    factor_type = models.CharField(
        max_length=50,
        choices=[
            ('TRANSACTION_AMOUNT', 'Transaction Amount'),
            ('TRANSACTION_COUNT', 'Transaction Count'),
            ('DORMANCY_DAYS', 'Dormancy Duration Days'),
            ('ACTIVITY_VELOCITY', 'Activity Velocity'),
            ('RISK_SCORE', 'Risk Score'),
        ]
    )
    
    operator = models.CharField(
        max_length=20,
        choices=[
            ('GT', 'Greater Than'),
            ('GTE', 'Greater Than or Equal'),
            ('LT', 'Less Than'),
            ('LTE', 'Less Than or Equal'),
            ('EQ', 'Equal To'),
            ('NEQ', 'Not Equal To'),
            ('BETWEEN', 'Between Values'),
        ],
        default='GT'
    )
    
    threshold_value = models.DecimalField(max_digits=20, decimal_places=2)
    upper_threshold = models.DecimalField(
        max_digits=20,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Upper threshold for BETWEEN operator"
    )
    
    score_contribution = models.IntegerField(
        default=10,
        help_text="Points added to alert score when threshold is met"
    )
    
    description = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        db_table = 'alert_thresholds'
        unique_together = ('alert_config', 'factor_type', 'threshold_value')
    
    def __str__(self):
        if self.operator == 'BETWEEN' and self.upper_threshold:
            return f"{self.alert_config.name} - {self.factor_type}: {self.threshold_value} to {self.upper_threshold}"
        return f"{self.alert_config.name} - {self.factor_type}: {self.get_operator_display()} {self.threshold_value}" 
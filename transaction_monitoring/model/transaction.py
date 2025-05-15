from django.db import models
from django.utils import timezone
import uuid

class Transactions(models.Model):
    """
    Model representing a financial transaction.
    """
    transaction_id = models.CharField(max_length=64, primary_key=True)
    transaction_date = models.DateField()
    transaction_timestamp = models.DateTimeField(default=timezone.now)
    currency_code = models.CharField(max_length=10)
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    transaction_type_code = models.CharField(max_length=20)
    
    source_account_number = models.CharField(max_length=64, db_index=True)
    source_account_holder_id = models.CharField(max_length=64, null=True, blank=True)
    source_customer_name = models.CharField(max_length=255, null=True, blank=True)
    source_account_type_code = models.CharField(max_length=20, null=True, blank=True)
    source_country_code = models.CharField(max_length=10, null=True, blank=True)
    source_country_name = models.CharField(max_length=64, null=True, blank=True)
    source_branch_code = models.CharField(max_length=20, null=True, blank=True)
    
    destination_account_number = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    destination_account_holder_id = models.CharField(max_length=64, null=True, blank=True)
    destination_customer_name = models.CharField(max_length=255, null=True, blank=True)
    destination_account_type_code = models.CharField(max_length=20, null=True, blank=True)
    destination_country_code = models.CharField(max_length=10, null=True, blank=True)
    destination_country_name = models.CharField(max_length=64, null=True, blank=True)
    
    channel_code = models.CharField(max_length=20, null=True, blank=True)
    branch_code = models.CharField(max_length=20, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    terminal_id = models.CharField(max_length=64, null=True, blank=True)
    geo_location = models.CharField(max_length=255, null=True, blank=True)
    
    purpose_code = models.CharField(max_length=20, null=True, blank=True)
    correspondent_bank_code = models.CharField(max_length=20, null=True, blank=True)
    beneficiary_bank_code = models.CharField(max_length=20, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    narrative = models.TextField(null=True, blank=True)
    
    destination_currency_code = models.CharField(max_length=10, null=True, blank=True)
    exchange_rate = models.DecimalField(max_digits=20, decimal_places=6, null=True, blank=True)
    
    # AML specific fields
    is_checked = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'Transactions App'
        indexes = [
            models.Index(fields=['transaction_date']),
            models.Index(fields=['is_checked']),
            models.Index(fields=['source_account_number', 'transaction_timestamp']),
        ]
    
    def __str__(self):
        return f"{self.transaction_id} - {self.amount} {self.currency_code} - {self.transaction_type_code}"
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4())
        super().save(*args, **kwargs)

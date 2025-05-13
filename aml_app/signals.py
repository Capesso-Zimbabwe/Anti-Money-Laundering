from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Transaction1, Customer
from .transaction_monitor import analyze_transaction

@receiver(post_save, sender=Transaction1)
def analyze_transaction_on_save(sender, instance, created, **kwargs):
    """
    Signal handler to analyze transactions for AML indicators
    
    This will run whenever a Transaction1 is created or updated.
    For performance reasons, you might want to move this to an asynchronous task
    using something like Celery in a production environment.
    """
    # Skip if transaction has already been checked
    if instance.is_checked:
        return
        
    # Analyze the transaction - returns (SuspiciousTransaction, SuspiciousActivityReport) tuple
    suspicious_tx, suspicious_report = analyze_transaction(instance)
    
    # Mark the transaction as checked
    instance.is_checked = True
    
    # If suspicious, update status to Flagged and set the alert reason code
    if suspicious_tx:
        instance.transaction_status_code = 'RJCT'  # Rejected or flagged status
        
        # Set the AML alert reason code if it exists
        if suspicious_report:
            instance.aml_alert_reason_code = suspicious_report.suspicious_activity_type
            
            # Update customer risk rating if needed - optional feature
            try:
                if instance.source_account_holder_id:
                    customer = Customer.objects.filter(customer_id=instance.source_account_holder_id).first()
                    if customer and suspicious_report.risk_level == 'HIGH':
                        # Increase customer risk rating
                        if customer.risk_rating != 'CRITICAL':
                            customer.risk_rating = 'HIGH'
                            customer.risk_factors = (customer.risk_factors or '') + f"\nSuspicious transaction detected on {instance.transaction_date}"
                            customer.save()
            except Exception as e:
                # Log the error but continue processing
                print(f"Error updating customer risk: {e}")
        
    # Save without triggering the signal again
    instance._skip_signal = True
    instance.save()

# Prevent infinite recursion by adding a pre_save handler or modifying post_save
@receiver(post_save, sender=Transaction1)
def prevent_infinite_recursion(sender, instance, **kwargs):
    """
    Prevent the analyze_transaction_on_save signal from causing infinite recursion
    """
    if hasattr(instance, '_skip_signal') and instance._skip_signal:
        instance._skip_signal = False
        return False  # Returning False does not prevent the signal from being sent
    return True 
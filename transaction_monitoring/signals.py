"""
Signal handlers for the transaction monitoring application.
These signals coordinate the behavior of different components and microservices.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
import logging

from .model.transaction import Transactions
from .model.alert import Alert, SuspiciousActivityReport

# Configure logging
logger = logging.getLogger(__name__)

@receiver(post_save, sender=Transactions)
def process_new_transaction(sender, instance, created, **kwargs):
    """
    Signal handler that triggers transaction monitoring when a new transaction is saved.
    
    This decouples transaction creation from monitoring, making the system more maintainable.
    """
    if created:
        from .monitoring.monitor_service import TransactionMonitoringService
        
        logger.info(f"New transaction detected, triggering monitoring: {instance.transaction_id}")
        
        try:
            # Process transaction asynchronously
            # In production, this would be a task queue job
            service = TransactionMonitoringService()
            service.create_alerts_from_transaction(instance)
        except Exception as e:
            logger.error(f"Error processing transaction {instance.transaction_id}: {str(e)}")

@receiver(post_save, sender=Alert)
def handle_new_alert(sender, instance, created, **kwargs):
    """
    Signal handler for when a new alert is created.
    
    This could trigger notifications, workflow processes, etc.
    """
    if created:
        logger.info(f"New alert created: {instance.alert_id}")
        
        # Here you could add code to:
        # - Send notifications to compliance team
        # - Update metrics and dashboards
        # - Trigger additional analysis 

@receiver(post_save, sender=Transactions)
def evaluate_transaction(sender, instance, created, **kwargs):
    """
    Signal handler to evaluate transactions against rules.
    This is a placeholder for the actual implementation that would:
    1. Find applicable rules for the transaction type
    2. Run evaluation algorithms
    3. Generate alerts if thresholds are exceeded
    """
    if created:
        # In a real implementation, this would:
        # - Find applicable rules
        # - Run scoring algorithms
        # - Create alerts if needed
        pass 
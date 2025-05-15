from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
from django.apps import apps

from .engine.rule_engine import RuleEngine
from .engine.alert_engine import AlertEngine

logger = logging.getLogger(__name__)

class TransactionProcessor:
    """
    Main processor for transaction monitoring.
    
    This class orchestrates the evaluation of transactions against rules
    and the generation of alerts.
    """
    
    def __init__(self, rule_engine: RuleEngine, alert_engine: AlertEngine):
        """
        Initialize the transaction processor.
        
        Args:
            rule_engine: The rule engine to use for evaluation
            alert_engine: The alert engine to use for alert generation
        """
        self.rule_engine = rule_engine
        self.alert_engine = alert_engine
    
    def process_transaction(self, transaction: Any) -> List[Dict[str, Any]]:
        """
        Process a single transaction.
        
        Args:
            transaction: The transaction to process
            
        Returns:
            List of generated alerts
        """
        # Skip already processed transactions
        if getattr(transaction, 'is_checked', False):
            logger.debug(f"Skipping already processed transaction: {transaction.transaction_id}")
            return []
        
        # Get the necessary context for rule evaluation
        context = self._build_context(transaction)
        
        # Evaluate the transaction against rules
        rule_results = self.rule_engine.evaluate_transaction(transaction, context)
        
        # Generate alerts for triggered rules
        alerts = []
        for result in rule_results:
            alert = self.alert_engine.generate_alert(transaction, result)
            alerts.append(alert)
        
        # Mark transaction as processed
        self._mark_as_processed(transaction)
        
        # Return the generated alerts
        return alerts
    
    def process_transactions(self, transactions: List[Any]) -> List[Dict[str, Any]]:
        """
        Process multiple transactions.
        
        Args:
            transactions: List of transactions to process
            
        Returns:
            List of generated alerts
        """
        all_alerts = []
        
        for transaction in transactions:
            alerts = self.process_transaction(transaction)
            all_alerts.extend(alerts)
        
        return all_alerts
    
    def process_unprocessed_transactions(self, batch_size: int = 100) -> Dict[str, Any]:
        """
        Process all unprocessed transactions.
        
        Args:
            batch_size: Number of transactions to process in each batch
            
        Returns:
            Processing statistics
        """
        Transaction1 = apps.get_model('aml_app', 'Transaction1')
        
        # Get count of unprocessed transactions
        unprocessed_count = Transaction1.objects.filter(is_checked=False).count()
        
        if unprocessed_count == 0:
            logger.info("No unprocessed transactions found")
            return {
                "status": "success",
                "message": "No unprocessed transactions found",
                "processed_count": 0,
                "flagged_count": 0
            }
        
        # Process transactions in batches
        total_processed = 0
        total_flagged = 0
        
        # Calculate total batches
        total_batches = (unprocessed_count + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            # Get a batch of transactions
            batch = Transaction1.objects.filter(is_checked=False).order_by('transaction_timestamp')[:batch_size]
            
            # Process the batch
            batch_transactions = list(batch)
            alerts = self.process_transactions(batch_transactions)
            
            # Update statistics
            total_processed += len(batch_transactions)
            total_flagged += len(alerts)
            
            logger.info(f"Processed batch {batch_num + 1}/{total_batches}: {len(batch_transactions)} transactions, {len(alerts)} alerts")
        
        # Return statistics
        return {
            "status": "success",
            "message": f"Successfully processed {total_processed} transactions",
            "processed_count": total_processed,
            "flagged_count": total_flagged,
            "alert_rate": f"{(total_flagged / total_processed * 100):.2f}%" if total_processed > 0 else "0%"
        }
    
    def _build_context(self, transaction: Any) -> Dict[str, Any]:
        """
        Build context for rule evaluation.
        
        Args:
            transaction: The transaction to build context for
            
        Returns:
            Context dictionary
        """
        Transaction1 = apps.get_model('aml_app', 'Transaction1')
        Customer = apps.get_model('aml_app', 'Customer')
        
        context = {}
        
        # Get account history
        lookback_days = 180  # Default lookback period
        lookback_date = datetime.now() - timedelta(days=lookback_days)
        
        account_history = Transaction1.objects.filter(
            source_account_number=transaction.source_account_number,
            transaction_timestamp__gte=lookback_date
        ).exclude(
            transaction_id=transaction.transaction_id
        ).order_by('transaction_timestamp')
        
        context['account_history'] = list(account_history)
        
        # Get account information
        context['account_info'] = {
            'account_number': transaction.source_account_number,
        }
        
        # Get customer information if available
        if hasattr(transaction, 'source_account_holder_id') and transaction.source_account_holder_id:
            try:
                customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
                context['customer_info'] = {
                    'customer_id': customer.customer_id,
                    'customer_type': customer.customer_type,
                    'customer_status': customer.customer_status,
                    'risk_level': getattr(customer, 'risk_level', 'MEDIUM'),
                    'open_date': getattr(customer, 'onboarding_date', None),
                }
                
                # Add additional customer information
                if customer.customer_type == 'INDIVIDUAL':
                    context['customer_info'].update({
                        'name': f"{customer.first_name} {customer.last_name}",
                        'nationality': customer.nationality,
                        'residence_country': customer.residential_country,
                    })
                else:  # ENTITY
                    context['customer_info'].update({
                        'name': customer.entity_name,
                        'industry': customer.industry_description,
                        'incorporation_date': customer.date_of_incorporation,
                    })
            except Customer.DoesNotExist:
                # If customer not found, add basic info from transaction
                context['customer_info'] = {
                    'name': transaction.source_customer_name,
                }
        
        return context
    
    def _mark_as_processed(self, transaction: Any) -> None:
        """
        Mark a transaction as processed.
        
        Args:
            transaction: The transaction to mark
        """
        transaction.is_checked = True
        transaction.save()

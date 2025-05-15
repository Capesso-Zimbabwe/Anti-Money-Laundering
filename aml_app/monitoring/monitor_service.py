from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from django.apps import apps

from .engine.rule_engine import RuleEngine
from .engine.scoring_engine import ScoringEngine
from .engine.alert_engine import AlertEngine
from .rules.base_rule import BaseRule
from .rules.dormant_account import DormantAccountRule
from .rules.large_cash import LargeCashRule
from .config.rule_config import RuleConfig
from .config.transaction_types import TransactionTypeRegistry
from .monitor_processor import TransactionProcessor

logger = logging.getLogger(__name__)

class TransactionMonitoringService:
    """
    High-level service for transaction monitoring.
    
    This service initializes and configures the necessary components
    for transaction monitoring.
    """
    
    def __init__(self):
        """Initialize the transaction monitoring service."""
        # Initialize configuration components
        self.rule_config = RuleConfig()
        self.transaction_registry = TransactionTypeRegistry()
        
        # Initialize engines
        self.scoring_engine = ScoringEngine()
        self.rule_engine = RuleEngine(self.scoring_engine)
        self.alert_engine = AlertEngine()
        
        # Initialize processor
        self.processor = TransactionProcessor(self.rule_engine, self.alert_engine)
        
        # Register default rules
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register default rules with the rule engine."""
        # Register dormant account rule
        dormant_config = self.rule_config.get_rule_config('AML-ADR-ALL-ALL-A-M06-AIN')
        if dormant_config:
            dormant_rule = DormantAccountRule(dormant_config)
            self.rule_engine.register_rule(dormant_rule)
        
        # Register large cash rule
        large_cash_config = self.rule_config.get_rule_config('AML-LCT-CCE-INN-A-D01-LCT')
        if large_cash_config:
            large_cash_rule = LargeCashRule(large_cash_config)
            self.rule_engine.register_rule(large_cash_rule)
        
        logger.info("Registered default rules")
    
    def register_rule(self, rule: BaseRule) -> None:
        """
        Register a rule with the service.
        
        Args:
            rule: The rule to register
        """
        self.rule_engine.register_rule(rule)
    
    def process_transaction(self, transaction: Any) -> List[Dict[str, Any]]:
        """
        Process a single transaction.
        
        Args:
            transaction: The transaction to process
            
        Returns:
            List of generated alerts
        """
        return self.processor.process_transaction(transaction)
    
    def process_unprocessed_transactions(self, batch_size: int = 100) -> Dict[str, Any]:
        """
        Process all unprocessed transactions.
        
        Args:
            batch_size: Number of transactions to process in each batch
            
        Returns:
            Processing statistics
        """
        return self.processor.process_unprocessed_transactions(batch_size)
    
    def update_rule_config(self, rule_id: str, config: Dict[str, Any]) -> bool:
        """
        Update the configuration for a rule.
        
        Args:
            rule_id: The ID of the rule
            config: The updated configuration
            
        Returns:
            True if the update was successful
        """
        # Update configuration
        self.rule_config.set_rule_config(rule_id, config)
        
        # Save configuration
        success = self.rule_config.save()
        
        # Recreate and re-register the rule
        if success:
            # Unregister the existing rule
            self.rule_engine.unregister_rule(rule_id)
            
            # Create and register the updated rule
            if rule_id == 'AML-ADR-ALL-ALL-A-M06-AIN':
                rule = DormantAccountRule(config)
                self.rule_engine.register_rule(rule)
            elif rule_id == 'AML-LCT-CCE-INN-A-D01-LCT':
                rule = LargeCashRule(config)
                self.rule_engine.register_rule(rule)
            
            logger.info(f"Updated configuration for rule: {rule_id}")
        
        return success
    
    def create_alerts_from_transaction(self, transaction: Any) -> List[Dict[str, Any]]:
        """
        Process a transaction and create alert records in the database.
        
        Args:
            transaction: The transaction to process
            
        Returns:
            List of created alert objects
        """
        # Process the transaction
        alert_data_list = self.process_transaction(transaction)
        
        # Create alerts in the database
        created_alerts = []
        for alert_data in alert_data_list:
            alert = self._create_alert_record(transaction, alert_data)
            created_alerts.append(alert)
        
        return created_alerts
    
    def _create_alert_record(self, transaction: Any, alert_data: Dict[str, Any]) -> Any:
        """
        Create an alert record in the database.
        
        Args:
            transaction: The transaction that triggered the alert
            alert_data: The alert data
            
        Returns:
            Created alert object
        """
        SuspiciousTransaction1 = apps.get_model('aml_app', 'SuspiciousTransaction1')
        SuspiciousActivityReport = apps.get_model('aml_app', 'SuspiciousActivityReport')
        
        # Create suspicious transaction record
        suspicious_tx = SuspiciousTransaction1(
            transaction=transaction,
            risk_level=alert_data['risk_level'],
            flagged_reason=alert_data['narrative'],
            suspicious_date=transaction.transaction_date,
            suspicious_description=alert_data['narrative'],
            manual_review_required=True,
            sender_account=transaction.source_account_number,
            receiver_account=transaction.destination_account_number,
            beneficiary_account=transaction.destination_account_number,
            beneficiary_name=transaction.destination_customer_name,
            amount=transaction.amount,
            report_id=alert_data['alert_id']
        )
        
        # Add customer details if available
        if hasattr(transaction, 'source_account_holder_id') and transaction.source_account_holder_id:
            suspicious_tx.customer_id = transaction.source_account_holder_id
        
        suspicious_tx.save()
        
        # Create SAR report
        sar_report = SuspiciousActivityReport(
            report_id=alert_data['alert_id'],
            report_reference_number=f"SAR-{alert_data['alert_id']}",
            report_type='SAR',
            report_status='DRAFT',
            suspicious_activity_type='UNUSUAL_ACTIVITY',
            detection_date=datetime.now(),
            activity_start_date=transaction.transaction_date,
            activity_end_date=transaction.transaction_date,
            total_suspicious_amount=transaction.amount,
            currency_code=transaction.currency_code,
            related_transactions=transaction.transaction_id,
            primary_subject_name=transaction.source_customer_name or "Unknown",
            risk_level=alert_data['risk_level'],
            suspicious_activity_description=alert_data['narrative'],
            red_flags_identified=alert_data['narrative'],
            internal_actions_taken="Flagged for review",
            filing_institution_name="Bank",
            filing_institution_id="BANK1",
            preparer_name="AML System",
            preparer_position="Automated Detection",
            preparer_contact="system@bank.com",
            approver_name="Pending Review",
            approver_position="Compliance Officer",
            created_by="AML System"
        )
        
        sar_report.save()
        
        return suspicious_tx

from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
from .base_rule import BaseRule

class LargeCashRule(BaseRule):
    """
    Rule to detect unusually large cash deposits.
    
    This rule monitors for individual cash deposits that exceed
    configured thresholds.
    
    Rule ID: AML-LCT-CCE-INN-A-D01-LCT
    """
    
    def __init__(self, config=None):
        """
        Initialize the rule with configuration.
        
        Args:
            config: Configuration dictionary or None to use defaults
        """
        # Default configuration
        default_config = {
            'rule_id': 'AML-LCT-CCE-INN-A-D01-LCT',
            'rule_name': 'Large Cash Transaction',
            'description': 'Detects unusually large cash deposits.',
            'alert_level': 'Transaction',
            'evaluation_trigger': 'Transaction',
            'scoring_algorithm': 'MAX',
            'transaction_types': ['CCE-INN'],
            'thresholds': {
                'transaction_amount': 10000,
                'currency': 'USD'
            },
            'recurrence': {
                'lookback_period_days': 30,
                'min_occurrences': 1
            },
            'enabled': True,
            'version': '1.0'
        }
        
        # Merge default config with provided config
        rule_config = default_config
        if config:
            rule_config.update(config)
        
        # Initialize base class
        super().__init__(rule_config)
    
    def evaluate(self, transaction: Any, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate if the transaction is a large cash deposit.
        
        Args:
            transaction: The transaction to evaluate
            context: Dictionary containing additional context
            
        Returns:
            Tuple of (triggered: bool, details: Dict)
        """
        # Skip if transaction is not of required type
        if not self._is_deposit(transaction.transaction_type_code):
            return False, {}
        
        # Check if transaction amount exceeds threshold
        threshold = self.thresholds.get('transaction_amount', 10000)
        if transaction.amount < threshold:
            return False, {}
        
        # Check currency if specified
        currency = self.thresholds.get('currency')
        if currency and transaction.currency_code != currency:
            return False, {}
        
        # Get customer risk level if available
        customer_info = context.get('customer_info', {})
        customer_risk = customer_info.get('risk_level', 'MEDIUM')
        
        # Build detail object
        details = {
            'transaction_id': transaction.transaction_id,
            'amount': transaction.amount,
            'threshold': threshold,
            'transaction_type': transaction.transaction_type_code,
            'transaction_date': transaction.transaction_date,
            'customer_id': getattr(transaction, 'source_account_holder_id', None),
            'customer_name': getattr(transaction, 'source_customer_name', 'Unknown'),
            'customer_risk': customer_risk,
            'account_number': transaction.source_account_number,
            'recurrence': 1  # For scoring purposes
        }
        
        # Add branch information if available
        if hasattr(transaction, 'branch_code') and transaction.branch_code:
            details['branch_code'] = transaction.branch_code
            details['branch_name'] = getattr(transaction, 'branch_name', '')
        
        # Add location information if available
        if hasattr(transaction, 'geo_location') and transaction.geo_location:
            details['location'] = transaction.geo_location
        
        # Add channel information if available
        if hasattr(transaction, 'channel_code') and transaction.channel_code:
            details['channel'] = transaction.channel_code
        
        return True, details
    
    def _is_deposit(self, transaction_type_code: str) -> bool:
        """
        Check if transaction type is a deposit.
        
        Args:
            transaction_type_code: The transaction type code
            
        Returns:
            True if transaction is a deposit
        """
        deposit_codes = [
            'DEPOSIT', 'CASH DEP', 'CHEQUE DEP', 'DIRECT CR',
            'CSH+', 'CSH_CP+', 'CSH_CP_HR+'
        ]
        return transaction_type_code in deposit_codes

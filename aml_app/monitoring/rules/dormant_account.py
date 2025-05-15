from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
from .base_rule import BaseRule

class DormantAccountRule(BaseRule):
    """
    Rule to detect significant activity in previously inactive accounts.
    
    This rule monitors dormant accounts and generates alerts when significant
    activity is detected for such accounts.
    
    Rule ID: AML-ADR-ALL-ALL-A-M06-AIN
    """
    
    def __init__(self, config=None):
        """
        Initialize the rule with configuration.
        
        Args:
            config: Configuration dictionary or None to use defaults
        """
        # Default configuration
        default_config = {
            'rule_id': 'AML-ADR-ALL-ALL-A-M06-AIN',
            'rule_name': 'Activity Seen in A Dormant Account',
            'description': 'Detects significant activity in previously inactive accounts.',
            'alert_level': 'Account',
            'evaluation_trigger': 'Daily Activity',
            'scoring_algorithm': 'MAX',
            'transaction_types': ['ALL-ALL'],
            'thresholds': {
                'account_age_days': 180,
                'activity_amount': 10000,
                'inactive_period_months': 6,
                'max_prior_activity': 100
            },
            'recurrence': {
                'lookback_period_months': 1,
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
        Evaluate if the transaction represents activity in a dormant account.
        
        Args:
            transaction: The transaction to evaluate
            context: Dictionary containing account history and other required context
            
        Returns:
            Tuple of (triggered: bool, details: Dict)
        """
        # Get account history from context
        account_history = context.get('account_history', [])
        account_info = context.get('account_info', {})
        
        # Check if account meets minimum age requirement
        account_open_date = account_info.get('open_date')
        if not account_open_date:
            return False, {}
            
        account_age_days = (datetime.now().date() - account_open_date).days
        if account_age_days < self.thresholds['account_age_days']:
            return False, {}
        
        # Calculate activity in current month
        current_period_start = datetime.now() - timedelta(days=30)
        current_activity = self._calculate_activity(account_history, current_period_start, datetime.now())
        
        # If current activity is below threshold, no alert
        if current_activity < self.thresholds['activity_amount']:
            return False, {}
        
        # Calculate activity in previous inactive period
        prior_period_start = current_period_start - timedelta(days=30 * self.thresholds['inactive_period_months'])
        prior_period_end = current_period_start
        prior_activity = self._calculate_activity(account_history, prior_period_start, prior_period_end)
        
        # Check if prior activity was below the dormancy threshold
        if prior_activity > self.thresholds['max_prior_activity']:
            return False, {}
        
        # Account was dormant and now has significant activity
        details = {
            'account_number': transaction.source_account_number,
            'account_age_days': account_age_days,
            'current_activity': current_activity,
            'prior_activity': prior_activity,
            'inactive_period_months': self.thresholds['inactive_period_months'],
            'transaction_id': transaction.transaction_id,
            'amount': transaction.amount,
            'recurrence': 1  # For scoring purposes
        }
        
        return True, details
    
    def _calculate_activity(self, account_history: List[Any], start_date: datetime, end_date: datetime) -> float:
        """
        Calculate the total activity amount in an account during a period.
        
        Args:
            account_history: List of transactions for the account
            start_date: Start date for the period
            end_date: End date for the period
            
        Returns:
            Total activity amount (sum of absolute transaction amounts)
        """
        total_activity = 0.0
        
        for tx in account_history:
            # Check if transaction is within the period
            tx_date = tx.transaction_timestamp
            if start_date <= tx_date <= end_date:
                total_activity += abs(tx.amount)
        
        return total_activity

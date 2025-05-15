from typing import Dict, List, Any, Optional
from datetime import datetime
import random
import string
import logging

logger = logging.getLogger(__name__)

class AlertEngine:
    """
    Engine for generating and managing alerts.
    """
    
    def __init__(self):
        """Initialize the alert engine."""
        self.alerts = []
    
    def generate_alert(self, transaction: Any, rule_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an alert from a rule result.
        
        Args:
            transaction: The transaction that triggered the alert
            rule_result: The result of the rule evaluation
            
        Returns:
            Dictionary representing the alert
        """
        # Generate a unique alert ID
        alert_id = self._generate_alert_id(rule_result['rule']['rule_id'])
        
        # Create the alert
        alert = {
            'alert_id': alert_id,
            'rule_id': rule_result['rule']['rule_id'],
            'rule_name': rule_result['rule']['rule_name'],
            'transaction_id': transaction.transaction_id,
            'account_number': transaction.source_account_number,
            'customer_id': getattr(transaction, 'source_account_holder_id', None),
            'score': rule_result['score'],
            'risk_level': self._get_risk_level(rule_result['score']),
            'details': rule_result['details'],
            'transaction_date': transaction.transaction_date,
            'alert_date': datetime.now(),
            'status': 'NEW',
            'assigned_to': None,
            'narrative': self._generate_narrative(transaction, rule_result)
        }
        
        logger.info(f"Generated alert: {alert_id} - Rule: {rule_result['rule']['rule_id']} - Score: {rule_result['score']}")
        
        return alert
    
    def _generate_alert_id(self, rule_id: str) -> str:
        """
        Generate a unique alert ID.
        
        Args:
            rule_id: The ID of the rule that triggered the alert
            
        Returns:
            Unique alert ID
        """
        # Generate a timestamp
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Generate a random string
        random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        
        # Extract rule prefix
        rule_prefix = rule_id.split('-')[0] if '-' in rule_id else rule_id[:3]
        
        # Construct the alert ID
        alert_id = f"ALT-{rule_prefix}-{timestamp}-{random_str}"
        
        return alert_id
    
    def _get_risk_level(self, score: int) -> str:
        """
        Get the risk level based on the score.
        
        Args:
            score: The alert score
            
        Returns:
            Risk level (HIGH, MEDIUM, LOW)
        """
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_narrative(self, transaction: Any, rule_result: Dict[str, Any]) -> str:
        """
        Generate a narrative description for the alert.
        
        Args:
            transaction: The transaction that triggered the alert
            rule_result: The result of the rule evaluation
            
        Returns:
            Narrative description
        """
        rule_name = rule_result['rule']['rule_name']
        details = rule_result['details']
        
        # Basic narrative
        narrative = f"Alert generated for rule: {rule_name}. "
        
        # Add transaction details
        narrative += f"Transaction ID: {transaction.transaction_id}, "
        narrative += f"Amount: {transaction.amount} {transaction.currency_code}. "
        
        # Add specific details based on the rule
        if 'recurrence' in details:
            narrative += f"Activity occurred {details['recurrence']} times. "
            
        if 'amount' in details:
            narrative += f"Total amount: {details['amount']} {transaction.currency_code}. "
            
        # Add risk level
        narrative += f"Risk level: {self._get_risk_level(rule_result['score'])}."
        
        return narrative

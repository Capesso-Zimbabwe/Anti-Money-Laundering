from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

class BaseRule(ABC):
    """
    Abstract base class for all transaction monitoring rules.
    
    Each rule must implement the evaluate method which determines
    if a transaction meets the criteria for flagging.
    """
    
    def __init__(self, rule_config: Dict[str, Any]):
        """
        Initialize the rule with its configuration.
        
        Args:
            rule_config: Dictionary containing rule configuration
        """
        self.rule_id = rule_config.get('rule_id', '')
        self.rule_name = rule_config.get('rule_name', '')
        self.description = rule_config.get('description', '')
        self.alert_level = rule_config.get('alert_level', 'Transaction')
        self.evaluation_trigger = rule_config.get('evaluation_trigger', 'Transaction')
        self.scoring_algorithm = rule_config.get('scoring_algorithm', 'MAX')
        self.transaction_types = rule_config.get('transaction_types', [])
        self.enabled = rule_config.get('enabled', True)
        self.thresholds = rule_config.get('thresholds', {})
        self.recurrence_settings = rule_config.get('recurrence', {})
        
        # Additional metadata
        self.create_date = datetime.now()
        self.last_updated = datetime.now()
        self.version = rule_config.get('version', '1.0')
    
    @abstractmethod
    def evaluate(self, transaction: Any, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate the rule against a transaction and context.
        
        Args:
            transaction: The transaction to evaluate
            context: Additional context data needed for evaluation
            
        Returns:
            Tuple containing (triggered: bool, details: Dict)
        """
        pass
    
    def get_rule_info(self) -> Dict[str, Any]:
        """Get rule metadata."""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'description': self.description,
            'alert_level': self.alert_level,
            'transaction_types': self.transaction_types,
            'version': self.version
        }
    
    def matches_transaction_type(self, transaction_type: str) -> bool:
        """
        Check if a transaction type is monitored by this rule.
        
        Args:
            transaction_type: The transaction type code
            
        Returns:
            True if this rule monitors the transaction type
        """
        if 'ALL-ALL' in self.transaction_types:
            return True
            
        for tt in self.transaction_types:
            # Lookup in transaction type groups
            if transaction_type in self._get_transaction_codes(tt):
                return True
        return False
    
    def _get_transaction_codes(self, group_name: str) -> List[str]:
        """
        Get the transaction codes for a group.
        This would typically fetch from a configuration service.
        
        Args:
            group_name: The name of the transaction type group
            
        Returns:
            List of transaction codes in the group
        """
        # In a real implementation, this would fetch from a configuration service
        # For now, return a simplified implementation
        transaction_groups = {
            'CCE-INN': ['DEPOSIT', 'CASH DEP', 'CHEQUE DEP', 'DIRECT CR'],
            'CCE-OUT': ['WITHDRAWAL', 'WITHDRAW', 'CASH WDL', 'ATM WDL'],
            'TRF-ALL': ['TRANSFER', 'WIRE', 'SWIFT', 'ACH'],
            'PMT-ALL': ['BILL PMT', 'PAYMENT', 'PMT', 'DIRECT DEBIT'],
            'FEE-ALL': ['FEE', 'SRV CHARGE', 'CHARGE'],
            'ADJ-ALL': ['REV', 'ADJ', 'CORRECTION']
        }
        
        return transaction_groups.get(group_name, [])

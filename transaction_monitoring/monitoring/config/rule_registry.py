from typing import Dict, List, Any, Type

from ..rules.base_rule import BaseRule
from ..rules.dormant_account import DormantAccountRule
from ..rules.large_cash import LargeCashRule

class RuleRegistry:
    """
    Registry of available rule types and their implementations.
    
    This registry maps rule types to their implementation classes
    and provides metadata about configurable parameters.
    """
    
    def __init__(self):
        """Initialize the rule registry with built-in rules."""
        self.rule_types = {}
        self.register_built_in_rules()
    
    def register_built_in_rules(self):
        """Register the built-in rule types."""
        # Register dormant account rule type
        self.register_rule_type(
            rule_type_id="dormant_account",
            rule_type_name="Dormant Account Activity",
            rule_class=DormantAccountRule,
            description="Detects activity in previously dormant accounts",
            configurable_params=[
                {
                    "name": "account_age_days",
                    "display_name": "Minimum Account Age (days)",
                    "type": "integer",
                    "default": 90,
                    "description": "Minimum age of account in days to be considered for dormancy checks"
                },
                {
                    "name": "inactive_period_months",
                    "display_name": "Inactive Period (months)",
                    "type": "integer",
                    "default": 3,
                    "description": "Number of months with minimal activity to consider account dormant"
                },
                {
                    "name": "activity_amount",
                    "display_name": "Activity Amount Threshold",
                    "type": "float",
                    "default": 10000.00,
                    "description": "Minimum amount to trigger alert when activity occurs in dormant account"
                },
                {
                    "name": "max_prior_activity",
                    "display_name": "Maximum Prior Activity",
                    "type": "float",
                    "default": 1000.00,
                    "description": "Maximum allowed activity amount during dormancy period"
                }
            ]
        )
        
        # Register large cash rule type
        self.register_rule_type(
            rule_type_id="large_cash",
            rule_type_name="Large Cash Transaction",
            rule_class=LargeCashRule,
            description="Detects unusually large cash deposits",
            configurable_params=[
                {
                    "name": "transaction_amount",
                    "display_name": "Transaction Amount Threshold",
                    "type": "float",
                    "default": 10000.00,
                    "description": "Minimum transaction amount to trigger an alert"
                },
                {
                    "name": "currency",
                    "display_name": "Currency",
                    "type": "string",
                    "default": "USD",
                    "description": "Currency code for the threshold amount"
                },
                {
                    "name": "lookback_period_days",
                    "display_name": "Lookback Period (days)",
                    "type": "integer",
                    "default": 30,
                    "description": "Number of days to look back for similar transactions"
                }
            ]
        )
    
    def register_rule_type(self, rule_type_id: str, rule_type_name: str, 
                          rule_class: Type[BaseRule], description: str,
                          configurable_params: List[Dict[str, Any]]) -> None:
        """
        Register a rule type with the registry.
        
        Args:
            rule_type_id: Unique identifier for the rule type
            rule_type_name: Human-readable name for the rule type
            rule_class: Implementation class for the rule
            description: Description of what the rule detects
            configurable_params: List of parameters that can be configured
        """
        self.rule_types[rule_type_id] = {
            "id": rule_type_id,
            "name": rule_type_name,
            "class": rule_class,
            "description": description,
            "configurable_params": configurable_params
        }
    
    def get_rule_type(self, rule_type_id: str) -> Dict[str, Any]:
        """
        Get information about a rule type.
        
        Args:
            rule_type_id: The ID of the rule type
            
        Returns:
            Dictionary with rule type information
        """
        return self.rule_types.get(rule_type_id, {})
    
    def get_all_rule_types(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered rule types.
        
        Returns:
            List of dictionaries with rule type information
        """
        return [
            {
                "id": rule_id,
                "name": rule_info["name"],
                "description": rule_info["description"],
                "configurable_params": rule_info["configurable_params"]
            }
            for rule_id, rule_info in self.rule_types.items()
        ]
    
    def create_rule_instance(self, rule_type_id: str, config: Dict[str, Any]) -> BaseRule:
        """
        Create an instance of a rule with the specified configuration.
        
        Args:
            rule_type_id: The ID of the rule type
            config: The configuration for the rule
            
        Returns:
            An instance of the rule
            
        Raises:
            ValueError: If the rule type ID is invalid
        """
        rule_type = self.rule_types.get(rule_type_id)
        if not rule_type:
            raise ValueError(f"Invalid rule type ID: {rule_type_id}")
        
        rule_class = rule_type["class"]
        return rule_class(config)

# Create a singleton instance
rule_registry = RuleRegistry() 
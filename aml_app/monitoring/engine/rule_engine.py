from typing import Dict, List, Any, Optional
import logging

from ..rules.base_rule import BaseRule

logger = logging.getLogger(__name__)

class RuleEngine:
    """
    Core rule evaluation engine.
    
    This engine manages the evaluation of rules against transactions
    and calculates risk scores.
    """
    
    def __init__(self, scoring_engine=None):
        """
        Initialize the rule engine.
        
        Args:
            scoring_engine: Optional scoring engine instance
        """
        self.rules = []
        self.scoring_engine = scoring_engine
    
    def register_rule(self, rule: BaseRule) -> None:
        """
        Register a rule with the engine.
        
        Args:
            rule: The rule to register
        """
        self.rules.append(rule)
        logger.info(f"Registered rule: {rule.rule_id} - {rule.rule_name}")
    
    def unregister_rule(self, rule_id: str) -> None:
        """
        Unregister a rule from the engine.
        
        Args:
            rule_id: The ID of the rule to unregister
        """
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        logger.info(f"Unregistered rule: {rule_id}")
    
    def evaluate_transaction(self, transaction: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a transaction against all registered rules.
        
        Args:
            transaction: The transaction to evaluate
            context: Additional context needed for rule evaluation
            
        Returns:
            List of dictionaries containing rule results and scores
        """
        results = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            # Skip rules that don't apply to this transaction type
            if not rule.matches_transaction_type(transaction.transaction_type_code):
                continue
                
            try:
                # Evaluate the rule
                triggered, details = rule.evaluate(transaction, context)
                
                if triggered:
                    # Calculate the risk score
                    score = self.scoring_engine.calculate_score(rule, transaction, details)
                    
                    # If score exceeds threshold, add to results
                    if score >= self.scoring_engine.get_minimum_alert_score():
                        results.append({
                            'rule': rule.get_rule_info(),
                            'score': score,
                            'details': details
                        })
                        
                        logger.info(
                            f"Rule triggered: {rule.rule_id} - Score: {score} - "
                            f"Transaction: {transaction.transaction_id}"
                        )
                    else:
                        logger.debug(
                            f"Rule triggered but score below threshold: {rule.rule_id} - "
                            f"Score: {score} - Transaction: {transaction.transaction_id}"
                        )
            except Exception as e:
                logger.error(
                    f"Error evaluating rule {rule.rule_id} on transaction "
                    f"{transaction.transaction_id}: {str(e)}"
                )
                
        return results

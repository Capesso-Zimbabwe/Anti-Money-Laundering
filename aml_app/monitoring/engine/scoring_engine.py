from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ScoringEngine:
    """
    Risk scoring engine that calculates alert scores based on
    configurable scoring factors and thresholds.
    """
    
    def __init__(self):
        """Initialize the scoring engine with default settings."""
        self.minimum_alert_score = 40
        
        # Default scoring factors
        self.scoring_factors = {
            'RECURRENCE': {
                1: 0,
                2: 10,
                3: 20
            },
            'ACTIVITY_VALUE': {
                10000: 10,
                15000: 20,
                20000: 30,
                25000: 40
            },
            'COUNTRY_RISK': {
                'LOW': 0,
                'MEDIUM': 10,
                'HIGH': 30
            },
            'PARTY_RISK': {
                'LOW': 0,
                'MEDIUM': 10,
                'HIGH': 30
            }
        }
    
    def get_minimum_alert_score(self) -> int:
        """
        Get the minimum score required to generate an alert.
        
        Returns:
            Minimum score threshold
        """
        return self.minimum_alert_score
    
    def calculate_score(self, rule: Any, transaction: Any, details: Dict[str, Any]) -> int:
        """
        Calculate the risk score for a rule result.
        
        Args:
            rule: The rule that was triggered
            transaction: The transaction that triggered the rule
            details: The details of the rule evaluation
            
        Returns:
            Calculated risk score
        """
        total_score = 0
        
        # Calculate value score
        if 'amount' in details:
            value_score = self._get_score_by_threshold(
                'ACTIVITY_VALUE', 
                details['amount']
            )
            total_score += value_score
            logger.debug(f"Value score: {value_score} for amount {details['amount']}")
        
        # Calculate recurrence score
        if 'recurrence' in details:
            recurrence_score = self._get_score_by_threshold(
                'RECURRENCE', 
                details['recurrence']
            )
            total_score += recurrence_score
            logger.debug(f"Recurrence score: {recurrence_score} for recurrence {details['recurrence']}")
        
        # Calculate country risk score
        if 'country_risk' in details:
            country_score = self.scoring_factors['COUNTRY_RISK'].get(
                details['country_risk'], 0
            )
            total_score += country_score
            logger.debug(f"Country score: {country_score} for risk {details['country_risk']}")
        
        # Calculate party risk score
        if 'party_risk' in details:
            party_score = self.scoring_factors['PARTY_RISK'].get(
                details['party_risk'], 0
            )
            total_score += party_score
            logger.debug(f"Party score: {party_score} for risk {details['party_risk']}")
        
        # Apply scoring algorithm (MAX or AVG)
        if rule.scoring_algorithm == 'AVG' and len(details) > 0:
            total_score = total_score / len(details)
            
        logger.debug(f"Final score: {total_score} using algorithm {rule.scoring_algorithm}")
        return total_score
    
    def _get_score_by_threshold(self, factor: str, value: Any) -> int:
        """
        Get score for a value based on thresholds.
        
        Args:
            factor: The scoring factor name
            value: The value to score
            
        Returns:
            The score for the value
        """
        if factor not in self.scoring_factors:
            return 0
            
        thresholds = self.scoring_factors[factor]
        
        # For numeric thresholds, find the highest threshold that value exceeds
        if all(isinstance(k, (int, float)) for k in thresholds.keys()):
            sorted_thresholds = sorted(thresholds.keys())
            for threshold in reversed(sorted_thresholds):
                if value >= threshold:
                    return thresholds[threshold]
        # For categorical thresholds, exact match
        elif isinstance(value, str) and value in thresholds:
            return thresholds[value]
        
        return 0

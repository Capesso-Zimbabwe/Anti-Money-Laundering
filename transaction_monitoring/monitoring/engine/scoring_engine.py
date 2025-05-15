"""
Risk scoring engine for transaction monitoring.
"""

from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
from django.apps import apps

logger = logging.getLogger(__name__)

class ScoringEngine:
    """
    Engine for calculating risk scores for transactions.
    
    This engine evaluates transaction data against configured risk factors
    and calculates a risk score based on the rule thresholds.
    """
    
    def __init__(self, min_alert_score: int = 40):
        """
        Initialize the scoring engine.
        
        Args:
            min_alert_score: Minimum score required to generate an alert
        """
        self.min_alert_score = min_alert_score
    
    def get_minimum_alert_score(self) -> int:
        """
        Get the minimum score required to generate an alert.
        
        Returns:
            Minimum alert score
        """
        return self.min_alert_score
    
    def set_minimum_alert_score(self, score: int) -> None:
        """
        Set the minimum score required to generate an alert.
        
        Args:
            score: Minimum alert score
        """
        self.min_alert_score = score
    
    def calculate_score(self, rule: Any, transaction: Any, details: Dict[str, Any]) -> int:
        """
        Calculate the risk score for a transaction.
        
        Args:
            rule: The rule that triggered
            transaction: The transaction being evaluated
            details: Details about the rule trigger
            
        Returns:
            Calculated risk score
        """
        # First check if we have a model with configured scoring thresholds
        ScoringThreshold = apps.get_model('transaction_monitoring', 'ScoringThreshold', require_ready=False)
        scoring_thresholds = {}
        
        try:
            # Query configured thresholds from database
            thresholds = ScoringThreshold.objects.filter(rule__rule_code=rule.rule_id.split('-', 1)[1])
            
            # Group thresholds by factor type
            for threshold in thresholds:
                if threshold.factor_type not in scoring_thresholds:
                    scoring_thresholds[threshold.factor_type] = []
                scoring_thresholds[threshold.factor_type].append({
                    'value': float(threshold.threshold_value),
                    'score': threshold.score
                })
        except Exception as e:
            logger.warning(f"Failed to load scoring thresholds from database: {str(e)}")
            # Fall back to rule.thresholds if configured thresholds are not available
            scoring_thresholds = {}
        
        # Base score starts at 0
        total_score = 0
        scores_by_factor = {}
        
        # Activity Value Scoring (transaction amount)
        activity_value = transaction.amount
        activity_score = 0
        
        if 'ACTIVITY_VALUE' in scoring_thresholds and scoring_thresholds['ACTIVITY_VALUE']:
            # Get all thresholds that the transaction exceeds
            applicable_thresholds = [t for t in scoring_thresholds['ACTIVITY_VALUE'] if activity_value >= t['value']]
            
            if applicable_thresholds:
                # Get the highest score among applicable thresholds
                activity_score = max(t['score'] for t in applicable_thresholds)
        else:
            # Default scoring based on rule thresholds
            activity_thresholds = rule.thresholds.get('activity_value', [])
            for threshold in sorted(activity_thresholds, key=lambda x: x.get('value', 0), reverse=True):
                if activity_value >= threshold.get('value', 0):
                    activity_score = threshold.get('score', 0)
                    break
        
        scores_by_factor['ACTIVITY_VALUE'] = activity_score
        total_score += activity_score
        
        # Recurrence Scoring (frequency of activity)
        recurrence_count = details.get('recurrence_count', 1)
        recurrence_score = 0
        
        if 'RECURRENCE' in scoring_thresholds and scoring_thresholds['RECURRENCE']:
            # Get all thresholds that the transaction meets or exceeds
            applicable_thresholds = [t for t in scoring_thresholds['RECURRENCE'] if recurrence_count >= t['value']]
            
            if applicable_thresholds:
                # Get the highest score among applicable thresholds
                recurrence_score = max(t['score'] for t in applicable_thresholds)
        else:
            # Default scoring based on rule recurrence settings
            recurrence_thresholds = rule.recurrence_settings.get('recurrence_thresholds', [])
            for threshold in sorted(recurrence_thresholds, key=lambda x: x.get('value', 0), reverse=True):
                if recurrence_count >= threshold.get('value', 0):
                    recurrence_score = threshold.get('score', 0)
                    break
        
        scores_by_factor['RECURRENCE'] = recurrence_score
        total_score += recurrence_score
        
        # Country Risk Scoring
        country_risk_level = details.get('country_risk_level', 0)
        country_score = 0
        
        if 'COUNTRY_RISK' in scoring_thresholds and scoring_thresholds['COUNTRY_RISK']:
            # Get all thresholds that the transaction meets or exceeds
            applicable_thresholds = [t for t in scoring_thresholds['COUNTRY_RISK'] if country_risk_level >= t['value']]
            
            if applicable_thresholds:
                # Get the highest score among applicable thresholds
                country_score = max(t['score'] for t in applicable_thresholds)
        
        scores_by_factor['COUNTRY_RISK'] = country_score
        total_score += country_score
        
        # Party Risk Scoring
        party_risk_level = details.get('party_risk_level', 0)
        party_score = 0
        
        if 'PARTY_RISK' in scoring_thresholds and scoring_thresholds['PARTY_RISK']:
            # Get all thresholds that the transaction meets or exceeds
            applicable_thresholds = [t for t in scoring_thresholds['PARTY_RISK'] if party_risk_level >= t['value']]
            
            if applicable_thresholds:
                # Get the highest score among applicable thresholds
                party_score = max(t['score'] for t in applicable_thresholds)
        
        scores_by_factor['PARTY_RISK'] = party_score
        total_score += party_score
        
        # Account Age Scoring
        if hasattr(transaction, 'account_age_days'):
            account_age_days = transaction.account_age_days
            account_age_score = 0
            
            if 'ACCOUNT_AGE' in scoring_thresholds and scoring_thresholds['ACCOUNT_AGE']:
                # Get all thresholds that the transaction meets or exceeds
                applicable_thresholds = [t for t in scoring_thresholds['ACCOUNT_AGE'] if account_age_days <= t['value']]
                
                if applicable_thresholds:
                    # Get the highest score among applicable thresholds
                    account_age_score = max(t['score'] for t in applicable_thresholds)
            
            scores_by_factor['ACCOUNT_AGE'] = account_age_score
            total_score += account_age_score
        
        # Log the scoring breakdown
        logger.debug(
            f"Scoring for transaction {transaction.transaction_id}, rule {rule.rule_id}: "
            f"Total: {total_score}, Factors: {scores_by_factor}"
        )
        
        # Add scoring breakdown to details
        details['scoring'] = {
            'total_score': total_score,
            'min_alert_score': self.min_alert_score,
            'factors': scores_by_factor
        }
        
        return total_score
    
    def combine_scores(self, scores: List[int], algorithm: str = 'MAX') -> int:
        """
        Combine multiple scores according to the specified algorithm.
        
        Args:
            scores: List of scores to combine
            algorithm: Algorithm to use ('MAX', 'SUM', 'AVG')
            
        Returns:
            Combined score
        """
        if not scores:
            return 0
        
        if algorithm == 'MAX':
            return max(scores)
        elif algorithm == 'SUM':
            return sum(scores)
        elif algorithm == 'AVG':
            return sum(scores) // len(scores)
        else:
            logger.warning(f"Unknown scoring algorithm: {algorithm}, using MAX instead")
            return max(scores)

import unittest
from django.test import TestCase
from datetime import datetime

from ..engine.scoring_engine import ScoringEngine
from ..rules.dormant_account import DormantAccountRule
from ..rules.large_cash import LargeCashRule

class MockTransaction:
    """Mock transaction for testing."""
    
    def __init__(self, **kwargs):
        """Initialize with provided attributes."""
        for key, value in kwargs.items():
            setattr(self, key, value)

class ScoringEngineTest(TestCase):
    """Tests for the scoring engine."""
    
    def setUp(self):
        """Set up test environment."""
        self.scoring_engine = ScoringEngine()
        
        # Create mock rules
        self.dormant_rule = DormantAccountRule({
            'rule_id': 'AML-ADR-ALL-ALL-A-M06-AIN',
            'rule_name': 'Activity Seen in A Dormant Account',
            'scoring_algorithm': 'MAX'
        })
        
        self.cash_rule = LargeCashRule({
            'rule_id': 'AML-LCT-CCE-INN-A-D01-LCT',
            'rule_name': 'Large Cash Transaction',
            'scoring_algorithm': 'MAX'
        })
        
        # Create mock transaction
        self.transaction = MockTransaction(
            transaction_id='T12345',
            amount=15000.00,
            currency_code='USD'
        )
    
    def test_get_minimum_alert_score(self):
        """Test getting minimum alert score."""
        min_score = self.scoring_engine.get_minimum_alert_score()
        self.assertEqual(min_score, 40)
    
    def test_calculate_score_with_amount(self):
        """Test score calculation with amount."""
        # Create details with amount
        details = {
            'amount': 15000.00
        }
        
        # Calculate score
        score = self.scoring_engine.calculate_score(self.cash_rule, self.transaction, details)
        
        # Check score
        # For amount 15000, should get a score of 20 from the default scoring factors
        self.assertEqual(score, 20)
    
    def test_calculate_score_with_recurrence(self):
        """Test score calculation with recurrence."""
        # Create details with recurrence
        details = {
            'recurrence': 3
        }
        
        # Calculate score
        score = self.scoring_engine.calculate_score(self.cash_rule, self.transaction, details)
        
        # Check score
        # For recurrence 3, should get a score of 20 from the default scoring factors
        self.assertEqual(score, 20)
    
    def test_calculate_score_with_combined_factors(self):
        """Test score calculation with multiple factors."""
        # Create details with multiple factors
        details = {
            'amount': 20000.00,
            'recurrence': 2,
            'country_risk': 'HIGH'
        }
        
        # Calculate score
        score = self.scoring_engine.calculate_score(self.cash_rule, self.transaction, details)
        
        # Check score
        # Amount 20000 = 30, Recurrence 2 = 10, Country Risk HIGH = 30
        # With MAX algorithm, should be the sum: 70
        self.assertEqual(score, 70)
    
    def test_calculate_score_with_avg_algorithm(self):
        """Test score calculation with AVG algorithm."""
        # Set rule to use AVG algorithm
        self.cash_rule.scoring_algorithm = 'AVG'
        
        # Create details with multiple factors
        details = {
            'amount': 25000.00,
            'recurrence': 3,
            'country_risk': 'HIGH'
        }
        
        # Calculate score
        score = self.scoring_engine.calculate_score(self.cash_rule, self.transaction, details)
        
        # Check score
        # Amount 25000 = 40, Recurrence 3 = 20, Country Risk HIGH = 30
        # With AVG algorithm, should be the average: (40 + 20 + 30) / 3 = 30
        self.assertEqual(score, 30)
    
    def test_get_score_by_threshold(self):
        """Test getting score by threshold."""
        # Test various thresholds
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 5000), 0
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 10000), 10
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 15000), 20
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 20000), 30
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 25000), 40
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('ACTIVITY_VALUE', 30000), 40
        )
    
    def test_get_score_for_categorical_value(self):
        """Test getting score for categorical value."""
        # Test various categories
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('COUNTRY_RISK', 'LOW'), 0
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('COUNTRY_RISK', 'MEDIUM'), 10
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('COUNTRY_RISK', 'HIGH'), 30
        )
        self.assertEqual(
            self.scoring_engine._get_score_by_threshold('COUNTRY_RISK', 'UNKNOWN'), 0
        )


if __name__ == '__main__':
    unittest.main()

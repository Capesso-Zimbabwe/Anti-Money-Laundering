import unittest
from datetime import datetime, timedelta
from django.test import TestCase
from django.utils import timezone

from ..rules.base_rule import BaseRule
from ..rules.dormant_account import DormantAccountRule
from ..rules.large_cash import LargeCashRule
from ..engine.rule_engine import RuleEngine
from ..engine.scoring_engine import ScoringEngine

class MockTransaction:
    """Mock transaction for testing."""
    
    def __init__(self, **kwargs):
        """Initialize with provided attributes."""
        for key, value in kwargs.items():
            setattr(self, key, value)

class BaseRuleTest(TestCase):
    """Base class for rule tests."""
    
    def setUp(self):
        """Set up test environment."""
        self.scoring_engine = ScoringEngine()
        self.rule_engine = RuleEngine(self.scoring_engine)
    
    def create_mock_transaction(self, **kwargs):
        """Create a mock transaction with default values."""
        defaults = {
            'transaction_id': 'T12345',
            'source_account_number': 'A12345',
            'destination_account_number': 'B12345',
            'source_customer_name': 'John Doe',
            'destination_customer_name': 'Jane Doe',
            'amount': 1000.00,
            'currency_code': 'USD',
            'transaction_type_code': 'TRANSFER',
            'transaction_date': datetime.now().date(),
            'transaction_timestamp': datetime.now(),
            'is_checked': False,
        }
        # Override defaults with provided values
        defaults.update(kwargs)
        
        return MockTransaction(**defaults)
    
    def create_mock_context(self, account_history=None, **kwargs):
        """Create a mock context with default values."""
        context = {
            'account_history': account_history or [],
            'account_info': {
                'account_number': 'A12345',
                'open_date': datetime.now().date() - timedelta(days=365),
            },
            'customer_info': {
                'customer_id': 'C12345',
                'customer_type': 'INDIVIDUAL',
                'risk_level': 'MEDIUM',
                'name': 'John Doe',
                'nationality': 'US',
            }
        }
        # Override defaults with provided values
        for key, value in kwargs.items():
            if key in context:
                context[key].update(value)
            else:
                context[key] = value
        
        return context


class DormantAccountRuleTest(BaseRuleTest):
    """Tests for the dormant account rule."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        
        # Create rule with test configuration
        self.rule_config = {
            'rule_id': 'AML-ADR-ALL-ALL-A-M06-AIN',
            'rule_name': 'Activity Seen in A Dormant Account',
            'thresholds': {
                'account_age_days': 180,
                'activity_amount': 10000,
                'inactive_period_months': 6,
                'max_prior_activity': 100
            },
            'enabled': True
        }
        
        self.rule = DormantAccountRule(self.rule_config)
        self.rule_engine.register_rule(self.rule)
    
    def test_dormant_account_activity(self):
        """Test detection of activity in a dormant account."""
        # Create a transaction with significant amount
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='DEPOSIT'
        )
        
        # Create an empty account history (dormant account)
        account_history = []
        
        # Create context
        context = self.create_mock_context(
            account_history=account_history,
            account_info={
                'open_date': datetime.now().date() - timedelta(days=200)
            }
        )
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was triggered
        self.assertTrue(triggered)
        self.assertEqual(details['amount'], 15000.00)
    
    def test_dormant_account_small_activity(self):
        """Test that small activity in a dormant account doesn't trigger."""
        # Create a transaction with small amount
        transaction = self.create_mock_transaction(
            amount=5000.00,
            transaction_type_code='DEPOSIT'
        )
        
        # Create an empty account history (dormant account)
        account_history = []
        
        # Create context
        context = self.create_mock_context(
            account_history=account_history,
            account_info={
                'open_date': datetime.now().date() - timedelta(days=200)
            }
        )
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was not triggered
        self.assertFalse(triggered)


class LargeCashRuleTest(BaseRuleTest):
    """Tests for the large cash rule."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        
        # Create rule with test configuration
        self.rule_config = {
            'rule_id': 'AML-LCT-CCE-INN-A-D01-LCT',
            'rule_name': 'Large Cash Transaction',
            'thresholds': {
                'transaction_amount': 10000,
                'currency': 'USD'
            },
            'enabled': True
        }
        
        self.rule = LargeCashRule(self.rule_config)
        self.rule_engine.register_rule(self.rule)
    
    def test_large_cash_deposit(self):
        """Test detection of large cash deposit."""
        # Create a transaction with large amount
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='CASH DEP'
        )
        
        # Create context
        context = self.create_mock_context()
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was triggered
        self.assertTrue(triggered)
        self.assertEqual(details['amount'], 15000.00)
        self.assertEqual(details['threshold'], 10000)
    
    def test_small_cash_deposit(self):
        """Test that small cash deposit doesn't trigger."""
        # Create a transaction with small amount
        transaction = self.create_mock_transaction(
            amount=5000.00,
            transaction_type_code='CASH DEP'
        )
        
        # Create context
        context = self.create_mock_context()
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was not triggered
        self.assertFalse(triggered)
    
    def test_wrong_transaction_type(self):
        """Test that non-deposit transaction type doesn't trigger."""
        # Create a transaction with large amount but wrong type
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='WITHDRAWAL'
        )
        
        # Create context
        context = self.create_mock_context()
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was not triggered
        self.assertFalse(triggered)
    
    def test_wrong_currency(self):
        """Test that transaction with wrong currency doesn't trigger."""
        # Create a transaction with large amount but wrong currency
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='CASH DEP',
            currency_code='EUR'
        )
        
        # Create context
        context = self.create_mock_context()
        
        # Evaluate rule
        triggered, details = self.rule.evaluate(transaction, context)
        
        # Check that rule was not triggered
        self.assertFalse(triggered)


class RuleEngineTest(BaseRuleTest):
    """Tests for the rule engine."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        
        # Register rules
        self.dormant_rule = DormantAccountRule({
            'rule_id': 'AML-ADR-ALL-ALL-A-M06-AIN',
            'rule_name': 'Activity Seen in A Dormant Account',
            'thresholds': {
                'account_age_days': 180,
                'activity_amount': 10000,
                'inactive_period_months': 6,
                'max_prior_activity': 100
            },
            'enabled': True
        })
        
        self.cash_rule = LargeCashRule({
            'rule_id': 'AML-LCT-CCE-INN-A-D01-LCT',
            'rule_name': 'Large Cash Transaction',
            'thresholds': {
                'transaction_amount': 10000,
                'currency': 'USD'
            },
            'enabled': True
        })
        
        self.rule_engine.register_rule(self.dormant_rule)
        self.rule_engine.register_rule(self.cash_rule)
    
    def test_evaluate_transaction_triggers_rules(self):
        """Test that rule engine evaluates and triggers appropriate rules."""
        # Create a transaction that should trigger both rules
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='CASH DEP'
        )
        
        # Create context that would trigger dormant account rule
        context = self.create_mock_context(
            account_history=[],
            account_info={
                'open_date': datetime.now().date() - timedelta(days=200)
            }
        )
        
        # Evaluate transaction
        results = self.rule_engine.evaluate_transaction(transaction, context)
        
        # Check that both rules were triggered
        self.assertEqual(len(results), 2)
        rule_ids = [result['rule']['rule_id'] for result in results]
        self.assertIn('AML-ADR-ALL-ALL-A-M06-AIN', rule_ids)
        self.assertIn('AML-LCT-CCE-INN-A-D01-LCT', rule_ids)
    
    def test_disabled_rule_not_triggered(self):
        """Test that disabled rules are not triggered."""
        # Disable dormant account rule
        self.dormant_rule.enabled = False
        
        # Create a transaction that would trigger both rules
        transaction = self.create_mock_transaction(
            amount=15000.00,
            transaction_type_code='CASH DEP'
        )
        
        # Create context that would trigger dormant account rule
        context = self.create_mock_context(
            account_history=[],
            account_info={
                'open_date': datetime.now().date() - timedelta(days=200)
            }
        )
        
        # Evaluate transaction
        results = self.rule_engine.evaluate_transaction(transaction, context)
        
        # Check that only large cash rule was triggered
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['rule']['rule_id'], 'AML-LCT-CCE-INN-A-D01-LCT')


if __name__ == '__main__':
    unittest.main()

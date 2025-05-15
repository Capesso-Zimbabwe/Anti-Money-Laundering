from django.db import models

# Import models from the existing structure
from transaction_monitoring.model.rule_settings import (
    AMLRules, 
    ScoringThreshold, 
    TransactionTypeGroup, 
    TransactionType, 
    RuleExecution
)
from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.alert import SuspiciousTransactions, SuspiciousActivityReports

# These models define the transaction monitoring system
# See specific model files for implementation details

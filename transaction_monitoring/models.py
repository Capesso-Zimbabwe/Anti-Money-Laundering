from django.db import models

# Import models from the existing structure
from transaction_monitoring.model.rule_settings import (
    AMLRules, 
    ScoringThreshold, 
    TransactionTypeGroup, 
    TransactionType, 
    RuleExecution
)
from transaction_monitoring.model.transaction import Transactions, TransactionDetail
from transaction_monitoring.model.alert import Alert, RelatedEntity, SuspiciousActivityReport, AlertSARRelationship

# Import models for dormant account monitoring
from transaction_monitoring.model.customer import Customer, CustomerIdentification
from transaction_monitoring.model.account import (
    Account, 
    AccountHolder, 
    AccountStatusHistory, 
    AccountParameter
)
from transaction_monitoring.model.alert_config import (
    AlertConfiguration,
    DormantAccountAlertConfig,
    AlertThreshold
)

# These models define the transaction monitoring system
# See specific model files for implementation details

"""
API Serializers for transaction monitoring data.
"""

from rest_framework import serializers
from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.alert import SuspiciousTransactions, SuspiciousActivityReports
from transaction_monitoring.model.rule_settings import (
    AMLRules, 
    ScoringThreshold, 
    TransactionTypeGroup, 
    TransactionType, 
    RuleExecution
)


class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for Transaction model."""
    
    class Meta:
        model = Transactions
        fields = '__all__'


class SuspiciousTransactionSerializer(serializers.ModelSerializer):
    """Serializer for SuspiciousTransaction model."""
    
    transaction = TransactionSerializer(read_only=True)
    
    class Meta:
        model = SuspiciousTransactions
        fields = '__all__'


class SuspiciousActivityReportSerializer(serializers.ModelSerializer):
    """Serializer for SuspiciousActivityReport model."""
    
    class Meta:
        model = SuspiciousActivityReports
        fields = '__all__'


class ScoringThresholdSerializer(serializers.ModelSerializer):
    """Serializer for ScoringThreshold model."""
    
    class Meta:
        model = ScoringThreshold
        fields = ['id', 'factor_type', 'threshold_value', 'score', 'description']


class TransactionTypeGroupSerializer(serializers.ModelSerializer):
    """Serializer for TransactionTypeGroup model."""
    
    class Meta:
        model = TransactionTypeGroup
        fields = ['group_code', 'description']


class TransactionTypeSerializer(serializers.ModelSerializer):
    """Serializer for TransactionType model."""
    
    groups = TransactionTypeGroupSerializer(many=True, read_only=True)
    
    class Meta:
        model = TransactionType
        fields = ['transaction_code', 'description', 'groups', 'jurisdiction']


class RuleExecutionSerializer(serializers.ModelSerializer):
    """Serializer for RuleExecution model."""
    
    class Meta:
        model = RuleExecution
        fields = ['id', 'execution_date', 'execution_time_ms', 'transactions_evaluated', 'alerts_generated']


class AMLRuleSerializer(serializers.ModelSerializer):
    """Serializer for AMLRule model."""
    
    thresholds = serializers.JSONField()
    recurrence_settings = serializers.JSONField()
    scoring_thresholds = ScoringThresholdSerializer(many=True, read_only=True)
    executions = RuleExecutionSerializer(many=True, read_only=True)
    
    class Meta:
        model = AMLRules
        fields = [
            'rule_code', 'rule_name', 'description', 'rule_type',
            'alert_level', 'evaluation_trigger', 'transaction_types',
            'enabled', 'scoring_algorithm', 'min_alert_score',
            'thresholds', 'recurrence_settings', 'scoring_thresholds',
            'executions', 'created_at', 'updated_at', 'last_modified_by'
        ]


class RuleUpdateSerializer(serializers.Serializer):
    """Serializer for rule updates."""
    
    enabled = serializers.BooleanField(required=False)
    thresholds = serializers.JSONField(required=False)
    recurrence_settings = serializers.JSONField(required=False)
    alert_level = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    transaction_types = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    min_alert_score = serializers.IntegerField(required=False)
    scoring_algorithm = serializers.CharField(required=False)


class ScoringThresholdCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating scoring thresholds."""
    
    class Meta:
        model = ScoringThreshold
        fields = ['factor_type', 'threshold_value', 'score', 'description']


class RuleScoringConfigSerializer(serializers.Serializer):
    """Serializer for complete rule scoring configuration."""
    
    rule_code = serializers.CharField()
    activity_value_thresholds = ScoringThresholdCreateSerializer(many=True, required=False)
    recurrence_thresholds = ScoringThresholdCreateSerializer(many=True, required=False)
    country_risk_thresholds = ScoringThresholdCreateSerializer(many=True, required=False)
    party_risk_thresholds = ScoringThresholdCreateSerializer(many=True, required=False)
    account_age_thresholds = ScoringThresholdCreateSerializer(many=True, required=False) 
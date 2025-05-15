"""
API Views for transaction monitoring.
"""

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone

from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.alert import SuspiciousTransactions, SuspiciousActivityReports
from transaction_monitoring.model.rule_settings import (
    AMLRules, 
    ScoringThreshold, 
    TransactionTypeGroup, 
    TransactionType, 
    RuleExecution
)
from transaction_monitoring.monitoring.monitor_service import TransactionMonitoringService

from .serializers import (
    TransactionSerializer,
    SuspiciousTransactionSerializer,
    SuspiciousActivityReportSerializer,
    AMLRuleSerializer,
    RuleUpdateSerializer,
    ScoringThresholdSerializer,
    ScoringThresholdCreateSerializer,
    TransactionTypeGroupSerializer,
    TransactionTypeSerializer,
    RuleExecutionSerializer,
    RuleScoringConfigSerializer
)

from rest_framework.views import APIView

# Initialize the transaction monitoring service
monitoring_service = TransactionMonitoringService()


class TransactionViewSet(viewsets.ModelViewSet):
    """API endpoint for transaction data."""
    queryset = Transactions.objects.all().order_by('-transaction_date')
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['post'])
    def analyze(self, request, pk=None):
        """Analyze a specific transaction."""
        transaction = self.get_object()
        alerts = monitoring_service.create_alerts_from_transaction(transaction)
        
        return Response({
            'status': 'success',
            'message': f'Transaction {transaction.transaction_id} analyzed',
            'alerts_count': len(alerts),
            'alert_ids': [alert.report_id for alert in alerts]
        })
    
    @action(detail=False, methods=['post'])
    def process_batch(self, request):
        """Process a batch of unprocessed transactions."""
        batch_size = int(request.data.get('batch_size', 100))
        result = monitoring_service.process_unprocessed_transactions(batch_size)
        return Response(result)


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for suspicious transaction alerts."""
    queryset = SuspiciousTransactions.objects.all().order_by('-created_at')
    serializer_class = SuspiciousTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        """Mark an alert as reviewed."""
        alert = self.get_object()
        reviewer = request.user.username
        notes = request.data.get('notes', '')
        
        alert.mark_as_reviewed(reviewer, notes)
        
        return Response({
            'status': 'success',
            'message': f'Alert {alert.report_id} marked as reviewed'
        })
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get alert statistics."""
        total = SuspiciousTransactions.objects.count()
        pending = SuspiciousTransactions.objects.filter(review_status='Pending').count()
        reviewed = SuspiciousTransactions.objects.filter(review_status='Reviewed').count()
        high_risk = SuspiciousTransactions.objects.filter(risk_level='HIGH').count()
        medium_risk = SuspiciousTransactions.objects.filter(risk_level='MEDIUM').count()
        low_risk = SuspiciousTransactions.objects.filter(risk_level='LOW').count()
        
        return Response({
            'total': total,
            'pending': pending,
            'reviewed': reviewed,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk
        })


class SARViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for SAR reports."""
    queryset = SuspiciousActivityReports.objects.all().order_by('-created_at')
    serializer_class = SuspiciousActivityReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a SAR report."""
        report = self.get_object()
        approver_name = request.data.get('approver_name', request.user.get_full_name())
        approver_position = request.data.get('approver_position', 'Compliance Officer')
        notes = request.data.get('notes', '')
        
        report.mark_as_approved(approver_name, approver_position, notes)
        
        return Response({
            'status': 'success',
            'message': f'Report {report.report_id} approved'
        })


class RuleViewSet(viewsets.ModelViewSet):
    """API endpoint for AML rules."""
    queryset = AMLRules.objects.all().order_by('rule_code')
    serializer_class = AMLRuleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['patch'])
    def update_config(self, request, pk=None):
        """Update rule configuration."""
        rule = self.get_object()
        serializer = RuleUpdateSerializer(data=request.data, partial=True)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Update rule settings in database
        if 'enabled' in serializer.validated_data:
            rule.enabled = serializer.validated_data['enabled']
            
        if 'thresholds' in serializer.validated_data:
            rule.set_thresholds(serializer.validated_data['thresholds'])
            
        if 'recurrence_settings' in serializer.validated_data:
            rule.set_recurrence_settings(serializer.validated_data['recurrence_settings'])
            
        if 'alert_level' in serializer.validated_data:
            rule.alert_level = serializer.validated_data['alert_level']
            
        if 'description' in serializer.validated_data:
            rule.description = serializer.validated_data['description']
        
        if 'min_alert_score' in serializer.validated_data:
            rule.min_alert_score = serializer.validated_data['min_alert_score']
            
        if 'scoring_algorithm' in serializer.validated_data:
            rule.scoring_algorithm = serializer.validated_data['scoring_algorithm']
            
        rule.last_modified_by = request.user.username
        rule.save()
        
        # Update rule in monitoring service
        rule_id = f"AML-{rule.rule_code}"
        config = {
            'rule_id': rule_id,
            'rule_name': rule.rule_name,
            'description': rule.description,
            'alert_level': rule.alert_level,
            'evaluation_trigger': rule.evaluation_trigger,
            'scoring_algorithm': rule.scoring_algorithm,
            'transaction_types': rule.transaction_types.split(',') if rule.transaction_types else ['ALL-ALL'],
            'thresholds': rule.get_thresholds(),
            'recurrence': rule.get_recurrence_settings(),
            'enabled': rule.enabled,
            'min_alert_score': rule.min_alert_score,
            'version': '1.0'
        }
        
        success = monitoring_service.update_rule_config(rule_id, config)
        
        if success:
            return Response({
                'status': 'success',
                'message': f'Rule {rule_id} configuration updated'
            })
        else:
            return Response({
                'status': 'error',
                'message': 'Failed to update rule configuration'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['get'])
    def scoring_thresholds(self, request, pk=None):
        """Get scoring thresholds for a rule."""
        rule = self.get_object()
        thresholds = ScoringThreshold.objects.filter(rule=rule)
        serializer = ScoringThresholdSerializer(thresholds, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def update_scoring(self, request, pk=None):
        """Update scoring thresholds for a rule."""
        rule = self.get_object()
        serializer = RuleScoringConfigSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Use transaction to ensure atomicity
        with transaction.atomic():
            # Clear existing thresholds for this rule
            ScoringThreshold.objects.filter(rule=rule).delete()
            
            # Create new thresholds
            thresholds_to_create = []
            
            # Process activity value thresholds
            for threshold_data in serializer.validated_data.get('activity_value_thresholds', []):
                threshold = ScoringThreshold(
                    rule=rule,
                    factor_type='ACTIVITY_VALUE',
                    threshold_value=threshold_data['threshold_value'],
                    score=threshold_data['score'],
                    description=threshold_data.get('description', '')
                )
                thresholds_to_create.append(threshold)
            
            # Process recurrence thresholds
            for threshold_data in serializer.validated_data.get('recurrence_thresholds', []):
                threshold = ScoringThreshold(
                    rule=rule,
                    factor_type='RECURRENCE',
                    threshold_value=threshold_data['threshold_value'],
                    score=threshold_data['score'],
                    description=threshold_data.get('description', '')
                )
                thresholds_to_create.append(threshold)
            
            # Process country risk thresholds
            for threshold_data in serializer.validated_data.get('country_risk_thresholds', []):
                threshold = ScoringThreshold(
                    rule=rule,
                    factor_type='COUNTRY_RISK',
                    threshold_value=threshold_data['threshold_value'],
                    score=threshold_data['score'],
                    description=threshold_data.get('description', '')
                )
                thresholds_to_create.append(threshold)
            
            # Process party risk thresholds
            for threshold_data in serializer.validated_data.get('party_risk_thresholds', []):
                threshold = ScoringThreshold(
                    rule=rule,
                    factor_type='PARTY_RISK',
                    threshold_value=threshold_data['threshold_value'],
                    score=threshold_data['score'],
                    description=threshold_data.get('description', '')
                )
                thresholds_to_create.append(threshold)
            
            # Process account age thresholds
            for threshold_data in serializer.validated_data.get('account_age_thresholds', []):
                threshold = ScoringThreshold(
                    rule=rule,
                    factor_type='ACCOUNT_AGE',
                    threshold_value=threshold_data['threshold_value'],
                    score=threshold_data['score'],
                    description=threshold_data.get('description', '')
                )
                thresholds_to_create.append(threshold)
            
            # Bulk create all thresholds
            ScoringThreshold.objects.bulk_create(thresholds_to_create)
            
            # Update last modified info
            rule.last_modified_by = request.user.username
            rule.save()
        
        # Return the updated thresholds
        updated_thresholds = ScoringThreshold.objects.filter(rule=rule)
        threshold_serializer = ScoringThresholdSerializer(updated_thresholds, many=True)
        
        return Response({
            'status': 'success',
            'message': f'Scoring thresholds updated for rule {rule.rule_code}',
            'thresholds': threshold_serializer.data
        })


class TransactionTypeGroupViewSet(viewsets.ModelViewSet):
    """API endpoint for transaction type groups."""
    queryset = TransactionTypeGroup.objects.all().order_by('group_code')
    serializer_class = TransactionTypeGroupSerializer
    permission_classes = [permissions.IsAuthenticated]


class TransactionTypeViewSet(viewsets.ModelViewSet):
    """API endpoint for transaction types."""
    queryset = TransactionType.objects.all().order_by('transaction_code')
    serializer_class = TransactionTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def by_group(self, request):
        """Get transaction types grouped by their group."""
        groups = TransactionTypeGroup.objects.all()
        result = {}
        
        for group in groups:
            types = TransactionType.objects.filter(groups=group)
            type_serializer = TransactionTypeSerializer(types, many=True)
            result[group.group_code] = {
                'description': group.description,
                'transaction_types': type_serializer.data
            }
        
        return Response(result)
    
    @action(detail=False, methods=['get'])
    def by_jurisdiction(self, request):
        """Get transaction types grouped by jurisdiction."""
        jurisdiction = request.query_params.get('jurisdiction', None)
        if jurisdiction:
            types = TransactionType.objects.filter(jurisdiction=jurisdiction)
        else:
            types = TransactionType.objects.all()
        
        serializer = TransactionTypeSerializer(types, many=True)
        return Response(serializer.data)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def engine_statistics(request):
    """Get rule engine statistics."""
    rule_engine = monitoring_service.rule_engine
    stats = rule_engine.get_statistics()
    
    # Format some values for readability
    if 'avg_evaluation_time' in stats:
        stats['avg_evaluation_time_ms'] = round(stats['avg_evaluation_time'] * 1000, 2)
    
    if 'cache_hit_rate' in stats:
        stats['cache_hit_rate_percent'] = round(stats['cache_hit_rate'] * 100, 2)
    
    if 'trigger_rate' in stats:
        stats['trigger_rate_percent'] = round(stats['trigger_rate'] * 100, 2)
    
    if 'uptime' in stats:
        # Convert to hours, minutes, seconds
        uptime_seconds = stats['uptime']
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        stats['uptime_formatted'] = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    
    return Response(stats)


@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def reset_engine_statistics(request):
    """Reset rule engine statistics."""
    rule_engine = monitoring_service.rule_engine
    rule_engine.reset_statistics()
    
    return Response({
        'status': 'success',
        'message': 'Rule engine statistics reset'
    })


class RuleConfigUpdateAPIView(APIView):
    """
    API endpoint to update rule configuration.
    """
    def post(self, request, rule_code):
        rule = get_object_or_404(AMLRules, rule_code=rule_code)
        
        # Extract data from request
        description = request.data.get('description')
        alert_level = request.data.get('alert_level')
        min_alert_score = request.data.get('min_alert_score')
        scoring_algorithm = request.data.get('scoring_algorithm')
        enabled = request.data.get('enabled', False)
        transaction_types = request.data.get('transaction_types')
        
        # Update rule fields if provided
        if description is not None:
            rule.description = description
            
        if alert_level is not None:
            rule.alert_level = alert_level
            
        if min_alert_score is not None:
            rule.min_alert_score = int(min_alert_score)
            
        if scoring_algorithm is not None:
            rule.scoring_algorithm = scoring_algorithm
            
        if transaction_types is not None:
            # Join list of transaction types with space
            if isinstance(transaction_types, list):
                rule.transaction_types = ' '.join(transaction_types)
            else:
                rule.transaction_types = transaction_types
        
        rule.enabled = enabled
        rule.updated_at = timezone.now()
        rule.save()
        
        return Response({
            'status': 'success',
            'message': f"Rule '{rule.rule_name}' updated successfully",
            'rule': {
                'rule_code': rule.rule_code,
                'rule_name': rule.rule_name,
                'description': rule.description,
                'alert_level': rule.alert_level,
                'min_alert_score': rule.min_alert_score,
                'scoring_algorithm': rule.scoring_algorithm,
                'enabled': rule.enabled,
                'transaction_types': rule.transaction_types,
                'updated_at': rule.updated_at
            }
        }, status=status.HTTP_200_OK)


class RuleScoringUpdateAPIView(APIView):
    """
    API endpoint to update rule scoring thresholds.
    """
    def post(self, request, rule_code):
        rule = get_object_or_404(AMLRules, rule_code=rule_code)
        
        # Extract threshold data
        activity_value_thresholds = request.data.get('activity_value_thresholds', [])
        recurrence_thresholds = request.data.get('recurrence_thresholds', [])
        
        with transaction.atomic():
            # Update activity value thresholds
            if activity_value_thresholds:
                # Delete existing thresholds
                ScoringThreshold.objects.filter(
                    rule=rule, 
                    factor_type='ACTIVITY_VALUE'
                ).delete()
                
                # Create new thresholds
                for threshold_data in activity_value_thresholds:
                    ScoringThreshold.objects.create(
                        rule=rule,
                        factor_type='ACTIVITY_VALUE',
                        threshold_value=threshold_data['threshold_value'],
                        score=threshold_data['score']
                    )
            
            # Update recurrence thresholds
            if recurrence_thresholds:
                # Delete existing thresholds
                ScoringThreshold.objects.filter(
                    rule=rule, 
                    factor_type='RECURRENCE'
                ).delete()
                
                # Create new thresholds
                for threshold_data in recurrence_thresholds:
                    ScoringThreshold.objects.create(
                        rule=rule,
                        factor_type='RECURRENCE',
                        threshold_value=threshold_data['threshold_value'],
                        score=threshold_data['score']
                    )
            
            # Update rule's last updated timestamp
            rule.updated_at = timezone.now()
            rule.save()
            
        return Response({
            'status': 'success',
            'message': f"Scoring thresholds for rule '{rule.rule_name}' updated successfully",
            'rule_code': rule.rule_code
        }, status=status.HTTP_200_OK) 
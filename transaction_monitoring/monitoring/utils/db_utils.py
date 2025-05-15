"""
Database utilities for transaction monitoring.

This module provides functions for efficient database operations,
particularly for large-scale transaction processing.
"""

import logging
from typing import Dict, List, Any, Tuple, Optional
from django.apps import apps
from django.db.models import Q, F, Count, Sum, Avg, Min, Max
from django.db import connection, transaction as db_transaction
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def get_account_transactions(account_number: str, lookback_days: int = 180) -> List[Any]:
    """
    Get transactions for an account within a specific lookback period.
    
    Args:
        account_number: The account number
        lookback_days: Number of days to look back
        
    Returns:
        List of transactions
    """
    Transaction1 = apps.get_model('aml_app', 'Transaction1')
    
    lookback_date = datetime.now() - timedelta(days=lookback_days)
    
    # Get transactions where the account is either source or destination
    transactions = Transaction1.objects.filter(
        Q(source_account_number=account_number) | 
        Q(destination_account_number=account_number),
        transaction_timestamp__gte=lookback_date
    ).order_by('transaction_timestamp')
    
    return list(transactions)

def get_customer_info(customer_id: str) -> Optional[Dict[str, Any]]:
    """
    Get customer information.
    
    Args:
        customer_id: The customer ID
        
    Returns:
        Dictionary with customer information or None if not found
    """
    Customer = apps.get_model('aml_app', 'Customer')
    
    try:
        customer = Customer.objects.get(customer_id=customer_id)
        
        # Base info for all customer types
        info = {
            'customer_id': customer.customer_id,
            'customer_type': customer.customer_type,
            'customer_status': customer.customer_status,
            'risk_level': getattr(customer, 'risk_level', 'MEDIUM'),
            'open_date': getattr(customer, 'onboarding_date', None),
        }
        
        # Add type-specific info
        if customer.customer_type == 'INDIVIDUAL':
            info.update({
                'name': f"{customer.first_name} {customer.last_name}",
                'nationality': customer.nationality,
                'residence_country': customer.residential_country,
            })
        else:  # ENTITY
            info.update({
                'name': customer.entity_name,
                'industry': customer.industry_description,
                'incorporation_date': customer.date_of_incorporation,
            })
        
        return info
    except Customer.DoesNotExist:
        return None

def create_suspicious_transaction(transaction: Any, alert: Dict[str, Any]) -> Any:
    """
    Create a suspicious transaction record.
    
    Args:
        transaction: The transaction that triggered the alert
        alert: The alert data
        
    Returns:
        Created SuspiciousTransaction1 instance
    """
    SuspiciousTransaction1 = apps.get_model('aml_app', 'SuspiciousTransaction1')
    
    suspicious_tx = SuspiciousTransaction1(
        transaction=transaction,
        risk_level=alert['risk_level'],
        flagged_reason=alert['narrative'],
        suspicious_date=transaction.transaction_date,
        suspicious_description=alert['narrative'],
        manual_review_required=True,
        sender_account=transaction.source_account_number,
        receiver_account=transaction.destination_account_number,
        beneficiary_account=transaction.destination_account_number,
        beneficiary_name=transaction.destination_customer_name,
        amount=transaction.amount,
        report_id=alert['alert_id']
    )
    
    suspicious_tx.save()
    return suspicious_tx

def create_sar_report(transaction: Any, alert: Dict[str, Any]) -> Any:
    """
    Create a Suspicious Activity Report.
    
    Args:
        transaction: The transaction that triggered the alert
        alert: The alert data
        
    Returns:
        Created SuspiciousActivityReport instance
    """
    SuspiciousActivityReport = apps.get_model('aml_app', 'SuspiciousActivityReport')
    
    sar_report = SuspiciousActivityReport(
        report_id=alert['alert_id'],
        report_reference_number=f"SAR-{alert['alert_id']}",
        report_type='SAR',
        report_status='DRAFT',
        suspicious_activity_type='UNUSUAL_ACTIVITY',
        detection_date=datetime.now(),
        activity_start_date=transaction.transaction_date,
        activity_end_date=transaction.transaction_date,
        total_suspicious_amount=transaction.amount,
        currency_code=transaction.currency_code,
        related_transactions=transaction.transaction_id,
        primary_subject_name=transaction.source_customer_name or "Unknown",
        risk_level=alert['risk_level'],
        suspicious_activity_description=alert['narrative'],
        red_flags_identified=alert['narrative'],
        internal_actions_taken="Flagged for review",
        filing_institution_name="Bank",
        filing_institution_id="BANK1",
        preparer_name="AML System",
        preparer_position="Automated Detection",
        preparer_contact="system@bank.com",
        approver_name="Pending Review",
        approver_position="Compliance Officer",
        created_by="AML System"
    )
    
    sar_report.save()
    return sar_report

def batch_fetch_unprocessed_transactions(batch_size: int = 100) -> List[Any]:
    """
    Fetch a batch of unprocessed transactions.
    
    This function uses a pessimistic lock to ensure transactions aren't
    processed multiple times by concurrent processes.
    
    Args:
        batch_size: Maximum number of transactions to fetch
        
    Returns:
        List of unprocessed transaction objects
    """
    from transaction_monitoring.model.transaction import Transactions
    
    with db_transaction.atomic():
        # Select transactions with FOR UPDATE to lock rows
        transactions = Transactions.objects.filter(
            processed=False
        ).order_by(
            'transaction_date'
        )[:batch_size].select_for_update(skip_locked=True)
        
        # Materialize the queryset to apply the locks
        return list(transactions)

def mark_transactions_processed(transaction_ids: List[str]) -> int:
    """
    Mark multiple transactions as processed.
    
    Args:
        transaction_ids: List of transaction IDs
        
    Returns:
        Number of transactions marked as processed
    """
    from transaction_monitoring.model.transaction import Transactions
    
    if not transaction_ids:
        return 0
    
    with db_transaction.atomic():
        updated = Transactions.objects.filter(
            transaction_id__in=transaction_ids
        ).update(
            processed=True,
            processed_at=datetime.now()
        )
        
        return updated

def get_transaction_history(
    account_number: str,
    days: int = 30,
    transaction_types: List[str] = None
) -> List[Any]:
    """
    Get transaction history for an account.
    
    Args:
        account_number: The account number
        days: Number of days of history to fetch
        transaction_types: Optional filter for transaction types
        
    Returns:
        List of transaction objects
    """
    from transaction_monitoring.model.transaction import Transactions
    
    start_date = datetime.now() - timedelta(days=days)
    
    query = Transactions.objects.filter(
        Q(source_account_number=account_number) | 
        Q(destination_account_number=account_number),
        transaction_date__gte=start_date
    ).order_by('-transaction_date')
    
    if transaction_types:
        query = query.filter(transaction_type_code__in=transaction_types)
    
    return list(query)

def get_account_aggregates(
    account_number: str,
    days: int = 30
) -> Dict[str, Any]:
    """
    Get transaction aggregates for an account.
    
    Args:
        account_number: The account number
        days: Number of days to include
        
    Returns:
        Dictionary with aggregate values
    """
    from transaction_monitoring.model.transaction import Transactions
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Outgoing transactions
    outgoing = Transactions.objects.filter(
        source_account_number=account_number,
        transaction_date__gte=start_date
    )
    
    # Incoming transactions
    incoming = Transactions.objects.filter(
        destination_account_number=account_number,
        transaction_date__gte=start_date
    )
    
    outgoing_agg = outgoing.aggregate(
        count=Count('id'),
        total=Sum('amount'),
        avg=Avg('amount'),
        max=Max('amount')
    )
    
    incoming_agg = incoming.aggregate(
        count=Count('id'),
        total=Sum('amount'),
        avg=Avg('amount'),
        max=Max('amount')
    )
    
    # Get transaction type distribution
    type_distribution = Transactions.objects.filter(
        Q(source_account_number=account_number) |
        Q(destination_account_number=account_number),
        transaction_date__gte=start_date
    ).values('transaction_type_code').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Calculate net flow
    net_flow = (incoming_agg['total'] or 0) - (outgoing_agg['total'] or 0)
    
    return {
        'outgoing': outgoing_agg,
        'incoming': incoming_agg,
        'net_flow': net_flow,
        'type_distribution': list(type_distribution),
        'total_transactions': (outgoing_agg['count'] or 0) + (incoming_agg['count'] or 0)
    }

def get_largest_transactions(
    account_number: str,
    limit: int = 5,
    days: int = 30
) -> List[Any]:
    """
    Get largest transactions for an account.
    
    Args:
        account_number: The account number
        limit: Maximum number of transactions to return
        days: Number of days to include
        
    Returns:
        List of transaction objects
    """
    from transaction_monitoring.model.transaction import Transactions
    
    start_date = datetime.now() - timedelta(days=days)
    
    transactions = Transactions.objects.filter(
        Q(source_account_number=account_number) |
        Q(destination_account_number=account_number),
        transaction_date__gte=start_date
    ).order_by('-amount')[:limit]
    
    return list(transactions)

def execute_raw_query(query: str, params: Tuple = None) -> List[Dict[str, Any]]:
    """
    Execute a raw SQL query.
    
    This is useful for complex queries that are difficult to express with the ORM.
    
    Args:
        query: The SQL query string
        params: Query parameters
        
    Returns:
        List of dictionaries representing rows
    """
    with connection.cursor() as cursor:
        cursor.execute(query, params or ())
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

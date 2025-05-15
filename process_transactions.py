import os
import django
import time
from datetime import datetime

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aml_project.settings')
django.setup()

from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.alert import SuspiciousTransactions
from transaction_monitoring.monitoring.monitor_service import TransactionMonitoringService

def main():
    # Get unprocessed transactions
    unprocessed_transactions = Transactions.objects.filter(processed=False)
    total_count = unprocessed_transactions.count()
    
    if total_count == 0:
        print("No unprocessed transactions found. Run generate_test_data.py first.")
        return
    
    print(f"Processing {total_count} transactions...")
    
    # Initialize monitoring service
    monitoring_service = TransactionMonitoringService()
    
    # Process in batches
    batch_size = 10
    processed_count = 0
    alert_count = 0
    
    for i in range(0, total_count, batch_size):
        batch = unprocessed_transactions[i:i+batch_size]
        print(f"Processing batch {i//batch_size + 1}...")
        
        for transaction in batch:
            # Process the transaction
            result = monitoring_service.process_transaction(transaction)
            
            # Mark as processed
            transaction.processed = True
            transaction.processed_date = datetime.now()
            transaction.save()
            
            processed_count += 1
            
            # Check if any alerts were generated
            if result and 'alerts' in result and result['alerts']:
                alert_count += len(result['alerts'])
                
                # Print alert information
                for alert in result['alerts']:
                    print(f"Alert generated: {alert.report_id} - {alert.flagged_reason} - Score: {alert.risk_score}")
        
        # Pause between batches
        if i + batch_size < total_count:
            time.sleep(1)
    
    # Get statistics after processing
    alerts = SuspiciousTransactions.objects.all().order_by('-created_at')
    total_alerts = alerts.count()
    
    print("\nTransaction processing complete!")
    print(f"Processed {processed_count} transactions")
    print(f"Generated {alert_count} alerts during this run")
    print(f"Total alerts in system: {total_alerts}")
    
    # Display recent alerts
    if alerts:
        print("\nMost recent alerts:")
        for alert in alerts[:5]:
            print(f"- {alert.report_id}: {alert.customer_name} - {alert.flagged_reason} ({alert.risk_level}) - Score: {alert.risk_score}")

if __name__ == "__main__":
    main() 
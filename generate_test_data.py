import os
import django
import random
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aml_project.settings')
django.setup()

from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.rule_settings import AMLRules

# Get existing rules to create transactions that will trigger them
rules = AMLRules.objects.filter(enabled=True)
rule_codes = [rule.rule_code for rule in rules]

# Sample data for transactions
customers = [
    {"customer_id": "CUST001", "customer_name": "John Smith", "risk_level": "LOW"},
    {"customer_id": "CUST002", "customer_name": "Jane Doe", "risk_level": "MEDIUM"},
    {"customer_id": "CUST003", "customer_name": "Robert Johnson", "risk_level": "HIGH"},
    {"customer_id": "CUST004", "customer_name": "Sarah Williams", "risk_level": "LOW"},
    {"customer_id": "CUST005", "customer_name": "Michael Brown", "risk_level": "MEDIUM"},
]

account_types = ["Checking", "Savings", "Investment", "Loan", "Credit"]
transaction_types = ["DEBIT", "CREDIT", "TRANSFER", "WITHDRAWAL", "DEPOSIT", "PAYMENT"]
locations = ["New York", "Los Angeles", "Chicago", "Miami", "Dallas", "London", "Paris", "Tokyo"]

# Helper function to generate transaction data
def generate_random_transaction(is_suspicious=False):
    customer = random.choice(customers)
    
    # Calculate a date within the last 30 days
    days_ago = random.randint(0, 30)
    transaction_date = datetime.now() - timedelta(days=days_ago)
    
    # Generate amount (suspicious transactions have higher amounts)
    if is_suspicious:
        amount = Decimal(str(random.uniform(5000, 50000)))
    else:
        amount = Decimal(str(random.uniform(10, 3000)))
    
    transaction = Transactions(
        transaction_id=f"TRX{uuid.uuid4().hex[:8].upper()}",
        customer_id=customer["customer_id"],
        customer_name=customer["customer_name"],
        account_number=f"ACC{random.randint(10000, 99999)}",
        account_type=random.choice(account_types),
        transaction_type=random.choice(transaction_types),
        amount=amount,
        currency="USD",
        transaction_date=transaction_date,
        description=f"Test transaction for {'suspicious' if is_suspicious else 'normal'} activity",
        source_location=random.choice(locations),
        destination_location=random.choice(locations),
        processed=False,
        processed_date=None,
        customer_risk_level=customer["risk_level"],
        transaction_risk_score=0
    )
    return transaction

def generate_dormant_account_transaction():
    """Generate transaction that should trigger dormant account rule"""
    customer = random.choice(customers)
    transaction_date = datetime.now() - timedelta(days=2)
    
    # Create a transaction on an account that hasn't been used for a long time
    transaction = Transactions(
        transaction_id=f"TRX{uuid.uuid4().hex[:8].upper()}",
        customer_id=customer["customer_id"],
        customer_name=customer["customer_name"],
        account_number=f"DORMANT{random.randint(10000, 99999)}",
        account_type="Savings",
        transaction_type="WITHDRAWAL",
        amount=Decimal(str(random.uniform(2000, 5000))),
        currency="USD",
        transaction_date=transaction_date,
        description="Activity on dormant account",
        source_location=random.choice(locations),
        destination_location=random.choice(locations),
        processed=False,
        processed_date=None,
        customer_risk_level=customer["risk_level"],
        transaction_risk_score=0,
        # Add a custom field to identify this as a dormant account
        last_activity_date=datetime.now() - timedelta(days=365)
    )
    return transaction

def generate_large_cash_transaction():
    """Generate transaction that should trigger large cash rule"""
    customer = random.choice(customers)
    transaction_date = datetime.now() - timedelta(days=1)
    
    transaction = Transactions(
        transaction_id=f"TRX{uuid.uuid4().hex[:8].upper()}",
        customer_id=customer["customer_id"],
        customer_name=customer["customer_name"],
        account_number=f"ACC{random.randint(10000, 99999)}",
        account_type="Checking",
        transaction_type="DEPOSIT",
        amount=Decimal(str(random.uniform(9500, 15000))),  # Just under/over $10,000 threshold
        currency="USD",
        transaction_date=transaction_date,
        description="Large cash deposit",
        source_location=random.choice(locations),
        destination_location=random.choice(locations),
        processed=False,
        processed_date=None,
        customer_risk_level=customer["risk_level"],
        transaction_risk_score=0,
        cash_transaction=True
    )
    return transaction

def generate_structured_transactions():
    """Generate multiple smaller transactions that add up to a suspicious amount"""
    customer = random.choice(customers)
    transactions = []
    
    # Create 3-5 smaller transactions from the same customer
    num_transactions = random.randint(3, 5)
    base_date = datetime.now() - timedelta(days=3)
    
    for i in range(num_transactions):
        transaction_date = base_date + timedelta(hours=random.randint(1, 8))
        
        transaction = Transactions(
            transaction_id=f"TRX{uuid.uuid4().hex[:8].upper()}",
            customer_id=customer["customer_id"],
            customer_name=customer["customer_name"],
            account_number=f"ACC{random.randint(10000, 99999)}",
            account_type="Checking",
            transaction_type="DEPOSIT",
            amount=Decimal(str(random.uniform(2500, 3500))),  # Multiple transactions under reporting threshold
            currency="USD",
            transaction_date=transaction_date,
            description="Possible structured transaction",
            source_location=random.choice(locations),
            destination_location=random.choice(locations),
            processed=False,
            processed_date=None,
            customer_risk_level=customer["risk_level"],
            transaction_risk_score=0,
            cash_transaction=True
        )
        transactions.append(transaction)
    
    return transactions

def main():
    print("Generating test transaction data...")
    
    # Clear existing unprocessed transactions
    # Transactions.objects.filter(processed=False).delete()
    
    # Generate normal transactions
    normal_transactions = [generate_random_transaction(is_suspicious=False) for _ in range(20)]
    
    # Generate suspicious transactions
    suspicious_transactions = [generate_random_transaction(is_suspicious=True) for _ in range(5)]
    
    # Generate transactions that should trigger specific rules
    dormant_account_transactions = [generate_dormant_account_transaction() for _ in range(3)]
    large_cash_transactions = [generate_large_cash_transaction() for _ in range(4)]
    structured_transactions = generate_structured_transactions()
    
    # Combine all transactions
    all_transactions = (
        normal_transactions + 
        suspicious_transactions + 
        dormant_account_transactions + 
        large_cash_transactions + 
        structured_transactions
    )
    
    # Save to database
    Transactions.objects.bulk_create(all_transactions)
    
    print(f"Generated {len(all_transactions)} test transactions:")
    print(f"- {len(normal_transactions)} normal transactions")
    print(f"- {len(suspicious_transactions)} suspicious transactions")
    print(f"- {len(dormant_account_transactions)} dormant account transactions")
    print(f"- {len(large_cash_transactions)} large cash transactions")
    print(f"- {len(structured_transactions)} structured transactions")

if __name__ == "__main__":
    main() 
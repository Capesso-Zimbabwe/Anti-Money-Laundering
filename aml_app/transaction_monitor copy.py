from datetime import datetime, timedelta
from django.db.models import Sum, Count
from django.http import JsonResponse
from django.utils import timezone
from .models import Transaction1, AMLSettings, SuspiciousTransaction1, SuspiciousActivityReport, Customer

# Transaction type code categories
DEPOSIT_CODES = ['DEPOSIT', 'CASH DEP', 'CHEQUE DEP', 'DIRECT CR']
WITHDRAWAL_CODES = ['WITHDRAWAL','WITHDRAW', 'CASH WDL', 'ATM WDL']
TRANSFER_CODES = ['TRANSFER', 'WIRE', 'SWIFT', 'ACH']
PAYMENT_CODES = ['BILL PMT','PAYMENT', 'PMT', 'DIRECT DEBIT']
FEE_CODES = ['FEE', 'SRV CHARGE', 'CHARGE']
ADJUSTMENT_CODES = ['REV', 'ADJ', 'CORRECTION']

# Risk score definitions (1-10 scale)
RISK_SCORES = {
    'large_cash_deposits': 5,
    'large_withdrawals': 5,
    'large_transfers': 6,
    'large_payments': 4,
    'frequent_currency_exchange': 7,
    'structured_deposits': 9,
    'dormant_account_activity': 8,
    'rapid_fund_movement': 7,
    'inconsistent_transactions': 6,
    'high_risk_jurisdictions': 9,
    'small_frequent_transfers': 7,
    'nonprofit_suspicious': 8,
    'shell_companies': 8,
    'high_risk_jurisdictions_customers': 9
}

# Risk level mapping
def get_risk_level(score):
    if score >= 8:
        return 'HIGH'
    elif score >= 5:
        return 'MEDIUM'
    else:
        return 'LOW'

def is_deposit(transaction_type_code):
    """Check if transaction type is a deposit"""
    return transaction_type_code in DEPOSIT_CODES

def is_withdrawal(transaction_type_code):
    """Check if transaction type is a withdrawal"""
    return transaction_type_code in WITHDRAWAL_CODES

def is_transfer(transaction_type_code):
    """Check if transaction type is a transfer"""
    return transaction_type_code in TRANSFER_CODES

def is_payment(transaction_type_code):
    """Check if transaction type is a payment"""
    return transaction_type_code in PAYMENT_CODES

def is_fee(transaction_type_code):
    """Check if transaction type is a fee"""
    return transaction_type_code in FEE_CODES

def is_adjustment(transaction_type_code):
    """Check if transaction type is an adjustment"""
    return transaction_type_code in ADJUSTMENT_CODES

class TransactionMonitor:
    """
    Service to monitor transactions against AML indicators defined in AMLSettings
    
    This class processes transactions and flags them based on the suspicious
    transaction indicators configured in the AML settings.
    """
    
    def __init__(self, account_type='INDIVIDUAL'):
        """Initialize with AML settings for a particular account type"""
        try:
            self.settings = AMLSettings.objects.get(account_type=account_type)
        except AMLSettings.DoesNotExist:
            # Use default settings if specific account type not found
            self.settings = AMLSettings.objects.first()
            if not self.settings:
                self.settings = AMLSettings(account_type='INDIVIDUAL')
                self.settings.save()
    
    def check_transaction(self, transaction):
        """
        Analyze a transaction against all enabled suspicious indicators
        Returns list of dict with reasons and risk scores if suspicious, empty list if not
        """
        if not isinstance(transaction, Transaction1):
            raise ValueError("Transaction must be a Transaction1 instance")
        
        flagged_reasons = []
        
        # Run all enabled checks
        if self.settings.large_cash_deposits:
            reason = self._check_large_cash_deposits(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'large_cash_deposits',
                    'risk_score': RISK_SCORES['large_cash_deposits']
                })
        
        # Check for large withdrawals
        if self.settings.large_withdrawals:
            reason = self._check_large_withdrawals(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'large_withdrawals',
                    'risk_score': RISK_SCORES['large_withdrawals']
                })
        
        # Check for large transfers
        if self.settings.large_transfers:
            reason = self._check_large_transfers(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'large_transfers',
                    'risk_score': RISK_SCORES['large_transfers']
                })
        
        # Check for large payments
        if self.settings.large_payments:
            reason = self._check_large_payments(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'large_payments',
                    'risk_score': RISK_SCORES['large_payments']
                })
        
        if self.settings.frequent_currency_exchange:
            reason = self._check_frequent_currency_exchange(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'frequent_currency_exchange',
                    'risk_score': RISK_SCORES['frequent_currency_exchange']
                })
        
        if self.settings.structured_deposits:
            reason = self._check_structured_deposits(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'structured_deposits',
                    'risk_score': RISK_SCORES['structured_deposits']
                })
        
        if self.settings.dormant_account_activity:
            reason = self._check_dormant_account_activity(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'dormant_account_activity',
                    'risk_score': RISK_SCORES['dormant_account_activity']
                })
        
        if self.settings.rapid_fund_movement:
            reason = self._check_rapid_fund_movement(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'rapid_fund_movement',
                    'risk_score': RISK_SCORES['rapid_fund_movement']
                })
        
        if self.settings.inconsistent_transactions:
            reason = self._check_inconsistent_transactions(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'inconsistent_transactions',
                    'risk_score': RISK_SCORES['inconsistent_transactions']
                })
        
        if self.settings.high_risk_jurisdictions:
            reason = self._check_high_risk_jurisdictions(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'high_risk_jurisdictions',
                    'risk_score': RISK_SCORES['high_risk_jurisdictions']
                })
        
        if self.settings.small_frequent_transfers:
            reason = self._check_small_frequent_transfers(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'small_frequent_transfers',
                    'risk_score': RISK_SCORES['small_frequent_transfers']
                })
        
        if self.settings.nonprofit_suspicious:
            reason = self._check_nonprofit_suspicious(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'nonprofit_suspicious',
                    'risk_score': RISK_SCORES['nonprofit_suspicious']
                })
        
        if self.settings.shell_companies:
            reason = self._check_shell_companies(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'shell_companies',
                    'risk_score': RISK_SCORES['shell_companies']
                })
        
        if self.settings.high_risk_jurisdictions_customers:
            reason = self._check_high_risk_jurisdictions_customers(transaction)
            if reason:
                flagged_reasons.append({
                    'reason': reason,
                    'indicator': 'high_risk_jurisdictions_customers',
                    'risk_score': RISK_SCORES['high_risk_jurisdictions_customers']
                })
        
        return flagged_reasons
    
    def _check_large_cash_deposits(self, transaction):
        """Check for unusually large cash deposits"""
        if (is_deposit(transaction.transaction_type_code) and 
            transaction.amount >= self.settings.large_cash_deposits_threshold):
            
            # Build a more detailed narrative
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get origination details
            origin_details = ""
            if transaction.source_country_name:
                if transaction.source_country_name != "United States":
                    origin_details = f" from {transaction.source_country_name}"
                    if transaction.source_branch_code or transaction.correspondent_bank_code:
                        bank_info = transaction.correspondent_bank_code or transaction.source_branch_code
                        origin_details += f" through {bank_info}"
            
            # Get deposit method
            deposit_method = "cash"
            if transaction.channel_code == "BRN":
                deposit_method = "Branch transactions conducted in-person at physical bank locations"
            elif transaction.channel_code == "ATM":
                deposit_method = "Automated Teller Machine transactions"
            elif transaction.channel_code == "OLB":
                deposit_method = "Online Banking transactions through web or mobile platforms"
            elif transaction.channel_code == "POS":
                deposit_method = " Point of Sale transactions at merchant terminals using card payments"

            
            
            # Build the narrative
            result = f"{customer_name} deposited {amount_str} via {deposit_method}{origin_details}, at {transaction.branch_name} branch . "
            result += f"This amount exceeds the large deposit threshold of {self.settings.large_cash_deposits_threshold:,.2f} {transaction.currency_code}."
            
            return result
        return None
    
    def _check_large_withdrawals(self, transaction):
        """Check for unusually large withdrawals"""
        if (is_withdrawal(transaction.transaction_type_code) and 
            transaction.amount >= self.settings.large_withdrawals_threshold):
            
            # Build a more detailed narrative
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get withdrawal method
            withdrawal_method = "cash"
            if transaction.transaction_type_code == "WITHDRAWAL":
                withdrawal_method = "withdrawal"
            elif transaction.transaction_type_code == "ATM WDL":
                withdrawal_method = "ATM withdrawal"
                if transaction.terminal_id:
                    withdrawal_method += f" (Terminal ID: {transaction.terminal_id})"
            
            # Get destination details
            destination_details = ""
            if transaction.destination_country_name and transaction.destination_country_name != "United States":
                destination_details = f" to be used in {transaction.destination_country_name}"
            
            # Add location information if available
            location_info = ""
            if transaction.geo_location:
                location_info = f" from {transaction.geo_location}"
            
            # Build the narrative
            result = f"{customer_name} made a {amount_str} {withdrawal_method}{location_info}{destination_details}. "
            result += f"This amount exceeds the large withdrawal threshold of {self.settings.large_withdrawals_threshold:,.2f} {transaction.currency_code}."
            
            return result
        return None
    
    def _check_large_transfers(self, transaction):
        """Check for unusually large transfers"""
        # Use the cash deposit threshold if transfer threshold is not explicitly set
        threshold = getattr(self.settings, 'large_transfers_threshold', self.settings.large_cash_deposits_threshold)
        
        if (is_transfer(transaction.transaction_type_code) and 
            transaction.amount >= threshold):
            
            # Build a more detailed narrative
            sender_name = transaction.source_customer_name or "Client"
            recipient_name = transaction.destination_customer_name or "recipient"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get transfer type
            transfer_type = "transfer"
            if transaction.transaction_type_code == "WIRE":
                transfer_type = "wire transfer"
            elif transaction.transaction_type_code == "SWIFT":
                transfer_type = "SWIFT transfer"
            elif transaction.transaction_type_code == "ACH":
                transfer_type = "ACH transfer"
            
            # Get international transfer details
            international_details = ""
            domestic_transfer = True
            
            if transaction.destination_country_name and transaction.source_country_name:
                # Check if it's an international transfer
                if transaction.destination_country_name != transaction.source_country_name:
                    domestic_transfer = False
                    international_details = f" to {transaction.destination_country_name}"
                    if transaction.beneficiary_bank_code:
                        international_details += f" through {transaction.beneficiary_bank_code}"
            
            # Add purpose if available
            purpose_info = ""
            if transaction.purpose_code:
                purpose_info = f" for {transaction.purpose_code}"
            elif transaction.description:
                purpose_info = f" for {transaction.description}"
            
            # Build the narrative
            result = f"{sender_name} sent {amount_str} via {transfer_type} to {recipient_name}{international_details}{purpose_info}. "
            
            if not domestic_transfer:
                result += "This is an international transfer. "
                
            result += f"This amount exceeds the large transfer threshold of {threshold:,.2f} {transaction.currency_code}."
            
            return result
        return None
    
    def _check_large_payments(self, transaction):
        """Check for unusually large payments"""
        # Use the cash deposit threshold if payment threshold is not explicitly set
        threshold = getattr(self.settings, 'large_payments_threshold', self.settings.large_cash_deposits_threshold)
        
        if (is_payment(transaction.transaction_type_code) and 
            transaction.amount >= threshold):
            
            # Build a more detailed narrative
            sender_name = transaction.source_customer_name or "Client"
            recipient_name = transaction.destination_customer_name or "payee"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get payment method
            payment_method = "payment"
            if transaction.transaction_type_code == "BILL PMT":
                payment_method = "bill payment"
            elif transaction.transaction_type_code == "DIRECT DEBIT":
                payment_method = "direct debit payment"
            
            # Add purpose if available
            purpose_info = ""
            if transaction.description:
                purpose_info = f" for {transaction.description}"
            elif transaction.narrative:
                purpose_info = f" for {transaction.narrative}"
            
            # Add recipient details
            recipient_details = ""
            if transaction.destination_account_number:
                recipient_details = f" to account {transaction.destination_account_number}"
                if transaction.beneficiary_bank_code:
                    recipient_details += f" at {transaction.beneficiary_bank_code}"
            
            # Build the narrative
            result = f"{sender_name} made a {amount_str} {payment_method}{purpose_info}{recipient_details}. "
            result += f"This amount exceeds the large payment threshold of {threshold:,.2f} {transaction.currency_code}."
            
            return result
        return None
    
    def _check_frequent_currency_exchange(self, transaction):
        """Check for frequent exchange of cash into other currencies"""
        # Only applies to transfer transactions
        if not is_transfer(transaction.transaction_type_code):
            return None
            
        # Check if source and destination currencies differ (currency exchange)
        if transaction.currency_code != 'USD':  # Simplified example, would need actual currency comparison
            # Count previous currency exchanges in the time window
            time_window = datetime.now() - timedelta(days=self.settings.currency_exchange_time_window)
            
            # Using Q objects to check for all transfer codes
            exchange_query = Transaction1.objects.filter(
                source_account_number=transaction.source_account_number,
                transaction_timestamp__gte=time_window,
                currency_code__ne='USD'  # Simplified currency exchange detection
            )
            
            # Filter for transfer type codes
            from django.db.models import Q
            transfer_type_filter = Q()
            for code in TRANSFER_CODES:
                transfer_type_filter |= Q(transaction_type_code=code)
            
            exchanges = exchange_query.filter(transfer_type_filter)
            exchange_count = exchanges.count()
            
            if exchange_count >= self.settings.currency_exchange_count_threshold:
                # Build a more detailed narrative
                customer_name = transaction.source_customer_name or "Client"
                amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
                
                # Get transaction details
                current_exchange = f"exchanged {amount_str}"
                if transaction.destination_currency_code:
                    current_exchange += f" to {transaction.destination_currency_code}"
                
                # Get previous currency details
                currencies = set()
                countries = set()
                for ex in exchanges:
                    if ex.currency_code:
                        currencies.add(ex.currency_code)
                    if ex.destination_country_name:
                        countries.add(ex.destination_country_name)
                
                # Format currency list
                currency_str = ", ".join(currencies)
                
                # Build the narrative
                result = f"{customer_name} has {current_exchange}. "
                result += f"This is the {exchange_count}th currency exchange transaction within {self.settings.currency_exchange_time_window} days"
                
                if currency_str:
                    result += f", involving currencies: {currency_str}"
                
                if countries:
                    country_str = ", ".join(countries)
                    result += f". These exchanges involved transactions with {country_str}"
                
                result += ". This pattern of frequent currency exchanges may indicate potential layering activity."
                
                return result
        return None
    
    def _check_structured_deposits(self, transaction):
        """Check for structuring deposits to avoid reporting thresholds"""
        if not is_deposit(transaction.transaction_type_code):
            return None
            
        # Look for multiple deposits below threshold but summing to significant amount
        time_window = datetime.now() - timedelta(days=self.settings.structured_deposits_window)
        
        # Using Q objects to check for all deposit codes
        from django.db.models import Q
        deposit_type_filter = Q()
        for code in DEPOSIT_CODES:
            deposit_type_filter |= Q(transaction_type_code=code)
        
        related_deposits = Transaction1.objects.filter(
            source_account_number=transaction.source_account_number,
            transaction_timestamp__gte=time_window,
            amount__lt=self.settings.large_cash_deposits_threshold  # Only deposits below reporting threshold
        ).filter(deposit_type_filter)
        
        deposit_count = related_deposits.count()
        deposit_sum = related_deposits.aggregate(Sum('amount'))['amount__sum'] or 0
        
        if (deposit_count >= self.settings.structured_deposits_count and 
            deposit_sum >= self.settings.structured_deposits_threshold):
            
            # Get more detailed information about deposits for better reporting
            # Get deposit methods used
            deposit_methods = set()
            for dep in related_deposits:
                if dep.transaction_type_code:
                    deposit_methods.add(dep.transaction_type_code)
            
            # Get source information
            source_countries = set([dep.source_country_name for dep in related_deposits if dep.source_country_name])
            
            # Get date patterns - are the deposits made on the same day?
            dates = set([dep.transaction_date for dep in related_deposits])
            date_pattern = "same day" if len(dates) == 1 else f"{len(dates)} different days"
            
            # Calculate average deposit size
            avg_deposit = deposit_sum / deposit_count if deposit_count > 0 else 0
            
            # Check if deposits are evenly distributed (possible sign of deliberate structuring)
            amounts = [dep.amount for dep in related_deposits]
            max_amount = max(amounts) if amounts else 0
            min_amount = min(amounts) if amounts else 0
            amount_variance = max_amount - min_amount
            
            uniform_deposits = amount_variance < (avg_deposit * 0.2)  # If variance is less than 20% of average
            
            # Build detailed description
            result = f"Client made {deposit_count} deposits totaling {deposit_sum} {transaction.currency_code} within {self.settings.structured_deposits_window} days, "
            result += f"with all transactions below the reporting threshold of {self.settings.large_cash_deposits_threshold}. "
            
            # Add deposit method info
            if deposit_methods:
                result += f"Deposits were made via {', '.join(deposit_methods)}. "
            
            # Add pattern info
            result += f"Deposits occurred on {date_pattern}"
            if source_countries:
                result += f" from {', '.join(source_countries)}"
            result += ". "
            
            # Add uniformity info if relevant
            if uniform_deposits and deposit_count > 2:
                result += f"Deposits show uniform pattern with similar amounts (avg: {avg_deposit:.2f}, range: {min_amount:.2f}-{max_amount:.2f}), "
                result += "suggesting possible deliberate structuring to avoid reporting requirements."
            
            return result
        return None
    
    def _check_dormant_account_activity(self, transaction):
        """Check for dormant accounts suddenly receiving large deposits"""
        # Check if the account was dormant
        last_activity = Transaction1.objects.filter(
            source_account_number=transaction.source_account_number
        ).exclude(
            transaction_id=transaction.transaction_id
        ).order_by('-transaction_timestamp').first()
        
        if not last_activity:
            return None  # New account, not dormant
            
        days_since_activity = (transaction.transaction_timestamp - last_activity.transaction_timestamp).days
        
        if (days_since_activity >= self.settings.dormant_days_threshold and 
            transaction.amount >= self.settings.dormant_activity_amount):
            
            # Build a more detailed narrative
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get transaction type information
            transaction_type = "transaction"
            if is_deposit(transaction.transaction_type_code):
                transaction_type = "deposit"
            elif is_withdrawal(transaction.transaction_type_code):
                transaction_type = "withdrawal"
            elif is_transfer(transaction.transaction_type_code):
                transaction_type = "transfer"
            elif is_payment(transaction.transaction_type_code):
                transaction_type = "payment"
            
            # Get origin information
            origin_info = ""
            if transaction.source_country_name and transaction.source_country_name != "United States":
                origin_info = f" from {transaction.source_country_name}"
                if transaction.correspondent_bank_code:
                    origin_info += f" via {transaction.correspondent_bank_code}"
            
            # Get previous activity details
            previous_tx_date = last_activity.transaction_timestamp.strftime("%B %d, %Y")
            
            # Build the narrative
            result = f"Account for {customer_name} showed a {amount_str} {transaction_type}{origin_info} "
            result += f"after being dormant for {days_since_activity} days. "
            result += f"The last activity on this account was on {previous_tx_date}. "
            result += f"This sudden activity on a previously dormant account exceeds the dormant activity threshold of {self.settings.dormant_activity_amount:,.2f} {transaction.currency_code}."
            
            return result
        return None
    
    def _check_rapid_fund_movement(self, transaction):
        """Check for rapid movement of funds in and out of accounts"""
        # Only applies to outgoing funds (transfers and withdrawals)
        if not (is_transfer(transaction.transaction_type_code) or is_withdrawal(transaction.transaction_type_code)):
            return None
            
        # Look for deposits followed quickly by withdrawals
        time_window = datetime.now() - timedelta(hours=self.settings.rapid_movement_window)
        
        # Using Q objects to check for all deposit codes
        from django.db.models import Q
        deposit_type_filter = Q()
        for code in DEPOSIT_CODES:
            deposit_type_filter |= Q(transaction_type_code=code)
        
        # Find recent deposits
        recent_deposits = Transaction1.objects.filter(
            destination_account_number=transaction.source_account_number,
            transaction_timestamp__gte=time_window
        ).filter(deposit_type_filter)
        
        deposit_sum = recent_deposits.aggregate(Sum('amount'))['amount__sum'] or 0
        
        # Calculate the percentage of deposited funds being moved
        if deposit_sum > 0:
            percentage = (transaction.amount / deposit_sum) * 100
            if percentage >= self.settings.rapid_movement_percentage:
                # Get source countries/institutions for incoming funds
                source_countries = set([dep.source_country_name for dep in recent_deposits if dep.source_country_name])
                source_banks = set([dep.correspondent_bank_code for dep in recent_deposits if dep.correspondent_bank_code])
                
                # Get destination info for outgoing funds
                destination_info = f"to {transaction.destination_customer_name or 'unknown recipient'}"
                if transaction.destination_country_name:
                    destination_info += f" in {transaction.destination_country_name}"
                if transaction.beneficiary_bank_code:
                    destination_info += f" via {transaction.beneficiary_bank_code}"
                
                # Count distinct transactions for deposits
                deposit_count = recent_deposits.count()
                
                # Check if this is part of a splitting pattern (one large deposit followed by multiple smaller outgoing)
                large_deposit = recent_deposits.order_by('-amount').first()
                is_splitting = False
                splitting_detail = ""
                
                if large_deposit and large_deposit.amount > transaction.amount * 2:
                    # Look for other outgoing transactions from the same source
                    other_outgoing = Transaction1.objects.filter(
                        source_account_number=transaction.source_account_number,
                        transaction_timestamp__gte=large_deposit.transaction_timestamp,
                        transaction_id__ne=transaction.transaction_id
                    ).filter(Q(transaction_type_code__in=TRANSFER_CODES) | Q(transaction_type_code__in=WITHDRAWAL_CODES))
                    
                    if other_outgoing.count() > 0:
                        outgoing_count = other_outgoing.count() + 1  # Include current transaction
                        outgoing_sum = other_outgoing.aggregate(Sum('amount'))['amount__sum'] or 0
                        outgoing_sum += transaction.amount
                        
                        # Get unique destination accounts
                        dest_accounts = set([tx.destination_account_number for tx in other_outgoing if tx.destination_account_number])
                        if transaction.destination_account_number:
                            dest_accounts.add(transaction.destination_account_number)
                            
                        # Get unique financial institutions
                        fin_institutions = set([tx.beneficiary_bank_code for tx in other_outgoing if tx.beneficiary_bank_code])
                        if transaction.beneficiary_bank_code:
                            fin_institutions.add(transaction.beneficiary_bank_code)
                        
                        if outgoing_count >= 2 and len(dest_accounts) >= 2:
                            is_splitting = True
                            splitting_detail = f" Funds were split into {outgoing_count} separate transactions to {len(dest_accounts)} different accounts"
                            if len(fin_institutions) > 1:
                                splitting_detail += f" across {len(fin_institutions)} different financial institutions"
                
                # Build the comprehensive description
                source_detail = ""
                if source_countries or source_banks:
                    source_detail = " from "
                    if source_countries:
                        source_detail += f"{', '.join(source_countries)}"
                    if source_banks:
                        source_detail += f" via {', '.join(source_banks)}"
                
                result = f"Client received {deposit_sum} {transaction.currency_code} in {deposit_count} deposit(s){source_detail} within the past {self.settings.rapid_movement_window} hours. "
                result += f"{percentage:.1f}% of these funds ({transaction.amount} {transaction.currency_code}) were moved {destination_info} within {self.settings.rapid_movement_window} hours."
                
                if is_splitting:
                    result += splitting_detail
                
                return result
                
        return None
    
    def _check_inconsistent_transactions(self, transaction):
        """Check for transactions inconsistent with customer's known business activities"""
        # Calculate average transaction size for this account
        account_transactions = Transaction1.objects.filter(
            source_account_number=transaction.source_account_number
        ).exclude(
            transaction_id=transaction.transaction_id
        )
        
        if account_transactions.count() < 3:
            return None  # Not enough history to determine consistency
            
        avg_amount = account_transactions.aggregate(Sum('amount'))['amount__sum'] / account_transactions.count()
        
        # Check if transaction amount is significantly higher than average
        if transaction.amount > (avg_amount * self.settings.inconsistent_amount_multiplier):
            # Build a more detailed narrative
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            avg_amount_str = f"{avg_amount:.2f} {transaction.currency_code}"
            multiplier = transaction.amount / avg_amount
            
            # Get transaction type
            transaction_type = "transaction"
            if is_deposit(transaction.transaction_type_code):
                transaction_type = "deposit"
            elif is_withdrawal(transaction.transaction_type_code):
                transaction_type = "withdrawal"
            elif is_transfer(transaction.transaction_type_code):
                transaction_type = "transfer"
            elif is_payment(transaction.transaction_type_code):
                transaction_type = "payment"
            
            # Get transaction details
            transaction_details = ""
            if transaction.description:
                transaction_details = f" for {transaction.description}"
            
            if is_transfer(transaction.transaction_type_code) or is_payment(transaction.transaction_type_code):
                if transaction.destination_customer_name:
                    transaction_details += f" to {transaction.destination_customer_name}"
                if transaction.destination_country_name and transaction.destination_country_name != "United States":
                    transaction_details += f" in {transaction.destination_country_name}"
            
            # Get industry information if available
            industry_info = ""
            if hasattr(transaction, 'source_account_holder_id') and transaction.source_account_holder_id:
                try:
                    customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
                    if customer.industry_description:
                        industry_info = f" Client is in the {customer.industry_description} industry."
                except Customer.DoesNotExist:
                    pass
            
            # Build the narrative
            result = f"{customer_name} made a {amount_str} {transaction_type}{transaction_details}. "
            result += f"This amount is {multiplier:.1f}x higher than the account's average transaction amount of {avg_amount_str}."
            
            if industry_info:
                result += industry_info
            
            result += " This significant deviation from established transaction patterns may indicate unusual activity requiring further investigation."
            
            return result
        return None
    
    def _check_high_risk_jurisdictions(self, transaction):
        """Check for transfers to/from high-risk jurisdictions"""
        high_risk_countries = self.settings.high_risk_countries.split(',')
        
        if transaction.source_country_code in high_risk_countries:
            # Build a more detailed narrative for source country
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get transaction type
            transaction_type = "transaction"
            if is_deposit(transaction.transaction_type_code):
                transaction_type = "deposit"
            elif is_transfer(transaction.transaction_type_code):
                transaction_type = "transfer"
            
            # Get recipient information
            recipient_info = ""
            if transaction.destination_customer_name:
                recipient_info = f" to {transaction.destination_customer_name}"
                if transaction.destination_account_number:
                    recipient_info += f" (account: {transaction.destination_account_number})"
            
            # Get bank information
            bank_info = ""
            if transaction.correspondent_bank_code:
                bank_info = f" through {transaction.correspondent_bank_code}"
            
            # Build the narrative
            result = f"{customer_name} initiated a {amount_str} {transaction_type}{recipient_info} "
            result += f"from {transaction.source_country_name} ({transaction.source_country_code}){bank_info}. "
            result += f"{transaction.source_country_name} is classified as a high-risk jurisdiction under AML regulations."
            
            return result
            
        if transaction.destination_country_code in high_risk_countries:
            # Build a more detailed narrative for destination country
            customer_name = transaction.source_customer_name or "Client"
            amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            
            # Get transaction type
            transaction_type = "transaction"
            if is_transfer(transaction.transaction_type_code):
                transaction_type = "transfer"
            elif is_payment(transaction.transaction_type_code):
                transaction_type = "payment"
            
            # Get recipient information
            recipient_info = ""
            if transaction.destination_customer_name:
                recipient_info = f" to {transaction.destination_customer_name}"
                if transaction.destination_account_number:
                    recipient_info += f" (account: {transaction.destination_account_number})"
            
            # Get bank information
            bank_info = ""
            if transaction.beneficiary_bank_code:
                bank_info = f" through {transaction.beneficiary_bank_code}"
            
            # Add purpose if available
            purpose_info = ""
            if transaction.purpose_code:
                purpose_info = f" for {transaction.purpose_code}"
            elif transaction.description:
                purpose_info = f" for {transaction.description}"
            
            # Build the narrative
            result = f"{customer_name} sent a {amount_str} {transaction_type}{recipient_info} "
            result += f"to {transaction.destination_country_name} ({transaction.destination_country_code}){bank_info}{purpose_info}. "
            result += f"{transaction.destination_country_name} is classified as a high-risk jurisdiction under AML regulations."
            
            return result
        
        return None
    
    def _check_small_frequent_transfers(self, transaction):
        """Check for frequent small transfers that may indicate avoidance of detection"""
        if not is_transfer(transaction.transaction_type_code) or transaction.amount > self.settings.small_transfer_threshold:
            return None
            
        # Count small transfers in the time window
        time_window = datetime.now() - timedelta(days=self.settings.small_transfer_window)
        
        # Using Q objects to check for all transfer codes
        from django.db.models import Q
        transfer_type_filter = Q()
        for code in TRANSFER_CODES:
            transfer_type_filter |= Q(transaction_type_code=code)
        
        small_transfers = Transaction1.objects.filter(
            source_account_number=transaction.source_account_number,
            transaction_timestamp__gte=time_window,
            amount__lte=self.settings.small_transfer_threshold
        ).filter(transfer_type_filter)
        
        transfer_count = small_transfers.count()
        transfer_sum = small_transfers.aggregate(Sum('amount'))['amount__sum'] or 0
        
        if transfer_count >= self.settings.small_transfer_frequency:
            # Build a more detailed narrative
            customer_name = transaction.source_customer_name or "Client"
            current_amount_str = f"{transaction.amount:,.2f} {transaction.currency_code}"
            total_amount_str = f"{transfer_sum:,.2f} {transaction.currency_code}"
            
            # Get current transfer details
            current_transfer = f"transferred {current_amount_str}"
            recipient_info = ""
            if transaction.destination_customer_name:
                recipient_info = f" to {transaction.destination_customer_name}"
                if transaction.destination_country_name and transaction.destination_country_name != "United States":
                    recipient_info += f" in {transaction.destination_country_name}"
            
            # Get unique recipients information
            recipients = set()
            countries = set()
            for tx in small_transfers:
                if tx.destination_customer_name:
                    recipients.add(tx.destination_customer_name)
                if tx.destination_country_name:
                    countries.add(tx.destination_country_name)
            
            recipient_count = len(recipients)
            country_count = len(countries)
            
            # Build the narrative
            result = f"{customer_name} has {current_transfer}{recipient_info}. "
            result += f"This is part of a pattern involving {transfer_count} small transfers totaling {total_amount_str} "
            result += f"within the past {self.settings.small_transfer_window} days. "
            
            if recipient_count > 1:
                result += f"These transfers were sent to {recipient_count} different recipients"
                if country_count > 1:
                    result += f" across {country_count} different countries"
                result += ". "
            
            result += f"All transfers were below the reporting threshold of {self.settings.small_transfer_threshold:,.2f} {transaction.currency_code}, "
            result += "which may indicate structuring to avoid regulatory detection."
            
            return result
        return None
    
    def _check_nonprofit_suspicious(self, transaction):
        """Check for non-profit organizations with unexplained transactions"""
        # Get customer information if available
        if transaction.source_account_holder_id:
            try:
                customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
                # Check if customer is a non-profit from the industry code/description
                if customer.industry_code == 'NONPROFIT' or (customer.industry_description and 'non-profit' in customer.industry_description.lower()):

                    if transaction.amount >= self.settings.nonprofit_transaction_threshold:
                        return f"Large transaction of {transaction.amount} {transaction.currency_code} from non-profit organization"
            except Customer.DoesNotExist:
                pass
                
        # Fallback to account type check if customer information not available
        if transaction.source_account_type_code == 'NONPROFIT' and transaction.amount >= self.settings.nonprofit_transaction_threshold:
            return f"Large transaction of {transaction.amount} {transaction.currency_code} from non-profit organization"
            
        return None
    
    def _check_shell_companies(self, transaction):
        """Check for trusts or shell companies with no clear business purpose"""
        # Check if we have a customer record for this transaction
        if transaction.source_account_holder_id:
            try:
                customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
                
                # If this is a business/entity customer
                if customer.customer_type == 'ENTITY':
                    # Calculate days since incorporation/onboarding
                    if customer.date_of_incorporation:
                        days_since_incorporation = (timezone.now().date() - customer.date_of_incorporation).days
                    elif customer.onboarding_date:
                        days_since_incorporation = (timezone.now().date() - customer.onboarding_date).days
                    else:
                        # Use the created_at date if other dates not available
                        days_since_incorporation = (timezone.now().date() - customer.created_at.date()).days
                    
                    # Check if it's a new entity
                    if days_since_incorporation < self.settings.shell_company_age_threshold:
                        return f"Transaction from new business entity (age: {days_since_incorporation} days) below shell company threshold of {self.settings.shell_company_age_threshold} days"
            except Customer.DoesNotExist:
                pass
        
        # Fallback to simplified check if customer information is not available
        if transaction.source_account_type_code == 'BUSINESS':
            customer_age_days = 30  # Example value - simplified approach
            if customer_age_days < self.settings.shell_company_age_threshold:
                return f"Transaction from new business entity (age: {customer_age_days} days) below shell company threshold of {self.settings.shell_company_age_threshold} days"
                
        return None
    
    def _check_high_risk_jurisdictions_customers(self, transaction):
        """Check for customers linked to high-risk jurisdictions"""
        high_risk_countries = self.settings.high_risk_countries.split(',')
        
        # Try to get customer information from linked Customer model
        if transaction.source_account_holder_id:
            try:
                customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
                
                # Check if customer's residence country is high-risk
                if (customer.residential_country in high_risk_countries or 
                    customer.tax_residence_country in high_risk_countries or
                    customer.primary_id_issuing_country in high_risk_countries):
                    return f"Customer linked to high-risk jurisdiction: {customer.residential_country or customer.tax_residence_country or customer.primary_id_issuing_country}"
            except Customer.DoesNotExist:
                pass
        
        # Fallback to transaction country data if customer information not available
        if (transaction.source_country_code in high_risk_countries or 
            transaction.destination_country_code in high_risk_countries):
            return "Customer linked to high-risk jurisdiction"
            
        return None
    
    def flag_transaction(self, transaction, reason_data_list):
        """
        Create a suspicious transaction record and suspicious activity report
        
        Args:
            transaction: The Transaction1 instance
            reason_data_list: List of dicts with reason, indicator, risk_score
            
        Returns:
            Tuple of (SuspiciousTransaction1, SuspiciousActivityReport) instances
        """
        if not reason_data_list:
            return None, None
            
        # Calculate overall risk score (average of all indicators)
        risk_scores = [item['risk_score'] for item in reason_data_list]
        overall_score = sum(risk_scores) / len(risk_scores)
        
        # Determine risk level based on overall score
        if overall_score >= 8:
            risk_level = 'High'
            sar_risk_level = 'HIGH'
        elif overall_score >= 5:
            risk_level = 'Medium'
            sar_risk_level = 'MEDIUM'
        else:
            risk_level = 'Low'
            sar_risk_level = 'LOW'
        
        # Extract just the reason messages for the suspicious transaction
        reason_messages = [item['reason'] for item in reason_data_list]
        flagged_reason = "\n".join(reason_messages)
        
        # Create SuspiciousTransaction1 record
        suspicious_tx = SuspiciousTransaction1.objects.create(
            transaction=transaction,
            risk_level=risk_level,
            flagged_reason=flagged_reason,
            manual_review_required=True,
            sender_account=transaction.source_account_number,
            receiver_account=transaction.destination_account_number,
            beneficiary_account=transaction.destination_account_number,
            beneficiary_name=transaction.destination_customer_name,
            amount=transaction.amount,
            branch_code=getattr(transaction, 'branch_code', ''),  # Use getattr to safely get attributes
            branch_name=getattr(transaction, 'branch_name', '')
        )
        
        # Try to get customer information
        customer_name = getattr(transaction, 'source_customer_name', "Unknown") or "Unknown"
        customer_id = getattr(transaction, 'customer_id', "") or ""
        customer_email = ""
        customer_phone = ""
        
        # If we have a customer ID, get more detailed information
        if customer_id:
            try:
                customer = Customer.objects.get(customer_id=customer_id)
                customer_name = f"{customer.last_name}, {customer.first_name}" if customer.customer_type == 'INDIVIDUAL' else customer.entity_name
                customer_id = customer.customer_id
                customer_email = customer.primary_email or customer.secondary_email 
                customer_address = f"{customer.residential_address}, {customer.residential_city}, {customer.residential_country}"                
                customer_phone = customer.primary_phone or ""
                customer_id_number=customer.primary_id_number
                customer_id_type=customer.primary_id_type
                customer_account_type=customer.customer_type
                customer_nationality=customer.nationality 



                
                
                # Update suspicious transaction with customer details
                suspicious_tx.customer_id = customer.customer_id
                suspicious_tx.customer_name = customer_name
                suspicious_tx.customer_email = customer_email
                suspicious_tx.customer_phone = customer_phone
                suspicious_tx.id_document_number = customer_id_number
                suspicious_tx.id_document_type = customer_id_type
                suspicious_tx.customer_address = customer_address
                suspicious_tx.account_type = customer_account_type

                
                # Add ID document information if available
                # if hasattr(customer, 'primary_id_type') and customer.primary_id_type:
                #     suspicious_tx.id_document_type = customer.primary_id_type
                #     suspicious_tx.id_document_number = customer.primary_id_number
                
                # Add account details
                # suspicious_tx.account_type = customer.customer_type

                suspicious_tx.save()
                
            except Customer.DoesNotExist:
                pass
        
        # Create SuspiciousActivityReport
        # Determine suspicious activity type based on indicators
        activity_types = set([item['indicator'] for item in reason_data_list])
        
        if 'structured_deposits' in activity_types:
            suspicious_activity_type = 'STRUCTURING'
        elif 'high_risk_jurisdictions' in activity_types or 'high_risk_jurisdictions_customers' in activity_types:
            suspicious_activity_type = 'SANCTIONS_VIOLATION'
        else:
            suspicious_activity_type = 'UNUSUAL_ACTIVITY'
            
        # Generate a unique report reference
        report_ref = f"SAR-{transaction.transaction_id}-{timezone.now().strftime('%Y%m%d')}"
        report_id = f"RPT{timezone.now().strftime('%Y%m%d')}{transaction.transaction_id[:5]}"
        
        transaction_date = getattr(transaction, 'transaction_date', timezone.now().date())
        
        # Create the SAR report
        sar_report = SuspiciousActivityReport.objects.create(
            report_id=report_id,
            report_reference_number=report_ref,
            report_type='SAR',
            report_status='DRAFT',
            suspicious_activity_type=suspicious_activity_type,
            secondary_activity_types=','.join(activity_types),
            detection_date=timezone.now(),
            activity_start_date=transaction_date,
            activity_end_date=transaction_date,
            total_suspicious_amount=transaction.amount,
            currency_code=transaction.currency_code,
            related_transactions=transaction.transaction_id,
            primary_subject_name=customer_name,
            primary_subject_nationality=customer_nationality,
            primary_subject_id=customer_id,
            primary_subject_id_type="Account" if not customer_id else "Customer ID",
            primary_subject_address=customer_address,
            primary_account_number=transaction.source_account_number,
            risk_level=sar_risk_level,
            suspicious_activity_description=flagged_reason,
            red_flags_identified=flagged_reason,
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
        
        return suspicious_tx, sar_report


def analyze_transaction(transaction):
    """
    Convenience function to analyze a single transaction
    
    Args:
        transaction: A Transaction1 instance to analyze
        
    Returns:
        Tuple of (SuspiciousTransaction1, SuspiciousActivityReport) if flagged, (None, None) otherwise
    """
    # Default account type
    account_type = 'INDIVIDUAL'
    
    # Try to get account type from Customer model if customer_id is available
    if hasattr(transaction, 'source_account_holder_id') and transaction.source_account_holder_id:
        try:
            customer = Customer.objects.get(customer_id=transaction.source_account_holder_id)
            # Map Customer model's customer_type to AMLSettings account_type
            if customer.customer_type == 'ENTITY':
                if hasattr(customer, 'industry_description') and customer.industry_description and 'NON' in customer.industry_description.upper() and 'PROFIT' in customer.industry_description.upper():
                    account_type = 'NONPROFIT'
                else:
                    account_type = 'BUSINESS'
            elif customer.customer_type == 'INDIVIDUAL':
                account_type = 'INDIVIDUAL'
        except Customer.DoesNotExist:
            # If customer not found, try to determine from transaction metadata
            pass
    
    # Fallback: Use transaction metadata if Customer model lookup failed
    if account_type == 'INDIVIDUAL' and hasattr(transaction, 'source_account_type_code') and transaction.source_account_type_code:
        if transaction.source_account_type_code in ['BUSINESS', 'CORP']:
            account_type = 'BUSINESS'
        elif transaction.source_account_type_code in ['TRUST']:
            account_type = 'TRUST'
        elif transaction.source_account_type_code in ['NONPROFIT']:
            account_type = 'NONPROFIT'
    
    monitor = TransactionMonitor(account_type)
    reason_data = monitor.check_transaction(transaction)
    
    if reason_data:
        return monitor.flag_transaction(transaction, reason_data)
    return None, None


#############################
def test_transaction_monitor_view(request):
    # Retrieve a transaction for testing; adjust your query as needed
    transaction = Transaction1.objects.first()
    if not transaction:
        return JsonResponse({"error": "No transaction available to analyze."}, status=404)

    suspicious_tx, sar_report = analyze_transaction(transaction)

    if suspicious_tx or sar_report:
        result = {
            "Suspicious Transaction": str(suspicious_tx),
            "Suspicious Activity Report": str(sar_report)
        }
    else:
        result = {"message": "No suspicious activity detected for this transaction."}
    
    return JsonResponse(result)
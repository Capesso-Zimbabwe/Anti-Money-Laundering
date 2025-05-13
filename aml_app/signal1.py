








from decimal import Decimal
from datetime import timedelta
from django.db.models import Avg, Sum
from django.utils.timezone import now
from .models import AMLSettings,AMLSettingss, Alert, KYCProfile, Transaction, SuspiciousTransaction

def detect_suspicious_transactions(transaction):
    """
    Function to detect suspicious transactions dynamically using AML settings from the database.
    Each transaction is processed only once, as marked by the is_checked flag.
    """
    # If the transaction has already been checked, do not process it again.
    if transaction.is_checked:
        return

    flagged_reasons = []

    # Fetch AML screening parameters from the database
    settings = AMLSettingss.objects.first()
    if not settings:
        settings = AMLSettingss.objects.create()  # Create default settings if missing

    # Convert float values from settings to Decimal
    transaction_threshold = Decimal(settings.transaction_threshold)
    cash_deposit_limit = Decimal(settings.cash_deposit_limit)
    structuring_limit = Decimal(settings.structuring_limit)
    mismatched_behavior_multiplier = Decimal(settings.mismatched_behavior_multiplier)
    cash_deposit_no_withdrawal = Decimal(settings.cash_deposit_no_withdrawal)
    dormant_account_transfer_limit = Decimal(settings.dormant_account_transfer_limit)

    # Retrieve KYCProfile using the transaction's customer_id
    kyc_profile = KYCProfile.objects.filter(customer_id=transaction.customer_id).first() if transaction.customer_id else None

    # 1. Transaction Amount & Frequency Triggers
    if transaction.amount > transaction_threshold:
        flagged_reasons.append(f"Transaction amount exceeds ${transaction_threshold}")

    if transaction.payment_type == "Cash Deposit" and transaction.amount > cash_deposit_limit:
        flagged_reasons.append(f"Large cash deposit exceeds ${cash_deposit_limit}")

    # 2. Structuring Transactions Below Threshold
    structuring_txns = Transaction.objects.filter(
        customer_id=transaction.customer_id,
        amount__gte=structuring_limit, amount__lt=transaction_threshold,
        date__gte=transaction.date - timedelta(days=3)
    ).count()

    if structuring_txns >= settings.structuring_txn_count:
        flagged_reasons.append("Possible structuring below AML reporting threshold")

    # 3. Dormant Account Reactivated with Large International Transfer
    last_txn = Transaction.objects.filter(customer_id=transaction.customer_id).order_by('-date').exclude(id=transaction.id).first()
    if last_txn and (transaction.date - last_txn.date).days > settings.inactive_days:
        if transaction.sender_bank_location != transaction.receiver_bank_location and transaction.amount > dormant_account_transfer_limit:
            flagged_reasons.append("Dormant account reactivated with large international transfer")

    # 4. Mismatched Customer Behavior (Transaction Amount vs Profile)
    avg_amount = Transaction.objects.filter(
        customer_id=transaction.customer_id
    ).aggregate(avg_amount=Avg('amount'))['avg_amount']

    if avg_amount:
        avg_amount = Decimal(avg_amount)
        if transaction.amount > avg_amount * mismatched_behavior_multiplier:
            flagged_reasons.append("Unusual transaction amount compared to customer history")

    # 5. High Cash Deposits Without Withdrawals
    cash_deposits = Transaction.objects.filter(
        customer_id=transaction.customer_id,
        payment_type="Cash Deposit",
        date__gte=now().date() - timedelta(days=30)
    ).aggregate(total=Sum('amount'))['total'] or Decimal(0)

    cash_withdrawals = Transaction.objects.filter(
        customer_id=transaction.customer_id,
        payment_type="Cash Withdrawal",
        date__gte=now().date() - timedelta(days=30)
    ).aggregate(total=Sum('amount'))['total'] or Decimal(0)

    if cash_deposits > cash_deposit_no_withdrawal and cash_withdrawals == 0:
        flagged_reasons.append("High cash deposits with no corresponding withdrawals")

    # 6. High-Risk Countries Check
    high_risk_countries = settings.high_risk_countries.split(",")
    if transaction.sender_bank_location in high_risk_countries or transaction.receiver_bank_location in high_risk_countries:
        flagged_reasons.append("Transaction linked to a country under sanctions or with weak AML regulations")

    # 7. Circular Transaction (Reversed within X days)
    if Transaction.objects.filter(
        sender_account=transaction.receiver_account,
        receiver_account=transaction.sender_account,
        amount=transaction.amount,
        date__gte=transaction.date - timedelta(days=settings.circular_transaction_days)
    ).exists():
        flagged_reasons.append("Potential circular transaction (funds moved back to origin account)")

    # 8. Multiple Unrelated Beneficiaries
    distinct_receivers = Transaction.objects.filter(
        sender_account=transaction.sender_account,
        date__gte=now().date() - timedelta(days=2)
    ).values_list('receiver_account', flat=True).distinct().count()

    if distinct_receivers > settings.multiple_beneficiaries:
        flagged_reasons.append(f"Sender transferring funds to {distinct_receivers} different beneficiaries")

    # 9. Geo-location Mismatch
    distinct_locations = Transaction.objects.filter(
        customer_id=transaction.customer_id,
        date__gte=now().date() - timedelta(days=2)
    ).values_list('sender_bank_location', flat=True).distinct().count()

    if distinct_locations > settings.geo_location_mismatch:
        flagged_reasons.append(f"Multiple transactions from {distinct_locations} distant locations in short time")

    # 10. Employee Risk
    if settings.employee_risk_flag and kyc_profile and kyc_profile.full_name.lower() == "bank employee":
        flagged_reasons.append("Possible bank employee involvement in suspicious transactions")

    # Create SuspiciousTransaction + Alert if flagged
    if flagged_reasons:
        suspicious_txn = SuspiciousTransaction.objects.create(
            transaction=transaction,
            customer_id=kyc_profile.customer_id if kyc_profile else "Unknown",
            customer_name=kyc_profile.full_name if kyc_profile else "Unknown",
            customer_email=kyc_profile.email if kyc_profile else "Unknown",
            customer_phone=kyc_profile.phone_number if kyc_profile else "Unknown",
            id_document_type=kyc_profile.id_document_type if kyc_profile else "Unknown",
            id_document_number=kyc_profile.id_document_number if kyc_profile else "Unknown",
            account_number=transaction.account_number,
            account_type="Current",
            account_status="Active",
            sender_account=transaction.sender_account,
            receiver_account=transaction.receiver_account,
            amount=transaction.amount,
            risk_level='High' if len(flagged_reasons) > 2 else 'Medium',
            flagged_reason=", ".join(flagged_reasons),
            manual_review_required=True
        )
        print(f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}")

        # ✅ Also create an Alert referencing this suspicious transaction
        Alert.objects.create(
            alert_type="TXN",
            severity="HIGH" if len(flagged_reasons) > 2 else "MEDIUM",
            status="OPEN",
            suspicious_txn=suspicious_txn,
            title="Suspicious Transaction",
            message=f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}"
        )

    # Mark the transaction as checked so it won't be processed again.
    transaction.is_checked = True
    transaction.save()














####################################################################################################

from aml_app.models import BlacklistEntry, SuspiciousTransaction, Transaction, Customer

def detect_blacklisted_transactions(transaction):
    """
    Function to detect transactions involving blacklisted individuals.
    It checks whether the sender or receiver is in the blacklist and flags the transaction if found.
    """
    flagged_reasons = []

    # 1. Retrieve sender and receiver customer details
    sender_customer = Customer.objects.filter(customer_id=transaction.customer_id).first()
    receiver_customer = Customer.objects.filter(customer_id=transaction.receiver_account).first()

    # 2. Blacklist check for sender
    if sender_customer and sender_customer.id_number:
        if BlacklistEntry.objects.filter(id_number=sender_customer.id_number).exists():
            flagged_reasons.append("Sender is on the blacklist")

    # 3. Blacklist check for receiver
    if receiver_customer and receiver_customer.id_number:
        if BlacklistEntry.objects.filter(id_number=receiver_customer.id_number).exists():
            flagged_reasons.append("Receiver is on the blacklist")

    # 4. Save SuspiciousTransaction & Alert if flagged
    if flagged_reasons:
        suspicious_txn = SuspiciousTransaction.objects.create(
            transaction=transaction,
            customer_id=sender_customer.customer_id if sender_customer else "Unknown",
            customer_name=sender_customer.full_name if sender_customer else "Unknown",
            customer_email=sender_customer.email if sender_customer else "Unknown",
            customer_phone=sender_customer.phone_number if sender_customer else "Unknown",
            id_document_type=sender_customer.id_document_type if sender_customer else "Unknown",
            id_document_number=sender_customer.id_document_number if sender_customer else "Unknown",
            account_number=transaction.account_number,
            account_type="Current",
            account_status="Active",
            sender_account=transaction.sender_account,
            receiver_account=transaction.receiver_account,
            amount=transaction.amount,
            risk_level='High',
            flagged_reason=", ".join(flagged_reasons),
            manual_review_required=True
        )
        print(f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}")

        # ✅ Also create an Alert referencing this suspicious transaction
        Alert.objects.create(
            alert_type="TXN",
            severity="HIGH",  # Always High for blacklist
            status="OPEN",
            suspicious_txn=suspicious_txn,
            title="Blacklisted Transaction",
            message=f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}"
        )

#########################################################################################################################

from aml_app.models import BlacklistEntry, SuspiciousTransaction, Transaction, Customer

def detect_whitelisted_transactions(transaction):
    """
    Function to detect transactions involving watchlisted individuals.
    It checks whether the sender or receiver is in the watchlist and flags the transaction if found.
    """
    flagged_reasons = []

    # 1. Retrieve sender and receiver customer details
    sender_customer = Customer.objects.filter(customer_id=transaction.customer_id).first()
    receiver_customer = Customer.objects.filter(customer_id=transaction.receiver_account).first()

    # 2. Watchlist check for sender
    if sender_customer and sender_customer.id_number:
        if WatchlistEntry.objects.filter(id_number=sender_customer.id_number).exists():
            flagged_reasons.append("Sender is on the Watchlist")

    # 3. Watchlist check for receiver
    if receiver_customer and receiver_customer.id_number:
        if WatchlistEntry.objects.filter(id_number=receiver_customer.id_number).exists():
            flagged_reasons.append("Receiver is on the Watchlist")

    # 4. Save SuspiciousTransaction & Alert if flagged
    if flagged_reasons:
        suspicious_txn = SuspiciousTransaction.objects.create(
            transaction=transaction,
            customer_id=sender_customer.customer_id if sender_customer else "Unknown",
            customer_name=sender_customer.full_name if sender_customer else "Unknown",
            customer_email=sender_customer.email if sender_customer else "Unknown",
            customer_phone=sender_customer.phone_number if sender_customer else "Unknown",
            id_document_type=sender_customer.id_document_type if sender_customer else "Unknown",
            id_document_number=sender_customer.id_document_number if sender_customer else "Unknown",
            account_number=transaction.account_number,
            account_type="Current",
            account_status="Active",
            sender_account=transaction.sender_account,
            receiver_account=transaction.receiver_account,
            amount=transaction.amount,
            risk_level='High',
            flagged_reason=", ".join(flagged_reasons),
            manual_review_required=True
        )
        print(f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}")

        # ✅ Create an Alert referencing this suspicious transaction
        Alert.objects.create(
            alert_type="TXN",
            severity="HIGH",  # or MEDIUM/LOW if you have logic to choose
            status="OPEN",
            suspicious_txn=suspicious_txn,
            title="Watchlist Transaction",
            message=f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}"
        )




# from django.utils.timezone import now
# from datetime import timedelta
# from django.db.models import Avg, Sum
# from aml_app.models import SuspiciousTransaction, Transaction, Customer

# def detect_suspicious_transactions(transaction):
#     """
#     Function to detect suspicious transactions based on predefined AML rules.
#     """
#     flagged_reasons = []

#     # Retrieve customer if available
#     customer = None
#     if transaction.customer_id:
#         customer = Customer.objects.filter(customer_id=transaction.customer_id).first()
    
#     # 1. Transaction Amount & Frequency Triggers
#     if transaction.amount > 10000:
#         flagged_reasons.append("Transaction amount exceeds $10,000")

#     if customer:
#         recent_transactions = Transaction.objects.filter(
#             customer_id=transaction.customer_id
#         ).exclude(id=transaction.id)

#         if recent_transactions.count() >= 5:
#             flagged_reasons.append("High transaction frequency in a short period")

#         if customer.full_name.lower() == "bank employee":
#             flagged_reasons.append("Possible bank employee involvement in suspicious transactions")
    
#     # 2. Account & Customer Behavior Triggers
#     if hasattr(transaction, 'description') and transaction.description:
#         description_lower = transaction.description.lower()
#         if "gift" in description_lower:
#             flagged_reasons.append("Transaction lacks clear economic purpose")
    
#     if customer and customer.date_of_birth:
#         age = now().year - customer.date_of_birth.year
#         if age > 90:
#             flagged_reasons.append("High-value transaction by an elderly account holder (potential fraud)")
    
#     # 3. Third-Party & Beneficiary Triggers
#     if customer and customer.full_name != transaction.receiver_account:
#         flagged_reasons.append("Funds deposited by third party with no clear relationship")
    
#     if "offshore" in transaction.receiver_bank_location.lower():
#         flagged_reasons.append("Transaction involves offshore companies in secrecy jurisdictions")
    
#     # 4. Cash & Unusual Payment Method Triggers
#     if transaction.payment_type == "Cash Deposit" and transaction.amount > 5000:
#         flagged_reasons.append("Large cash deposit without a clear source of funds")
    
#     if hasattr(transaction, 'description') and transaction.description:
#         if "crypto" in description_lower or "bitcoin" in description_lower:
#             flagged_reasons.append("Use of virtual currency or anonymous financial instruments")
    
#     # 5. High-Risk Country & Business Triggers
#     high_risk_countries = ["North Korea", "Iran", "Syria", "Sudan", "Cuba"]
#     if transaction.sender_bank_location in high_risk_countries or transaction.receiver_bank_location in high_risk_countries:
#         flagged_reasons.append("Transaction linked to a country under sanctions or with weak AML regulations")
    
#     if hasattr(transaction, 'description') and transaction.description:
#         if "casino" in description_lower:
#             flagged_reasons.append("Transaction involves a high-risk industry (casinos)")
    
#         if "charity" in description_lower and transaction.amount > 5000:
#             flagged_reasons.append("Large donation to a non-profit in a high-risk area")
    
#     # 6. Trade-Based Money Laundering Triggers
#     if hasattr(transaction, 'description') and transaction.description:
#         if "invoice" in description_lower and transaction.amount > 10000:
#             flagged_reasons.append("Possible over/under-invoicing in trade-based money laundering")
    
#         if "shipment" in description_lower and transaction.receiver_bank_location != transaction.sender_bank_location:
#             flagged_reasons.append("Frequent cross-border shipments with unclear business purposes")
    
#     # 7. Unusual Loan & Asset Purchase Triggers
#     if hasattr(transaction, 'description') and transaction.description:
#         if "loan repayment" in description_lower and transaction.amount > 20000:
#             flagged_reasons.append("Large loan repayment with no reasonable explanation")
    
#         if "real estate" in description_lower or "luxury" in description_lower:
#             flagged_reasons.append("Large purchase of real estate or luxury assets with no clear income source")
    
#     # 8. Employee & Insider Triggers
#     if customer and customer.full_name.lower() == "bank employee":
#         flagged_reasons.append("Possible bank employee involvement in suspicious transactions")
    
#     # 9. Circular Transaction (Reversed within 24h)
#     if Transaction.objects.filter(
#         sender_account=transaction.receiver_account,
#         receiver_account=transaction.sender_account,
#         amount=transaction.amount,
#         date__gte=transaction.date - timedelta(days=1)
#     ).exists():
#         flagged_reasons.append("Potential circular transaction (funds moved back to origin account)")

#     # 10. Mismatched Customer Behavior (Transaction Amount vs Profile)
#     if customer:
#         avg_amount = Transaction.objects.filter(
#             customer_id=transaction.customer_id
#         ).aggregate(avg_amount=Avg('amount'))['avg_amount']
        
#         if avg_amount and transaction.amount > avg_amount * 5:
#             flagged_reasons.append("Unusual transaction amount compared to customer history")

#     # 11. High Cash Deposits Without Withdrawals
#     if customer:
#         cash_deposits = Transaction.objects.filter(
#             customer_id=transaction.customer_id,
#             payment_type="Cash Deposit",
#             date__gte=now().date() - timedelta(days=30)
#         ).aggregate(total=Sum('amount'))['total'] or 0

#         cash_withdrawals = Transaction.objects.filter(
#             customer_id=transaction.customer_id,
#             payment_type="Cash Withdrawal",
#             date__gte=now().date() - timedelta(days=30)
#         ).aggregate(total=Sum('amount'))['total'] or 0

#         if cash_deposits > 50000 and cash_withdrawals == 0:
#             flagged_reasons.append("High cash deposits with no corresponding withdrawals")

#     # 12. Multiple Unrelated Beneficiaries
#     distinct_receivers = Transaction.objects.filter(
#         sender_account=transaction.sender_account,
#         date__gte=now().date() - timedelta(days=2)
#     ).values_list('receiver_account', flat=True).distinct().count()

#     if distinct_receivers > 5:
#         flagged_reasons.append("Sender transferring funds to multiple unrelated beneficiaries")

#     # 13. Dormant Account Reactivated with Large International Transfer
#     last_txn = Transaction.objects.filter(customer_id=transaction.customer_id).order_by('-date').exclude(id=transaction.id).first()
#     if last_txn and (transaction.date - last_txn.date).days > 365:
#         if transaction.sender_bank_location != transaction.receiver_bank_location and transaction.amount > 5000:
#             flagged_reasons.append("Dormant account reactivated with large international transfer")

#     # 14. Structuring Transactions Below Threshold
#     structuring_txns = Transaction.objects.filter(
#         customer_id=transaction.customer_id,
#         amount__gte=9500, amount__lt=10000,
#         date__gte=transaction.date - timedelta(days=3)
#     ).count()

#     if structuring_txns >= 3:
#         flagged_reasons.append("Possible structuring below AML reporting threshold")

#     # 15. Geo-location Mismatch
#     distinct_locations = Transaction.objects.filter(
#         customer_id=transaction.customer_id,
#         date__gte=now().date() - timedelta(days=2)
#     ).values_list('sender_bank_location', flat=True).distinct().count()

#     if distinct_locations > 2:
#         flagged_reasons.append("Multiple transactions from geographically distant locations in short time")

#     # Flagging suspicious transactions
#     if flagged_reasons:
#         SuspiciousTransaction.objects.create(
#             transaction=transaction,
#             customer_id=customer.customer_id if customer else "Unknown",
#             customer_name=customer.full_name if customer else "Unknown",
#             customer_email=customer.email if customer else "Unknown",
#             customer_phone=customer.phone_number if customer else "Unknown",
#             id_document_type=customer.id_document_type if customer else "Unknown",
#             id_document_number=customer.id_document_number if customer else "Unknown",
#             account_number=transaction.account_number,
#             account_type="Current",
#             account_status="Active",
#             sender_account=transaction.sender_account,
#             receiver_account=transaction.receiver_account,
#             amount=transaction.amount,
#             risk_level='High' if len(flagged_reasons) > 2 else 'Medium',
#             flagged_reason=", ".join(flagged_reasons),
#             manual_review_required=True
#         )
#         print(f"Transaction {transaction.transaction_id} flagged: {', '.join(flagged_reasons)}")






from django.utils.timezone import now
from django.core.exceptions import ObjectDoesNotExist
from .models import (
    KYCProfile, KYCTestResult, BlacklistEntry, PoliticallyExposedPerson, SanctionsList,
    WatchlistEntry, AdverseMediaCheck
)

# def perform_kyc_screening(identifier):
#     """
#     Performs KYC screening based on either id_document_number or customer_id.
#     """
#     try:
#         # ✅ 1. Try to find the customer using id_document_number first, then fallback to customer_id
#         kyc_profile = KYCProfile.objects.filter(id_document_number=identifier).first() or \
#                       KYCProfile.objects.filter(customer_id=identifier).first()

#         if not kyc_profile:
#             return f"Error: No customer found with ID '{identifier}'"

#         flagged_reasons = []
#         high_risk = False  # If any flag is high-risk, overall risk is high

#         # ✅ 2. Initialize KYC Test Result
#         test_result = KYCTestResult(
#             kyc_profile=kyc_profile,
#             # ✅ Populate basic customer details
#             full_name=kyc_profile.full_name,
#             customer_id=kyc_profile.customer_id,
#             id_document_number=kyc_profile.id_document_number,
#             risk_level="Low",
#             politically_exposed_person=False,
#             sanctions_list_check=False,
#             watchlist_check=False,
#             adverse_media_check=False,
#             suspicious_activity_flag=False,
#             financial_crime_check=False,
#             fraud_check=False,
#             enhanced_due_diligence_required=False,
#             transaction_monitoring_required=False,
#             high_risk_country=False,
#             kyc_status="Pending",
#             verification_notes="",
#             reviewer="Automated System",
#             review_date=now()
#         )

#         # ✅ 3. Check Against **Blacklist**
#         if BlacklistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).exists():
#             test_result.suspicious_activity_flag = True
#             high_risk = True
#             flagged_reasons.append("Customer is blacklisted.")

#         # ✅ 4. Check Against **Sanctions List**
#         sanctions_match = SanctionsList.objects.filter(id_document_number=kyc_profile.id_document_number).first()
#         if sanctions_match:
#             test_result.sanctions_list_check = True
#             test_result.risk_level = "High"
#             high_risk = True
#             flagged_reasons.append(f"Customer found in sanctions list ({sanctions_match.sanctions_source}).")

#         # ✅ 5. Check Against **Watchlist**
#         if WatchlistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).exists():
#             test_result.watchlist_check = True
#             test_result.risk_level = "High"
#             high_risk = True
#             flagged_reasons.append("Customer is on a watchlist.")

#         # ✅ 6. Check Against **Adverse Media**
#         adverse_media = AdverseMediaCheck.objects.filter(id_document_number=kyc_profile.id_document_number).first()
#         if adverse_media:
#             test_result.adverse_media_check = True
#             test_result.risk_level = "Medium"
#             flagged_reasons.append(f"Customer has adverse media: {adverse_media.headline}.")

#         # # ✅ 7. Check If Customer is a **Politically Exposed Person (PEP)**
#         pep_match = PoliticallyExposedPerson.objects.filter(id_document_number=kyc_profile.id_document_number).first()
#         if pep_match:
#             test_result.politically_exposed_person = True
#             test_result.risk_level = "High"
#             test_result.enhanced_due_diligence_required = True
#             high_risk = True
#             flagged_reasons.append(f"Customer is a PEP: {pep_match.position}.")

#         # ✅ 8. Flag if Customer is from **High-Risk Countries**
#         high_risk_countries = ["North Korea", "Iran", "Syria", "Venezuela"]
#         if kyc_profile.country in high_risk_countries:
#             test_result.high_risk_country = True
#             test_result.risk_level = "High"
#             high_risk = True
#             flagged_reasons.append(f"Customer from high-risk country: {kyc_profile.country}.")

#         # ✅ 9. Fraud & Financial Crime Checks (Using Past KYC Test Results)
#         past_kyc_results = KYCTestResult.objects.filter(kyc_profile=kyc_profile)
#         if past_kyc_results.filter(fraud_check=True).exists():
#             test_result.fraud_check = True
#             test_result.risk_level = "High"
#             high_risk = True
#             flagged_reasons.append("Previous fraud detected.")

#         if past_kyc_results.filter(financial_crime_check=True).exists():
#             test_result.financial_crime_check = True
#             test_result.risk_level = "High"
#             high_risk = True
#             flagged_reasons.append("Linked to financial crime cases.")

#         # ✅ 10. Set Final Risk Level
#         if high_risk:
#             test_result.risk_level = "High"
#             test_result.kyc_status = "Rejected"
#         elif test_result.risk_level == "Medium":
#             test_result.kyc_status = "Pending"
#         else:
#             test_result.risk_level = "Low"
#             test_result.kyc_status = "Verified"

#         # ✅ 11. Save Final KYC Test Result
#         test_result.verification_notes = "; ".join(flagged_reasons)
#         test_result.save()

#         return test_result

#     except ObjectDoesNotExist:
#         return "Error: KYC profile not found."


from django.core.exceptions import ObjectDoesNotExist
from django.utils.timezone import now


def perform_kyc_screening(identifier):
    """
    Performs KYC screening based on either id_document_number or customer_id.
    """
    try:
        # ✅ 1. Try to find the customer using id_document_number first, then fallback to customer_id
        kyc_profile = KYCProfile.objects.filter(id_document_number=identifier).first() or \
                      KYCProfile.objects.filter(customer_id=identifier).first()

        if not kyc_profile:
            return f"Error: No customer found with ID '{identifier}'"

        # ✅ Remove any existing KYCTestResult to prevent duplicates
        KYCTestResult.objects.filter(kyc_profile__id_document_number=kyc_profile.id_document_number).delete()

        flagged_reasons = []
        high_risk = False  # If any flag is high-risk, overall risk is high

        # ✅ 2. Initialize KYC Test Result
        test_result = KYCTestResult(
            kyc_profile=kyc_profile,
            # ✅ Populate basic customer details
            full_name=kyc_profile.full_name,
            customer_id=kyc_profile.customer_id,
            id_document_number=kyc_profile.id_document_number,
            risk_level="Low",
            politically_exposed_person=False,
            sanctions_list_check=False,
            watchlist_check=False,
            adverse_media_check=False,
            suspicious_activity_flag=False,
            financial_crime_check=False,
            fraud_check=False,
            enhanced_due_diligence_required=False,
            transaction_monitoring_required=False,
            high_risk_country=False,
            kyc_status="Pending",
            verification_notes="",
            reviewer="Automated System",
            review_date=now()
        )

        # ✅ 3. Check Against **Blacklist**
        if BlacklistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).exists():
            test_result.suspicious_activity_flag = True
            high_risk = True
            flagged_reasons.append("Customer is blacklisted.")

        # ✅ 4. Check Against **Sanctions List**
        sanctions_match = SanctionsList.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if sanctions_match:
            test_result.sanctions_list_check = True
            test_result.risk_level = "High"
            high_risk = True
            flagged_reasons.append(f"Customer found in sanctions list ({sanctions_match.sanctions_source}).")

        # ✅ 5. Check Against **Watchlist**
        if WatchlistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).exists():
            test_result.watchlist_check = True
            test_result.risk_level = "High"
            high_risk = True
            flagged_reasons.append("Customer is on a watchlist.")

        # ✅ 6. Check Against **Adverse Media**
        adverse_media = AdverseMediaCheck.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if adverse_media:
            test_result.adverse_media_check = True
            test_result.risk_level = "Medium"
            flagged_reasons.append(f"Customer has adverse media: {adverse_media.headline}.")

        # ✅ 7. Check If Customer is a **Politically Exposed Person (PEP)**
        pep_match = PoliticallyExposedPerson.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if pep_match:
            test_result.politically_exposed_person = True
            test_result.risk_level = "High"
            test_result.enhanced_due_diligence_required = True
            high_risk = True
            flagged_reasons.append(f"Customer is a PEP: {pep_match.position}.")

        # ✅ 8. Flag if Customer is from **High-Risk Countries**
        high_risk_countries = ["North Korea", "Iran", "Syria", "Venezuela"]
        if kyc_profile.country in high_risk_countries:
            test_result.high_risk_country = True
            test_result.risk_level = "High"
            high_risk = True
            flagged_reasons.append(f"Customer from high-risk country: {kyc_profile.country}.")

        # ✅ 9. Fraud & Financial Crime Checks (Using Past KYC Test Results)
        past_kyc_results = KYCTestResult.objects.filter(kyc_profile=kyc_profile)
        if past_kyc_results.filter(fraud_check=True).exists():
            test_result.fraud_check = True
            test_result.risk_level = "High"
            high_risk = True
            flagged_reasons.append("Previous fraud detected.")

        if past_kyc_results.filter(financial_crime_check=True).exists():
            test_result.financial_crime_check = True
            test_result.risk_level = "High"
            high_risk = True
            flagged_reasons.append("Linked to financial crime cases.")

        # ✅ 10. Set Final Risk Level
        if high_risk:
            test_result.risk_level = "High"
            test_result.kyc_status = "Rejected"
        elif test_result.risk_level == "Medium":
            test_result.kyc_status = "Pending"
        else:
            test_result.risk_level = "Low"
            test_result.kyc_status = "Verified"

        # ✅ 11. Save Final KYC Test Result
        test_result.verification_notes = "; ".join(flagged_reasons)
        test_result.save()


        # ✅ Create an alert if high risk
        if high_risk:
            Alert.objects.create(
                alert_type="KYC",
                severity="HIGH",
                status="OPEN",
                kyc_test=test_result,
                title="High-Risk KYC Profile",
                message="KYC Profile flagged as high risk. Please review."
            )


        return test_result

    except ObjectDoesNotExist:
        return "Error: KYC profile not found."

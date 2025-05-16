from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
from django.db.models import Sum, Q
from django.utils import timezone
from .base_rule import BaseRule
from transaction_monitoring.model.account import Account
from transaction_monitoring.model.transaction import Transactions
from transaction_monitoring.model.alert import Alert
from transaction_monitoring.model.rule_settings import AMLRules, DormantAccountRule as DormantAccountRuleModel

class DormantAccountRule(BaseRule):
    """
    Rule to detect significant activity in previously inactive accounts.
    
    This rule monitors dormant accounts and generates alerts when significant
    activity is detected for such accounts.
    
    An account is considered "dormant" if it was inactive for a considerable amount of time,
    based on a definition of dormant accounts determined by the institution.
    
    Rule ID: AML-ADR-ALL-ALL-A-M06-AIN
    """
    
    RULE_CODE = 'AML-ADR-ALL-ALL-A-M06-AIN'
    
    def __init__(self, config=None):
        """
        Initialize the rule with configuration from the database.
        """
        print("Initializing DormantAccountRule")
        
        # Default configuration as fallback
        default_config = {
            'rule_id': self.RULE_CODE,
            'rule_name': 'Activity Seen in A Dormant Account',
            'description': 'Detects significant activity in previously inactive accounts.',
            'alert_level': 'Account',
            'evaluation_trigger': 'Daily Activity',
            'scoring_algorithm': 'MAX',
            'transaction_types': ['ALL-ALL'],
            'thresholds': {
                'account_age_days': 180,                # MIN AGE (Days)
                'activity_amount': 10000,               # MIN VALUE for recent activity
                'inactive_period_months': 6,            # Previous Y months
                'max_prior_activity': 100,              # MAX VALUE for prior period
                'recent_activity_period_months': 1      # Last X months
            },
            'recurrence': {
                'lookback_period_months': 1,
                'min_occurrences': 1
            },
            'enabled': True,
            'version': '1.0'
        }
        
        # First, try to load rule configuration from database
        db_config = None
        try:
            rule_model = AMLRules.objects.get(rule_code=self.RULE_CODE)
            db_config = self._load_config_from_db(rule_model)
            if db_config:
                print(f"Loaded configuration from database for rule {self.RULE_CODE}")
        except (AMLRules.DoesNotExist, Exception) as e:
            # If database configuration not available, use default
            print(f"Could not load rule configuration from database: {e}")
            print("Using default configuration")
        
        # Merge default config with provided config and DB config
        final_config = default_config.copy()
        
        # Update with database config if available
        if db_config:
            for key, value in db_config.items():
                if isinstance(value, dict) and key in final_config and isinstance(final_config[key], dict):
                    final_config[key].update(value)
                else:
                    final_config[key] = value
        
        # Update with provided config if available
        if config:
            for key, value in config.items():
                if isinstance(value, dict) and key in final_config and isinstance(final_config[key], dict):
                    final_config[key].update(value)
                else:
                    final_config[key] = value
        
        print(f"Final configuration: rule_id={final_config['rule_id']}, thresholds={final_config['thresholds']}")
        
        # Initialize the base class with the merged configuration
        # This will set self.config to the merged configuration
        super().__init__(final_config)
    
    def _load_config_from_db(self, rule_model: AMLRules) -> Dict:
        """
        Load configuration from database rule models.
        
        Args:
            rule_model: The AMLRules model instance
            
        Returns:
            Configuration dictionary
        """
        config = {
            'rule_id': rule_model.rule_code,
            'rule_name': rule_model.rule_name,
            'description': rule_model.description,
            'alert_level': rule_model.alert_level,
            'evaluation_trigger': rule_model.evaluation_trigger,
            'scoring_algorithm': rule_model.scoring_algorithm,
            'enabled': rule_model.enabled,
            'thresholds': {},
        }
        
        # Parse transaction types
        if rule_model.transaction_types:
            config['transaction_types'] = rule_model.transaction_types.split(',')
        
        # Load specific dormant account rule configurations
        try:
            dormant_config = DormantAccountRuleModel.objects.get(rule=rule_model)
            config['thresholds'] = {
                'account_age_days': dormant_config.account_age_days,
                'activity_amount': float(dormant_config.activity_amount_threshold),
                'inactive_period_months': dormant_config.inactive_period_months,
                'max_prior_activity': float(dormant_config.max_prior_activity),
                'recent_activity_period_months': 1  # Default
            }
        except Exception as e:
            print(f"Error loading dormant account config: {e}")
        
        return config
    
    def evaluate(self, transaction: Any, context: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate if the transaction represents activity in a dormant account.
        
        Args:
            transaction: The transaction to evaluate
            context: Dictionary containing account history and other required context
            
        Returns:
            Tuple of (triggered: bool, details: Dict)
        """
        print("\n==== STARTING DORMANT ACCOUNT RULE EVALUATION ====")
        print(f"Context options: {context}")
        print(f"Rule ID: {self.rule_id}")
        print(f"Thresholds: {self.thresholds}")
        
        # Extract account information from transaction
        account = None
        account_number = None
        
        # Debug info
        debug_info = {
            'transaction_id': getattr(transaction, 'transaction_id', 'Unknown'),
            'source_account_number': getattr(transaction, 'source_account_number', None),
            'destination_account_number': getattr(transaction, 'destination_account_number', None),
            'transaction_date': getattr(transaction, 'transaction_date', None),
            'amount': getattr(transaction, 'amount', 0),
        }
        
        print(f"Transaction ID: {debug_info['transaction_id']}")
        print(f"Transaction amount: {debug_info['amount']}")
        print(f"Source account: {debug_info['source_account_number']}")
        print(f"Destination account: {debug_info['destination_account_number']}")
        
        # If transaction has source_account object, use it directly
        if hasattr(transaction, 'source_account') and transaction.source_account:
            account = transaction.source_account
            account_number = transaction.source_account_number
            print(f"Using direct source_account relation: {account_number}")
        # Or if destination_account object exists, use that
        elif hasattr(transaction, 'destination_account') and transaction.destination_account:
            account = transaction.destination_account
            account_number = transaction.destination_account_number
            print(f"Using direct destination_account relation: {account_number}")
        # If no direct relationship, try to find account by number
        else:
            print("No direct account relationship found, trying lookup by account number")
            # Try the source account number first
            if hasattr(transaction, 'source_account_number') and transaction.source_account_number:
                account_number = transaction.source_account_number
                try:
                    account = Account.objects.get(account_number=account_number)
                    print(f"Found account by source_account_number: {account_number}")
                except Account.DoesNotExist:
                    debug_info['account_lookup_error'] = f"Source account {account_number} not found"
                    print(f"ERROR: Source account {account_number} not found in database")
            
            # If no account found by source, try destination
            if not account and hasattr(transaction, 'destination_account_number') and transaction.destination_account_number:
                account_number = transaction.destination_account_number
                try:
                    account = Account.objects.get(account_number=account_number)
                    print(f"Found account by destination_account_number: {account_number}")
                except Account.DoesNotExist:
                    debug_info['account_lookup_error'] = f"Destination account {account_number} not found"
                    print(f"ERROR: Destination account {account_number} not found in database")
        
        # Still no account found
        if not account:
            print("ERROR: No valid account found for this transaction")
            return False, {
                'reason': f'No valid account found for numbers: source={getattr(transaction, "source_account_number", "None")}, destination={getattr(transaction, "destination_account_number", "None")}',
                'debug_info': debug_info
            }
        
        # Add account info to debug
        debug_info['account'] = {
            'account_number': account_number,
            'status': getattr(account, 'status', 'Unknown'),
            'is_dormant_flag': getattr(account, 'is_dormant', False),
            'last_transaction_date': getattr(account, 'last_transaction_date', None),
            'last_activity_date': getattr(account, 'last_activity_date', None),
            'opening_date': getattr(account, 'opening_date', None),
            'dormancy_start_date': getattr(account, 'dormancy_start_date', None),
        }
        
        print("\n==== ACCOUNT DETAILS ====")
        print(f"Account number: {account_number}")
        print(f"Account status: {debug_info['account']['status']}")
        print(f"Is dormant flag: {debug_info['account']['is_dormant_flag']}")
        print(f"Last transaction date: {debug_info['account']['last_transaction_date']}")
        print(f"Last activity date: {debug_info['account']['last_activity_date']}")
        print(f"Opening date: {debug_info['account']['opening_date']}")
        print(f"Dormancy start date: {debug_info['account']['dormancy_start_date']}")
        
        # Check if this account already has an open alert for this rule
        existing_alerts = Alert.objects.filter(
            rule_code=self.rule_id,
            primary_account_number=account_number,
            status__in=['NEW', 'ASSIGNED', 'INVESTIGATING']
        ).count()
        
        print(f"Existing open alerts for this account/rule: {existing_alerts}")
        
        if existing_alerts > 0:
            print("Skipping rule evaluation because account already has an open alert")
            return False, {'reason': 'Account already has an open alert for this rule', 'debug_info': debug_info}
        
        # Check if account is actually dormant
        # First check the account status field
        is_dormant = False
        
        print("\n==== CHECKING DORMANCY STATUS ====")
        
        # Force dormancy to true for testing if requested
        if context.get('force_dormant', False):
            is_dormant = True
            debug_info['dormant_reason'] = 'Forced for testing via UI'
            print(f"Account {account_number} dormancy forced to TRUE for testing")
        # Otherwise use regular dormancy checks
        elif account.status == 'DORMANT':
            is_dormant = True
            debug_info['dormant_reason'] = 'status=DORMANT'
            print(f"Account {account_number} is dormant based on status field: {account.status}")
        elif account.is_dormant:  # Then check the is_dormant flag directly
            is_dormant = True
            debug_info['dormant_reason'] = 'is_dormant=True'
            print(f"Account {account_number} is dormant based on is_dormant flag: {account.is_dormant}")
        # If not explicitly marked dormant, check last activity date
        elif hasattr(account, 'last_activity_date') and account.last_activity_date:
            inactive_period_months = self.thresholds.get('inactive_period_months', 6)
            
            # Use transaction_date to determine dormancy if available, otherwise use current date
            reference_date = None
            if hasattr(transaction, 'transaction_date') and transaction.transaction_date:
                if isinstance(transaction.transaction_date, datetime):
                    reference_date = transaction.transaction_date.date()
                else:
                    reference_date = transaction.transaction_date
            
            if not reference_date:
                # Fall back to current date if transaction date not available
                reference_date = timezone.now().date()
                
            # Calculate days since last activity
            days_since_last_activity = (reference_date - account.last_activity_date).days
            debug_info['days_since_last_activity'] = days_since_last_activity
            
            dormancy_threshold_date = reference_date - timedelta(days=30 * inactive_period_months)
            
            print(f"Reference date for dormancy check: {reference_date}")
            print(f"Checking last activity date: {account.last_activity_date}")
            print(f"Days since last activity: {days_since_last_activity}")
            print(f"Dormancy threshold date: {dormancy_threshold_date}")
            print(f"Inactive period months: {inactive_period_months}")
            
            if account.last_activity_date <= dormancy_threshold_date:
                # Account has been inactive long enough to be considered dormant
                is_dormant = True
                debug_info['dormant_reason'] = f'last_activity_date ({account.last_activity_date}) older than threshold ({dormancy_threshold_date})'
                print(f"Account {account_number} is dormant based on last activity date being older than threshold")
            else:
                print(f"Account {account_number} is NOT dormant - last activity date too recent")
        else:
            print(f"Account {account_number} is NOT dormant and has no last_activity_date")

        print(f"Final dormancy check result: is_dormant={is_dormant}")
        print(f"Dormancy reason: {debug_info.get('dormant_reason', 'Not dormant')}")

        # If the account is not dormant according to any criteria, no need to proceed
        if not is_dormant:
            print("Stopping rule evaluation because account is NOT dormant")
            return False, {
                'reason': f'Account {account_number} is not dormant (status: {account.status})',
                'debug_info': debug_info
            }
        
        print("\n==== CHECKING ACCOUNT AGE ====")
        # Check account age requirement
        account_open_date = None
        if hasattr(account, 'open_date'):
            account_open_date = account.open_date
            print(f"Using open_date: {account_open_date}")
        elif hasattr(account, 'opening_date'):
            account_open_date = account.opening_date
            print(f"Using opening_date: {account_open_date}")
        else:
            print("ERROR: No open date or opening date available")
        
        if not account_open_date:
            print("Stopping rule evaluation because account open date not available")
            return False, {'reason': 'Account open date not available', 'debug_info': debug_info}
        
        # Get reference date (transaction date or current date)
        reference_date = None
        if hasattr(transaction, 'transaction_date') and transaction.transaction_date:
            if isinstance(transaction.transaction_date, datetime):
                reference_date = transaction.transaction_date.date()
            else:
                reference_date = transaction.transaction_date
        
        if not reference_date:
            reference_date = timezone.now().date()
            
        account_age_days = (reference_date - account_open_date).days
        min_age_days = self.thresholds.get('account_age_days', 180)
        
        print(f"Reference date for age check: {reference_date}")
        print(f"Account age: {account_age_days} days, minimum required: {min_age_days} days")
        
        if account_age_days < min_age_days and not context.get('test_mode', False):
            print(f"Stopping rule evaluation because account age ({account_age_days} days) less than minimum ({min_age_days} days)")
            return False, {
                'reason': f'Account age ({account_age_days} days) less than minimum ({min_age_days} days)',
                'debug_info': debug_info
            }
        else:
            if account_age_days < min_age_days:
                print(f"Account age ({account_age_days} days) less than minimum ({min_age_days} days) but continuing due to test mode")
        
        print("\n==== CHECKING TRANSACTION TYPE ====")
        # Check transaction type
        transaction_types = self.transaction_types
        
        if hasattr(transaction, 'transaction_type_code'):
            print(f"Transaction type: {transaction.transaction_type_code}")
        else:
            print("Transaction has no transaction_type_code")
        
        print(f"Allowed transaction types: {transaction_types}")
        
        # If transaction types specified and transaction doesn't match, skip
        if ('ALL-ALL' not in transaction_types and 
            hasattr(transaction, 'transaction_type_code') and 
            transaction.transaction_type_code not in transaction_types and 
            not context.get('test_mode', False)):
            print(f"Stopping rule evaluation because transaction type {transaction.transaction_type_code} not in monitored types {transaction_types}")
            return False, {
                'reason': f"Transaction type {transaction.transaction_type_code} not in monitored types {transaction_types}",
                'debug_info': debug_info
            }
        
        print("\n==== CALCULATING ACTIVITY PERIODS ====")
        # Get transaction date first for proper period calculations
        transaction_date = None
        if hasattr(transaction, 'transaction_timestamp') and transaction.transaction_timestamp:
            # Make sure the timestamp is properly parsed as a datetime
            try:
                if isinstance(transaction.transaction_timestamp, str):
                    # Parse ISO format string or other format if needed
                    print(f"Parsing timestamp from string: {transaction.transaction_timestamp}")
                    transaction_date = datetime.fromisoformat(transaction.transaction_timestamp.replace('Z', '+00:00'))
                else:
                    transaction_date = transaction.transaction_timestamp
            except Exception as e:
                print(f"Error parsing timestamp: {e}, using transaction_date instead")
                transaction_date = None

        if transaction_date is None and hasattr(transaction, 'transaction_date') and transaction.transaction_date:
            # Try to convert to datetime if it's a date
            if isinstance(transaction.transaction_date, datetime):
                transaction_date = transaction.transaction_date
                print(f"Using transaction_date as datetime: {transaction_date}")
            else:
                try:
                    # Assume it's a date and convert to datetime at midnight
                    transaction_date = timezone.make_aware(
                        datetime.combine(transaction.transaction_date, datetime.min.time())
                    )
                    print(f"Converted transaction_date to datetime: {transaction_date}")
                except Exception as e:
                    print(f"Error converting transaction_date: {e}, using current time")
                    # Last resort - use now
                    transaction_date = timezone.now()
        else:
            # No date info available, use current time
            if transaction_date is None:
                transaction_date = timezone.now()
                print(f"No transaction date available, using current time: {transaction_date}")
            else:
                print(f"Using transaction_timestamp: {transaction_date}")

        # Calculate recent activity period using transaction date as reference
        recent_months = self.thresholds.get('recent_activity_period_months', 1)
        recent_period_end = transaction_date  # Use transaction date as period end
        recent_period_start = recent_period_end - timedelta(days=30 * recent_months)
        
        # Calculate prior inactive period (previous Y months)
        inactive_period_months = self.thresholds.get('inactive_period_months', 6)
        prior_period_end = recent_period_start
        prior_period_start = prior_period_end - timedelta(days=30 * inactive_period_months)
        
        print(f"Transaction date being used: {transaction_date}")
        print(f"Recent period: {recent_period_start.date()} to {recent_period_end.date()}")
        print(f"Prior period: {prior_period_start.date()} to {prior_period_end.date()}")

        debug_info['transaction_date_used'] = transaction_date
        debug_info['recent_period_start'] = recent_period_start
        debug_info['recent_period_end'] = recent_period_end
        
        if transaction_date < recent_period_start and not context.get('test_mode', False):
            print(f"Stopping rule evaluation because transaction ({transaction_date}) is outside the recent activity period")
            return False, {
                'reason': 'Transaction is outside the recent activity period',
                'debug_info': debug_info
            }
        elif transaction_date < recent_period_start:
            print(f"Transaction ({transaction_date}) is outside the recent activity period but continuing due to test mode")
        
        print("\n==== CALCULATING ACCOUNT ACTIVITY ====")
        # Get transaction data for the account
        recent_activity = self._get_account_activity(account_number, recent_period_start, recent_period_end, transaction_types)
        print(f"Recent activity from database: {recent_activity}")

        # Add current transaction amount to recent activity if it's not already counted
        # (it might not be in the database yet if we're evaluating it in real-time)
        current_amount = 0
        if hasattr(transaction, 'amount'):
            try:
                current_amount = float(transaction.amount)
                # Check if this transaction's timestamp falls within our recent period
                if transaction_date >= recent_period_start and transaction_date <= recent_period_end:
                    print(f"Adding current transaction amount {current_amount} to recent activity")
                    recent_activity += current_amount
                else:
                    print(f"Not adding current transaction amount as it's outside the recent period")
            except (ValueError, TypeError) as e:
                print(f"Error adding current transaction amount: {e}")

        prior_activity = self._get_account_activity(account_number, prior_period_start, prior_period_end, transaction_types)
        print(f"Prior activity: {prior_activity}")
        
        debug_info['recent_activity'] = recent_activity
        debug_info['current_transaction_amount'] = current_amount
        debug_info['prior_activity'] = prior_activity
        
        print("\n==== CHECKING ACTIVITY THRESHOLDS ====")
        # Check against thresholds
        min_value = self.thresholds.get('activity_amount', 10000)
        max_prior_value = self.thresholds.get('max_prior_activity', 100)

        # For testing, we may want to modify these thresholds
        is_test_mode = context.get('test_mode', False)
        debug_info['test_mode'] = is_test_mode

        print(f"Checking thresholds: recent_activity={recent_activity}, min_value={min_value}")
        print(f"Prior activity={prior_activity}, max_prior_value={max_prior_value}")
        print(f"Test mode enabled: {is_test_mode}")

        if recent_activity < min_value and not is_test_mode:
            print(f"Stopping rule evaluation because recent activity ({recent_activity}) less than minimum value ({min_value})")
            return False, {
                'reason': f'Recent activity ({recent_activity}) less than minimum value ({min_value})',
                'debug_info': debug_info
            }
        elif recent_activity < min_value:
            print(f"Recent activity ({recent_activity}) less than minimum value ({min_value}) but continuing due to test mode")

        if prior_activity > max_prior_value and not is_test_mode:
            print(f"Stopping rule evaluation because prior activity ({prior_activity}) greater than maximum allowed ({max_prior_value})")
            return False, {
                'reason': f'Prior activity ({prior_activity}) greater than maximum allowed ({max_prior_value})',
                'debug_info': debug_info
            }
        elif prior_activity > max_prior_value:
            print(f"Prior activity ({prior_activity}) greater than maximum allowed ({max_prior_value}) but continuing due to test mode")
        
        print("\n==== RULE TRIGGERED - GENERATING ALERT ====")
        # Account was dormant and now has significant activity
        score = self._calculate_score(recent_activity, prior_activity, min_value, max_prior_value)
        
        details = {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'account_number': account_number,
            'account_status': account.status,
            'account_age_days': account_age_days,
            'is_dormant_flagged': is_dormant,
            'dormancy_start_date': account.dormancy_start_date if hasattr(account, 'dormancy_start_date') else None,
            'last_activity_date': account.last_activity_date,
            'days_since_last_activity': debug_info.get('days_since_last_activity'),
            'recent_activity': recent_activity,
            'recent_period': f"{recent_period_start.date()} to {recent_period_end.date()}",
            'prior_activity': prior_activity,
            'prior_period': f"{prior_period_start.date()} to {prior_period_end.date()}",
            'min_value': min_value,
            'max_prior_value': max_prior_value,
            'inactive_period_months': inactive_period_months,
            'transaction_id': transaction.transaction_id,
            'amount': float(transaction.amount),
            'currency': transaction.currency_code,
            'transaction_date': transaction.transaction_date,
            'transaction_type': transaction.transaction_type_code,
            'score': score,
            'debug_info': debug_info  # Add the debug info to the alert details for traceability
        }
        
        print(f"Alert score: {score}")
        print("==== DORMANT ACCOUNT RULE EVALUATION COMPLETE - ALERT GENERATED ====\n")
        
        return True, details
    
    def _get_account_activity(self, account_number: str, start_date: datetime, 
                             end_date: datetime, transaction_types=None) -> float:
        """
        Calculate the total activity amount in an account during a period using database queries.
        
        Args:
            account_number: The account number to query
            start_date: Start date for the period
            end_date: End date for the period
            transaction_types: List of transaction type codes to filter by
            
        Returns:
            Total activity amount (sum of absolute transaction amounts)
        """
        print(f"\n----- Getting account activity for {account_number} -----")
        print(f"Period: {start_date.date()} to {end_date.date()}")
        print(f"Transaction types: {transaction_types}")
        
        # Use default transaction types if none provided
        if transaction_types is None:
            transaction_types = self.transaction_types
            print(f"Using default transaction types from rule: {transaction_types}")
        
        # Start with base queries - check both source and destination
        source_query = Transactions.objects.filter(
            source_account_number=account_number,
            transaction_timestamp__gte=start_date,
            transaction_timestamp__lte=end_date
        )
        
        dest_query = Transactions.objects.filter(
            destination_account_number=account_number,
            transaction_timestamp__gte=start_date,
            transaction_timestamp__lte=end_date
        )
        
        # Print SQL queries for debug purposes
        print(f"Source query: {source_query.query}")
        print(f"Destination query: {dest_query.query}")
        
        # Apply transaction type filtering if specified and not ALL-ALL
        if transaction_types and 'ALL-ALL' not in transaction_types:
            source_query = source_query.filter(transaction_type_code__in=transaction_types)
            dest_query = dest_query.filter(transaction_type_code__in=transaction_types)
            print(f"Applied transaction type filtering: {transaction_types}")
        
        # Calculate sums
        source_total = source_query.aggregate(total=Sum('amount'))['total'] or 0
        dest_total = dest_query.aggregate(total=Sum('amount'))['total'] or 0
        
        print(f"Source transactions total: {source_total}")
        print(f"Destination transactions total: {dest_total}")
        
        # Count transactions
        source_count = source_query.count()
        dest_count = dest_query.count()
        print(f"Source transaction count: {source_count}")
        print(f"Destination transaction count: {dest_count}")
        
        # List transactions for debugging
        if source_count > 0:
            print("Source transactions:")
            for i, tx in enumerate(source_query[:5]):  # Show up to 5 transactions
                print(f"  {i+1}. {tx.transaction_id}: {tx.amount} {tx.currency_code} on {tx.transaction_date}")
            if source_count > 5:
                print(f"  ... and {source_count - 5} more")
        
        if dest_count > 0:
            print("Destination transactions:")
            for i, tx in enumerate(dest_query[:5]):  # Show up to 5 transactions
                print(f"  {i+1}. {tx.transaction_id}: {tx.amount} {tx.currency_code} on {tx.transaction_date}")
            if dest_count > 5:
                print(f"  ... and {dest_count - 5} more")
            
        # Return total activity (absolute values)
        total_activity = float(abs(source_total) + abs(dest_total))
        print(f"Total activity: {total_activity}")
        return total_activity
    
    def _calculate_score(self, recent_activity: float, prior_activity: float, 
                         min_threshold: float, max_prior_threshold: float) -> int:
        """
        Calculate a risk score for the alert based on activity patterns.
        
        Args:
            recent_activity: Total activity in recent period
            prior_activity: Total activity in prior period
            min_threshold: Minimum threshold for recent activity
            max_prior_threshold: Maximum threshold for prior activity
            
        Returns:
            Risk score from 0-100
        """
        print("\n----- Calculating risk score -----")
        print(f"Recent activity: {recent_activity}, Min threshold: {min_threshold}")
        print(f"Prior activity: {prior_activity}, Max prior threshold: {max_prior_threshold}")
        
        # Get scoring algorithm from rule configuration
        scoring_algorithm = self.scoring_algorithm
        print(f"Using scoring algorithm: {scoring_algorithm}")
        
        # Base score starts at 50
        score = 50
        print("Starting with base score: 50")
        
        # Add points based on how much the recent activity exceeds the threshold
        if recent_activity > min_threshold:
            ratio = recent_activity / min_threshold
            print(f"Recent activity ratio: {ratio:.2f} times the minimum threshold")
            
            if ratio > 10:
                score += 30
                print("Adding 30 points for very high recent activity (>10x threshold)")
            elif ratio > 5:
                score += 20
                print("Adding 20 points for high recent activity (>5x threshold)")
            elif ratio > 2:
                score += 10
                print("Adding 10 points for moderate recent activity (>2x threshold)")
        else:
            print("Recent activity does not exceed minimum threshold")
        
        # Add points based on dormancy (how much below the max prior threshold)
        if max_prior_threshold > 0:
            dormancy_ratio = prior_activity / max_prior_threshold
            print(f"Dormancy ratio: {dormancy_ratio:.2f} (prior activity / max threshold)")
            
            if dormancy_ratio < 0.1:
                score += 20  # Very dormant
                print("Adding 20 points for very dormant account (<10% of max prior)")
            elif dormancy_ratio < 0.5:
                score += 10  # Moderately dormant
                print("Adding 10 points for moderately dormant account (<50% of max prior)")
        
        # Cap score at 100
        final_score = min(score, 100)
        print(f"Final score (capped at 100): {final_score}")
        return final_score

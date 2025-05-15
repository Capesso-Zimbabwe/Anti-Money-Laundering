from typing import Dict, List, Any, Set

class TransactionTypeRegistry:
    """
    Registry for transaction type codes and groups.
    
    This class manages the mapping of transaction type codes to their
    respective groups.
    """
    
    def __init__(self):
        """Initialize the transaction type registry."""
        # Default transaction type groups
        self.transaction_groups = {
            'ALL-ALL': {
                'description': 'All Transactions & Transfers',
                'included_codes': ['*'],  # All codes
                'excluded_codes': []
            },
            'CCE-INN': {
                'description': 'Cash/Cash-Equivalent Deposits',
                'included_codes': [
                    'DEPOSIT', 'CASH DEP', 'CHEQUE DEP', 'DIRECT CR',
                    'CSH+', 'CSH_CP+', 'CSH_CP_HR+'
                ],
                'excluded_codes': []
            },
            'CCE-OUT': {
                'description': 'Cash/Cash-Equivalent Withdrawals',
                'included_codes': [
                    'WITHDRAWAL','WITHDRAW', 'CASH WDL', 'ATM WDL'
                ],
                'excluded_codes': []
            },
            'TRF-ALL': {
                'description': 'All Transfers',
                'included_codes': [
                    'TRANSFER', 'WIRE', 'SWIFT', 'ACH'
                ],
                'excluded_codes': []
            },
            'PMT-ALL': {
                'description': 'All Payments',
                'included_codes': [
                    'BILL PMT','PAYMENT', 'PMT', 'DIRECT DEBIT'
                ],
                'excluded_codes': []
            }
        }
    
    def get_transaction_codes(self, group_name: str) -> List[str]:
        """
        Get the transaction codes for a group.
        
        Args:
            group_name: The name of the transaction type group
            
        Returns:
            List of transaction codes in the group
        """
        if group_name not in self.transaction_groups:
            return []
            
        group = self.transaction_groups[group_name]
        
        # If wildcard is included, return all known transaction codes
        if '*' in group['included_codes']:
            all_codes = set()
            for g in self.transaction_groups.values():
                all_codes.update(g['included_codes'])
            all_codes.discard('*')
            return list(all_codes - set(group['excluded_codes']))
        
        # Otherwise return included codes minus excluded codes
        return list(set(group['included_codes']) - set(group['excluded_codes']))
    
    def is_code_in_group(self, code: str, group_name: str) -> bool:
        """
        Check if a transaction code is in a group.
        
        Args:
            code: The transaction code
            group_name: The group name
            
        Returns:
            True if the code is in the group
        """
        if group_name not in self.transaction_groups:
            return False
            
        group = self.transaction_groups[group_name]
        
        # Check excluded codes first
        if code in group['excluded_codes']:
            return False
            
        # Check for wildcard
        if '*' in group['included_codes']:
            return True
            
        # Check included codes
        return code in group['included_codes']
    
    def register_group(self, group_name: str, description: str, included_codes: List[str], excluded_codes: List[str] = None) -> None:
        """
        Register a new transaction type group.
        
        Args:
            group_name: The name of the group
            description: Description of the group
            included_codes: List of transaction codes to include
            excluded_codes: List of transaction codes to exclude
        """
        self.transaction_groups[group_name] = {
            'description': description,
            'included_codes': included_codes,
            'excluded_codes': excluded_codes or []
        }
    
    def unregister_group(self, group_name: str) -> bool:
        """
        Unregister a transaction type group.
        
        Args:
            group_name: The name of the group
            
        Returns:
            True if the group was unregistered, False if it didn't exist
        """
        if group_name in self.transaction_groups:
            del self.transaction_groups[group_name]
            return True
        return False

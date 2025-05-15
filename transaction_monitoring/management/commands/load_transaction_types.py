from django.core.management.base import BaseCommand
from django.db import transaction
from transaction_monitoring.model.rule_settings import TransactionTypeGroup, TransactionType
from transaction_monitoring.monitoring.config.transaction_types import TransactionTypeRegistry

class Command(BaseCommand):
    help = 'Load transaction types from registry into the database'

    def handle(self, *args, **options):
        registry = TransactionTypeRegistry()
        
        self.stdout.write(self.style.NOTICE("Starting transaction type data load..."))
        
        # Use transaction atomic to ensure all-or-nothing operation
        with transaction.atomic():
            # Load transaction type groups
            groups_created = 0
            for group_code, group_data in registry.transaction_groups.items():
                group, created = TransactionTypeGroup.objects.update_or_create(
                    group_code=group_code,
                    defaults={
                        'description': group_data['description']
                    }
                )
                if created:
                    groups_created += 1
                    self.stdout.write(self.style.SUCCESS(f"Created group: {group_code} - {group_data['description']}"))
                else:
                    self.stdout.write(f"Updated group: {group_code} - {group_data['description']}")
            
            # Load transaction types and associate with groups
            types_created = 0
            for group_code, group_data in registry.transaction_groups.items():
                try:
                    group = TransactionTypeGroup.objects.get(group_code=group_code)
                    
                    # Skip if using wildcard
                    if '*' in group_data['included_codes']:
                        self.stdout.write(f"Skipping wildcard group: {group_code}")
                        continue
                    
                    # Process included transaction codes
                    for code in group_data['included_codes']:
                        if not code or code == '*':
                            continue
                            
                        # Create transaction type if it doesn't exist
                        tx_type, created = TransactionType.objects.update_or_create(
                            transaction_code=code,
                            defaults={
                                'description': f"{code} transaction"
                            }
                        )
                        
                        # Add to group
                        tx_type.groups.add(group)
                        
                        if created:
                            types_created += 1
                            self.stdout.write(self.style.SUCCESS(f"Created type: {code} in group {group_code}"))
                        else:
                            self.stdout.write(f"Added type: {code} to group {group_code}")
                except TransactionTypeGroup.DoesNotExist:
                    self.stdout.write(self.style.WARNING(f"Group {group_code} does not exist, skipping transaction types"))
        
        # Final summary
        self.stdout.write(self.style.SUCCESS(
            f"Successfully loaded transaction types: "
            f"{groups_created} groups created, {types_created} transaction types created."
        ))
        
        # Check total counts
        group_count = TransactionTypeGroup.objects.count()
        type_count = TransactionType.objects.count()
        self.stdout.write(f"Database now contains {group_count} transaction type groups and {type_count} transaction types.") 
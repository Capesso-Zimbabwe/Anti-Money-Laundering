import logging
from django.core.management.base import BaseCommand
from transaction_monitoring.views import process_dormant_account_rule
from django.http import HttpRequest

class Command(BaseCommand):
    help = 'Process the dormant account rule for a transaction or account'

    def add_arguments(self, parser):
        parser.add_argument('--transaction', type=str, help='Process a specific transaction ID')
        parser.add_argument('--account', type=str, help='Process all transactions for an account')

    def handle(self, *args, **options):
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger('dormant_rule_processor')
        
        # Create dummy request object
        request = HttpRequest()
        
        transaction_id = options.get('transaction')
        account_number = options.get('account')
        
        if not transaction_id and not account_number:
            self.stdout.write(self.style.ERROR('Please provide either --transaction or --account'))
            return
        
        self.stdout.write(self.style.SUCCESS('Starting dormant account rule processing...'))
        
        if transaction_id:
            self.stdout.write(f'Processing transaction: {transaction_id}')
            response = process_dormant_account_rule(request, transaction_id=transaction_id)
            response_data = response.content.decode('utf-8')
            self.stdout.write(response_data)
        
        if account_number:
            self.stdout.write(f'Processing account: {account_number}')
            response = process_dormant_account_rule(request, account_number=account_number)
            response_data = response.content.decode('utf-8')
            self.stdout.write(response_data)
        
        self.stdout.write(self.style.SUCCESS('Processing completed')) 
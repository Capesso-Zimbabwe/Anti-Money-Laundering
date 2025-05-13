from django.core.management.base import BaseCommand
from django.utils import timezone
from kyc_app.services import KYCScreeningService


class Command(BaseCommand):
    help = 'Run automated KYC rescreening for profiles due for review based on risk level'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Only display profiles that would be rescreened without actually performing the screening',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS(f'Starting KYC rescreening job at {timezone.now()}'))
        
        # Get profiles due for rescreening
        profiles = KYCScreeningService.get_profiles_due_for_rescreening()
        self.stdout.write(f'Found {len(profiles)} profiles due for rescreening')
        
        # If dry run, just list the profiles
        if options['dry_run']:
            for profile in profiles:
                self.stdout.write(f'  - {profile.full_name} (ID: {profile.customer_id})')
            self.stdout.write(self.style.SUCCESS('Dry run completed.'))
            return
        
        # Otherwise, run the rescreening
        results = KYCScreeningService.run_automatic_rescreening()
        
        # Output results
        success_count = len([r for r in results if r['status'] == 'Success'])
        error_count = len(results) - success_count
        
        self.stdout.write(f'Completed rescreening: {success_count} successful, {error_count} errors')
        
        # Show error details if any
        if error_count > 0:
            self.stdout.write(self.style.WARNING('Error details:'))
            for result in results:
                if result['status'].startswith('Error'):
                    self.stdout.write(f"  - {result['profile'].full_name}: {result['status']}")
        
        self.stdout.write(self.style.SUCCESS(f'Rescreening job completed at {timezone.now()}')) 
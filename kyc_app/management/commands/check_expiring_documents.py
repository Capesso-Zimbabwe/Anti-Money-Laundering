from django.core.management.base import BaseCommand
from django.utils import timezone
from kyc_app.services import KYCScreeningService


class Command(BaseCommand):
    help = 'Check for KYC profiles with expiring ID documents and send notifications'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Days before expiry to send notification (default: 30)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Only display profiles with expiring documents without sending notifications',
        )

    def handle(self, *args, **options):
        days_before = options['days']
        self.stdout.write(self.style.SUCCESS(f'Checking for ID documents expiring in the next {days_before} days'))
        
        # Get profiles with expiring documents
        profiles = KYCScreeningService.check_expiring_documents(days_before=days_before)
        
        # If no profiles found
        if not profiles:
            self.stdout.write('No profiles with expiring ID documents found.')
            return
        
        self.stdout.write(f'Found {len(profiles)} profiles with expiring ID documents:')
        
        for profile in profiles:
            days_remaining = (profile.id_expiry_date - timezone.now().date()).days
            self.stdout.write(f"  - {profile.full_name}: {profile.id_document_type} expires in {days_remaining} days")
            
            # Send notification if not dry run
            if not options['dry_run']:
                from kyc_app.services import KYCNotificationService
                notification_sent = KYCNotificationService.send_document_expiry_notification(profile)
                if notification_sent:
                    self.stdout.write(self.style.SUCCESS(f"    - Notification sent to {profile.email}"))
                else:
                    self.stdout.write(self.style.ERROR(f"    - Failed to send notification to {profile.email}"))
        
        if options['dry_run']:
            self.stdout.write(self.style.SUCCESS('Dry run completed. No notifications sent.'))
        else:
            self.stdout.write(self.style.SUCCESS('Document expiry check completed and notifications sent.')) 
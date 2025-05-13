from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.db.models import Q

from .models import KYCProfile, KYCTestResult, KYCWorkflowState
from .perform_kyc_screening import perform_kyc_screening


class KYCScreeningService:
    """Service class to handle KYC screening operations"""
    
    @staticmethod
    def get_profiles_due_for_rescreening():
        """
        Get KYC profiles that are due for rescreening based on risk level and last screening date.
        - High risk: Rescreen every 3 months
        - Medium risk: Rescreen every 6 months
        - Low risk: Rescreen every 12 months
        """
        today = timezone.now().date()
        three_months_ago = today - timezone.timedelta(days=90)
        six_months_ago = today - timezone.timedelta(days=180)
        twelve_months_ago = today - timezone.timedelta(days=365)
        
        # Get profiles with an approved workflow state
        profiles_with_state = KYCProfile.objects.filter(
            workflow_state__current_state='APPROVED'
        ).select_related('workflow_state')
        
        # Construct query based on risk level and last screening date
        profiles_due = []
        
        for profile in profiles_with_state:
            # Get the latest test result for this profile
            latest_test = KYCTestResult.objects.filter(
                kyc_profile=profile
            ).order_by('-created_at').first()
            
            if not latest_test:
                profiles_due.append(profile)
                continue
            
            # Check if profile is due for rescreening based on risk level
            if latest_test.risk_level == 'High' and latest_test.created_at.date() <= three_months_ago:
                profiles_due.append(profile)
            elif latest_test.risk_level == 'Medium' and latest_test.created_at.date() <= six_months_ago:
                profiles_due.append(profile)
            elif latest_test.risk_level == 'Low' and latest_test.created_at.date() <= twelve_months_ago:
                profiles_due.append(profile)
        
        return profiles_due
    
    @staticmethod
    def run_automatic_rescreening():
        """
        Run automatic rescreening for all profiles that are due
        """
        profiles = KYCScreeningService.get_profiles_due_for_rescreening()
        results = []
        
        for profile in profiles:
            # Update workflow state to indicate rescreening
            if hasattr(profile, 'workflow_state'):
                profile.workflow_state.transition_to(
                    'SCREENING',
                    user='Automated System',
                    notes='Automated periodic rescreening'
                )
            
            # Run the screening
            result = perform_kyc_screening(profile.id_document_number)
            
            if not isinstance(result, str):  # If result is not an error message
                # Update workflow state based on screening result
                if hasattr(profile, 'workflow_state'):
                    if result.kyc_status == 'Verified':
                        profile.workflow_state.transition_to(
                            'APPROVED',
                            user='Automated System',
                            notes=f'Automatic approval after rescreening. Risk level: {result.risk_level}'
                        )
                    elif result.kyc_status == 'Rejected':
                        profile.workflow_state.transition_to(
                            'REJECTED',
                            user='Automated System',
                            notes=f'Automatic rejection after rescreening. Risk level: {result.risk_level}'
                        )
                    else:
                        profile.workflow_state.transition_to(
                            'APPROVAL_PENDING',
                            user='Automated System',
                            notes=f'Manual review required after rescreening. Risk level: {result.risk_level}'
                        )
                
                results.append({
                    'profile': profile,
                    'result': result,
                    'status': 'Success'
                })
                
                # Send notification about rescreening
                KYCNotificationService.send_rescreening_notification(profile, result)
            else:
                # Log error
                results.append({
                    'profile': profile,
                    'result': None,
                    'status': f'Error: {result}'
                })
        
        return results
    
    @staticmethod
    def check_expiring_documents(days_before=30):
        """
        Check for KYC profiles with expiring ID documents
        """
        today = timezone.now().date()
        expiry_threshold = today + timezone.timedelta(days=days_before)
        
        expiring_profiles = KYCProfile.objects.filter(
            id_expiry_date__lte=expiry_threshold,
            id_expiry_date__gt=today
        )
        
        for profile in expiring_profiles:
            KYCNotificationService.send_document_expiry_notification(profile)
        
        return expiring_profiles


class KYCNotificationService:
    """Service class to handle KYC-related notifications"""
    
    @staticmethod
    def send_rescreening_notification(profile, test_result):
        """
        Send notification about KYC rescreening result
        """
        if not profile.email:
            return False
            
        subject = f'KYC Rescreening Completed - {profile.full_name}'
        
        # Determine message based on result
        if test_result.kyc_status == 'Verified':
            message = f'Your KYC verification has been renewed and approved with a risk level of {test_result.risk_level}.'
        elif test_result.kyc_status == 'Rejected':
            message = f'Your KYC verification has been reviewed and requires attention. Please contact our compliance team.'
        else:
            message = f'Your KYC information is being reviewed by our compliance team.'
            
        # Try to send email
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [profile.email],
                fail_silently=False,
            )
            return True
        except Exception as e:
            # Log error
            print(f"Error sending email to {profile.email}: {str(e)}")
            return False
    
    @staticmethod
    def send_document_expiry_notification(profile):
        """
        Send notification about expiring ID document
        """
        if not profile.email:
            return False
            
        days_remaining = (profile.id_expiry_date - timezone.now().date()).days
        
        subject = f'Your ID Document is Expiring Soon - {profile.full_name}'
        message = f'''
        Dear {profile.full_name},
        
        This is to inform you that your {profile.id_document_type} document will expire in {days_remaining} days.
        
        Please update your identification document before expiry to ensure uninterrupted service.
        
        Thank you,
        Compliance Team
        '''
            
        # Try to send email
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [profile.email],
                fail_silently=False,
            )
            return True
        except Exception as e:
            # Log error
            print(f"Error sending email to {profile.email}: {str(e)}")
            return False
    
    @staticmethod
    def send_workflow_state_notification(workflow_state, old_state, new_state):
        """
        Send notification about workflow state change
        """
        profile = workflow_state.kyc_profile
        
        if not profile.email:
            return False
            
        subject = f'KYC Status Update - {profile.full_name}'
        
        # Map states to user-friendly messages
        state_messages = {
            'SUBMITTED': 'Your KYC application has been received and is pending review.',
            'DOC_REVIEW': 'Your KYC documents are being reviewed by our team.',
            'SCREENING': 'Your KYC information is being screened against various databases.',
            'INVESTIGATION': 'Additional verification is being performed on your KYC information.',
            'APPROVAL_PENDING': 'Your KYC application is awaiting final approval.',
            'APPROVED': 'Congratulations! Your KYC verification has been approved.',
            'REJECTED': 'Your KYC verification could not be completed. Please contact our support team.',
            'EXPIRED': 'Your KYC verification has expired. Please renew it to continue.',
        }
        
        message = state_messages.get(new_state, f'Your KYC status has been updated to {new_state}.')
            
        # Try to send email
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [profile.email],
                fail_silently=False,
            )
            return True
        except Exception as e:
            # Log error
            print(f"Error sending email to {profile.email}: {str(e)}")
            return False 
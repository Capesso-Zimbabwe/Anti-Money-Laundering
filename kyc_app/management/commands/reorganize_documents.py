import os
import shutil
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from kyc_app.models import KYCProfile, KYCBusiness, Document

class Command(BaseCommand):
    help = 'Reorganizes existing document files into customer/business-specific folders'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simulate operations without making actual changes',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        media_root = settings.MEDIA_ROOT

        self.stdout.write(self.style.NOTICE('Starting document reorganization...'))
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No actual changes will be made'))

        # Reorganize KYC Profile documents
        self.stdout.write(self.style.NOTICE('Processing KYC Profile documents...'))
        profiles_processed = 0
        profiles_skipped = 0
        
        for profile in KYCProfile.objects.all():
            try:
                if profile.id_document_file:
                    # Get original path and verify it exists
                    original_path = os.path.join(media_root, profile.id_document_file.name)
                    if os.path.exists(original_path):
                        # Generate new path
                        new_relative_path = f"customers/customer_{profile.customer_id}/id_documents/{os.path.basename(profile.id_document_file.name)}"
                        new_path = os.path.join(media_root, new_relative_path)
                        
                        # Create directory if needed
                        os.makedirs(os.path.dirname(new_path), exist_ok=True)
                        
                        # Copy file to new location
                        if not dry_run:
                            # Create directory
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            
                            # Copy file
                            shutil.copy2(original_path, new_path)
                            
                            # Update the database field
                            profile.id_document_file.name = new_relative_path
                            profile.save(update_fields=['id_document_file'])
                            
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Processed profile {profile.customer_id}: "
                                f"{original_path} -> {new_path}"
                            )
                        )
                        profiles_processed += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f"File not found for profile {profile.customer_id}: {original_path}"
                            )
                        )
                        profiles_skipped += 1
                else:
                    profiles_skipped += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"Error processing profile {profile.customer_id}: {str(e)}"
                    )
                )
                profiles_skipped += 1
        
        # Reorganize Business documents
        self.stdout.write(self.style.NOTICE('Processing Business documents...'))
        businesses_processed = 0
        businesses_skipped = 0
        
        for business in KYCBusiness.objects.all():
            try:
                documents_processed = False
                
                # Process registration_document
                if business.registration_document:
                    original_path = os.path.join(media_root, business.registration_document.name)
                    if os.path.exists(original_path):
                        new_relative_path = f"businesses/business_{business.business_id}/registration_docs/{os.path.basename(business.registration_document.name)}"
                        new_path = os.path.join(media_root, new_relative_path)
                        
                        if not dry_run:
                            # Create directory
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            
                            # Copy file
                            shutil.copy2(original_path, new_path)
                            
                            # Update the database field
                            business.registration_document.name = new_relative_path
                            documents_processed = True
                    
                # Process tax_document
                if business.tax_document:
                    original_path = os.path.join(media_root, business.tax_document.name)
                    if os.path.exists(original_path):
                        new_relative_path = f"businesses/business_{business.business_id}/tax_docs/{os.path.basename(business.tax_document.name)}"
                        new_path = os.path.join(media_root, new_relative_path)
                        
                        if not dry_run:
                            # Create directory
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            
                            # Copy file
                            shutil.copy2(original_path, new_path)
                            
                            # Update the database field
                            business.tax_document.name = new_relative_path
                            documents_processed = True
                
                # Save business if documents were processed
                if documents_processed and not dry_run:
                    business.save(update_fields=['registration_document', 'tax_document'])
                    businesses_processed += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Processed business {business.business_id} documents"
                        )
                    )
                else:
                    businesses_skipped += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"Error processing business {business.business_id}: {str(e)}"
                    )
                )
                businesses_skipped += 1
                
        # Reorganize Document model documents
        self.stdout.write(self.style.NOTICE('Processing Document model files...'))
        docs_processed = 0
        docs_skipped = 0
        
        for doc in Document.objects.all():
            try:
                if doc.document_file:
                    original_path = os.path.join(media_root, doc.document_file.name)
                    if os.path.exists(original_path):
                        # Generate new path
                        new_relative_path = f"customers/customer_{doc.profile.customer_id}/{doc.document_type}/{os.path.basename(doc.document_file.name)}"
                        new_path = os.path.join(media_root, new_relative_path)
                        
                        if not dry_run:
                            # Create directory
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            
                            # Copy file
                            shutil.copy2(original_path, new_path)
                            
                            # Update the database field
                            doc.document_file.name = new_relative_path
                            doc.save(update_fields=['document_file'])
                            
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Processed document {doc.id} for profile {doc.profile.customer_id}: "
                                f"{original_path} -> {new_path}"
                            )
                        )
                        docs_processed += 1
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f"File not found for document {doc.id}: {original_path}"
                            )
                        )
                        docs_skipped += 1
                else:
                    docs_skipped += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"Error processing document {doc.id}: {str(e)}"
                    )
                )
                docs_skipped += 1
                
        # Final summary
        self.stdout.write(self.style.SUCCESS("Document reorganization completed!"))
        self.stdout.write(f"Profiles: {profiles_processed} processed, {profiles_skipped} skipped")
        self.stdout.write(f"Businesses: {businesses_processed} processed, {businesses_skipped} skipped")
        self.stdout.write(f"Documents: {docs_processed} processed, {docs_skipped} skipped")
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    "This was a dry run. No files were actually moved. "
                    "Run without --dry-run to make actual changes."
                )
            ) 
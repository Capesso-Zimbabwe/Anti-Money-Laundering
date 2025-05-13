from django.urls import path

from aml_app.functions_view import generate_aml_report_pdf
from kyc_app.dilisense import check_individual, download_individual_report
from kyc_app.kyc_view import api_check_entity, api_generate_entity_report, api_list_sources, generate_aml_kyc_report, kyc_aml_screening, kyc_search_view, register_kyc_Busi, register_kyc_profile, run_individual_kyc, run_kyc_aml_screening

from . import views

app_name = 'kyc_app'

urlpatterns = [
    # KYC Registration URLs
    path('register-business/', views.register_kyc_business, name='register_kyc_business'),
    path('register-business-multi/', views.register_kyc_business_multi, name='register_kyc_business_multi'),
    path('register-kyc/', views.register_kyc_profile, name='register_kyc_profile'),
    path('register-kyc-busi/', register_kyc_Busi, name='register_kyc_business'), 

    
    # KYC Drafts Management
    path('kyc-drafts/', views.kyc_profile_drafts, name='kyc_profile_drafts'),
    path('delete-draft/<int:profile_id>/', views.delete_kyc_draft, name='delete_kyc_draft'),
    
    # KYC Workflow Dashboard
    path('workflow-dashboard/', views.kyc_workflow_dashboard, name='kyc_workflow_dashboard'),
    
    # KYC Review URLs
    path('review-kyc-profile/<int:profile_id>/', views.review_kyc_profile, name='review_kyc_profile'),
    path('review-kyc-business/<int:business_id>/', views.review_kyc_business, name='review_kyc_business'),
    
    # KYC Approval/Rejection Reason Views
    path('view-rejection-reason/<int:profile_id>/', views.view_rejection_reason, name='view_rejection_reason'),
    path('view-approval-reason/<int:profile_id>/', views.view_approval_reason, name='view_approval_reason'),
    path('reopen-kyc-review/<int:profile_id>/', views.reopen_kyc_review, name='reopen_kyc_review'),
    
    # KYC Reports URLs
    path('reports/', views.kyc_reports_list, name='kyc_reports_list'),
    path('report/<str:report_id>/', views.view_kyc_report, name='view_kyc_report'),
    path('generate-report/<int:profile_id>/<str:report_type>/', views.generate_kyc_report, name='generate_kyc_report'),
    path('download-report/<str:report_id>/', views.download_kyc_report, name='download_kyc_report'),
    
    # Reports Dashboard and Batch Generation
    path('reports-dashboard/', views.reports_dashboard, name='reports_dashboard'),
    path('batch-generate-reports/', views.batch_generate_reports, name='batch_generate_reports'),
    
    # Bulk Import URLs
    path('bulk-import/', views.bulk_import_profiles, name='bulk_import_profiles'),
    path('download-import-template/', views.download_import_template, name='download_import_template'),
    
    # KYC Screening URLs
    path('kyc-search/', kyc_search_view, name='kyc_search'),
    path('run-individual-kyc/<str:customer_id>/', run_individual_kyc, name='run_individual_kyc'),
    path('kyc-screening/', kyc_aml_screening, name='kyc_aml_screening'),
    path('run-kyc-aml-screening/', run_kyc_aml_screening, name='run_kyc_aml_screening'),
    
    # KYC Reports URLs
    path('aml-report-kyc/', generate_aml_kyc_report, name='aml_report_kyc'),
    
    # Dilisense API URLs
    path('api/check-individual/', check_individual, name='check_individual'),
    path('api/download-report/', download_individual_report, name='download_report'),
    path('api/dilisense/check-entity/', api_check_entity, name='api_check_entity'),
    path('api/dilisense/generate-entity-report/', api_generate_entity_report, name='api_generate_entity_report'),
    path('api/dilisense/list-sources/', api_list_sources, name='api_list_sources'),
    path('document-verification/', views.document_verification_dashboard, name='document_verification_dashboard'),
    path('verify-document/<int:document_id>/', views.verify_document, name='verify_document'),
    
    # Document Browser URLs
    path('documents/', views.browse_documents, name='browse_documents'),
    path('documents/customer/<str:customer_id>/', views.customer_documents, name='customer_documents'),
    path('documents/business/<str:business_id>/', views.business_documents, name='business_documents'),
    path('documents/view/<int:document_id>/', views.view_document, name='view_document'),
    path('documents/customer/<str:customer_id>/upload/', views.upload_customer_document, name='upload_customer_document'),
    path('documents/business/<str:business_id>/upload/', views.upload_business_document, name='upload_business_document'),
    
    # Debug view for field lengths
    path('debug/field-lengths/', views.debug_field_lengths, name='debug_field_lengths'),
] 
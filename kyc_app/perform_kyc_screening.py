from aml_app.models import AdverseMediaCheck, Alert, BlacklistEntry, PoliticallyExposedPerson, SanctionsList, WatchlistEntry
from kyc_app.models import KYCProfile, KYCTestResult, KYCWorkflowState
from django.core.exceptions import ObjectDoesNotExist
from django.utils.timezone import make_aware, now
from .risk_scoring import KYCRiskScorer



#######################################################################################################

def perform_kyc_screening(identifier):
    """
    Performs KYC screening based on either id_document_number or customer_id.
    Uses advanced risk scoring to calculate risk levels.
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
        enhanced_due_diligence = False

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
        blacklist_entry = BlacklistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if blacklist_entry:
            test_result.suspicious_activity_flag = True
            flagged_reasons.append(f"Customer is blacklisted: {blacklist_entry.reason}")

        # ✅ 4. Check Against **Sanctions List**
        sanctions_match = SanctionsList.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if sanctions_match:
            test_result.sanctions_list_check = True
            flagged_reasons.append(f"Customer found in sanctions list ({sanctions_match.sanctions_source}).")

        # ✅ 5. Check Against **Watchlist**
        watchlist_entry = WatchlistEntry.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if watchlist_entry:
            test_result.watchlist_check = True
            flagged_reasons.append(f"Customer is on a watchlist: {watchlist_entry.reason}")

        # ✅ 6. Check Against **Adverse Media**
        adverse_media = AdverseMediaCheck.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if adverse_media:
            test_result.adverse_media_check = True
            flagged_reasons.append(f"Customer has adverse media: {adverse_media.headline}.")

        # ✅ 7. Check If Customer is a **Politically Exposed Person (PEP)**
        pep_match = PoliticallyExposedPerson.objects.filter(id_document_number=kyc_profile.id_document_number).first()
        if pep_match:
            test_result.politically_exposed_person = True
            test_result.enhanced_due_diligence_required = True
            enhanced_due_diligence = True
            flagged_reasons.append(f"Customer is a PEP: {pep_match.position}.")

        # ✅ 8. Flag if Customer is from **High-Risk Countries**
        high_risk_countries = ["North Korea", "Iran", "Syria", "Venezuela", "Yemen", "Libya", "Somalia"]
        if kyc_profile.country in high_risk_countries:
            test_result.high_risk_country = True
            flagged_reasons.append(f"Customer from high-risk country: {kyc_profile.country}.")

        # ✅ 9. Fraud & Financial Crime Checks (Using Past KYC Test Results)
        past_kyc_results = KYCTestResult.objects.filter(kyc_profile=kyc_profile)
        if past_kyc_results.filter(fraud_check=True).exists():
            test_result.fraud_check = True
            flagged_reasons.append("Previous fraud detected.")

        if past_kyc_results.filter(financial_crime_check=True).exists():
            test_result.financial_crime_check = True
            flagged_reasons.append("Linked to financial crime cases.")

        # ✅ 10. Use the risk scorer to calculate risk score and level
        risk_scorer = KYCRiskScorer()
        risk_assessment = risk_scorer.score_kyc_profile(kyc_profile, test_result)
        
        # Set the risk level based on the calculated score
        test_result.risk_level = risk_assessment['risk_level']
        
        # Set KYC status based on risk level and checks
        if test_result.sanctions_list_check or test_result.suspicious_activity_flag:
            # Automatic rejection for sanctions or blacklist matches
            test_result.kyc_status = "Rejected"
        elif test_result.risk_level == "High" or enhanced_due_diligence:
            # High risk or PEP requires enhanced due diligence
            test_result.kyc_status = "Pending"
            test_result.enhanced_due_diligence_required = True
        elif test_result.risk_level == "Medium":
            # Medium risk requires standard review
            test_result.kyc_status = "Pending"
        else:
            # Low risk can be auto-approved
            test_result.kyc_status = "Verified"
        
        # For any risk level, if there are certain flags, require transaction monitoring
        if (test_result.politically_exposed_person or 
            test_result.adverse_media_check or 
            test_result.high_risk_country or
            risk_assessment['overall_score'] > 50):
            test_result.transaction_monitoring_required = True

        # ✅ 11. Add risk score details to verification notes
        risk_notes = [
            f"Overall risk score: {risk_assessment['overall_score']}",
            f"Risk level: {risk_assessment['risk_level']}",
            "Risk factor scores:"
        ]
        
        for factor, score in risk_assessment['risk_factors'].items():
            risk_notes.append(f"- {factor}: {score}")
        
        # Combine all notes
        all_notes = flagged_reasons + ["\n"] + risk_notes
        test_result.verification_notes = "; ".join(flagged_reasons) + "\n\n" + "\n".join(risk_notes)
        
        # ✅ 12. Save Final KYC Test Result
        test_result.save()

        # ✅ 13. Update the workflow state if it exists
        try:
            if hasattr(kyc_profile, 'workflow_state'):
                # Map KYC status to workflow state
                state_mapping = {
                    'Verified': 'APPROVED',
                    'Rejected': 'REJECTED',
                    'Pending': 'APPROVAL_PENDING'
                }
                
                # Get the mapped state or default to APPROVAL_PENDING
                new_state = state_mapping.get(test_result.kyc_status, 'APPROVAL_PENDING')
                
                # Add enhanced due diligence note if required
                notes = f"Risk Level: {test_result.risk_level}"
                if test_result.enhanced_due_diligence_required:
                    notes += "; Enhanced Due Diligence Required"
                
                # Transition the workflow state
                kyc_profile.workflow_state.transition_to(
                    new_state,
                    user='Automated System',
                    notes=notes
                )
        except Exception as e:
            # Log the error but continue
            print(f"Error updating workflow state: {str(e)}")

        # ✅ 14. Create an alert if high risk
        if test_result.risk_level == "High" or test_result.sanctions_list_check or test_result.suspicious_activity_flag:
            severity = "HIGH"
            title = "High-Risk KYC Profile"
            message = "KYC Profile flagged as high risk. Please review."
            
            if test_result.sanctions_list_check:
                title = "Sanctions Match Detected"
                message = "Customer matches sanctions list. Immediate review required."
            elif test_result.suspicious_activity_flag:
                title = "Blacklisted Customer Detected"
                message = "Customer found on blacklist. Immediate review required."
            
            Alert.objects.create(
                alert_type="KYC",
                severity=severity,
                status="OPEN",
                kyc_test=test_result,
                title=title,
                message=message
            )
        elif test_result.risk_level == "Medium" or test_result.politically_exposed_person:
            Alert.objects.create(
                alert_type="KYC",
                severity="MEDIUM",
                status="OPEN",
                kyc_test=test_result,
                title="Medium-Risk KYC Profile",
                message=f"KYC Profile flagged as medium risk. {'; '.join(flagged_reasons)}"
            )

        return test_result

    except ObjectDoesNotExist:
        return "Error: KYC profile not found."
    except Exception as e:
        return f"Error during KYC screening: {str(e)}"

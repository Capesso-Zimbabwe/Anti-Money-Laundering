from django.utils import timezone
from django.conf import settings
from decimal import Decimal


class KYCRiskScorer:
    """
    A sophisticated risk scoring system for KYC profiles.
    Uses weighted risk factors to calculate an overall risk score.
    """
    
    # Default risk factor weights (should be configurable in admin)
    DEFAULT_WEIGHTS = {
        'pep_status': 25,  # Politically Exposed Person
        'sanctions': 30,   # Sanctions list match
        'country_risk': 15,  # High-risk country
        'adverse_media': 10,  # Adverse media mentions
        'transaction_volume': 8,  # Transaction volume
        'document_quality': 7,  # Quality/validity of documents
        'duration_of_relationship': 5,  # How long relationship has existed
    }
    
    # High-risk countries (should be configurable in admin)
    HIGH_RISK_COUNTRIES = [
        'AF', 'KP', 'IR', 'SY', 'VE', 'IQ', 'YE', 'LY',
        'SO', 'MM', 'SS', 'CD', 'ER', 'ZW', 'HT'
    ]
    
    # Medium-risk countries
    MEDIUM_RISK_COUNTRIES = [
        'NG', 'PK', 'LB', 'BY', 'RU', 'TD', 'SD',
        'UZ', 'TM', 'CF', 'CM', 'NE', 'ML', 'MZ'
    ]
    
    def __init__(self, custom_weights=None, custom_high_risk_countries=None, custom_medium_risk_countries=None):
        """
        Initialize the risk scorer with optional custom configurations.
        """
        self.weights = custom_weights or self.DEFAULT_WEIGHTS
        self.high_risk_countries = custom_high_risk_countries or self.HIGH_RISK_COUNTRIES
        self.medium_risk_countries = custom_medium_risk_countries or self.MEDIUM_RISK_COUNTRIES
        
        # Normalize weights to ensure they sum to 100
        total_weight = sum(self.weights.values())
        if total_weight != 100:
            for key in self.weights:
                self.weights[key] = (self.weights[key] / total_weight) * 100
    
    def calculate_country_risk(self, country_code):
        """
        Calculate risk score based on country.
        Returns a score between 0-100.
        """
        country_code = country_code.upper()
        
        if country_code in self.high_risk_countries:
            return 100  # Highest risk
        elif country_code in self.medium_risk_countries:
            return 50   # Medium risk
        else:
            return 10   # Lower risk (still not zero, as all countries have some risk)
    
    def calculate_pep_risk(self, is_pep, pep_level=None):
        """
        Calculate risk based on PEP status.
        PEP level can be 'primary', 'family', 'associate', or None.
        """
        if not is_pep:
            return 0
            
        # Different levels of PEP risk
        pep_risk_levels = {
            'primary': 100,    # The person is directly a PEP
            'family': 75,      # Immediate family of a PEP
            'associate': 50,   # Close associate of a PEP
            None: 80           # PEP but level not specified
        }
        
        return pep_risk_levels.get(pep_level, 80)
    
    def calculate_sanctions_risk(self, has_sanctions, sanctions_details=None):
        """
        Calculate risk based on sanctions lists.
        """
        if not has_sanctions:
            return 0
            
        # If sanctioned, it's almost always maximum risk
        return 100
    
    def calculate_adverse_media_risk(self, has_adverse_media, severity=None):
        """
        Calculate risk based on adverse media mentions.
        Severity can be 'high', 'medium', 'low', or None.
        """
        if not has_adverse_media:
            return 0
            
        # Risk levels based on severity
        severity_levels = {
            'high': 100,
            'medium': 60,
            'low': 30,
            None: 50  # Default if severity not specified
        }
        
        return severity_levels.get(severity, 50)
    
    def calculate_transaction_risk(self, transaction_volume, expected_volume=None):
        """
        Calculate risk based on transaction volume relative to expected volume.
        """
        if transaction_volume is None:
            return 0
            
        if expected_volume is None or expected_volume == 0:
            # Without expected volume, use absolute thresholds
            if transaction_volume > 1000000:  # High volume
                return 80
            elif transaction_volume > 100000:  # Medium-high
                return 60
            elif transaction_volume > 10000:  # Medium
                return 40
            else:  # Low
                return 20
        else:
            # Calculate risk based on deviation from expected
            ratio = transaction_volume / expected_volume
            
            if ratio > 3:  # Volume > 3x expected
                return 100
            elif ratio > 2:  # Volume 2-3x expected
                return 75
            elif ratio > 1.5:  # Volume 1.5-2x expected
                return 50
            elif ratio > 1.2:  # Volume 1.2-1.5x expected
                return 25
            else:  # Volume as expected or lower
                return 10
    
    def calculate_document_risk(self, document_quality):
        """
        Calculate risk based on document quality.
        Quality can be 'high', 'medium', 'low', or None.
        """
        quality_levels = {
            'high': 10,   # Clear, verified
            'medium': 40,  # Some issues but acceptable
            'low': 80,     # Poor quality, hard to verify
            None: 50       # Default if quality not specified
        }
        
        return quality_levels.get(document_quality, 50)
    
    def calculate_relationship_risk(self, relationship_duration_days):
        """
        Calculate risk based on duration of relationship.
        New relationships have higher risk.
        """
        if relationship_duration_days is None:
            return 50  # Default medium risk
            
        if relationship_duration_days < 90:  # < 3 months
            return 80
        elif relationship_duration_days < 365:  # < 1 year
            return 50
        elif relationship_duration_days < 1095:  # < 3 years
            return 30
        else:  # 3+ years
            return 10
    
    def calculate_overall_risk(self, risk_factors):
        """
        Calculate the weighted overall risk score.
        risk_factors is a dictionary with risk category names and their scores.
        """
        overall_score = 0
        
        for factor, score in risk_factors.items():
            if factor in self.weights:
                # Apply the weight to the score
                weighted_score = score * (self.weights[factor] / 100)
                overall_score += weighted_score
        
        return round(overall_score, 2)
    
    def get_risk_level(self, score):
        """
        Convert numeric score to risk level.
        """
        if score >= 75:
            return 'High'
        elif score >= 40:
            return 'Medium'
        else:
            return 'Low'
    
    def score_kyc_profile(self, kyc_profile, test_result=None):
        """
        Score a KYC profile and associated test result.
        Returns a dictionary with detailed risk scores.
        """
        # Initialize risk factors
        risk_factors = {}
        
        # Country risk (based on country of residence)
        if kyc_profile.country:
            # Extract country code from country name - this is simplified,
            # in practice you would use a country name to code mapping
            country_code = kyc_profile.country[:2].upper()
            risk_factors['country_risk'] = self.calculate_country_risk(country_code)
        
        # Relationship duration risk
        if kyc_profile.created_at:
            days = (timezone.now().date() - kyc_profile.created_at.date()).days
            risk_factors['duration_of_relationship'] = self.calculate_relationship_risk(days)
        
        # If we have a test result, use its data
        if test_result:
            # PEP risk
            risk_factors['pep_status'] = self.calculate_pep_risk(test_result.politically_exposed_person)
            
            # Sanctions risk
            risk_factors['sanctions'] = self.calculate_sanctions_risk(test_result.sanctions_list_check)
            
            # Adverse media risk
            risk_factors['adverse_media'] = self.calculate_adverse_media_risk(test_result.adverse_media_check)
            
            # Document quality (placeholder - would be populated from document verification)
            risk_factors['document_quality'] = 50  # Default medium risk
        
        # Transaction volume risk (placeholder - would be calculated from transaction history)
        risk_factors['transaction_volume'] = 30  # Default low-medium risk
        
        # Calculate overall risk score
        overall_score = self.calculate_overall_risk(risk_factors)
        
        # Determine risk level
        risk_level = self.get_risk_level(overall_score)
        
        # Return comprehensive risk assessment
        return {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'weights': self.weights
        } 
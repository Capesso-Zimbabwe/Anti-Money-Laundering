from typing import Dict, List, Any, Optional
import json
import os
import logging

logger = logging.getLogger(__name__)

class RuleConfig:
    """
    Configuration management for transaction monitoring rules.
    
    This class handles loading, saving, and validating rule configurations.
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to configuration file or None for default
        """
        self.config_path = config_path or 'config/rules.json'
        self.config = {}
        self.load()
    
    def load(self) -> bool:
        """
        Load rule configurations from file or database.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            # First try to load from file
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                    logger.info(f"Loaded rule configuration from {self.config_path}")
                    return True
            
            # If file doesn't exist, try to load from database
            # This would be implemented to fetch from your AMLSettings
            if not self.config:
                self.config = self._load_from_db()
                logger.info("Loaded rule configuration from database")
                return True
            
            # If no configuration exists, use defaults
            if not self.config:
                self.config = self._get_default_config()
                logger.warning("Using default rule configuration")
                return True
                
            return False
        except Exception as e:
            logger.error(f"Error loading rule configuration: {str(e)}")
            return False
    
    def save(self) -> bool:
        """
        Save rule configurations to file or database.
        
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Save to file
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
                
            # Also save to database if needed
            # self._save_to_db()
            
            logger.info(f"Saved rule configuration to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving rule configuration: {str(e)}")
            return False
    
    def get_rule_config(self, rule_id: str) -> Dict[str, Any]:
        """
        Get configuration for a specific rule.
        
        Args:
            rule_id: The ID of the rule
            
        Returns:
            Rule configuration dictionary
        """
        return self.config.get(rule_id, {})
    
    def set_rule_config(self, rule_id: str, config: Dict[str, Any]) -> None:
        """
        Set configuration for a specific rule.
        
        Args:
            rule_id: The ID of the rule
            config: The rule configuration
        """
        self.config[rule_id] = config
    
    def enable_rule(self, rule_id: str) -> bool:
        """
        Enable a rule.
        
        Args:
            rule_id: The ID of the rule
            
        Returns:
            True if the rule was enabled, False otherwise
        """
        if rule_id in self.config:
            self.config[rule_id]['enabled'] = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """
        Disable a rule.
        
        Args:
            rule_id: The ID of the rule
            
        Returns:
            True if the rule was disabled, False otherwise
        """
        if rule_id in self.config:
            self.config[rule_id]['enabled'] = False
            return True
        return False
    
    def _load_from_db(self) -> Dict[str, Any]:
        """
        Load rule configurations from database.
        
        Returns:
            Dictionary of rule configurations
        """
        # This would be implemented to fetch from your AMLSettings
        from django.apps import apps
        AMLSettings = apps.get_model('aml_app', 'AMLSettings')
        
        try:
            settings = AMLSettings.objects.all()
            config = {}
            
            for setting in settings:
                # Convert stored settings to rule configuration
                rule_id = f"AML-{setting.rule_code}"
                config[rule_id] = {
                    'rule_id': rule_id,
                    'rule_name': setting.rule_name,
                    'description': setting.description or '',
                    'enabled': setting.enabled,
                    'transaction_types': setting.transaction_types.split(',') if setting.transaction_types else ['ALL-ALL'],
                    'alert_level': setting.alert_level or 'Account',
                    'evaluation_trigger': setting.evaluation_trigger or 'Daily Activity',
                    'scoring_algorithm': setting.scoring_algorithm or 'MAX',
                    'thresholds': json.loads(setting.thresholds) if hasattr(setting, 'thresholds') and setting.thresholds else {},
                    'recurrence': json.loads(setting.recurrence_settings) if hasattr(setting, 'recurrence_settings') and setting.recurrence_settings else {}
                }
            
            return config
        except Exception as e:
            logger.error(f"Error loading rule configuration from database: {str(e)}")
            return {}
    
    def _save_to_db(self) -> bool:
        """
        Save rule configurations to database.
        
        Returns:
            True if saved successfully
        """
        # This would be implemented to save to your AMLSettings
        from django.apps import apps
        AMLSettings = apps.get_model('aml_app', 'AMLSettings')
        
        try:
            for rule_id, config in self.config.items():
                # Extract rule code from rule_id
                rule_code = rule_id.split('-', 1)[1] if '-' in rule_id else rule_id
                
                # Prepare data for saving
                rule_data = {
                    'rule_name': config['rule_name'],
                    'description': config.get('description', ''),
                    'enabled': config.get('enabled', True),
                    'transaction_types': ','.join(config.get('transaction_types', ['ALL-ALL'])),
                    'alert_level': config.get('alert_level', 'Account'),
                    'evaluation_trigger': config.get('evaluation_trigger', 'Daily Activity'),
                    'scoring_algorithm': config.get('scoring_algorithm', 'MAX')
                }
                
                # Convert dictionaries to JSON strings if the fields exist
                if 'thresholds' in config:
                    rule_data['thresholds'] = json.dumps(config['thresholds'])
                
                if 'recurrence' in config:
                    rule_data['recurrence_settings'] = json.dumps(config['recurrence'])
                
                # Update or create the record
                setting, created = AMLSettings.objects.update_or_create(
                    rule_code=rule_code,
                    defaults=rule_data
                )
            
            return True
        except Exception as e:
            logger.error(f"Error saving rule configuration to database: {str(e)}")
            return False
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default rule configurations.
        
        Returns:
            Dictionary of default rule configurations
        """
        return {
            'AML-ADR-ALL-ALL-A-M06-AIN': {
                'rule_id': 'AML-ADR-ALL-ALL-A-M06-AIN',
                'rule_name': 'Activity Seen in A Dormant Account',
                'description': 'Detects significant activity in previously inactive accounts.',
                'alert_level': 'Account',
                'evaluation_trigger': 'Daily Activity',
                'scoring_algorithm': 'MAX',
                'transaction_types': ['ALL-ALL'],
                'thresholds': {
                    'account_age_days': 180,
                    'activity_amount': 10000,
                    'inactive_period_months': 6,
                    'max_prior_activity': 100
                },
                'recurrence': {
                    'lookback_period_months': 1,
                    'min_occurrences': 1
                },
                'enabled': True,
                'version': '1.0'
            },
            'AML-LCT-CCE-INN-A-D01-LCT': {
                'rule_id': 'AML-LCT-CCE-INN-A-D01-LCT',
                'rule_name': 'Large Cash Transaction',
                'description': 'Detects unusually large cash deposits.',
                'alert_level': 'Account',
                'evaluation_trigger': 'Transaction',
                'scoring_algorithm': 'MAX',
                'transaction_types': ['CCE-INN'],
                'thresholds': {
                    'transaction_amount': 10000,
                    'currency': 'USD'
                },
                'recurrence': {
                    'lookback_period_days': 30,
                    'min_occurrences': 1
                },
                'enabled': True,
                'version': '1.0'
            }
        }

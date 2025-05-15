"""
Logging utilities for the transaction monitoring system.

This module provides standardized logging functions and configuration
for consistent logging across the application.
"""

import logging
import json
from datetime import datetime
import traceback
import os
import sys

# Define log levels
LOG_LEVEL_DEBUG = logging.DEBUG
LOG_LEVEL_INFO = logging.INFO
LOG_LEVEL_WARNING = logging.WARNING
LOG_LEVEL_ERROR = logging.ERROR
LOG_LEVEL_CRITICAL = logging.CRITICAL

# Configure the default logger
def configure_logging(
    log_level=logging.INFO,
    log_to_console=True,
    log_to_file=True,
    log_file_path='logs/transaction_monitoring.log'
):
    """
    Configure the logging system.
    
    Args:
        log_level: The logging level
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        log_file_path: Path to log file
    """
    # Create logs directory if it doesn't exist
    if log_to_file:
        log_dir = os.path.dirname(log_file_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    
    # Create root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatters
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    
    # Add console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    
    # Add file handler
    if log_to_file:
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

# Structured logging functions
def log_transaction_processed(logger, transaction_id, result, rule_ids=None):
    """
    Log a processed transaction.
    
    Args:
        logger: The logger instance
        transaction_id: The transaction ID
        result: The processing result
        rule_ids: IDs of rules that were triggered
    """
    log_data = {
        'event': 'transaction_processed',
        'transaction_id': transaction_id,
        'timestamp': datetime.now().isoformat(),
        'result': result,
        'rule_ids': rule_ids or []
    }
    
    logger.info(f"Transaction processed: {json.dumps(log_data)}")

def log_rule_triggered(logger, rule_id, transaction_id, score, details=None):
    """
    Log a rule trigger event.
    
    Args:
        logger: The logger instance
        rule_id: The rule ID
        transaction_id: The transaction ID
        score: The risk score
        details: Additional details about the trigger
    """
    log_data = {
        'event': 'rule_triggered',
        'rule_id': rule_id,
        'transaction_id': transaction_id,
        'timestamp': datetime.now().isoformat(),
        'score': score,
        'details': details or {}
    }
    
    logger.info(f"Rule triggered: {json.dumps(log_data)}")

def log_alert_created(logger, alert_id, transaction_id, risk_level):
    """
    Log an alert creation event.
    
    Args:
        logger: The logger instance
        alert_id: The alert ID
        transaction_id: The transaction ID
        risk_level: The risk level
    """
    log_data = {
        'event': 'alert_created',
        'alert_id': alert_id,
        'transaction_id': transaction_id,
        'timestamp': datetime.now().isoformat(),
        'risk_level': risk_level
    }
    
    logger.info(f"Alert created: {json.dumps(log_data)}")

def log_error(logger, error_message, exception=None, context=None):
    """
    Log an error event with detailed information.
    
    Args:
        logger: The logger instance
        error_message: Description of the error
        exception: The exception object
        context: Additional context about when the error occurred
    """
    log_data = {
        'event': 'error',
        'timestamp': datetime.now().isoformat(),
        'error_message': error_message,
        'context': context or {}
    }
    
    if exception:
        log_data['exception_type'] = type(exception).__name__
        log_data['exception_message'] = str(exception)
        log_data['stacktrace'] = traceback.format_exc()
    
    logger.error(f"Error: {json.dumps(log_data)}")

def log_audit(logger, user, action, resource_id, details=None):
    """
    Log an audit event.
    
    Args:
        logger: The logger instance
        user: The user performing the action
        action: The action performed
        resource_id: The ID of the resource being acted upon
        details: Additional audit details
    """
    log_data = {
        'event': 'audit',
        'timestamp': datetime.now().isoformat(),
        'user': user,
        'action': action,
        'resource_id': resource_id,
        'details': details or {}
    }
    
    logger.info(f"Audit: {json.dumps(log_data)}")

"""
Cybersecurity Decision Support System - Logging Module
This module handles logging for audit trail and decision tracking.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any

# Log file configuration
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'cybersecurity_decisions.log')

def setup_logger():
    """
    Set up the logger for the cybersecurity decision support system.
    Creates log directory if it doesn't exist and configures logging format.
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    # Configure logger
    logger = logging.getLogger('cybersecurity_dss')
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # File handler for detailed logging
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Define log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Initialize logger
logger = setup_logger()

def log_incident_submission(incident_data: Dict[str, Any]):
    """
    Log incident submission details.
    
    Args:
        incident_data (dict): Dictionary containing incident information
    """
    log_message = (
        f"INCIDENT_SUBMITTED | "
        f"Attack Type: {incident_data.get('attack_type', 'Unknown')} | "
        f"Data Type: {incident_data.get('data_type', 'Unknown')} | "
        f"Impact Level: {incident_data.get('impact_level', 'Unknown')} | "
        f"Region: {incident_data.get('region', 'Unknown')} | "
        f"Risk Level: {incident_data.get('risk_level', 'Unknown')}"
    )
    logger.info(log_message)

def log_risk_assessment(incident_data: Dict[str, Any]):
    """
    Log risk assessment details.
    
    Args:
        incident_data (dict): Dictionary containing incident analysis results
    """
    log_message = (
        f"RISK_ASSESSMENT | "
        f"Risk Level: {incident_data.get('risk_level', 'Unknown')} | "
        f"Attack: {incident_data.get('attack_type', 'Unknown')} | "
        f"Impact: {incident_data.get('impact_level', 'Unknown')} | "
        f"Data: {incident_data.get('data_type', 'Unknown')}"
    )
    logger.info(log_message)

def log_cia_impact(incident_data: Dict[str, Any]):
    """
    Log CIA triad impact assessment.
    
    Args:
        incident_data (dict): Dictionary containing incident analysis results
    """
    cia_impact = incident_data.get('cia_impact', {})
    log_message = (
        f"CIA_IMPACT | "
        f"Attack: {incident_data.get('attack_type', 'Unknown')} | "
        f"Confidentiality: {cia_impact.get('confidentiality', 'Unknown')} | "
        f"Integrity: {cia_impact.get('integrity', 'Unknown')} | "
        f"Availability: {cia_impact.get('availability', 'Unknown')}"
    )
    logger.info(log_message)

def log_security_actions(incident_data: Dict[str, Any]):
    """
    Log recommended security actions.
    
    Args:
        incident_data (dict): Dictionary containing incident analysis results
    """
    actions = incident_data.get('security_actions', [])
    attack_type = incident_data.get('attack_type', 'Unknown')
    
    log_message = f"SECURITY_ACTIONS | Attack: {attack_type} | Actions Count: {len(actions)}"
    logger.info(log_message)
    
    # Log each action separately for detailed audit trail
    for i, action in enumerate(actions, 1):
        logger.info(f"ACTION_{i} | {action}")

def log_compliance_check(incident_data: Dict[str, Any]):
    """
    Log compliance requirements check.
    
    Args:
        incident_data (dict): Dictionary containing incident analysis results
    """
    compliance = incident_data.get('compliance')
    region = incident_data.get('region', 'Unknown')
    data_type = incident_data.get('data_type', 'Unknown')
    
    if compliance:
        log_message = (
            f"COMPLIANCE_REQUIRED | "
            f"Region: {region} | "
            f"Data Type: {data_type} | "
            f"Framework: {compliance.get('framework', 'Unknown')} | "
            f"Requirement: {compliance.get('requirement', 'Unknown')}"
        )
    else:
        log_message = (
            f"NO_COMPLIANCE | "
            f"Region: {region} | "
            f"Data Type: {data_type}"
        )
    
    logger.info(log_message)

def log_database_operation(operation: str, incident_id: int = None, success: bool = True):
    """
    Log database operations.
    
    Args:
        operation (str): Type of database operation
        incident_id (int): ID of the incident (if applicable)
        success (bool): Whether the operation was successful
    """
    status = "SUCCESS" if success else "FAILED"
    id_info = f"ID: {incident_id}" if incident_id else "No ID"
    
    log_message = f"DATABASE_{operation} | {status} | {id_info}"
    logger.info(log_message)

def log_system_event(event_type: str, message: str):
    """
    Log system events and errors.
    
    Args:
        event_type (str): Type of event (INFO, WARNING, ERROR)
        message (str): Event message
    """
    log_message = f"SYSTEM_EVENT | {event_type} | {message}"
    
    if event_type == "ERROR":
        logger.error(log_message)
    elif event_type == "WARNING":
        logger.warning(log_message)
    else:
        logger.info(log_message)

def log_user_action(action: str, details: str = ""):
    """
    Log user interactions with the system.
    
    Args:
        action (str): Action performed by user
        details (str): Additional details about the action
    """
    log_message = f"USER_ACTION | {action}"
    if details:
        log_message += f" | {details}"
    
    logger.info(log_message)

def log_complete_analysis(incident_data: Dict[str, Any]):
    """
    Log the complete incident analysis process.
    
    Args:
        incident_data (dict): Dictionary containing complete incident analysis
    """
    logger.info("=" * 80)
    logger.info("COMPLETE INCIDENT ANALYSIS STARTED")
    
    # Log each step of the analysis
    log_incident_submission(incident_data)
    log_risk_assessment(incident_data)
    log_cia_impact(incident_data)
    log_security_actions(incident_data)
    log_compliance_check(incident_data)
    
    logger.info("COMPLETE INCIDENT ANALYSIS COMPLETED")
    logger.info("=" * 80)

def get_log_summary(lines: int = 50) -> list:
    """
    Get recent log entries for display.
    
    Args:
        lines (int): Number of recent lines to retrieve
    
    Returns:
        list: Recent log entries
    """
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as file:
                log_lines = file.readlines()
                return log_lines[-lines:] if len(log_lines) > lines else log_lines
        else:
            return ["No log file found"]
    except Exception as e:
        return [f"Error reading log file: {str(e)}"]

def clear_logs():
    """
    Clear the log file (for testing or maintenance purposes).
    """
    try:
        if os.path.exists(LOG_FILE):
            open(LOG_FILE, 'w').close()
            logger.info("Log file cleared successfully")
        else:
            logger.info("No log file to clear")
    except Exception as e:
        logger.error(f"Error clearing log file: {str(e)}")

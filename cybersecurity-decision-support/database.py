"""
Cybersecurity Decision Support System - Database Module
This module handles SQLite database operations for storing incident details and recommendations.
"""

import sqlite3
import json
from datetime import datetime
import os

# Database file path
DB_FILE = 'cybersecurity_incidents.db'

def initialize_database():
    """
    Initialize the SQLite database and create required tables.
    Creates incidents table if it doesn't exist.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create incidents table with enhanced compliance fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                data_type TEXT NOT NULL,
                impact_level TEXT NOT NULL,
                region TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                cia_impact TEXT NOT NULL,
                security_actions TEXT NOT NULL,
                compliance TEXT,
                compliance_framework TEXT,
                law_reference TEXT,
                penalties TEXT,
                jurisdiction TEXT,
                incident_status TEXT DEFAULT 'Open'
            )
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise

def store_incident(incident_data):
    """
    Store incident details and analysis results in the database.
    
    Args:
        incident_data (dict): Dictionary containing all incident analysis results
    
    Returns:
        int: ID of the inserted record
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Convert complex objects to JSON strings for storage
        cia_impact_json = json.dumps(incident_data['cia_impact'])
        security_actions_json = json.dumps(incident_data['security_actions'])
        compliance_json = json.dumps(incident_data['compliance']) if incident_data['compliance'] else None
        
        # Extract compliance details for separate storage
        compliance_framework = incident_data['compliance']['framework'] if incident_data['compliance'] else None
        law_reference = incident_data['compliance']['law_reference'] if incident_data['compliance'] else None
        penalties = incident_data['compliance']['penalties'] if incident_data['compliance'] else None
        jurisdiction = incident_data['compliance']['jurisdiction'] if incident_data['compliance'] else None
        
        # Insert incident record with enhanced compliance fields
        cursor.execute('''
            INSERT INTO incidents (
                timestamp, attack_type, data_type, impact_level, region,
                risk_level, cia_impact, security_actions, compliance,
                compliance_framework, law_reference, penalties, jurisdiction
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            incident_data['attack_type'],
            incident_data['data_type'],
            incident_data['impact_level'],
            incident_data['region'],
            incident_data['risk_level'],
            cia_impact_json,
            security_actions_json,
            compliance_json,
            compliance_framework,
            law_reference,
            penalties,
            jurisdiction
        ))
        
        incident_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return incident_id
        
    except sqlite3.Error as e:
        print(f"Database error while storing incident: {e}")
        raise

def get_incident_history(limit=50):
    """
    Retrieve incident history from the database.
    
    Args:
        limit (int): Maximum number of records to retrieve
    
    Returns:
        list: List of incident records
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, attack_type, data_type, impact_level, 
                   region, risk_level, incident_status, compliance_framework,
                   law_reference, penalties, jurisdiction
            FROM incidents 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        records = cursor.fetchall()
        conn.close()
        
        return records
        
    except sqlite3.Error as e:
        print(f"Database error while retrieving history: {e}")
        return []

def get_incident_details(incident_id):
    """
    Retrieve detailed information for a specific incident.
    
    Args:
        incident_id (int): ID of the incident to retrieve
    
    Returns:
        dict: Detailed incident information
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM incidents WHERE id = ?
        ''', (incident_id,))
        
        record = cursor.fetchone()
        conn.close()
        
        if record:
            # Convert JSON strings back to Python objects
            cia_impact = json.loads(record[7]) if record[7] else {}
            security_actions = json.loads(record[8]) if record[8] else []
            compliance = json.loads(record[9]) if record[9] else None
            
            return {
                'id': record[0],
                'timestamp': record[1],
                'attack_type': record[2],
                'data_type': record[3],
                'impact_level': record[4],
                'region': record[5],
                'risk_level': record[6],
                'cia_impact': cia_impact,
                'security_actions': security_actions,
                'compliance': compliance,
                'compliance_framework': record[10],
                'law_reference': record[11],
                'penalties': record[12],
                'jurisdiction': record[13],
                'incident_status': record[14]
            }
        else:
            return None
            
    except sqlite3.Error as e:
        print(f"Database error while retrieving incident details: {e}")
        return None

def update_incident_status(incident_id, status):
    """
    Update the status of an incident.
    
    Args:
        incident_id (int): ID of the incident to update
        status (str): New status value
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE incidents 
            SET incident_status = ? 
            WHERE id = ?
        ''', (status, incident_id))
        
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error while updating status: {e}")
        raise

def get_incident_statistics():
    """
    Get statistical summary of incidents.
    
    Returns:
        dict: Statistics including total incidents, by risk level, by attack type
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Total incidents
        cursor.execute('SELECT COUNT(*) FROM incidents')
        total_incidents = cursor.fetchone()[0]
        
        # Incidents by risk level
        cursor.execute('''
            SELECT risk_level, COUNT(*) 
            FROM incidents 
            GROUP BY risk_level
        ''')
        by_risk_level = dict(cursor.fetchall())
        
        # Incidents by attack type
        cursor.execute('''
            SELECT attack_type, COUNT(*) 
            FROM incidents 
            GROUP BY attack_type
        ''')
        by_attack_type = dict(cursor.fetchall())
        
        # Recent incidents (last 7 days)
        cursor.execute('''
            SELECT COUNT(*) FROM incidents 
            WHERE timestamp >= datetime('now', '-7 days')
        ''')
        recent_incidents = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_incidents': total_incidents,
            'by_risk_level': by_risk_level,
            'by_attack_type': by_attack_type,
            'recent_incidents': recent_incidents
        }
        
    except sqlite3.Error as e:
        print(f"Database error while getting statistics: {e}")
        return {
            'total_incidents': 0,
            'by_risk_level': {},
            'by_attack_type': {},
            'recent_incidents': 0
        }

def delete_incident(incident_id):
    """
    Delete an incident from the database.
    
    Args:
        incident_id (int): ID of the incident to delete
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM incidents WHERE id = ?', (incident_id,))
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error while deleting incident: {e}")
        raise

# Initialize database when module is imported
if not os.path.exists(DB_FILE):
    initialize_database()

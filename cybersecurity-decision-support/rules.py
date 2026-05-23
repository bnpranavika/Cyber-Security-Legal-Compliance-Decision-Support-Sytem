"""
Cybersecurity Decision Support System - Rules Engine
This module contains the core logic for assessing cyber incidents and recommending response actions.
"""

# Attack types classification
ATTACK_TYPES = {
    'phishing': 'Phishing',
    'malware': 'Malware', 
    'ransomware': 'Ransomware',
    'data_breach': 'Data Breach',
    'unauthorized_access': 'Unauthorized Access',
    'ddos': 'DDoS'
}

# Data types classification
DATA_TYPES = {
    'personal': 'Personal',
    'financial': 'Financial',
    'health': 'Health',
    'credentials': 'Credentials',
    'none': 'None'
}

# Impact levels
IMPACT_LEVELS = {
    'low': 'Low',
    'medium': 'Medium',
    'high': 'High'
}

# Regions
REGIONS = {
    'india': 'India',
    'eu': 'EU',
    'usa': 'USA'
}

# Risk assessment rules
def assess_risk(attack_type, data_type, impact_level):
    """
    Assess risk level based on attack type, data type, and impact level.
    High impact + sensitive data = High risk
    Medium impact = Medium risk
    Low impact = Low risk
    """
    sensitive_data = ['personal', 'financial', 'health', 'credentials']
    
    if impact_level == 'high' and data_type in sensitive_data:
        return 'High'
    elif impact_level == 'medium':
        return 'Medium'
    elif impact_level == 'high':
        return 'Medium'  # High impact without sensitive data
    else:
        return 'Low'

# CIA Triad Impact Mapping
CIA_IMPACT = {
    'data_breach': {
        'confidentiality': 'High',
        'integrity': 'Medium',
        'availability': 'Low'
    },
    'ransomware': {
        'confidentiality': 'Medium',
        'integrity': 'High',
        'availability': 'High'
    },
    'unauthorized_access': {
        'confidentiality': 'High',
        'integrity': 'High',
        'availability': 'Low'
    },
    'phishing': {
        'confidentiality': 'Medium',
        'integrity': 'Low',
        'availability': 'Low'
    },
    'malware': {
        'confidentiality': 'Medium',
        'integrity': 'High',
        'availability': 'Medium'
    },
    'ddos': {
        'confidentiality': 'Low',
        'integrity': 'Low',
        'availability': 'High'
    }
}

# Security Action Mapping
SECURITY_ACTIONS = {
    'data_breach': [
        'Isolate affected system from network',
        'Revoke all access credentials',
        'Preserve forensic evidence and logs',
        'Review and strengthen encryption',
        'Conduct data impact assessment',
        'Notify affected stakeholders'
    ],
    'phishing': [
        'Reset compromised credentials immediately',
        'Enable Multi-Factor Authentication (MFA)',
        'Conduct user awareness training',
        'Block malicious email domains',
        'Scan email system for threats',
        'Review email filtering rules'
    ],
    'ransomware': [
        'Disconnect affected systems from network',
        'Activate incident response plan',
        'Restore from clean backups',
        'Conduct thorough malware scan',
        'Document all recovery actions',
        'Review backup and recovery procedures'
    ],
    'unauthorized_access': [
        'Force password reset for all users',
        'Review and analyze access logs',
        'Enable enhanced monitoring',
        'Audit user permissions',
        'Implement principle of least privilege',
        'Review authentication mechanisms'
    ],
    'malware': [
        'Isolate infected systems',
        'Run comprehensive anti-malware scans',
        'Update all security signatures',
        'Patch vulnerable applications',
        'Monitor for lateral movement',
        'Review endpoint protection'
    ],
    'ddos': [
        'Activate DDoS mitigation service',
        'Implement rate limiting',
        'Block malicious IP addresses',
        'Monitor network traffic patterns',
        'Engage ISP for traffic filtering',
        'Review network architecture'
    ]
}

# Comprehensive Compliance Requirements Mapping with Actual Cyber Laws
COMPLIANCE_REQUIREMENTS = {
    # European Union Regulations
    ('eu', 'personal'): {
        'framework': 'GDPR (General Data Protection Regulation)',
        'law_reference': 'Article 33 & 34, EU Regulation 2016/679',
        'requirement': 'Mandatory breach notification within 72 hours',
        'action': 'Notify supervisory authority and affected individuals without undue delay',
        'penalties': 'Up to €20 million or 4% of global annual turnover',
        'jurisdiction': 'European Union',
        'effective_date': 'May 25, 2018'
    },
    ('eu', 'financial'): {
        'framework': 'MiFID II / GDPR',
        'law_reference': 'Directive 2014/65/EU, GDPR Article 33',
        'requirement': 'Immediate reporting to financial authorities',
        'action': 'Report to national competent authority and ESMA within 24 hours',
        'penalties': 'Up to €5 million or 2% of annual turnover',
        'jurisdiction': 'European Union',
        'effective_date': 'January 3, 2018'
    },
    ('eu', 'health'): {
        'framework': 'GDPR / E-Health Directive',
        'law_reference': 'Article 33 GDPR, Directive 2011/24/EU',
        'requirement': 'Health data breach notification within 72 hours',
        'action': 'Notify data protection authority and healthcare regulators',
        'penalties': 'Up to €10 million or 2% of global turnover',
        'jurisdiction': 'European Union',
        'effective_date': 'May 25, 2018'
    },
    
    # United States Federal Laws
    ('usa', 'personal'): {
        'framework': 'CCPA / CPA (State Privacy Laws)',
        'law_reference': 'California Consumer Privacy Act, Cal. Civ. Code § 1798.82',
        'requirement': 'Breach notification within 45 days (California)',
        'action': 'Notify affected consumers and state Attorney General',
        'penalties': 'Up to $7,500 per intentional violation',
        'jurisdiction': 'United States (Federal + State)',
        'effective_date': 'January 1, 2020'
    },
    ('usa', 'financial'): {
        'framework': 'GLBA + FFIEC + CISA',
        'law_reference': 'Gramm-Leach-Bliley Act, 15 U.S.C. § 6801',
        'requirement': 'Immediate notification to federal regulators',
        'action': 'Report to FTC, FFIEC, and financial institutions within 30 days',
        'penalties': 'Up to $100,000 per violation',
        'jurisdiction': 'United States',
        'effective_date': 'November 12, 1999'
    },
    ('usa', 'health'): {
        'framework': 'HIPAA + HITECH',
        'law_reference': 'Health Insurance Portability and Accountability Act, 45 C.F.R. § 164.408',
        'requirement': 'Breach notification within 60 days of discovery',
        'action': 'Notify HHS, affected individuals, and media (500+ affected)',
        'penalties': 'Up to $1.5 million per year per violation',
        'jurisdiction': 'United States',
        'effective_date': 'April 14, 2003'
    },
    ('usa', 'credentials'): {
        'framework': 'CISA + State Data Breach Laws',
        'law_reference': 'Cybersecurity Information Sharing Act 2015',
        'requirement': 'Report credential theft to CISA within 72 hours',
        'action': 'Share threat intelligence with federal agencies',
        'penalties': 'No direct penalties, but mandatory for federal contractors',
        'jurisdiction': 'United States',
        'effective_date': 'December 18, 2015'
    },
    
    # Indian Cyber Laws
    ('india', 'personal'): {
        'framework': 'DPDP Act 2023 + IT Act 2000',
        'law_reference': 'Digital Personal Data Protection Act, Section 8(5)',
        'requirement': 'Report data breach to Data Protection Board within 72 hours',
        'action': 'Notify affected individuals and Data Protection Board of India',
        'penalties': 'Up to ₹250 crore (approximately $3.3 million)',
        'jurisdiction': 'India',
        'effective_date': 'August 1, 2023'
    },
    ('india', 'financial'): {
        'framework': 'RBI Master Direction + IT Act',
        'law_reference': 'RBI Master Direction on Cyber Security, 2016',
        'requirement': 'Report to RBI within 6 hours of major incident',
        'action': 'Notify RBI, CERT-In, and affected customers immediately',
        'penalties': 'Up to ₹10 crore per day of non-compliance',
        'jurisdiction': 'India',
        'effective_date': 'April 2, 2016'
    },
    ('india', 'health'): {
        'framework': 'Digital Information Security in Healthcare Act (DISHA)',
        'law_reference': 'DISHA Bill, Section 23',
        'requirement': 'Report health data breach within 24 hours',
        'action': 'Notify Health Ministry and affected patients',
        'penalties': 'Up to ₹5 crore and imprisonment up to 3 years',
        'jurisdiction': 'India',
        'effective_date': 'Pending (Bill under consideration)'
    },
    ('india', 'credentials'): {
        'framework': 'IT Act 2000 + CERT-In Rules',
        'law_reference': 'Information Technology Rules, 2021',
        'requirement': 'Report to CERT-In within 6 hours of discovery',
        'action': 'File incident report with CERT-In and preserve digital evidence',
        'penalties': 'Up to ₹1 lakh per day of delay',
        'jurisdiction': 'India',
        'effective_date': 'June 25, 2021'
    },
    
    # Additional Cross-Border Compliance
    ('eu', 'credentials'): {
        'framework': 'NIS2 Directive + GDPR',
        'law_reference': 'Directive (EU) 2022/2555',
        'requirement': 'Report security incidents within 24 hours',
        'action': 'Notify national CSIRT and implement risk management measures',
        'penalties': 'Up to €10 million or 2% of global turnover',
        'jurisdiction': 'European Union',
        'effective_date': 'October 16, 2024'
    },
    ('usa', 'none'): {
        'framework': 'CISA Cyber Incident Reporting',
        'law_reference': 'Cyber Incident Reporting for Critical Infrastructure Act 2022',
        'requirement': 'Report significant cyber incidents within 72 hours',
        'action': 'Submit detailed report to CISA',
        'penalties': 'Civil penalties up to $10,000 per day',
        'jurisdiction': 'United States',
        'effective_date': 'March 15, 2023'
    },
    ('india', 'none'): {
        'framework': 'IT Act 2000 Section 70',
        'law_reference': 'Information Technology Act, 2000',
        'requirement': 'Report cyber terrorism incidents immediately',
        'action': 'Notify CERT-In and law enforcement agencies',
        'penalties': 'Imprisonment up to 10 years and fine',
        'jurisdiction': 'India',
        'effective_date': 'October 17, 2000'
    }
}

def get_cia_impact(attack_type):
    """Get CIA triad impact for the given attack type."""
    return CIA_IMPACT.get(attack_type, {
        'confidentiality': 'Unknown',
        'integrity': 'Unknown', 
        'availability': 'Unknown'
    })

def get_security_actions(attack_type):
    """Get recommended security actions for the given attack type."""
    return SECURITY_ACTIONS.get(attack_type, ['No specific actions available'])

def get_compliance_requirement(region, data_type):
    """Get compliance requirements based on region and data type."""
    return COMPLIANCE_REQUIREMENTS.get((region, data_type), None)

def analyze_incident(attack_type, data_type, impact_level, region):
    """
    Complete incident analysis function.
    Returns a dictionary with all analysis results.
    """
    # Assess risk level
    risk_level = assess_risk(attack_type, data_type, impact_level)
    
    # Get CIA impact
    cia_impact = get_cia_impact(attack_type)
    
    # Get security actions
    security_actions = get_security_actions(attack_type)
    
    # Get compliance requirements
    compliance = get_compliance_requirement(region, data_type)
    
    # Return comprehensive analysis
    return {
        'risk_level': risk_level,
        'cia_impact': cia_impact,
        'security_actions': security_actions,
        'compliance': compliance,
        'attack_type': attack_type,
        'data_type': data_type,
        'impact_level': impact_level,
        'region': region
    }

def format_cia_impact(cia_impact):
    """Format CIA impact for display."""
    formatted = []
    for principle, level in cia_impact.items():
        formatted.append(f"{principle.capitalize()} – {level}")
    return formatted

def format_compliance(compliance):
    """Format compliance information for display."""
    if not compliance:
        return "No specific compliance requirements"
    
    return [
        f"Framework: {compliance['framework']}",
        f"Law Reference: {compliance['law_reference']}",
        f"Requirement: {compliance['requirement']}",
        f"Action: {compliance['action']}",
        f"Penalties: {compliance['penalties']}",
        f"Jurisdiction: {compliance['jurisdiction']}",
        f"Effective Date: {compliance['effective_date']}"
    ]

# Cybersecurity Decision Support System

A beginner-friendly web-based tool that analyzes cyber incident details and recommends technical cybersecurity response actions along with relevant compliance requirements.

## 🎯 Purpose

This system simulates a Security Operations Center (SOC) decision-support tool that converts cyber incident details into structured response actions aligned with cybersecurity frameworks (NIST CSF).

## 🏗️ Project Structure

```
cybersecurity-decision-support/
├── app.py              # Streamlit UI application
├── rules.py            # Security decision logic and rules engine
├── database.py         # SQLite database operations
├── logger.py           # Logging and audit trail functionality
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

## 🚀 Features

### Core Functionality
- **Incident Analysis**: Analyze cyber incidents based on attack type, data affected, impact level, and region
- **Risk Assessment**: Automatic risk level calculation (Low, Medium, High)
- **CIA Triad Mapping**: Confidentiality, Integrity, Availability impact assessment
- **Security Actions**: Recommended cybersecurity response actions for each attack type
- **Compliance Requirements**: Region-specific compliance framework mapping
- **Data Storage**: SQLite database for incident history and tracking
- **Audit Trail**: Comprehensive logging of all decisions and actions

### Attack Types Supported
- Phishing
- Malware
- Ransomware
- Data Breach
- Unauthorized Access
- DDoS

### Compliance Frameworks
- **GDPR** (EU region with personal data)
- **IT Act / DPDP** (India region with personal data)
- **CISA Guidance** (USA region with financial data)
- **HIPAA** (USA region with health data)
- **RBI Guidelines** (India region with financial data)

## 📋 Requirements

- Python 3.7 or higher
- Streamlit
- Pandas
- SQLite (included with Python)

## 🛠️ Installation and Setup

1. **Clone or download the project** to your local machine

2. **Navigate to the project directory**:
   ```bash
   cd cybersecurity-decision-support
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   streamlit run app.py
   ```

5. **Open your browser** and navigate to the URL shown (usually `http://localhost:8501`)

## 📖 How to Use

### 1. Incident Analysis
- Fill in the incident details form:
  - **Attack Type**: Select the type of cyber attack
  - **Data Type Affected**: Choose the type of data compromised
  - **Impact Level**: Assess the business impact (Low, Medium, High)
  - **Organization Region**: Select your organization's region
- Click "Analyze Incident" to get recommendations

### 2. View Results
The system will provide:
- **Risk Level**: Calculated based on impact and data sensitivity
- **CIA Impact**: Confidentiality, Integrity, Availability assessment
- **Recommended Actions**: Specific cybersecurity response steps
- **Compliance Requirements**: Applicable regulatory requirements
- **Incident ID**: Unique identifier for tracking

### 3. Incident History
- View all past incidents in a tabular format
- Access detailed information for each incident
- Update incident status (Open, In Progress, Resolved, Closed)

### 4. Dashboard
- View key metrics and statistics
- Analyze incident trends by risk level and attack type
- Monitor recent activity (last 7 days)

### 5. System Logs
- Review audit trail of all system activities
- Track decision-making process
- Monitor system health and errors

## 🔧 Technical Details

### Risk Assessment Logic
- **High Risk**: High impact + sensitive data (Personal, Financial, Health, Credentials)
- **Medium Risk**: Medium impact OR High impact without sensitive data
- **Low Risk**: Low impact

### CIA Triad Mapping Examples
- **Data Breach**: Confidentiality = High
- **Ransomware**: Availability = High
- **Unauthorized Access**: Confidentiality + Integrity = High

### Security Action Examples
- **Data Breach**: Isolate system, revoke access, preserve logs, encryption review
- **Phishing**: Reset credentials, enable MFA, user awareness training
- **Ransomware**: Disconnect from network, restore from backup, malware scan

## 📊 Data Storage

The system uses SQLite to store:
- Incident details and timestamps
- Risk assessment results
- Recommended actions
- Compliance requirements
- Incident status updates

Database file: `cybersecurity_incidents.db` (created automatically)

## 📝 Logging

Comprehensive audit trail maintained in:
- File: `logs/cybersecurity_decisions.log`
- Console output for immediate feedback
- Structured logging format with timestamps
- Tracks all user actions, decisions, and system events

## 🔒 Security Considerations

- All data is stored locally on your machine
- No external API calls or data transmission
- No sensitive information is logged
- Database and log files are created in the project directory
- Suitable for training and demonstration purposes

## 🚨 Important Notes

- This is a **training and educational tool**
- **Not a replacement for professional cybersecurity services**
- Compliance information is for **guidance only**
- Always consult with legal and cybersecurity professionals for real incidents
- The system provides **technical recommendations**, not legal advice

## 🤝 Contributing

This project is designed for educational purposes. Feel free to:
- Extend the rule engine with additional attack types
- Add more compliance frameworks
- Enhance the UI with additional features
- Integrate with other security tools

## 📄 License

This project is provided for educational purposes. Use responsibly and in accordance with your organization's security policies.

## 🆘 Troubleshooting

### Common Issues

1. **Port already in use**:
   ```bash
   streamlit run app.py --server.port 8502
   ```

2. **Module not found**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Database errors**:
   - Delete `cybersecurity_incidents.db` and restart the application
   - Ensure write permissions in the project directory

4. **Log file errors**:
   - Check that the `logs/` directory has write permissions
   - Delete old log files if they become too large

### Getting Help

- Check the system logs for detailed error messages
- Ensure all dependencies are properly installed
- Verify Python version compatibility (3.7+)

---

**⚠️ Disclaimer**: This tool is for educational and training purposes only. It does not provide legal advice and should not be used as a substitute for professional cybersecurity services or legal consultation.

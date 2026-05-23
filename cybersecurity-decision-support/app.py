"""
Cybersecurity Decision Support System - Streamlit UI
This module provides the web interface for the cybersecurity incident response system.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our custom modules
from rules import (
    ATTACK_TYPES, DATA_TYPES, IMPACT_LEVELS, REGIONS,
    analyze_incident, format_cia_impact, format_compliance
)
from database import (
    initialize_database, store_incident, get_incident_history, 
    get_incident_details, update_incident_status, get_incident_statistics
)
from logger import (
    log_user_action, log_complete_analysis, log_database_operation,
    log_system_event, get_log_summary
)

# Configure Streamlit page
st.set_page_config(
    page_title="Cybersecurity Decision Support System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Fun and engaging CSS for better styling and visibility
def apply_custom_css():
    st.markdown("""
    <style>
        /* Animated gradient background */
        .stApp {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        /* Main header with animation */
        .main-header {
            font-size: 2.5rem;
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4, #45B7D1, #96CEB4);
            background-size: 400% 400%;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            margin-bottom: 2rem;
            animation: gradientShift 3s ease infinite;
            font-weight: bold;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        /* Risk level with pulsing animation */
        .risk-high {
            color: #ff4757;
            font-weight: bold;
            font-size: 1.2rem;
            animation: pulse 2s infinite;
        }
        .risk-medium {
            color: #ffa502;
            font-weight: bold;
            font-size: 1.2rem;
            animation: pulse 2.5s infinite;
        }
        .risk-low {
            color: #26de81;
            font-weight: bold;
            font-size: 1.2rem;
            animation: pulse 3s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        /* Fun box styles with hover effects */
        .action-box {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 1.2rem;
            border-radius: 15px;
            margin: 0.5rem 0;
            border: 2px solid #dee2e6;
            color: #212529;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .action-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2);
        }
        
        .compliance-box {
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            padding: 1.2rem;
            border-radius: 15px;
            margin: 0.5rem 0;
            border-left: 5px solid #28a745;
            color: #155724;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .compliance-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(40, 167, 69, 0.3);
        }
        
        .cia-box {
            background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
            padding: 1.2rem;
            border-radius: 15px;
            margin: 0.5rem 0;
            border-left: 5px solid #ffc107;
            color: #856404;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .cia-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(255, 193, 7, 0.3);
        }
        
        /* Bold text styling */
        .cia-box strong {
            color: #533f03;
            font-weight: 700;
        }
        .action-box strong {
            color: #343a40;
            font-weight: 700;
        }
        .compliance-box strong {
            color: #0d5320;
            font-weight: 700;
        }
        
        /* Fun button styling */
        .stButton > button {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(102, 126, 234, 0.4);
            background: linear-gradient(45deg, #764ba2, #667eea);
        }
        
        /* Form styling */
        .stSelectbox > div > div > select {
            color: #212529;
            border-radius: 10px;
        }
        
        /* Expander styling */
        .streamlit-expanderHeader {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            color: #495057;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        
        /* Sidebar styling */
        .css-1d391kg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        /* Success message animation */
        .stSuccess {
            animation: slideIn 0.5s ease;
        }
        
        @keyframes slideIn {
            from { transform: translateX(-100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        /* Loading spinner fun */
        .stSpinner > div {
            border-top-color: #667eea !important;
        }
        
        /* Card-like containers */
        div[data-testid="stVerticalBlock"] > div[style*="padding: 1rem"] {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            margin: 0.5rem 0;
        }
    </style>
    """, unsafe_allow_html=True)

def main():
    """Main application function."""
    apply_custom_css()
    
    # Initialize database
    try:
        initialize_database()
    except Exception as e:
        st.error(f"Database initialization error: {e}")
        log_system_event("ERROR", f"Database initialization failed: {e}")
        return
    
    # Sidebar navigation with fun emojis and animations
    st.sidebar.title("� CyberGuard DSS")
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🎯 Navigate to:")
    
    # Fun navigation options with emojis
    pages = {
        "🔍 Incident Analysis": "Incident Analysis",
        "📚 Incident History": "Incident History", 
        "📊 Dashboard": "Dashboard",
        "📋 System Logs": "System Logs"
    }
    
    selected_page = st.sidebar.selectbox(
        "Choose your adventure:",
        options=list(pages.keys()),
        format_func=lambda x: x
    )
    
    page = pages[selected_page]
    
    # Add fun sidebar elements
    st.sidebar.markdown("---")
    st.sidebar.markdown("### � Quick Stats:")
    
    # Get statistics for sidebar
    stats = get_incident_statistics()
    st.sidebar.markdown(f"📊 Total Incidents: {stats['total_incidents']}")
    st.sidebar.markdown(f"� High Risk: {stats['by_risk_level'].get('High', 0)}")
    st.sidebar.markdown(f"✅ Low Risk: {stats['by_risk_level'].get('Low', 0)}")
    
    # Random cyber security tip
    import random
    tips = [
        "💡 Tip: Always use MFA!",
        "🔐 Tip: Update passwords regularly!",
        "🛡️ Tip: Backup your data!",
        "🚨 Tip: Report suspicious activity!",
        "🔒 Tip: Use HTTPS everywhere!"
    ]
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"### 💬 {random.choice(tips)}")
    
    if page == "Incident Analysis":
        show_incident_analysis()
    elif page == "Incident History":
        show_incident_history()
    elif page == "Dashboard":
        show_dashboard()
    elif page == "System Logs":
        show_system_logs()

def show_incident_analysis():
    """Display the incident analysis page with fun elements."""
    st.markdown('<h1 class="main-header">� Cybersecurity Incident Analysis</h1>', 
                unsafe_allow_html=True)
    
    # Fun welcome message
    st.markdown("### 🚀 Let's analyze your cyber incident!")
    st.markdown("🎯 Fill in the details below and watch the magic happen! ✨")
    
    st.markdown("---")
    
    # Input form with fun styling
    with st.form("incident_form"):
        st.markdown("### 📝 Incident Details 🎨")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🎭 Attack Type")
            attack_type = st.selectbox(
                "Choose your attacker's style:",
                options=list(ATTACK_TYPES.keys()),
                format_func=lambda x: ATTACK_TYPES[x],
                help="Select the type of cyber attack",
                index=0
            )
            
            st.markdown("#### 📊 Data Type")
            data_type = st.selectbox(
                "What got compromised?",
                options=list(DATA_TYPES.keys()),
                format_func=lambda x: DATA_TYPES[x],
                help="Select the type of data compromised",
                index=0
            )
        
        with col2:
            st.markdown("#### 💥 Impact Level")
            impact_level = st.selectbox(
                "How bad is it?",
                options=list(IMPACT_LEVELS.keys()),
                format_func=lambda x: IMPACT_LEVELS[x],
                help="Select the business impact level",
                index=0
            )
            
            st.markdown("#### 🌍 Region")
            region = st.selectbox(
                "Where are you located?",
                options=list(REGIONS.keys()),
                format_func=lambda x: REGIONS[x],
                help="Select your organization's region",
                index=0
            )
        
        submitted = st.form_submit_button("🔍 Analyze Incident", use_container_width=True)
        
        if submitted:
            # Fun loading message
            st.balloons()
            st.markdown("### 🎉 Analyzing your incident... 🚀")
            
            # Log user action
            log_user_action("INCIDENT_ANALYSIS", 
                          f"Attack: {attack_type}, Data: {data_type}, Impact: {impact_level}, Region: {region}")
            
            # Perform analysis
            with st.spinner("🔮 Consulting our cyber crystal ball..."):
                try:
                    analysis_result = analyze_incident(attack_type, data_type, impact_level, region)
                    
                    # Store in database
                    incident_id = store_incident(analysis_result)
                    log_database_operation("STORE", incident_id, True)
                    
                    # Log complete analysis
                    log_complete_analysis(analysis_result)
                    
                    # Store results in session state for display outside form
                    st.session_state.current_analysis = analysis_result
                    st.session_state.current_incident_id = incident_id
                    
                    # Celebration message
                    st.success("🎊 Analysis complete! Check out your results below! 🎊")
                    
                except Exception as e:
                    st.error(f"❌ Oops! Analysis failed: {e}")
                    log_system_event("ERROR", f"Incident analysis failed: {e}")
    
    # Display analysis results outside the form
    if 'current_analysis' in st.session_state and 'current_incident_id' in st.session_state:
        display_analysis_results(st.session_state.current_analysis, st.session_state.current_incident_id)

def display_analysis_results(analysis_result, incident_id):
    """Display the analysis results in a fun and formatted way."""
    st.markdown("---")
    st.markdown("### 🎊 Analysis Results 🎉")
    
    # Risk Level with fun emoji
    risk_class = f"risk-{analysis_result['risk_level'].lower()}"
    risk_emoji = {"High": "🚨", "Medium": "⚠️", "Low": "✅"}
    st.markdown(f"### {risk_emoji.get(analysis_result['risk_level'], '�')} Risk Level: <span class='{risk_class}'>{analysis_result['risk_level']}</span>", 
                unsafe_allow_html=True)
    
    # CIA Impact with fun styling
    st.markdown("### 🎯 CIA Triad Impact 🎨")
    cia_formatted = format_cia_impact(analysis_result['cia_impact'])
    cia_html = "<div class='cia-box'>"
    for item in cia_formatted:
        parts = item.split(' – ')
        if len(parts) == 2:
            cia_html += f"• <strong>{parts[0]}</strong> – {parts[1]}<br>"
        else:
            cia_html += f"• <strong>{item}</strong><br>"
    cia_html += "</div>"
    st.markdown(cia_html, unsafe_allow_html=True)
    
    # Recommended Actions with fun styling
    st.markdown("### 🛡️ Recommended Cybersecurity Actions 🚀")
    actions_html = "<div class='action-box'>"
    for i, action in enumerate(analysis_result['security_actions'], 1):
        actions_html += f"<strong>{i}.</strong> {action}<br>"
    actions_html += "</div>"
    st.markdown(actions_html, unsafe_allow_html=True)
    
    # Compliance Requirements with Enhanced Display
    st.markdown("### ⚖️ Legal Compliance Requirements 📜")
    compliance_formatted = format_compliance(analysis_result['compliance'])
    compliance_html = "<div class='compliance-box'>"
    for item in compliance_formatted:
        if item.startswith("Framework:"):
            compliance_html += f"• <strong>{item}</strong><br>"
        elif item.startswith("Law Reference:"):
            compliance_html += f"• <strong>{item}</strong><br>"
        elif item.startswith("Penalties:"):
            compliance_html += f"• <strong>{item}</strong><br>"
        else:
            compliance_html += f"• {item}<br>"
    compliance_html += "</div>"
    st.markdown(compliance_html, unsafe_allow_html=True)
    
    # Additional compliance details if available
    if analysis_result['compliance']:
        with st.expander("📜 Detailed Legal Information 🔍"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Framework:** {analysis_result['compliance']['framework']}")
                st.write(f"**Jurisdiction:** {analysis_result['compliance']['jurisdiction']}")
                st.write(f"**Effective Date:** {analysis_result['compliance']['effective_date']}")
            with col2:
                st.write(f"**Law Reference:** {analysis_result['compliance']['law_reference']}")
                st.warning(f"**Potential Penalties:** {analysis_result['compliance']['penalties']}")
    
    # Incident ID and status with fun styling
    st.info(f"📋 Incident ID: {incident_id} | Status: Open 🆔")
    
    # Action buttons with fun emojis
    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Mark as Resolved", key=f"resolve_{incident_id}"):
            update_incident_status(incident_id, "Resolved")
            log_database_operation("UPDATE", incident_id, True)
            st.success("🎉 Incident marked as resolved! 🎉")
            st.balloons()
            st.rerun()
    
    with col2:
        if st.button("📋 View Details", key=f"details_{incident_id}"):
            st.session_state[f"show_details_{incident_id}"] = True
    
    # Show detailed information if requested
    if st.session_state.get(f"show_details_{incident_id}", False):
        show_detailed_incident_info(incident_id)

def show_detailed_incident_info(incident_id):
    """Display detailed incident information."""
    details = get_incident_details(incident_id)
    if details:
        st.markdown("---")
        st.subheader("📋 Detailed Incident Information")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Incident ID:** {details['id']}")
            st.write(f"**Timestamp:** {details['timestamp']}")
            st.write(f"**Attack Type:** {details['attack_type']}")
            st.write(f"**Data Type:** {details['data_type']}")
        
        with col2:
            st.write(f"**Impact Level:** {details['impact_level']}")
            st.write(f"**Region:** {details['region']}")
            st.write(f"**Risk Level:** {details['risk_level']}")
            st.write(f"**Status:** {details['incident_status']}")
        
        # Display compliance information if available
        if details.get('compliance_framework'):
            st.markdown("---")
            st.subheader("⚖️ Compliance Information")
            col3, col4 = st.columns(2)
            with col3:
                st.write(f"**Framework:** {details['compliance_framework']}")
                st.write(f"**Jurisdiction:** {details['jurisdiction']}")
            with col4:
                st.write(f"**Law Reference:** {details['law_reference']}")
                st.warning(f"**Penalties:** {details['penalties']}")

def show_incident_history():
    """Display the incident history page."""
    st.markdown('<h1 class="main-header">📚 Incident History</h1>', 
                unsafe_allow_html=True)
    
    # Get incident history
    incidents = get_incident_history(100)
    
    if incidents:
        # Convert to DataFrame for better display
        df = pd.DataFrame(incidents, columns=[
            'ID', 'Timestamp', 'Attack Type', 'Data Type', 
            'Impact Level', 'Region', 'Risk Level', 'Status',
            'Compliance Framework', 'Law Reference', 'Penalties', 'Jurisdiction'
        ])
        
        # Format timestamp for better readability
        df['Timestamp'] = pd.to_datetime(df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Display the table
        st.dataframe(df, use_container_width=True)
        
        # Incident details section
        st.markdown("---")
        st.subheader("🔍 View Incident Details")
        
        selected_id = st.selectbox(
            "Select Incident ID:",
            options=[incident[0] for incident in incidents],
            help="Select an incident to view detailed information"
        )
        
        if selected_id:
            details = get_incident_details(selected_id)
            if details:
                show_detailed_incident_info(selected_id)
                
                # Status update
                new_status = st.selectbox(
                    "Update Status:",
                    options=["Open", "In Progress", "Resolved", "Closed"],
                    index=["Open", "In Progress", "Resolved", "Closed"].index(details['incident_status'])
                )
                
                if st.button("Update Status") and new_status != details['incident_status']:
                    update_incident_status(selected_id, new_status)
                    log_database_operation("UPDATE", selected_id, True)
                    st.success(f"Incident {selected_id} status updated to {new_status}")
                    st.rerun()
    else:
        st.info("No incidents found in the database.")

def show_dashboard():
    """Display the dashboard with statistics."""
    st.markdown('<h1 class="main-header">📊 Dashboard</h1>', 
                unsafe_allow_html=True)
    
    # Get statistics
    stats = get_incident_statistics()
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Incidents", stats['total_incidents'])
    
    with col2:
        st.metric("Recent (7 days)", stats['recent_incidents'])
    
    with col3:
        high_risk = stats['by_risk_level'].get('High', 0)
        st.metric("High Risk", high_risk, delta=None)
    
    with col4:
        low_risk = stats['by_risk_level'].get('Low', 0)
        st.metric("Low Risk", low_risk, delta=None)
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Incidents by Risk Level")
        if stats['by_risk_level']:
            risk_data = pd.DataFrame(
                list(stats['by_risk_level'].items()),
                columns=['Risk Level', 'Count']
            )
            st.bar_chart(risk_data.set_index('Risk Level'))
        else:
            st.info("No data available")
    
    with col2:
        st.subheader("🎯 Incidents by Attack Type")
        if stats['by_attack_type']:
            attack_data = pd.DataFrame(
                list(stats['by_attack_type'].items()),
                columns=['Attack Type', 'Count']
            )
            st.bar_chart(attack_data.set_index('Attack Type'))
        else:
            st.info("No data available")

def show_system_logs():
    """Display system logs."""
    st.markdown('<h1 class="main-header">📋 System Logs</h1>', 
                unsafe_allow_html=True)
    
    # Log display options
    col1, col2 = st.columns([3, 1])
    
    with col2:
        num_lines = st.selectbox(
            "Number of lines:",
            options=[10, 25, 50, 100],
            index=2
        )
        
        if st.button("🔄 Refresh Logs"):
            st.rerun()
    
    with col1:
        log_entries = get_log_summary(num_lines)
        
        if log_entries:
            st.subheader(f"📝 Recent {len(log_entries)} Log Entries")
            
            # Display logs in a code block for better formatting
            log_text = "".join(log_entries)
            st.code(log_text, language=None)
        else:
            st.info("No log entries found.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"Application error: {e}")
        log_system_event("ERROR", f"Application startup failed: {e}")

import streamlit as st
import os
import hashlib
import re
import shutil
import json
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import requests
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Import API keys from config
import config

# --- 1. INTEGRATION ADAPTERS (Inline helpers for modularity) ---
from integrations.virustotal_lookup import check_file_reputation, check_url_reputation
from integrations.abuseip_lookup import check_ip_abuse
from integrations.ipinfo_lookup import get_ip_details

# --- 2. FORENSIC ENGINE MODULES ---

def calculate_hashes(file_path):
    """Calculate MD5 and SHA256 hashes of a file."""
    md5_hasher = hashlib.md5()
    sha256_hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
        return md5_hasher.hexdigest(), sha256_hasher.hexdigest()
    except Exception:
        return None, None

def scan_directory(directory):
    """Recursively scan a directory for files."""
    evidence_data = []
    max_size = 100 * 1024 * 1024  # 100MB limit
    if not os.path.exists(directory): return []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                if size > max_size: continue
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                md5, sha256 = calculate_hashes(file_path)
                evidence_data.append({
                    "name": file, "path": file_path, "size": size,
                    "modified_time": mtime, "md5": md5, "sha256": sha256
                })
            except Exception: continue
    return evidence_data

def extract_indicators(text):
    """Extract IP addresses, URLs, and Email addresses using regex."""
    if not text: return {"ips": [], "urls": [], "emails": []}
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    urls = list(set(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)))
    emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)))
    return {"ips": ips, "urls": urls, "emails": emails}

def calculate_risk_score(detections):
    """Score logic based on keywords, malicious hashes, IPs, and URLs."""
    score = 0
    if detections.get("keywords"): score += min(len(detections["keywords"]) * 10, 30)
    if detections.get("ips"): score += min(len(detections["ips"]) * 15, 30)
    if detections.get("urls"): score += min(len(detections["urls"]) * 10, 20)
    if detections.get("hashes"): score += 20
    score = min(score, 100)
    if score <= 20: level = "SAFE"
    elif score <= 50: level = "SUSPICIOUS"
    elif score <= 80: level = "HIGH RISK"
    else: level = "CRITICAL"
    return score, level

def generate_evidence_package(file_info, indicators, risk_data, api_results):
    """Package evidence into /evidence/ directory."""
    if not os.path.exists("evidence"): os.makedirs("evidence")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pkg_dir = os.path.join("evidence", f"evidence_{file_info['name']}_{timestamp}")
    os.makedirs(pkg_dir)
    try: shutil.copy2(file_info['path'], os.path.join(pkg_dir, file_info['name']))
    except: pass
    metadata = {
        "file": file_info['name'], "sha256": file_info['sha256'],
        "risk": risk_data, "indicators": indicators, "intel": api_results
    }
    with open(os.path.join(pkg_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)
    return pkg_dir

def create_report_pdf(res):
    """Generate a clean, tabular PDF report of the triage results."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    styles = getSampleStyleSheet()
    
    # Custom Heading Style
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.hexColor("#2c3e50"),
        spaceAfter=10,
        spaceBefore=15
    ))
    
    elements = []

    # Title & Header
    elements.append(Paragraph("🛡️ Cyber Forensic Triage Summary Report", styles['Title']))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Executive Summary Table
    elements.append(Paragraph("1. Executive Summary", styles['SectionHeader']))
    summary_data = [
        ["Metric", "Value"],
        ["Overall Risk Level", res['risk_level']],
        ["Risk Score", f"{res['risk_score']}/100"],
        ["Total Files Scanned", str(len(res["files"]))],
        ["Malicious Signals Detected", str(len(res["malicious_hashes"]) + len(res["malicious_ips"]) + len(res["malicious_urls"]))]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 250])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.hexColor("#1a1c24")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (1, 1), (1, 1), colors.red if res['risk_level'] in ['HIGH RISK', 'CRITICAL'] else colors.green),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # IP Intelligence Table
    if res["ip_intel"]:
        elements.append(Paragraph("2. Network Intelligence results", styles['SectionHeader']))
        intel_data = [["Detected IP", "Country", "Provider", "Threat Score"]]
        for item in res["ip_intel"]:
            intel_data.append([item.get("Detected IP"), item.get("Origin Country"), item.get("Provider (ISP)"), item.get("Threat Score")])
        
        intel_table = Table(intel_data, colWidths=[100, 100, 160, 90])
        intel_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.hexColor("#34495E")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(intel_table)
        elements.append(Spacer(1, 20))

    # Evidence Integrity Table
    elements.append(Paragraph("3. Evidence Integrity (Digital Fingerprints)", styles['SectionHeader']))
    h_data = [["File Name", "MD5 Hash", "SHA256 Hash"]]
    for f in res["findings"]:
        # Showing full hashes for forensic integrity
        h_data.append([f['file']['name'], f['file']['md5'], f['file']['sha256']])
    
    h_table = Table(h_data, colWidths=[130, 185, 235]) # Adjusted to fit full SHA256 (64 chars)
    h_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.hexColor("#34495E")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 0), (-1, -1), 7), # Slightly smaller font to fit full hashes
        ('FONTNAME', (0, 1), (-1, -1), 'Courier'), # Courier for fixed-width hashes
    ]))
    elements.append(h_table)
    elements.append(Spacer(1, 20))

    # High Risk Analysis
    suspicious_list = []
    for f in res["findings"]:
        reasons = []
        if f['keywords']: reasons.append(f"Suspicious Words: {', '.join(f['keywords'])}")
        if f['file']['sha256'] in res["malicious_hashes"]: reasons.append("Known Malicious Hash")
        
        intersect_ips = [ip for ip in f['indicators']['ips'] if ip in res["malicious_ips"]]
        if intersect_ips: reasons.append(f"Linked IPs: {', '.join(intersect_ips)}")
        
        if reasons:
            suspicious_list.append([f['file']['name'], "\n".join(reasons)])

    if suspicious_list:
        elements.append(Paragraph("4. High-Risk File Analysis Details", styles['SectionHeader']))
        susp_data = [["Flagged File", "Reasoning / Detection Signals"]] + suspicious_list
        susp_table = Table(susp_data, colWidths=[150, 300])
        susp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.hexColor("#C0392B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(susp_table)

    # Footer
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("<i>--- End of Forensic Triage Report ---</i>", styles['Normal']))

    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

# --- 3. STREAMLIT DASHBOARD UI ---

st.set_page_config(page_title="Forensic Triage PRO", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1a1c24; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    .risk-safe { color: #23d160; }
    .risk-suspicious { color: #ffdd57; }
    .risk-high { color: #ff3860; }
    .risk-critical { color: #ff0000; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Cyber Forensic TRIAGE System")
st.sidebar.title("Configuration")

# Persistent state initialization
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

if st.sidebar.button("Load Case Files"):
    st.session_state.target_folder = os.path.join(os.getcwd(), "demo_files")
else:
    if 'target_folder' not in st.session_state: st.session_state.target_folder = ""

folder_path = st.text_input("Enter Investigator Folder Path:", value=st.session_state.target_folder)

if st.button("🔎 Execute Triage Scan", type="primary"):
    if not folder_path or not os.path.exists(folder_path):
        st.error("Invalid path.")
    else:
        with st.spinner("Analyzing files and querying threat intelligence..."):
            files = scan_directory(folder_path)
            
            # Global analytics
            all_findings = []
            global_ips, global_urls = set(), set()
            malicious_hashes, malicious_ips, malicious_urls = [], [], []
            keyword_hits = set()
            
            KEYWORDS = ["backdoor", "beaconing", "payload", "c2", "unauthorized", "bypass", "exfiltrate", "malicious"]

            for f in files:
                # Content & Indicators
                content = ""
                if f['name'].endswith('.txt') or f['name'].endswith('.log'):
                    try:
                        with open(f['path'], 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read(50000)
                    except: pass
                
                indicators = extract_indicators(content)
                global_ips.update(indicators['ips'])
                global_urls.update(indicators['urls'])
                
                # Keyword check
                found_keys = [k for k in KEYWORDS if k in content.lower() or k in f['name'].lower()]
                keyword_hits.update(found_keys)
                
                # VT Hash Lookup
                vt_data = {}
                if f['sha256']:
                    vt_data = check_file_reputation(f['sha256'])
                    if vt_data and 'data' in vt_data:
                        if vt_data['data']['attributes']['last_analysis_stats'].get('malicious', 0) > 0:
                            malicious_hashes.append(f['sha256'])

                all_findings.append({
                    "file": f, "indicators": indicators, "keywords": found_keys, "vt": vt_data
                })

            # Multi-API IP/URL Intel
            ip_intel = []
            for ip in list(global_ips)[:5]:
                abuse = check_ip_abuse(ip)
                geo = get_ip_details(ip)
                score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                if score > 20: malicious_ips.append(ip)
                ip_intel.append({
                    "Detected IP": ip, "Origin Country": geo.get('country', 'N/A'), "Provider (ISP)": geo.get('org', 'N/A'), "Threat Score": f"{score}%"
                })
            
            for url in list(global_urls)[:5]:
                vt_url = check_url_reputation(url)
                if vt_url and 'data' in vt_url:
                    if vt_url['data']['attributes']['last_analysis_stats'].get('malicious', 0) > 0:
                        malicious_urls.append(url)

            # Final Scoring
            risk_score, risk_level = calculate_risk_score({
                "keywords": list(keyword_hits), "ips": malicious_ips, "urls": malicious_urls, "hashes": malicious_hashes
            })

            # Save to session state to prevent refresh issues
            st.session_state.scan_results = {
                "files": files,
                "findings": all_findings,
                "global_ips": global_ips,
                "global_urls": global_urls,
                "malicious_hashes": malicious_hashes,
                "malicious_ips": malicious_ips,
                "malicious_urls": malicious_urls,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "ip_intel": ip_intel,
                "keyword_hits": keyword_hits
            }

# Render Results from Session State
if st.session_state.scan_results:
    res = st.session_state.scan_results
    
    # PD-1: Risk Score Panel
    st.divider()
    
    col_score_header, col_download_btn = st.columns([3, 1])
    with col_score_header:
        st.subheader("📊 Triage Executive Summary")
    with col_download_btn:
        pdf_data = create_report_pdf(res)
        st.download_button(
            label="📥 Download Triage Report (PDF)",
            data=pdf_data,
            file_name=f"Forensic_Triage_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Overall System Risk", res["risk_level"])
    with c2: st.metric("Risk Score", f"{res['risk_score']}/100")
    with c3: st.metric("Malicious Signals", len(res["malicious_hashes"]) + len(res["malicious_ips"]) + len(res["malicious_urls"]))
    with c4: st.metric("Files Scanned", len(res["files"]))

    # PD-2: Indicator Table & IP Intel
    st.divider()
    col_l, col_r = st.columns(2)
    with col_l:
        st.subheader("📍 Forensic Indicators Discovered")
        ind_df = []
        for ip in res["global_ips"]: ind_df.append({"Type": "Address (IP)", "Value": ip})
        for url in res["global_urls"]: ind_df.append({"Type": "Link (URL)", "Value": url})
        st.dataframe(pd.DataFrame(ind_df) if ind_df else pd.DataFrame(columns=["Type", "Value"]), hide_index=True, use_container_width=True)
    
    with col_r:
        st.subheader("🌐 Global Intelligence Results")
        st.dataframe(pd.DataFrame(res["ip_intel"]) if res["ip_intel"] else pd.DataFrame(columns=["Detected IP", "Origin Country", "ISP", "Threat Score"]), hide_index=True, use_container_width=True)

    # PD-3: File Integrity Section
    st.divider()
    st.subheader("🔑 Evidence Verification (Digital Fingerprints)")
    st.info("💡 **For Non-Coders:** Digital fingerprints are unique IDs. If even one letter in a file is changed, the ID changes completely. This proves the evidence wasn't tampered with.")
    
    h_df = [{
        "File Name": f['file']['name'], 
        "Short ID (MD5)": f['file']['md5'], 
        "Security ID (SHA256)": f['file']['sha256']
    } for f in res["findings"]]
    st.dataframe(pd.DataFrame(h_df), hide_index=True, use_container_width=True)

    # PD-4: Suspicious File List
    st.divider()
    st.subheader("⚠️ High-Risk File Analysis")
    
    suspicious = []
    for f in res["findings"]:
        reasons = []
        if f['keywords']: reasons.append(f"Contains Suspicious Words: {', '.join(f['keywords'])}")
        if f['file']['sha256'] in res["malicious_hashes"]: reasons.append("Known Malicious Fingerprint Detected")
        
        intersect_ips = [ip for ip in f['indicators']['ips'] if ip in res["malicious_ips"]]
        intersect_urls = [url for url in f['indicators']['urls'] if url in res["malicious_urls"]]
        
        if intersect_ips: reasons.append(f"Linked to Malicious IP: {', '.join(intersect_ips)}")
        if intersect_urls: reasons.append(f"Linked to Malicious Link: {', '.join(intersect_urls)}")
        
        if reasons:
            f['flag_reasons'] = reasons
            suspicious.append(f)

    if suspicious:
        for item in suspicious:
            with st.expander(f"🚩 FLAG: {item['file']['name']}"):
                st.markdown("### 🔍 Why was this flagged?")
                for reason in item['flag_reasons']: st.write(f"- {reason}")
                
                st.markdown("### 📄 Content Preview (Suspicious Items Highlighted)")
                content = ""
                try:
                    with open(item['file']['path'], 'r', encoding='utf-8', errors='ignore') as f_read:
                        content = f_read.read(5000)
                except: pass

                if content:
                    highlighted = content
                    all_to_flag = list(item['keywords']) + \
                                  [ip for ip in item['indicators']['ips'] if ip in res["malicious_ips"]] + \
                                  [url for url in item['indicators']['urls'] if url in res["malicious_urls"]]
                    
                    for target in set(all_to_flag):
                        highlighted = re.sub(f"({re.escape(target)})", r'<span style="color:red; font-weight:bold; background-color:rgba(255,0,0,0.1); border-radius:3px; padding:0 2px;">\1</span>', highlighted, flags=re.IGNORECASE)
                    
                    st.markdown(f'<div style="background-color:#1e1e1e; padding:15px; border-radius:5px; font-family:monospace; white-space:pre-wrap; border-left:4px solid #ff3860;">{highlighted}</div>', unsafe_allow_html=True)

                if st.button(f"📦 Preserve Evidence: {item['file']['name']}", key=item['file']['md5'] + "_pres"):
                    path = generate_evidence_package(item['file'], item['indicators'], {"score": res["risk_score"], "level": res["risk_level"]}, item['vt'])
                    st.success(f"Preserved at: {path}")
    else:
        st.success("Analysis complete: No high-risk files identified.")

    # PD-5: Timeline Visualization
    st.divider()
    st.subheader("📅 Activity Timeline")
    t_df = pd.DataFrame([{"Time": f['modified_time'], "File": f['name']} for f in res["files"]])
    if not t_df.empty:
        st.plotly_chart(px.scatter(t_df, x="Time", y="File", title="Evidence Activity Overview"), use_container_width=True)

st.markdown("---")
st.caption("Forensic Triage Tool | Senior Cyber Engineering Prototype")
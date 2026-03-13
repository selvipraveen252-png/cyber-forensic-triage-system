# 🛡️ Cyber Forensic TRIAGE System Pro

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/built%20with-Streamlit-FF4B4B.svg)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A professional-grade **digital forensics and incident response platform** for rapid threat intelligence analysis and evidence gathering. Designed for security engineers, SOC analysts, incident responders, and digital forensics professionals to conduct thorough investigations in seconds during security incidents.

**Key Capabilities**: File integrity analysis • Indicator extraction • Threat intelligence correlation • Risk scoring • Evidence preservation • PDF reporting

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/selvipraveen252-png/cyber-forensic-triage-system.git
cd cyber-forensic-triage

# Install dependencies
pip install -r requirements.txt

# Configure API keys in config.py
# Obtain free keys from: VirusTotal, AbuseIPDB, IPinfo

# Launch the dashboard
streamlit run app_streamlit.py
```

The application will open at `http://localhost:8501`

---

## 📋 Core Features

### 🔐 Forensic Hash Analysis
- **Integrity Verification**: MD5 and SHA256 hashing for cryptographic file fingerprinting
- **Malware Detection**: Cross-reference file hashes against VirusTotal's 5M+ known malware signatures
- **Tamper Detection**: Cryptographic proof that evidence hasn't been modified

### 🔎 Indicator of Compromise (IOC) Extraction
Automated discovery and deduplication of:
- **IPv4 Addresses** - Identify C2 infrastructure and attacker command centers
- **URLs/Domains** - Flag phishing links, malware distribution, and suspicious downloads
- **Email Addresses** - Track attacker communications and compromise accounts

### 🌐 Multi-Source Threat Intelligence
Integrated threat feeds from industry-standard APIs:
- **VirusTotal** - Malware signatures, hash reputation, URL/domain analysis
- **AbuseIPDB** - IP reputation scoring, DDoS activity, hacking reports
- **IPinfo** - Geolocation, ASN data, ISP mapping, network ownership

### 📊 Advanced Risk Scoring System
Dynamic risk calculation (0-100) based on:
- Suspicious keyword detection (backdoor, c2, exfiltrate, payload, unauthorized access, etc.)
- Malicious IP/URL reputations from threat intelligence
- Known malware hash matches
- **Risk Levels**: 
  - ✅ **SAFE** (0-20)
  - ⚠️ **SUSPICIOUS** (21-50)
  - 🔴 **HIGH RISK** (51-80)
  - 🚨 **CRITICAL** (81-100)

### 📦 Evidence Preservation
- **Chain of Custody**: One-click evidence collection with metadata tracking
- **Evidence Packages**: Automated creation of `/evidence/` directories with:
  - Original file copy
  - JSON metadata with hashes, timestamps, and indicators
  - Threat intelligence results
  - Risk assessment scores
- **Forensically Sound**: Preserves evidence integrity for court admissibility

### 📈 Interactive Investigation Dashboard
- **Real-Time Analysis**: Streamlit-powered responsive interface
- **Visual Timeline**: Scatter plots of file modification times to identify "burst" attack patterns
- **Highlighted Detection**: Malicious indicators highlighted in bold red in file content previews
- **Exportable Reports**: PDF reports for incident documentation and stakeholder communication
- **Indicator Tables**: Centralized view of all extracted IPs, URLs, and emails

---

## 🏗️ Architecture & Project Structure

```
cyber-forensic-triage/
├── app_streamlit.py              # Core forensic engine & Streamlit UI
├── config.py                      # API key configuration
├── requirements.txt               # Python package dependencies
├── integrations/
│   ├── virustotal_lookup.py      # VirusTotal API client
│   ├── abuseip_lookup.py         # AbuseIPDB API client
│   ├── ipinfo_lookup.py          # IPinfo Geolocation API client
│   └── __pycache__/
├── demo_files/                    # Sample evidence files for testing
│   ├── chat_record.txt
│   ├── network_activity.txt
│   └── suspicious_log.txt
├── evidence/                      # Auto-generated evidence packages (output)
└── README.md                      # This documentation
```

### Module Overview
| Module | Purpose |
|--------|---------|
| `app_streamlit.py` | Main application: file scanning, IOC extraction, risk scoring, dashboard UI |
| `virustotal_lookup.py` | Hash/URL reputation checking against VirusTotal malware database |
| `abuseip_lookup.py` | IP reputation and abuse confidence scoring |
| `ipinfo_lookup.py` | Geolocation and ASN lookup for network artifacts |

---

## 🚀 Installation & Configuration

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Internet connection for API calls (threat intelligence)

### Step 1: Clone Repository
```bash
git clone https://github.com/selvipraveen252-png/cyber-forensic-triage-system.git
cd cyber-forensic-triage
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure API Keys
Edit `config.py` and add your API keys (free tiers available):

```python
# config.py
VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"
IPINFO_API_KEY = "your_ipinfo_api_key_here"
```

**Get Free API Keys:**
- [VirusTotal](https://www.virustotal.com/gui/home/upload) - 4 requests/minute
- [AbuseIPDB](https://www.abuseipdb.com/register) - 100 queries/day free
- [IPinfo](https://ipinfo.io/signup) - 50,000 queries/month free

### Step 4: Run Application
```bash
streamlit run app_streamlit.py
```

The application opens at `http://localhost:8501`

---

## 📖 Usage Guide

### Basic Workflow

#### 1. **Load Evidence Files**
In the sidebar, click **"Load Case Files"** to analyze demo samples or enter a custom folder path:
```
Enter path: C:\forensic_evidence\  (or /home/user/evidence/)
```

#### 2. **Execute Triage Scan**
Click **"🔎 Execute Triage Scan"** button:
- Recursively scans all files in the folder
- Computes MD5/SHA256 hashes
- Extracts IPs, URLs, emails from text/log files
- Queries VirusTotal, AbuseIPDB, IPinfo APIs
- Generates risk score and threat assessment

#### 3. **Review Results**
The dashboard displays:
- **Executive Summary**: Risk level, scores, malicious signals count
- **Forensic Indicators**: All extracted IPs, URLs, emails
- **Global Intelligence**: Geolocation and threat scores for discovered IPs
- **Evidence Integrity**: File hashes for forensic proof
- **High-Risk Analysis**: Detailed breakdown of flagged files with evidence
- **Activity Timeline**: Visual pattern of file modification times

#### 4. **Preserve Evidence**
For flagged files, click **"📦 Preserve Evidence"** to:
- Copy the original file to `/evidence/` directory
- Create `metadata.json` with all analysis data
- Generate evidence package with timestamp and chain of custody

#### 5. **Export Report**
Click **"📥 Download Triage Report (PDF)"** to generate:
- Professional forensic report
- Executive summary tables
- Network intelligence results
- File integrity hashes
- High-risk analysis details
- Suitable for incident documentation and legal proceedings

### Example Scenarios

**Scenario 1: Malware Incident**
```
1. Suspicious folder detected: C:\Users\John\Downloads\
2. Load folder in TRIAGE
3. System extracts 127.0.0.1 (suspicious IP) + malware keyword hits
4. AbuseIPDB shows 98% abuse confidence score
5. VirusTotal flags hash as known ransomware
6. Risk Score: 89/100 (CRITICAL)
7. Preserve evidence → chains of custody created
8. Export PDF for incident response team
```

**Scenario 2: Compromise Detection**
```
1. Found suspicious log during threat hunt: /var/log/auth.log
2. Extract indicators: finds attacker C2 IP 203.0.113.45
3. IPinfo maps to North Korea (ASN 131279)
4. AbuseIPDB confirms 150+ attack reports
5. Preserved in evidence package
6. Share PDF report with SOC and management
```

---

## 📚 Dependencies

```
streamlit              # Interactive dashboard framework
pandas                 # Data manipulation and analysis
plotly                 # Interactive visualization charts
reportlab              # PDF report generation
requests               # HTTP API requests
```

See [requirements.txt](requirements.txt) for specific versions.

---

## 🧪 Testing with Demo Files

The `/demo_files/` directory includes realistic forensic samples:

- **`suspicious_log.txt`** - Simulated attack logs with failed authentication attempts, beaconing patterns
- **`network_activity.txt`** - C2 communications, data exfiltration traffic
- **`chat_record.txt`** - Social engineering attempts with malicious download links

**Quick Test:**
```bash
streamlit run app_streamlit.py
# Click "Load Case Files" → "Execute Triage Scan"
# System analyzes demo files and demonstrates all features
```

---

## 🔮 Roadmap & Future Enhancements

### Planned Features
- [ ] Magic Byte validation (file signature verification)
- [ ] Memory dump analysis (Volatility integration)
- [ ] YARA rule scanning for advanced malware detection
- [ ] Evidence package export as signed ZIP archives
- [ ] Timeline correlation analysis
- [ ] Triage database with historical case storage
- [ ] Anonymous telemetry for research

### Known Limitations
- File size limit: 100MB per file (API constraint prevention)
- API rate limiting applies (check service quotas)
- Text file content extraction limited to first 50KB

---

## 🛠️ API Rate Limits

| Service | Free Tier |
|---------|-----------|
| VirusTotal | 4 requests/minute |
| AbuseIPDB | 100 queries/day |
| IPinfo | 50,000 queries/month |

To avoid rate limiting, the tool limits API queries to first 5 IPs and 5 URLs per scan.

---

## ⚖️ Legal & Ethical Disclaimer

**This tool is designed for:**
- ✅ Authorized digital forensics investigations
- ✅ Internal incident response
- ✅ Security research on owned systems
- ✅ Educational purposes

**Do NOT use this tool to:**
- ❌ Analyze systems without explicit authorization
- ❌ Violate privacy laws or regulations
- ❌ Perform unauthorized forensics

**Responsibility**: Users are responsible for compliance with local, state, and federal laws. Ensure proper authorization before analyzing any systems or evidence.

---

## 📝 Contributing

Contributions are welcome! Areas for improvement:
- Additional threat intelligence integrations
- Performance optimizations
- UI/UX enhancements
- Bug reports and fixes

Please submit pull requests or issues to the GitHub repository.

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author & Support

**Cyber Forensic TRIAGE System Pro**  
Built for security professionals and digital forensics teams.

For issues, questions, or feature requests, please open a GitHub issue.

---

## 🙏 Acknowledgments

- VirusTotal - Global malware database and hash intelligence
- AbuseIPDB - IP reputation and threat intelligence community
- IPinfo - Network geolocation and ASN data
- Streamlit - Interactive data application framework
- ReportLab - Professional PDF generation

---

**Last Updated:** 2026  
**Status:** Active Development

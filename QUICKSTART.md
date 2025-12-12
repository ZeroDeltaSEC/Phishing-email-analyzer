# 🚀 Quick Start Guide

Get started with Advanced Phishing Email Analyzer in 5 minutes!

## Installation (5 minutes)

### Step 1: Install System Tools
```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip curl \
    tcpdump tshark exiftool binwalk yara \
    firefox-esr geckodriver
```

### Step 2: Clone Repository
```bash
git clone https://github.com/yourusername/phishing-analyzer.git
cd phishing-analyzer
```

### Step 3: Install Python Dependencies
```bash
pip3 install selenium python-magic yara-python oletools
```

### Step 4: Install Ollama (AI Engine)
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b
```

### Step 5: Verify Setup
```bash
chmod +x setup.sh
./setup.sh
```

---

## Basic Usage

### Analyze an Email
```bash
python3 analyze_phishing_v2.py suspicious.eml
```

### With Full Network Capture (requires sudo)
```bash
sudo python3 analyze_phishing_v2.py suspicious.eml
```

### Test with Sample
```bash
python3 analyze_phishing_v2.py test_phishing.eml
```

---

## Understanding the Output

### Risk Score
- **0-34**: ✅ BENIGN (Safe)
- **35-59**: ⚠️ SUSPICIOUS (Caution needed)
- **60-100**: 🚨 MALICIOUS (Dangerous)

### Output Files
```
output/analysis_<filename>_<timestamp>/
├── analysis_report.txt      ← Read this first
├── analysis_report.html     ← Visual report
├── analysis_report.json     ← For automation
├── screenshots/             ← URL screenshots
└── attachments/             ← Extracted files
```

---

## Common Scenarios

### Scenario 1: Email with Suspicious Link
The analyzer will:
1. Check authentication (SPF/DKIM/DMARC)
2. Analyze content for phishing patterns
3. Detonate URL in isolated browser
4. Capture network traffic
5. Take screenshots
6. Generate risk score

### Scenario 2: Email with Office Attachment
The analyzer will:
1. Extract attachment
2. Scan for macros (VBA)
3. Check for embedded executables
4. Run YARA rules
5. Calculate file risk score

### Scenario 3: Brand Impersonation
The analyzer will detect:
- Typosquatted domains (paypa1.com vs paypal.com)
- Display name mismatches
- Authentication failures
- Urgent language patterns

---

## Tips for Best Results

### 1. Run in VM
Always analyze suspicious emails in a virtual machine

### 2. Use Sudo for Full Analysis
```bash
sudo python3 analyze_phishing_v2.py email.eml
# Enables full network traffic capture
```

### 3. Check All Reports
- `analysis_report.txt` - Detailed findings
- `analysis_report.html` - Visual summary
- Screenshots folder - See what URLs look like

### 4. Verify AI Model
```bash
ollama list  # Check installed models
ollama pull llama3.2:3b  # Install recommended model
```

---

## Troubleshooting

### "Ollama not found"
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b
```

### "Permission denied" for tcpdump
```bash
sudo python3 analyze_phishing_v2.py email.eml
# OR
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

### "Module not found"
```bash
pip3 install -r requirements.txt
```

### Selenium WebDriver Error
```bash
sudo apt install firefox-esr geckodriver
```

---

## What Gets Analyzed?

### ✅ Email Headers
- Authentication (SPF, DKIM, DMARC)
- Received chain
- Message-ID validation
- Reply-To mismatches

### ✅ Email Content
- Urgent/threatening language
- Brand impersonation
- Credential harvesting forms
- HTML tricks (hidden content, obfuscation)

### ✅ URLs
- Redirect chains
- SSL certificate validation
- Domain typosquatting
- Live detonation in browser
- Network traffic analysis
- Screenshot capture

### ✅ Attachments
- File type identification
- Macro detection
- Embedded file scanning
- YARA rule matching
- Hash calculation

### ✅ AI Analysis
- Contextual understanding
- Risk scoring
- Human-readable explanations

---

## Integration with Workflow

### For SOC Analysts
1. Receive suspicious email report
2. Export email as .eml file
3. Run analyzer: `python3 analyze_phishing_v2.py email.eml`
4. Review `analysis_report.html` for quick verdict
5. Check detailed text report for evidence
6. Share JSON report with SIEM/ticketing system

### For Automated Systems
```bash
# Run analyzer
python3 analyze_phishing_v2.py email.eml

# Parse JSON output
cat output/analysis_*/analysis_report.json | jq '.scores.verdict'

# Automate actions based on verdict
```

---

## Next Steps

📚 **Read Full Documentation**: [README.md](README.md)  
🔧 **Customize Patterns**: Edit `patterns/malware.yar`  
🎯 **Adjust Scoring**: Modify `modules/scoring_engine.py`  
🤖 **Change AI Model**: Edit `modules/ai_analyzer.py`

---

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/phishing-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/phishing-analyzer/discussions)
- **Documentation**: Check [README.md](README.md) for detailed information

---

**Happy Analyzing! 🎯**

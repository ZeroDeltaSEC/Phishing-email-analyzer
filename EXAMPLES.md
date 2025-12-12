# 📚 Usage Examples

Real-world examples and use cases for the Advanced Phishing Email Analyzer.

---

## Example 1: PayPal Phishing Email

### Email Characteristics
- **From**: `security@paypa1-secure.com` (typosquatting)
- **Subject**: "Urgent: Verify Your Account Within 24 Hours"
- **Content**: Credential harvesting form
- **Authentication**: SPF FAIL, DKIM NONE, DMARC FAIL

### Command
```bash
python3 analyze_phishing_v2.py paypal_phish.eml
```

### Results
```
🚨 MALICIOUS - Risk Score: 85/100

Component Breakdown:
• Authentication: HIGH RISK (70/100)
  - SPF authentication failed
  - DMARC validation failed
  
• Content Patterns: HIGH RISK (75/100)
  - Brand impersonation detected (PAYPAL)
  - Typosquatting: paypa1-secure.com
  - Credential harvesting form found
  - 5 urgent keywords detected
  
• URLs: CRITICAL (90/100)
  - Multiple redirects (3)
  - Credential form on final page
  - 5 domains contacted
  
Recommendations:
✗ DO NOT click any links
✗ DO NOT reply to this email
✓ Report to security team immediately
✓ Delete email
```

---

## Example 2: Legitimate Microsoft Email

### Email Characteristics
- **From**: `no-reply@microsoft.com`
- **Subject**: "Your Office 365 subscription renewal"
- **Authentication**: SPF PASS, DKIM PASS, DMARC PASS
- **Content**: Professional formatting, no urgent language

### Command
```bash
python3 analyze_phishing_v2.py microsoft_legit.eml
```

### Results
```
✅ BENIGN - Risk Score: 15/100

Component Breakdown:
• Authentication: LOW RISK (5/100)
  - All authentication checks passed
  - SPF: PASS
  - DKIM: PASS
  - DMARC: PASS
  
• Content Patterns: LOW RISK (10/100)
  - Professional formatting
  - No suspicious patterns
  - Known legitimate sender
  
• URLs: LOW RISK (15/100)
  - URLs match domain
  - Valid SSL certificates
  - No redirects
  
Recommendations:
✓ Email appears legitimate
✓ Standard caution advised
```

---

## Example 3: Malicious Office Document

### Email Characteristics
- **From**: `colleague@company.com` (spoofed)
- **Subject**: "Q4 Invoice - Please Review"
- **Attachment**: `invoice.docx` (contains macros)
- **Authentication**: DKIM FAIL

### Command
```bash
python3 analyze_phishing_v2.py invoice_email.eml
```

### Results
```
🚨 MALICIOUS - Risk Score: 72/100

Component Breakdown:
• Authentication: HIGH RISK (65/100)
  - DKIM validation failed
  - Suspicious Return-Path
  
• Attachments: CRITICAL (85/100)
  File: invoice.docx
  - VBA macros detected
  - Auto-execute macro (AutoOpen)
  - Shell execution commands found
  - URLDownloadToFile detected
  - YARA rule match: Suspicious_Macro
  
Threats Detected:
✗ Auto-execute macro (AutoOpen)
✗ Shell execution (WScript.Shell)
✗ File download capability (URLDownloadToFile)
✗ Obfuscation techniques detected

Recommendations:
✗ DO NOT open attachment
✗ DO NOT enable macros
✓ Quarantine email immediately
✓ Run full system scan
```

---

## Example 4: URL Redirector Chain

### Email Characteristics
- **Contains**: bit.ly shortened URL
- **Redirects**: Multiple redirects to phishing site
- **Final Page**: Credential harvesting form

### Command
```bash
sudo python3 analyze_phishing_v2.py redirect_phish.eml
```

### Results
```
🚨 MALICIOUS - Risk Score: 68/100

URL Analysis:
Original: http://bit.ly/abc123
  ↪ Redirect 1: http://suspicious-tracker.com/r/xyz
  ↪ Redirect 2: http://intermediate-site.net/go
  ↪ Final: http://phishing-harvest.com/login

Network Traffic Captured:
• 127 packets analyzed
• 8 domains contacted
• 2 external resources loaded

DOM Analysis:
✗ Password input form detected
✗ Hidden iframe found
✗ JavaScript obfuscation detected
✗ Suspicious form action

Screenshot: output/analysis_*/screenshots/url_1_screenshot.png

Recommendations:
✗ Malicious URL chain detected
✗ DO NOT visit this URL
✓ Add domains to blacklist
```

---

## Example 5: PDF with Malicious JavaScript

### Email Characteristics
- **Attachment**: `document.pdf`
- **Content**: Contains JavaScript
- **Triggers**: Auto-action on open

### Command
```bash
python3 analyze_phishing_v2.py pdf_malware.eml
```

### Results
```
⚠️ SUSPICIOUS - Risk Score: 58/100

PDF Analysis:
File: document.pdf
Size: 245 KB
SHA256: a1b2c3d4e5f6...

Threats Detected:
✗ JavaScript detected in PDF
✗ Auto-action (/AA) found
✗ OpenAction present
⚠️ Launch action detected

Structure Analysis:
• 12 objects analyzed
• 3 streams with filters
• Potentially obfuscated content

Recommendations:
⚠️ Do not open PDF in default viewer
✓ Use sandboxed PDF viewer
✓ Analyze in isolated environment
```

---

## Use Case Scenarios

### Scenario A: SOC Analyst Daily Workflow

**Morning Email Triage**

```bash
# 1. Export suspicious emails from mailbox
# Save as: suspicious_email_001.eml, suspicious_email_002.eml, etc.

# 2. Batch analyze
for email in suspicious_email_*.eml; do
    echo "Analyzing $email..."
    sudo python3 analyze_phishing_v2.py "$email"
done

# 3. Review HTML reports
firefox output/analysis_*/analysis_report.html

# 4. Extract high-risk findings
grep -r "MALICIOUS" output/*/analysis_report.txt > daily_threats.txt
```

**Actions Based on Verdicts:**
- **MALICIOUS** → Block sender, quarantine, alert users
- **SUSPICIOUS** → Add to monitoring, request user verification
- **BENIGN** → Whitelist, no action needed

---

### Scenario B: Automated Email Gateway Integration

**Integration Script**

```bash
#!/bin/bash
# Email gateway integration

EMAIL_FILE=$1
TEMP_DIR="/tmp/email_analysis"

# Run analysis
python3 analyze_phishing_v2.py "$EMAIL_FILE"

# Parse verdict
OUTPUT_DIR=$(ls -td output/analysis_* | head -1)
VERDICT=$(jq -r '.scores.verdict' "$OUTPUT_DIR/analysis_report.json")
SCORE=$(jq -r '.scores.final_score' "$OUTPUT_DIR/analysis_report.json")

# Take action
case $VERDICT in
    "MALICIOUS")
        echo "REJECT: Malicious email detected (Score: $SCORE)"
        # Quarantine email
        mv "$EMAIL_FILE" /var/quarantine/
        # Block sender
        echo "$SENDER" >> /etc/postfix/sender_blacklist
        # Alert security team
        curl -X POST https://alerts.company.com/api/phishing \
            -d "email=$EMAIL_FILE&score=$SCORE"
        exit 1
        ;;
    "SUSPICIOUS")
        echo "HOLD: Suspicious email (Score: $SCORE)"
        # Move to review queue
        mv "$EMAIL_FILE" /var/spool/review/
        # Notify analyst
        mail -s "Email needs review" analyst@company.com < "$OUTPUT_DIR/analysis_report.txt"
        exit 2
        ;;
    "BENIGN")
        echo "ALLOW: Email appears safe (Score: $SCORE)"
        exit 0
        ;;
esac
```

---

### Scenario C: Threat Intelligence Gathering

**Extract IOCs for Sharing**

```bash
# Analyze phishing campaign
python3 analyze_phishing_v2.py campaign_sample.eml

# Extract IOCs
OUTPUT_DIR=$(ls -td output/analysis_* | head -1)

# Get all domains
jq -r '.urls[].contacted_domains[]' \
    "$OUTPUT_DIR/analysis_report.json" | sort -u > iocs_domains.txt

# Get file hashes
jq -r '.attachments[].hashes.sha256' \
    "$OUTPUT_DIR/analysis_report.json" > iocs_hashes.txt

# Get all URLs
jq -r '.urls[].original_url' \
    "$OUTPUT_DIR/analysis_report.json" > iocs_urls.txt

# Create STIX bundle (if integrated)
python3 create_stix_bundle.py \
    --domains iocs_domains.txt \
    --hashes iocs_hashes.txt \
    --urls iocs_urls.txt \
    --output campaign_iocs.json

# Share with threat intel platforms
curl -X POST https://threatintel.platform.com/api/iocs \
    -H "Authorization: Bearer $API_TOKEN" \
    -d @campaign_iocs.json
```

---

### Scenario D: Training and Education

**Security Awareness Training**

```bash
# Use test samples for training
python3 analyze_phishing_v2.py test_phishing.eml

# Show trainees:
# 1. HTML report with visual indicators
firefox output/analysis_*/analysis_report.html

# 2. Screenshots of phishing sites
display output/analysis_*/screenshots/*.png

# 3. Detailed breakdown of red flags
cat output/analysis_*/analysis_report.txt | less

# Create training materials
# - Before/after examples
# - Common phishing tactics
# - How to spot red flags
```

---

## Advanced Usage

### Comparing Multiple Campaigns

```bash
# Analyze multiple emails from same campaign
for email in campaign*.eml; do
    python3 analyze_phishing_v2.py "$email"
done

# Compare patterns
echo "Campaign Analysis Summary"
echo "========================="
grep -h "Risk Score" output/*/analysis_report.txt
grep -h "Brand" output/*/analysis_report.txt
grep -h "Typosquatting" output/*/analysis_report.txt

# Find common indicators
find output -name "analysis_report.json" -exec \
    jq -r '.patterns.brand_impersonation' {} \; | sort | uniq -c
```

### Custom Scoring Thresholds

Edit `modules/scoring_engine.py`:
```python
def determine_verdict(self, final_score, component_scores):
    # More aggressive detection
    if final_score >= 50:  # Lower threshold
        return 'MALICIOUS'
    elif final_score >= 25:
        return 'SUSPICIOUS'
    else:
        return 'BENIGN'
```

---

## Tips & Best Practices

### ✅ DO
- Run in isolated VM environment
- Use sudo for full traffic capture
- Review all three report formats (TXT, JSON, HTML)
- Maintain analysis logs
- Update YARA rules regularly
- Keep Ollama model current

### ❌ DON'T
- Run on production systems
- Click URLs outside the tool
- Open extracted attachments directly
- Trust score alone without context
- Skip manual verification for critical decisions
- Ignore AI analysis warnings

---

## Performance Benchmarks

| Scenario | Time | Memory | Disk |
|----------|------|--------|------|
| Simple email (text only) | ~10s | <100MB | <5MB |
| Email + 1 URL | ~30s | ~150MB | ~10MB |
| Email + attachment | ~45s | ~200MB | ~15MB |
| Complex (URLs + attachments) | ~2m | ~300MB | ~25MB |

*Tested on: Ubuntu 22.04, 4 CPU cores, 8GB RAM*

---

## Need More Help?

- **Full Documentation**: [README.md](README.md)
- **Quick Start**: [QUICKSTART.md](QUICKSTART.md)
- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/phishing-analyzer/issues)
- **Discussions**: [Ask questions](https://github.com/yourusername/phishing-analyzer/discussions)

---

**Happy Hunting! 🎯**

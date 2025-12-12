"""
AI Analyzer Module
Uses local LLM (Ollama) for intelligent email analysis
"""

import subprocess
import json


class AIAnalyzer:
    def __init__(self, model='llama3.2:3b'):
        """
        Initialize AI Analyzer
        Default model: llama3.2:3b (better than tinyllama for analysis)
        """
        self.model = model
        self.timeout = 120  # 2 minutes max
    
    def analyze(self, headers, authentication, body_text, patterns, urls, attachments):
        """
        Comprehensive AI analysis of email
        """
        # Build comprehensive prompt
        prompt = self.build_analysis_prompt(
            headers, authentication, body_text, 
            patterns, urls, attachments
        )
        
        # Call Ollama
        try:
            result = self.call_ollama(prompt)
            return result
        except Exception as e:
            return f"AI Analysis Failed: {str(e)}\n\nPlease ensure Ollama is running with model '{self.model}' installed."
    
    def build_analysis_prompt(self, headers, authentication, body_text, patterns, urls, attachments):
        """Build comprehensive analysis prompt"""
        
        prompt = """You are a cybersecurity expert analyzing an email for phishing and malicious indicators.

=== EMAIL INFORMATION ===

FROM: {}
TO: {}
SUBJECT: {}

=== AUTHENTICATION ===
SPF: {}
DKIM: {}
DMARC: {}
Issues: {}

=== EMAIL BODY (first 500 characters) ===
{}

=== DETECTED PATTERNS ===
Urgent Keywords: {}
Suspicious Patterns: {}
Brand Impersonation: {}
Credential Harvesting: {}

=== URLs ===
Total URLs: {}
High-Risk URLs: {}

=== ATTACHMENTS ===
Total: {}
High-Risk: {}

=== YOUR TASK ===
Provide a concise risk assessment in the following format:

RISK SCORE: [0-100]
VERDICT: [SAFE | SUSPICIOUS | PHISHING]

KEY INDICATORS:
- [List 3-5 specific red flags or reassuring factors]

EXPLANATION:
[2-3 sentences explaining your assessment]

Focus on the most critical factors and be decisive in your verdict.""".format(
            headers.get('from', 'N/A'),
            headers.get('to', 'N/A'),
            headers.get('subject', 'N/A'),
            authentication.get('spf', 'UNKNOWN'),
            authentication.get('dkim', 'UNKNOWN'),
            authentication.get('dmarc', 'UNKNOWN'),
            ', '.join(authentication.get('issues', ['None'])),
            body_text[:500] if body_text else '[Empty]',
            len(patterns.get('urgent_keywords', [])),
            len(patterns.get('suspicious_patterns', [])),
            patterns.get('brand_impersonation', 'None'),
            patterns.get('credential_harvesting', 'None'),
            len(urls),
            sum(1 for u in urls if u.get('risk_level') in ['HIGH', 'CRITICAL']),
            len(attachments),
            sum(1 for a in attachments if a.get('analysis', {}).get('risk_level') in ['HIGH', 'CRITICAL'])
        )
        
        return prompt
    
    def call_ollama(self, prompt):
        """Call Ollama API"""
        try:
            # Check if Ollama is available
            check_cmd = 'which ollama'
            check_result = subprocess.run(
                check_cmd, 
                shell=True, 
                capture_output=True, 
                timeout=5
            )
            
            if check_result.returncode != 0:
                return "Ollama not found. Please install Ollama: https://ollama.ai"
            
            # Call Ollama
            cmd = ['ollama', 'run', self.model, prompt]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                error_msg = result.stderr.strip()
                
                # Check if model not found
                if 'not found' in error_msg.lower():
                    return f"Model '{self.model}' not found. Install it with: ollama pull {self.model}"
                
                return f"Ollama error: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return "AI analysis timeout - LLM took too long to respond (>2 minutes)"
        except Exception as e:
            return f"AI analysis error: {str(e)}"
    
    def fallback_analysis(self, patterns, urls, attachments, authentication):
        """
        Fallback rule-based analysis if AI is unavailable
        """
        score = 0
        verdict = "UNKNOWN"
        indicators = []
        
        # Authentication issues
        if authentication.get('spf') in ['FAIL', 'SOFTFAIL']:
            score += 25
            indicators.append("SPF authentication failed")
        
        if authentication.get('dkim') == 'FAIL':
            score += 25
            indicators.append("DKIM authentication failed")
        
        # Pattern detection
        if patterns.get('brand_impersonation'):
            score += 20
            indicators.append(f"Brand impersonation: {patterns['brand_impersonation']}")
        
        if patterns.get('credential_harvesting'):
            score += 30
            indicators.append("Credential harvesting detected")
        
        if len(patterns.get('urgent_keywords', [])) > 3:
            score += 15
            indicators.append("Excessive urgency language")
        
        # URLs
        high_risk_urls = sum(1 for u in urls if u.get('risk_level') in ['HIGH', 'CRITICAL'])
        if high_risk_urls > 0:
            score += 20
            indicators.append(f"{high_risk_urls} high-risk URLs")
        
        # Attachments
        high_risk_atts = sum(1 for a in attachments if a.get('analysis', {}).get('risk_level') in ['HIGH', 'CRITICAL'])
        if high_risk_atts > 0:
            score += 20
            indicators.append(f"{high_risk_atts} high-risk attachments")
        
        # Determine verdict
        if score >= 60:
            verdict = "PHISHING"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        # Format output
        output = f"""RISK SCORE: {score}
VERDICT: {verdict}

KEY INDICATORS:
"""
        
        for indicator in indicators[:5]:
            output += f"- {indicator}\n"
        
        if not indicators:
            output += "- No major red flags detected\n"
        
        output += f"""
EXPLANATION:
Based on rule-based analysis (AI unavailable), this email received a risk score of {score}/100. 
"""
        
        if verdict == "PHISHING":
            output += "Multiple strong indicators suggest this is a phishing attempt."
        elif verdict == "SUSPICIOUS":
            output += "Several concerning indicators warrant caution."
        else:
            output += "The email appears legitimate with minimal risk indicators."
        
        return output

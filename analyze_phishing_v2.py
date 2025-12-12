#!/usr/bin/env python3
"""
Advanced Phishing Email Analysis Tool v2.0
Full Stack Offline Analysis - No External APIs Required
Analyzes .eml files with deep inspection and intelligent scoring
"""

import email
import sys
import os
import hashlib
import re
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import subprocess
import time
from pathlib import Path
from collections import defaultdict
import socket
import ssl
import base64
from email.header import decode_header

# Import custom modules
from modules.url_detonator import URLDetonator
from modules.file_analyzer import FileAnalyzer
from modules.header_parser import HeaderParser
from modules.pattern_detector import PatternDetector
from modules.scoring_engine import ScoringEngine
from modules.ai_analyzer import AIAnalyzer
from modules.traffic_monitor import TrafficMonitor

class PhishingAnalyzer:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.base_name = os.path.splitext(os.path.basename(eml_path))[0]
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"output/analysis_{self.base_name}_{self.timestamp}"
        
        # Create directory structure
        self.setup_directories()
        
        # Initialize components
        self.url_detonator = URLDetonator(self.output_dir)
        self.file_analyzer = FileAnalyzer(self.output_dir)
        self.header_parser = HeaderParser()
        self.pattern_detector = PatternDetector()
        self.scoring_engine = ScoringEngine()
        self.ai_analyzer = AIAnalyzer()
        self.traffic_monitor = TrafficMonitor(self.output_dir)
        
        # Storage for analysis results
        self.results = {
            'headers': {},
            'authentication': {},
            'urls': [],
            'attachments': [],
            'patterns': {},
            'traffic': {},
            'scores': {},
            'verdict': {}
        }
    
    def setup_directories(self):
        """Create all necessary directories"""
        dirs = [
            self.output_dir,
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/attachments",
            f"{self.output_dir}/traffic_dumps",
            f"{self.output_dir}/detonation_logs",
            f"{self.output_dir}/extracted_content"
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
    
    def banner(self):
        """Display banner"""
        print("="*80)
        print(" 🎯 ADVANCED PHISHING EMAIL ANALYZER v2.0")
        print(" Full Stack Offline Analysis | No External APIs")
        print("="*80)
        print()
    
    def extract_body(self, msg):
        """Extract email body (text and HTML)"""
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                try:
                    if content_type == "text/plain":
                        body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == "text/html":
                        body_html += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            except:
                pass
        
        return body_text, body_html
    
    def decode_subject(self, subject):
        """Decode email subject handling various encodings"""
        if not subject:
            return "No Subject"
        
        decoded_parts = decode_header(subject)
        decoded_subject = ""
        
        for content, encoding in decoded_parts:
            if isinstance(content, bytes):
                try:
                    if encoding:
                        decoded_subject += content.decode(encoding)
                    else:
                        decoded_subject += content.decode('utf-8', errors='ignore')
                except:
                    decoded_subject += str(content)
            else:
                decoded_subject += str(content)
        
        return decoded_subject
    
    def analyze(self):
        """Main analysis orchestrator"""
        self.banner()
        
        if not os.path.exists(self.eml_path):
            print(f"❌ [ERROR] File not found: {self.eml_path}")
            sys.exit(1)
        
        print(f"📧 [+] Analyzing: {self.eml_path}")
        print(f"📁 [+] Output directory: {self.output_dir}\n")
        
        # Parse email
        with open(self.eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
        
        # Phase 1: Header Analysis
        print("="*80)
        print("PHASE 1: HEADER ANALYSIS")
        print("="*80)
        self.results['headers'] = self.header_parser.parse_headers(msg)
        self.results['authentication'] = self.header_parser.analyze_authentication(msg)
        self.print_header_results()
        
        # Phase 2: Body Analysis
        print("\n" + "="*80)
        print("PHASE 2: BODY & CONTENT ANALYSIS")
        print("="*80)
        body_text, body_html = self.extract_body(msg)
        
        # Pattern detection
        all_text = body_text + body_html + str(msg)
        self.results['patterns'] = self.pattern_detector.detect_patterns(
            body_text, body_html, 
            self.results['headers'].get('subject', ''),
            self.results['headers'].get('from', '')
        )
        self.print_pattern_results()
        
        # Phase 3: URL Analysis & Detonation
        print("\n" + "="*80)
        print("PHASE 3: URL ANALYSIS & DETONATION")
        print("="*80)
        urls = self.extract_urls(all_text)
        print(f"🔗 Found {len(urls)} URLs")
        
        if urls:
            for idx, url in enumerate(urls, 1):
                print(f"\n[URL {idx}/{len(urls)}] Analyzing: {url[:70]}...")
                
                # Detonate URL with traffic monitoring
                result = self.url_detonator.detonate_url(url, idx)
                self.results['urls'].append(result)
                
                # Brief pause between detonations
                if idx < len(urls):
                    time.sleep(2)
        
        self.print_url_results()
        
        # Phase 4: Attachment Analysis
        print("\n" + "="*80)
        print("PHASE 4: ATTACHMENT ANALYSIS")
        print("="*80)
        attachments = self.extract_attachments(msg)
        
        if attachments:
            for idx, att_info in enumerate(attachments, 1):
                print(f"\n[Attachment {idx}/{len(attachments)}] Analyzing: {att_info['filename']}")
                
                # Deep file analysis
                analysis = self.file_analyzer.analyze_file(
                    att_info['filepath'],
                    att_info['filename']
                )
                
                att_info['analysis'] = analysis
                self.results['attachments'].append(att_info)
        else:
            print("✓ No attachments found")
        
        self.print_attachment_results()
        
        # Phase 5: AI Analysis
        print("\n" + "="*80)
        print("PHASE 5: AI ANALYSIS")
        print("="*80)
        print("🤖 Running AI analysis (this may take 30-60 seconds)...")
        
        ai_result = self.ai_analyzer.analyze(
            headers=self.results['headers'],
            authentication=self.results['authentication'],
            body_text=body_text[:1000],
            patterns=self.results['patterns'],
            urls=self.results['urls'],
            attachments=self.results['attachments']
        )
        
        self.results['ai_analysis'] = ai_result
        print(f"\n{ai_result}")
        
        # Phase 6: Final Scoring & Verdict
        print("\n" + "="*80)
        print("PHASE 6: INTELLIGENT SCORING & VERDICT")
        print("="*80)
        
        final_score, verdict, explanation = self.scoring_engine.calculate_final_score(
            authentication=self.results['authentication'],
            patterns=self.results['patterns'],
            urls=self.results['urls'],
            attachments=self.results['attachments'],
            ai_analysis=ai_result
        )
        
        self.results['scores'] = {
            'final_score': final_score,
            'verdict': verdict,
            'explanation': explanation
        }
        
        self.print_final_verdict()
        
        # Generate Reports
        print("\n" + "="*80)
        print("GENERATING REPORTS")
        print("="*80)
        self.generate_reports()
        
        print(f"\n✅ Analysis complete!")
        print(f"📁 All results saved to: {self.output_dir}")
        
        return self.results
    
    def extract_urls(self, text):
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s<>"\'(){}[\]]+|www\.[^\s<>"\'(){}[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        return list(set(urls))  # Remove duplicates
    
    def extract_attachments(self, msg):
        """Extract and save all attachments"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                
                if filename:
                    # Decode filename if needed
                    decoded_filename = self.decode_subject(filename)
                    
                    filepath = os.path.join(
                        f"{self.output_dir}/attachments",
                        decoded_filename
                    )
                    
                    # Save attachment
                    try:
                        with open(filepath, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        
                        # Calculate hashes
                        file_hash = self.calculate_hashes(filepath)
                        file_size = os.path.getsize(filepath)
                        
                        attachments.append({
                            'filename': decoded_filename,
                            'filepath': filepath,
                            'size': file_size,
                            'hashes': file_hash
                        })
                    except Exception as e:
                        print(f"⚠️  Failed to save attachment: {e}")
        
        return attachments
    
    def calculate_hashes(self, filepath):
        """Calculate file hashes"""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    md5_hash.update(byte_block)
            
            return {
                'sha256': sha256_hash.hexdigest(),
                'md5': md5_hash.hexdigest()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def print_header_results(self):
        """Print header analysis results"""
        h = self.results['headers']
        a = self.results['authentication']
        
        print(f"\n📨 From: {h.get('from', 'N/A')}")
        print(f"📬 To: {h.get('to', 'N/A')}")
        print(f"📋 Subject: {h.get('subject', 'N/A')}")
        print(f"📅 Date: {h.get('date', 'N/A')}")
        print(f"🆔 Message-ID: {h.get('message_id', 'N/A')}")
        
        print(f"\n🔐 Authentication Status:")
        print(f"  SPF:   {a.get('spf', 'UNKNOWN')}")
        print(f"  DKIM:  {a.get('dkim', 'UNKNOWN')}")
        print(f"  DMARC: {a.get('dmarc', 'UNKNOWN')}")
        
        if a.get('issues'):
            print(f"\n⚠️  Authentication Issues:")
            for issue in a['issues']:
                print(f"  • {issue}")
    
    def print_pattern_results(self):
        """Print pattern detection results"""
        p = self.results['patterns']
        
        print(f"\n🔍 Pattern Detection:")
        print(f"  Urgent Keywords: {len(p.get('urgent_keywords', []))} found")
        if p.get('urgent_keywords'):
            print(f"    → {', '.join(p['urgent_keywords'][:5])}")
        
        print(f"  Suspicious Patterns: {len(p.get('suspicious_patterns', []))} found")
        if p.get('suspicious_patterns'):
            for pattern in p['suspicious_patterns'][:3]:
                print(f"    → {pattern}")
        
        if p.get('brand_impersonation'):
            print(f"\n⚠️  Possible Brand Impersonation: {p['brand_impersonation']}")
        
        if p.get('credential_harvesting'):
            print(f"⚠️  Credential Harvesting Detected: {p['credential_harvesting']}")
    
    def print_url_results(self):
        """Print URL analysis summary"""
        if not self.results['urls']:
            return
        
        print(f"\n🔗 URL Analysis Summary:")
        suspicious_count = sum(1 for u in self.results['urls'] if u.get('risk_level') in ['HIGH', 'CRITICAL'])
        print(f"  Total URLs: {len(self.results['urls'])}")
        print(f"  Suspicious: {suspicious_count}")
        
        for idx, url_result in enumerate(self.results['urls'], 1):
            risk = url_result.get('risk_level', 'UNKNOWN')
            risk_emoji = {'LOW': '✅', 'MEDIUM': '⚠️', 'HIGH': '🚨', 'CRITICAL': '☠️'}.get(risk, '❓')
            print(f"\n  [{idx}] {risk_emoji} Risk: {risk}")
            print(f"      URL: {url_result.get('original_url', '')[:60]}...")
            print(f"      Redirects: {url_result.get('redirect_count', 0)}")
            
            if url_result.get('contacted_domains'):
                print(f"      Contacted: {len(url_result['contacted_domains'])} domains")
    
    def print_attachment_results(self):
        """Print attachment analysis summary"""
        if not self.results['attachments']:
            return
        
        print(f"\n📎 Attachment Analysis:")
        for idx, att in enumerate(self.results['attachments'], 1):
            analysis = att.get('analysis', {})
            risk = analysis.get('risk_level', 'UNKNOWN')
            risk_emoji = {'LOW': '✅', 'MEDIUM': '⚠️', 'HIGH': '🚨', 'CRITICAL': '☠️'}.get(risk, '❓')
            
            print(f"\n  [{idx}] {risk_emoji} {att['filename']}")
            print(f"      Type: {analysis.get('file_type', 'Unknown')}")
            print(f"      Size: {att['size']} bytes")
            print(f"      Risk: {risk}")
            
            if analysis.get('threats'):
                print(f"      Threats:")
                for threat in analysis['threats'][:3]:
                    print(f"        • {threat}")
    
    def print_final_verdict(self):
        """Print final verdict"""
        score = self.results['scores']['final_score']
        verdict = self.results['scores']['verdict']
        
        # Visual representation
        bar_length = 50
        filled = int((score / 100) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        # Verdict emoji
        verdict_emoji = {
            'BENIGN': '✅',
            'SUSPICIOUS': '⚠️',
            'MALICIOUS': '🚨'
        }.get(verdict, '❓')
        
        print(f"\n{'='*80}")
        print(f" FINAL VERDICT")
        print(f"{'='*80}")
        print(f"\n{verdict_emoji} {verdict}")
        print(f"\n📊 Risk Score: {score}/100")
        print(f"[{bar}] {score}%")
        print(f"\n📝 Explanation:")
        print(self.results['scores']['explanation'])
    
    def generate_reports(self):
        """Generate comprehensive reports"""
        # Text Report
        report_file = f"{self.output_dir}/analysis_report.txt"
        self.generate_text_report(report_file)
        print(f"✓ Text report: {report_file}")
        
        # JSON Report
        json_file = f"{self.output_dir}/analysis_report.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"✓ JSON report: {json_file}")
        
        # HTML Report (optional, can be expanded)
        html_file = f"{self.output_dir}/analysis_report.html"
        self.generate_html_report(html_file)
        print(f"✓ HTML report: {html_file}")
    
    def generate_text_report(self, filename):
        """Generate detailed text report"""
        lines = []
        
        # Header
        lines.append("="*80)
        lines.append(" ADVANCED PHISHING EMAIL ANALYSIS REPORT")
        lines.append("="*80)
        lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Email File: {self.eml_path}")
        lines.append(f"Analyst: Phishing Analyzer v2.0")
        lines.append("="*80)
        lines.append("")
        
        # Executive Summary
        lines.append("="*80)
        lines.append(" EXECUTIVE SUMMARY")
        lines.append("="*80)
        lines.append(f"Verdict: {self.results['scores']['verdict']}")
        lines.append(f"Risk Score: {self.results['scores']['final_score']}/100")
        lines.append(f"\n{self.results['scores']['explanation']}")
        lines.append("")
        
        # Headers
        lines.append("="*80)
        lines.append(" EMAIL HEADERS")
        lines.append("="*80)
        for key, value in self.results['headers'].items():
            lines.append(f"{key.upper()}: {value}")
        lines.append("")
        
        # Authentication
        lines.append("="*80)
        lines.append(" AUTHENTICATION")
        lines.append("="*80)
        for key, value in self.results['authentication'].items():
            lines.append(f"{key.upper()}: {value}")
        lines.append("")
        
        # Patterns
        lines.append("="*80)
        lines.append(" PATTERN DETECTION")
        lines.append("="*80)
        lines.append(json.dumps(self.results['patterns'], indent=2))
        lines.append("")
        
        # URLs
        if self.results['urls']:
            lines.append("="*80)
            lines.append(f" URL ANALYSIS ({len(self.results['urls'])} URLs)")
            lines.append("="*80)
            for idx, url_result in enumerate(self.results['urls'], 1):
                lines.append(f"\n[URL {idx}]")
                lines.append(f"Original: {url_result.get('original_url', 'N/A')}")
                lines.append(f"Risk Level: {url_result.get('risk_level', 'UNKNOWN')}")
                lines.append(f"Redirects: {url_result.get('redirect_count', 0)}")
                if url_result.get('final_url'):
                    lines.append(f"Final URL: {url_result['final_url']}")
                if url_result.get('contacted_domains'):
                    lines.append(f"Contacted Domains: {', '.join(url_result['contacted_domains'])}")
                lines.append("-"*80)
            lines.append("")
        
        # Attachments
        if self.results['attachments']:
            lines.append("="*80)
            lines.append(f" ATTACHMENTS ({len(self.results['attachments'])})")
            lines.append("="*80)
            for idx, att in enumerate(self.results['attachments'], 1):
                lines.append(f"\n[Attachment {idx}]")
                lines.append(f"Filename: {att['filename']}")
                lines.append(f"Size: {att['size']} bytes")
                lines.append(f"SHA256: {att['hashes'].get('sha256', 'N/A')}")
                lines.append(f"MD5: {att['hashes'].get('md5', 'N/A')}")
                if att.get('analysis'):
                    lines.append(f"Risk Level: {att['analysis'].get('risk_level', 'UNKNOWN')}")
                    lines.append(f"File Type: {att['analysis'].get('file_type', 'Unknown')}")
                lines.append("-"*80)
            lines.append("")
        
        # AI Analysis
        lines.append("="*80)
        lines.append(" AI ANALYSIS")
        lines.append("="*80)
        lines.append(self.results.get('ai_analysis', 'Not available'))
        lines.append("")
        
        # Footer
        lines.append("="*80)
        lines.append(f"End of Report | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("="*80)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
    
    def generate_html_report(self, filename):
        """Generate HTML report with visual elements"""
        verdict = self.results['scores']['verdict']
        score = self.results['scores']['final_score']
        
        # Color based on verdict
        color_map = {
            'BENIGN': '#4CAF50',
            'SUSPICIOUS': '#FF9800',
            'MALICIOUS': '#F44336'
        }
        color = color_map.get(verdict, '#9E9E9E')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid {color}; padding-bottom: 20px; margin-bottom: 30px; }}
        .verdict {{ background: {color}; color: white; padding: 20px; border-radius: 8px; text-align: center; font-size: 24px; font-weight: bold; margin: 20px 0; }}
        .score {{ font-size: 48px; font-weight: bold; color: {color}; text-align: center; margin: 20px 0; }}
        .section {{ margin: 30px 0; padding: 20px; border-left: 4px solid {color}; background: #f9f9f9; }}
        .section-title {{ font-size: 20px; font-weight: bold; margin-bottom: 15px; color: #333; }}
        .metric {{ display: inline-block; margin: 10px 20px 10px 0; padding: 10px 15px; background: #e3f2fd; border-radius: 4px; }}
        .metric-label {{ font-weight: bold; color: #555; }}
        .metric-value {{ color: #1976d2; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        .risk-high {{ color: #F44336; font-weight: bold; }}
        .risk-medium {{ color: #FF9800; font-weight: bold; }}
        .risk-low {{ color: #4CAF50; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Phishing Email Analysis Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>File: {self.eml_path}</p>
        </div>
        
        <div class="verdict">{verdict}</div>
        <div class="score">{score}/100</div>
        
        <div class="section">
            <div class="section-title">📊 Summary</div>
            <div class="metric">
                <span class="metric-label">URLs Found:</span>
                <span class="metric-value">{len(self.results['urls'])}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Attachments:</span>
                <span class="metric-value">{len(self.results['attachments'])}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Suspicious Patterns:</span>
                <span class="metric-value">{len(self.results['patterns'].get('suspicious_patterns', []))}</span>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📧 Email Information</div>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                <tr><td>From</td><td>{self.results['headers'].get('from', 'N/A')}</td></tr>
                <tr><td>To</td><td>{self.results['headers'].get('to', 'N/A')}</td></tr>
                <tr><td>Subject</td><td>{self.results['headers'].get('subject', 'N/A')}</td></tr>
                <tr><td>Date</td><td>{self.results['headers'].get('date', 'N/A')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">🔐 Authentication</div>
            <table>
                <tr><th>Protocol</th><th>Status</th></tr>
                <tr><td>SPF</td><td>{self.results['authentication'].get('spf', 'UNKNOWN')}</td></tr>
                <tr><td>DKIM</td><td>{self.results['authentication'].get('dkim', 'UNKNOWN')}</td></tr>
                <tr><td>DMARC</td><td>{self.results['authentication'].get('dmarc', 'UNKNOWN')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">📝 Explanation</div>
            <p>{self.results['scores']['explanation']}</p>
        </div>
        
        <div style="text-align: center; margin-top: 40px; color: #999; font-size: 12px;">
            <p>Phishing Analyzer v2.0 | Offline Analysis Tool</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_phishing_v2.py <email.eml>")
        print("\nExample:")
        print("  python3 analyze_phishing_v2.py suspicious.eml")
        sys.exit(1)
    
    eml_file = sys.argv[1]
    analyzer = PhishingAnalyzer(eml_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()

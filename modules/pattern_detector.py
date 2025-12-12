"""
Pattern Detector Module
Detects phishing patterns, brand impersonation, and social engineering tactics
"""

import re
from difflib import SequenceMatcher


class PatternDetector:
    def __init__(self):
        # Load brand list
        self.brands = [
            'google', 'microsoft', 'amazon', 'apple', 'facebook', 'meta',
            'paypal', 'netflix', 'linkedin', 'instagram', 'twitter', 'bank',
            'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'fedex',
            'ups', 'dhl', 'usps', 'irs', 'ssa', 'fbi', 'cia', 'adobe',
            'dropbox', 'docusign', 'salesforce', 'ebay', 'walmart', 'target'
        ]
        
        # Urgent/suspicious keywords
        self.urgent_keywords = [
            'urgent', 'immediate', 'action required', 'verify', 'suspend',
            'suspended', 'locked', 'unusual', 'security alert', 'confirm',
            'update required', 'expire', 'limited time', 'act now',
            'click here', 'within 24', 'within 48', 'unauthorized',
            'suspicious activity', 'click immediately', 'verify identity',
            'account will be', 'reset password', 'update payment'
        ]
        
        # Credential harvesting indicators
        self.credential_patterns = [
            'enter password', 'confirm password', 'login', 'sign in',
            'verify account', 'update credentials', 'payment information',
            'credit card', 'ssn', 'social security', 'account number',
            'routing number', 'pin', 'cvv', 'security code'
        ]
    
    def detect_patterns(self, body_text, body_html, subject, from_addr):
        """Detect various phishing patterns"""
        patterns = {
            'urgent_keywords': [],
            'suspicious_patterns': [],
            'brand_impersonation': None,
            'typosquatting': None,
            'credential_harvesting': None,
            'html_analysis': {},
            'grammar_issues': 0,
            'urgency_score': 0
        }
        
        # Combine text for analysis
        all_text = f"{subject} {body_text} {body_html}".lower()
        
        # Detect urgent keywords
        for keyword in self.urgent_keywords:
            if keyword in all_text:
                patterns['urgent_keywords'].append(keyword)
        
        patterns['urgency_score'] = len(patterns['urgent_keywords']) * 10
        
        # Detect credential harvesting attempts
        for pattern in self.credential_patterns:
            if pattern in all_text:
                patterns['credential_harvesting'] = pattern
                patterns['suspicious_patterns'].append(f'Credential request: {pattern}')
                break
        
        # Brand impersonation detection
        brand_found = self.detect_brand_impersonation(from_addr, subject, all_text)
        if brand_found:
            patterns['brand_impersonation'] = brand_found
            patterns['suspicious_patterns'].append(f'Possible brand impersonation: {brand_found}')
        
        # Typosquatting detection
        typosquat = self.detect_typosquatting(from_addr)
        if typosquat:
            patterns['typosquatting'] = typosquat
            patterns['suspicious_patterns'].append(f'Typosquatting detected: {typosquat}')
        
        # HTML-specific analysis
        if body_html:
            patterns['html_analysis'] = self.analyze_html(body_html)
        
        # Grammar/spelling analysis
        patterns['grammar_issues'] = self.detect_grammar_issues(body_text, subject)
        
        # URL shorteners
        if self.detect_url_shorteners(all_text):
            patterns['suspicious_patterns'].append('URL shortener detected')
        
        # Excessive urgency
        if patterns['urgency_score'] > 30:
            patterns['suspicious_patterns'].append('Excessive urgency language')
        
        # Check for mismatched display names
        mismatch = self.check_display_name_mismatch(from_addr)
        if mismatch:
            patterns['suspicious_patterns'].append(f'Display name mismatch: {mismatch}')
        
        return patterns
    
    def detect_brand_impersonation(self, from_addr, subject, text):
        """Detect brand impersonation attempts"""
        for brand in self.brands:
            # Check if brand mentioned in subject/text but not in from_addr
            if brand in text:
                from_domain = self.extract_domain(from_addr)
                if from_domain and brand not in from_domain.lower():
                    # Brand mentioned but not from legitimate domain
                    return brand.upper()
        
        return None
    
    def detect_typosquatting(self, from_addr):
        """Detect typosquatting in email domain"""
        from_domain = self.extract_domain(from_addr)
        
        if not from_domain:
            return None
        
        # Check similarity with known brands
        for brand in self.brands:
            brand_domain = f"{brand}.com"
            similarity = SequenceMatcher(None, from_domain, brand_domain).ratio()
            
            # If very similar but not exact match
            if 0.7 < similarity < 1.0:
                return f"{from_domain} (similar to {brand_domain})"
        
        # Common typosquatting patterns
        suspicious_patterns = [
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Many hyphens
            r'[0-9]{5,}',  # Long number sequences
            r'[a-z]{20,}',  # Very long domain names
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, from_domain):
                return f"{from_domain} (suspicious pattern)"
        
        return None
    
    def analyze_html(self, html):
        """Analyze HTML for suspicious patterns"""
        analysis = {
            'hidden_content': False,
            'invisible_text': False,
            'mismatched_links': 0,
            'javascript_found': False,
            'obfuscation': False
        }
        
        html_lower = html.lower()
        
        # Check for hidden content
        if 'display:none' in html_lower or 'visibility:hidden' in html_lower:
            analysis['hidden_content'] = True
        
        # Check for invisible text (white text on white background)
        if re.search(r'color:\s*#?fff|color:\s*white', html_lower) and \
           re.search(r'background.*?#?fff|background.*?white', html_lower):
            analysis['invisible_text'] = True
        
        # Check for JavaScript
        if '<script' in html_lower or 'javascript:' in html_lower:
            analysis['javascript_found'] = True
        
        # Check for link/text mismatch
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(link_pattern, html, re.IGNORECASE)
        
        for href, text in matches:
            # If link text looks like a URL but href is different
            if 'http' in text and href not in text:
                analysis['mismatched_links'] += 1
        
        # Check for obfuscation
        if 'eval(' in html_lower or 'unescape(' in html_lower or \
           'fromcharcode' in html_lower or 'atob(' in html_lower:
            analysis['obfuscation'] = True
        
        return analysis
    
    def detect_grammar_issues(self, text, subject):
        """Detect potential grammar/spelling issues (simplified)"""
        issues = 0
        
        combined = f"{subject} {text}".lower()
        
        # Common phishing grammar mistakes
        common_mistakes = [
            'kindly',  # Overused in phishing
            'do the needful',  # Non-native English
            'please revert',
            'your account have been',  # Grammar error
            'kindly verify',
            'please confirm you account',
            'update you account',
            'click in this link',
            'within 24 hours time'
        ]
        
        for mistake in common_mistakes:
            if mistake in combined:
                issues += 1
        
        return issues
    
    def detect_url_shorteners(self, text):
        """Detect URL shortening services"""
        shorteners = [
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'short.link'
        ]
        
        for shortener in shorteners:
            if shortener in text.lower():
                return True
        
        return False
    
    def check_display_name_mismatch(self, from_addr):
        """Check if display name doesn't match email address"""
        # Extract display name and email
        match = re.search(r'([^<]+)<([^>]+)>', from_addr)
        
        if match:
            display_name = match.group(1).strip().lower()
            email = match.group(2).strip().lower()
            
            # Extract domain from email
            domain = self.extract_domain(email)
            
            # Check if display name contains a different domain or brand
            for brand in self.brands:
                if brand in display_name and brand not in domain:
                    return f"{brand} in display name but not in domain"
        
        return None
    
    def extract_domain(self, email_address):
        """Extract domain from email address"""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        if match:
            return match.group(1).lower()
        return None
    
    def calculate_social_engineering_score(self, patterns):
        """Calculate social engineering score"""
        score = 0
        
        # Urgency
        score += patterns['urgency_score']
        
        # Credential harvesting
        if patterns['credential_harvesting']:
            score += 30
        
        # Brand impersonation
        if patterns['brand_impersonation']:
            score += 25
        
        # Typosquatting
        if patterns['typosquatting']:
            score += 25
        
        # HTML tricks
        html = patterns['html_analysis']
        if html.get('hidden_content'):
            score += 15
        if html.get('obfuscation'):
            score += 20
        if html.get('mismatched_links', 0) > 0:
            score += 10
        
        # Grammar issues
        score += patterns['grammar_issues'] * 5
        
        return min(score, 100)  # Cap at 100

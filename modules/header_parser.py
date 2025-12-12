"""
Header Parser Module
Advanced email header analysis and authentication checking
"""

import re
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime


class HeaderParser:
    def __init__(self):
        self.known_legitimate_domains = [
            'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
            'facebook.com', 'paypal.com', 'linkedin.com', 'twitter.com'
        ]
    
    def parse_headers(self, msg):
        """Extract and parse all important headers"""
        headers = {}
        
        # Basic headers
        headers['from'] = msg.get('From', 'N/A')
        headers['to'] = msg.get('To', 'N/A')
        headers['subject'] = self.decode_header(msg.get('Subject', 'N/A'))
        headers['date'] = msg.get('Date', 'N/A')
        headers['message_id'] = msg.get('Message-ID', 'N/A')
        headers['return_path'] = msg.get('Return-Path', 'N/A')
        headers['reply_to'] = msg.get('Reply-To', 'N/A')
        
        # Parse From address
        headers['from_name'], headers['from_address'] = parseaddr(headers['from'])
        
        # Parse Reply-To if present
        if headers['reply_to'] != 'N/A':
            headers['reply_to_name'], headers['reply_to_address'] = parseaddr(headers['reply_to'])
        
        # Extract Received headers (email path)
        headers['received_headers'] = self.parse_received_headers(msg)
        
        # X-Headers (often contain useful info)
        headers['x_headers'] = self.extract_x_headers(msg)
        
        return headers
    
    def decode_header(self, header_value):
        """Decode email header"""
        from email.header import decode_header
        
        if not header_value:
            return "N/A"
        
        decoded_parts = decode_header(header_value)
        decoded_string = ""
        
        for content, encoding in decoded_parts:
            if isinstance(content, bytes):
                try:
                    if encoding:
                        decoded_string += content.decode(encoding)
                    else:
                        decoded_string += content.decode('utf-8', errors='ignore')
                except:
                    decoded_string += str(content)
            else:
                decoded_string += str(content)
        
        return decoded_string
    
    def parse_received_headers(self, msg):
        """Parse Received headers to trace email path"""
        received_headers = msg.get_all('Received', [])
        
        parsed_received = []
        
        for received in received_headers:
            hop = self.parse_single_received(received)
            parsed_received.append(hop)
        
        return parsed_received
    
    def parse_single_received(self, received_header):
        """Parse a single Received header"""
        hop = {
            'raw': received_header,
            'from_server': 'Unknown',
            'by_server': 'Unknown',
            'timestamp': 'Unknown',
            'ip_address': None
        }
        
        # Extract 'from' server
        from_match = re.search(r'from\s+([^\s]+)', received_header, re.IGNORECASE)
        if from_match:
            hop['from_server'] = from_match.group(1)
        
        # Extract 'by' server
        by_match = re.search(r'by\s+([^\s]+)', received_header, re.IGNORECASE)
        if by_match:
            hop['by_server'] = by_match.group(1)
        
        # Extract IP address
        ip_pattern = r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
        ip_match = re.search(ip_pattern, received_header)
        if ip_match:
            hop['ip_address'] = ip_match.group(1)
        
        # Extract timestamp
        date_pattern = r';\s*(.+?)(?:\s*\(|$)'
        date_match = re.search(date_pattern, received_header)
        if date_match:
            hop['timestamp'] = date_match.group(1).strip()
        
        return hop
    
    def extract_x_headers(self, msg):
        """Extract X- headers which often contain routing info"""
        x_headers = {}
        
        for key in msg.keys():
            if key.startswith('X-'):
                x_headers[key] = msg.get(key)
        
        return x_headers
    
    def analyze_authentication(self, msg):
        """Analyze email authentication (SPF, DKIM, DMARC)"""
        auth_results = {
            'spf': 'UNKNOWN',
            'dkim': 'UNKNOWN',
            'dmarc': 'UNKNOWN',
            'arc': 'UNKNOWN',
            'raw_authentication_results': '',
            'issues': []
        }
        
        # Get Authentication-Results header
        auth_header = msg.get('Authentication-Results', '')
        auth_results['raw_authentication_results'] = auth_header
        
        if auth_header:
            auth_lower = auth_header.lower()
            
            # Check SPF
            if 'spf=pass' in auth_lower:
                auth_results['spf'] = 'PASS'
            elif 'spf=fail' in auth_lower:
                auth_results['spf'] = 'FAIL'
                auth_results['issues'].append('SPF validation failed')
            elif 'spf=softfail' in auth_lower:
                auth_results['spf'] = 'SOFTFAIL'
                auth_results['issues'].append('SPF soft fail')
            elif 'spf=none' in auth_lower:
                auth_results['spf'] = 'NONE'
            
            # Check DKIM
            if 'dkim=pass' in auth_lower:
                auth_results['dkim'] = 'PASS'
            elif 'dkim=fail' in auth_lower:
                auth_results['dkim'] = 'FAIL'
                auth_results['issues'].append('DKIM validation failed')
            elif 'dkim=none' in auth_lower:
                auth_results['dkim'] = 'NONE'
            
            # Check DMARC
            if 'dmarc=pass' in auth_lower:
                auth_results['dmarc'] = 'PASS'
            elif 'dmarc=fail' in auth_lower:
                auth_results['dmarc'] = 'FAIL'
                auth_results['issues'].append('DMARC validation failed')
            elif 'dmarc=none' in auth_lower:
                auth_results['dmarc'] = 'NONE'
            
            # Check ARC (Authenticated Received Chain)
            if 'arc=pass' in auth_lower:
                auth_results['arc'] = 'PASS'
            elif 'arc=fail' in auth_lower:
                auth_results['arc'] = 'FAIL'
        
        # Check DKIM-Signature header separately
        dkim_sig = msg.get('DKIM-Signature', '')
        if dkim_sig and auth_results['dkim'] == 'UNKNOWN':
            auth_results['dkim'] = 'PRESENT'
        
        # Check for Reply-To / From mismatch
        from_addr = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        if reply_to and reply_to != from_addr:
            from_domain = self.extract_domain(from_addr)
            reply_to_domain = self.extract_domain(reply_to)
            
            if from_domain != reply_to_domain:
                auth_results['issues'].append(
                    f'Reply-To domain mismatch: From={from_domain}, Reply-To={reply_to_domain}'
                )
        
        # Check for suspicious Return-Path
        return_path = msg.get('Return-Path', '')
        if return_path:
            return_domain = self.extract_domain(return_path)
            from_domain = self.extract_domain(from_addr)
            
            if return_domain and from_domain and return_domain != from_domain:
                auth_results['issues'].append(
                    f'Return-Path domain mismatch: From={from_domain}, Return-Path={return_domain}'
                )
        
        return auth_results
    
    def extract_domain(self, email_address):
        """Extract domain from email address"""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        if match:
            return match.group(1).lower()
        return None
    
    def check_header_inconsistencies(self, headers):
        """Check for inconsistencies in headers"""
        issues = []
        
        # Check timezone consistency in Received headers
        received = headers.get('received_headers', [])
        if len(received) > 1:
            # Parse timestamps and check for anomalies
            timestamps = []
            for hop in received:
                ts = hop.get('timestamp')
                if ts and ts != 'Unknown':
                    try:
                        # This is simplified - full implementation would parse various date formats
                        timestamps.append(ts)
                    except:
                        pass
        
        # Check for suspicious server names in path
        for hop in received:
            from_server = hop.get('from_server', '').lower()
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'unknown', 'localhost', '127.0.0.1', 'dynamic',
                'dhcp', 'broadband', 'cable', 'residential'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in from_server:
                    issues.append(f'Suspicious server in email path: {from_server}')
                    break
        
        return issues
    
    def analyze_message_id(self, message_id):
        """Analyze Message-ID format"""
        analysis = {
            'valid_format': False,
            'domain': None,
            'suspicious': False
        }
        
        if not message_id or message_id == 'N/A':
            analysis['suspicious'] = True
            return analysis
        
        # Message-ID should be in format: <unique-id@domain>
        match = re.search(r'<(.+?)@(.+?)>', message_id)
        
        if match:
            analysis['valid_format'] = True
            analysis['domain'] = match.group(2)
        else:
            analysis['suspicious'] = True
        
        return analysis

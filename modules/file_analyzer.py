"""
File Analyzer Module
Deep analysis of email attachments using offline tools
"""

import subprocess
import os
import re
import json
import magic
from pathlib import Path


class FileAnalyzer:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.attachments_dir = f"{output_dir}/attachments"
        self.extracted_dir = f"{output_dir}/extracted_content"
    
    def analyze_file(self, filepath, filename):
        """
        Comprehensive file analysis
        """
        result = {
            'filename': filename,
            'filepath': filepath,
            'file_type': 'Unknown',
            'size': 0,
            'mime_type': '',
            'magic_bytes': '',
            'strings_analysis': {},
            'metadata': {},
            'embedded_files': [],
            'macros_detected': False,
            'yara_matches': [],
            'risk_level': 'LOW',
            'threats': [],
            'risk_score': 0
        }
        
        if not os.path.exists(filepath):
            result['error'] = 'File not found'
            return result
        
        result['size'] = os.path.getsize(filepath)
        
        # Step 1: File type identification
        print(f"      [1/7] Identifying file type...")
        result['file_type'], result['mime_type'] = self.identify_file_type(filepath)
        result['magic_bytes'] = self.get_magic_bytes(filepath)
        
        # Step 2: Strings extraction
        print(f"      [2/7] Extracting strings...")
        result['strings_analysis'] = self.extract_strings(filepath)
        
        # Step 3: Metadata extraction
        print(f"      [3/7] Extracting metadata...")
        result['metadata'] = self.extract_metadata(filepath)
        
        # Step 4: Check for embedded files
        print(f"      [4/7] Checking for embedded files...")
        result['embedded_files'] = self.check_embedded_files(filepath)
        
        # Step 5: Office document analysis
        if self.is_office_document(result['file_type']):
            print(f"      [5/7] Analyzing Office document...")
            office_analysis = self.analyze_office_doc(filepath)
            result['macros_detected'] = office_analysis['has_macros']
            result['threats'].extend(office_analysis['threats'])
        else:
            print(f"      [5/7] Skipping Office analysis (not applicable)")
        
        # Step 6: PDF analysis
        if 'pdf' in result['file_type'].lower():
            print(f"      [6/7] Analyzing PDF...")
            pdf_analysis = self.analyze_pdf(filepath)
            result['threats'].extend(pdf_analysis['threats'])
        else:
            print(f"      [6/7] Skipping PDF analysis (not applicable)")
        
        # Step 7: YARA scanning
        print(f"      [7/7] Running YARA rules...")
        result['yara_matches'] = self.run_yara_scan(filepath)
        
        # Calculate risk
        result['risk_level'], result['risk_score'] = self.calculate_file_risk(result)
        
        return result
    
    def identify_file_type(self, filepath):
        """Identify file type using multiple methods"""
        try:
            # Use file command
            cmd = f'file -b "{filepath}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            file_type = result.stdout.strip()
            
            # Use python-magic for MIME type
            mime_type = magic.from_file(filepath, mime=True)
            
            return file_type, mime_type
        except Exception as e:
            return f"Unknown ({str(e)})", "unknown"
    
    def get_magic_bytes(self, filepath):
        """Get first 16 bytes (magic bytes)"""
        try:
            with open(filepath, 'rb') as f:
                magic_bytes = f.read(16)
                return ' '.join(f'{b:02x}' for b in magic_bytes)
        except:
            return "N/A"
    
    def extract_strings(self, filepath):
        """Extract and analyze strings from file"""
        analysis = {
            'total_strings': 0,
            'suspicious_strings': [],
            'urls': [],
            'ips': [],
            'emails': []
        }
        
        try:
            # Extract strings using strings command
            cmd = f'strings -n 4 "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            strings_list = result.stdout.split('\n')
            analysis['total_strings'] = len(strings_list)
            
            # Patterns to search for
            url_pattern = r'https?://[^\s<>"\'(){}[\]]+'
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            
            suspicious_keywords = [
                'powershell', 'cmd.exe', 'eval', 'exec', 'system',
                'shell', 'download', 'invoke', 'base64', 'decode',
                'password', 'credential', 'token', 'admin', 'root'
            ]
            
            for string in strings_list[:1000]:  # Limit to first 1000 strings
                # Check URLs
                urls = re.findall(url_pattern, string, re.IGNORECASE)
                analysis['urls'].extend(urls)
                
                # Check IPs
                ips = re.findall(ip_pattern, string)
                analysis['ips'].extend(ips)
                
                # Check emails
                emails = re.findall(email_pattern, string)
                analysis['emails'].extend(emails)
                
                # Check suspicious keywords
                for keyword in suspicious_keywords:
                    if keyword.lower() in string.lower():
                        if string not in analysis['suspicious_strings']:
                            analysis['suspicious_strings'].append(string[:100])
            
            # Remove duplicates
            analysis['urls'] = list(set(analysis['urls']))[:10]
            analysis['ips'] = list(set(analysis['ips']))[:10]
            analysis['emails'] = list(set(analysis['emails']))[:10]
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def extract_metadata(self, filepath):
        """Extract file metadata using exiftool"""
        metadata = {}
        
        try:
            cmd = f'exiftool -j "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                metadata_json = json.loads(result.stdout)
                if metadata_json:
                    metadata = metadata_json[0]
                    
                    # Extract important fields
                    important_fields = [
                        'Author', 'Creator', 'Producer', 'CreatorTool',
                        'CreateDate', 'ModifyDate', 'Title', 'Subject',
                        'Company', 'LastModifiedBy'
                    ]
                    
                    filtered_metadata = {}
                    for field in important_fields:
                        if field in metadata:
                            filtered_metadata[field] = metadata[field]
                    
                    return filtered_metadata
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def check_embedded_files(self, filepath):
        """Check for embedded files using binwalk"""
        embedded = []
        
        try:
            cmd = f'binwalk -e "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Parse binwalk output
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('DECIMAL'):
                    embedded.append(line.strip())
            
        except Exception as e:
            embedded.append(f"Error: {str(e)}")
        
        return embedded[:10]  # Limit to first 10
    
    def is_office_document(self, file_type):
        """Check if file is an Office document"""
        office_extensions = [
            'word', 'excel', 'powerpoint', 'docx', 'xlsx', 'pptx',
            'doc', 'xls', 'ppt', 'office', 'openxml'
        ]
        return any(ext in file_type.lower() for ext in office_extensions)
    
    def analyze_office_doc(self, filepath):
        """Analyze Office documents for macros and threats"""
        analysis = {
            'has_macros': False,
            'threats': [],
            'vba_code': []
        }
        
        try:
            # Use olevba to extract VBA macros
            cmd = f'olevba "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            output = result.stdout
            
            # Check for macros
            if 'VBA MACRO' in output or 'Sub ' in output or 'Function ' in output:
                analysis['has_macros'] = True
                analysis['threats'].append('VBA Macros detected')
            
            # Check for suspicious patterns
            suspicious_patterns = [
                ('AutoOpen', 'Auto-execute macro'),
                ('AutoExec', 'Auto-execute macro'),
                ('Document_Open', 'Auto-execute macro'),
                ('Workbook_Open', 'Auto-execute macro'),
                ('Shell', 'Shell execution'),
                ('CreateObject', 'Object creation'),
                ('WScript', 'Windows Script execution'),
                ('powershell', 'PowerShell execution'),
                ('cmd', 'Command execution'),
                ('URLDownloadToFile', 'File download'),
                ('ChDir', 'Directory change')
            ]
            
            for pattern, description in suspicious_patterns:
                if pattern.lower() in output.lower():
                    analysis['threats'].append(f'{description} ({pattern})')
            
            # Use mraptor for additional analysis
            cmd = f'mraptor "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if 'SUSPICIOUS' in result.stdout or 'MALICIOUS' in result.stdout:
                analysis['threats'].append('Suspicious macro behavior detected')
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def analyze_pdf(self, filepath):
        """Analyze PDF for threats"""
        analysis = {
            'threats': [],
            'javascript': False,
            'embedded_files': False,
            'suspicious_actions': []
        }
        
        try:
            # Use pdfid.py or pdf-parser
            cmd = f'pdfid "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            output = result.stdout
            
            # Check for suspicious elements
            suspicious_elements = {
                '/JS': 'JavaScript',
                '/JavaScript': 'JavaScript',
                '/AA': 'Automatic Action',
                '/OpenAction': 'Automatic Action',
                '/Launch': 'Launch Action',
                '/EmbeddedFile': 'Embedded File',
                '/AcroForm': 'Form',
                '/XFA': 'XFA Form'
            }
            
            for element, description in suspicious_elements.items():
                if element in output:
                    analysis['threats'].append(f'{description} detected')
                    if 'JavaScript' in description:
                        analysis['javascript'] = True
                    if 'Embedded' in description:
                        analysis['embedded_files'] = True
            
            # Use pdf-parser for deeper analysis
            cmd = f'pdf-parser -a "{filepath}" 2>/dev/null | head -100'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Look for obfuscation
            if 'stream' in result.stdout.lower() and 'filter' in result.stdout.lower():
                analysis['suspicious_actions'].append('Potentially obfuscated content')
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def run_yara_scan(self, filepath):
        """Run YARA rules against file"""
        matches = []
        
        # Check if YARA rules exist
        yara_rules_file = 'patterns/malware.yar'
        
        if not os.path.exists(yara_rules_file):
            return matches
        
        try:
            cmd = f'yara "{yara_rules_file}" "{filepath}" 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    matches.append(line.strip())
                    
        except Exception as e:
            matches.append(f"YARA scan error: {str(e)}")
        
        return matches
    
    def calculate_file_risk(self, result):
        """Calculate file risk level"""
        risk_score = 0
        
        # File type risks
        dangerous_types = ['executable', 'script', 'dll', 'bat', 'vbs', 'js']
        if any(dt in result['file_type'].lower() for dt in dangerous_types):
            risk_score += 40
        
        # Macro risks
        if result['macros_detected']:
            risk_score += 30
        
        # Embedded files
        if result['embedded_files']:
            risk_score += 15
        
        # Suspicious strings
        strings_analysis = result['strings_analysis']
        if strings_analysis.get('suspicious_strings'):
            risk_score += 10
        if strings_analysis.get('urls'):
            risk_score += 5
        if strings_analysis.get('ips'):
            risk_score += 5
        
        # YARA matches
        if result['yara_matches']:
            risk_score += 25
        
        # Threats detected
        risk_score += len(result['threats']) * 10
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'CRITICAL'
        elif risk_score >= 40:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return risk_level, risk_score

"""
URL Detonation Module
Detonates URLs in a controlled environment and monitors all traffic
"""

import subprocess
import time
import os
import re
import json
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
import threading


class URLDetonator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.screenshots_dir = f"{output_dir}/screenshots"
        self.traffic_dir = f"{output_dir}/traffic_dumps"
        self.detonation_dir = f"{output_dir}/detonation_logs"
    
    def detonate_url(self, url, index):
        """
        Detonate URL in isolated environment and capture all activity
        """
        result = {
            'original_url': url,
            'index': index,
            'redirect_count': 0,
            'redirects': [],
            'final_url': url,
            'contacted_domains': [],
            'resources_loaded': [],
            'forms_detected': [],
            'javascript_analysis': {},
            'ssl_info': {},
            'risk_level': 'LOW',
            'risk_factors': [],
            'screenshot': None,
            'dom_analysis': {},
            'cookies_set': [],
            'storage_accessed': False
        }
        
        try:
            # Step 1: Check redirects with curl
            print("  [1/5] Checking redirects...")
            redirect_info = self.check_redirects_curl(url)
            result['redirect_count'] = redirect_info['redirect_count']
            result['redirects'] = redirect_info['redirects']
            result['final_url'] = redirect_info['final_url']
            
            if result['redirect_count'] > 0:
                print(f"      ↪ {result['redirect_count']} redirects detected")
            
            # Step 2: SSL/TLS Analysis
            print("  [2/5] Analyzing SSL/TLS...")
            result['ssl_info'] = self.analyze_ssl(result['final_url'])
            
            # Step 3: Capture network traffic with tcpdump
            print("  [3/5] Starting traffic capture...")
            pcap_file = f"{self.traffic_dir}/url_{index}_traffic.pcap"
            tcpdump_process = self.start_tcpdump(pcap_file)
            
            # Step 4: Browser detonation with Selenium
            print("  [4/5] Detonating URL in browser...")
            browser_result = self.detonate_with_selenium(url, index)
            result.update(browser_result)
            
            # Stop traffic capture
            time.sleep(2)  # Let traffic finish
            self.stop_tcpdump(tcpdump_process)
            
            # Step 5: Analyze captured traffic
            print("  [5/5] Analyzing network traffic...")
            traffic_analysis = self.analyze_pcap(pcap_file)
            result['contacted_domains'] = traffic_analysis['domains']
            result['resources_loaded'] = traffic_analysis['resources']
            
            # Calculate risk level
            result['risk_level'], result['risk_factors'] = self.calculate_url_risk(result)
            
            print(f"      ✓ Risk Level: {result['risk_level']}")
            
        except Exception as e:
            result['error'] = str(e)
            result['risk_level'] = 'UNKNOWN'
            print(f"      ⚠ Error during detonation: {e}")
        
        return result
    
    def check_redirects_curl(self, url):
        """Check URL redirects using curl"""
        try:
            cmd = f'curl -Lsv -o /dev/null --max-time 15 --max-redirs 10 "{url}" 2>&1'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            redirects = []
            lines = result.stderr.split('\n')
            
            for line in lines:
                if '< Location:' in line or '< location:' in line:
                    redirect_url = line.split(':', 1)[1].strip()
                    redirects.append(redirect_url)
            
            return {
                'redirects': redirects,
                'redirect_count': len(redirects),
                'final_url': redirects[-1] if redirects else url
            }
        except Exception as e:
            return {
                'redirects': [],
                'redirect_count': 0,
                'final_url': url,
                'error': str(e)
            }
    
    def analyze_ssl(self, url):
        """Analyze SSL/TLS certificate"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {'status': 'NO_SSL', 'risk': 'HIGH'}
            
            hostname = parsed.netloc
            
            # Use openssl to check certificate
            cmd = f'echo | timeout 10 openssl s_client -connect {hostname}:443 -servername {hostname} 2>/dev/null | openssl x509 -noout -text 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                cert_info = result.stdout
                
                # Extract issuer
                issuer_match = re.search(r'Issuer:.*CN\s*=\s*([^,\n]+)', cert_info)
                issuer = issuer_match.group(1) if issuer_match else 'Unknown'
                
                # Check for self-signed
                is_self_signed = 'self signed' in cert_info.lower()
                
                return {
                    'status': 'VALID_SSL',
                    'issuer': issuer,
                    'self_signed': is_self_signed,
                    'risk': 'HIGH' if is_self_signed else 'LOW'
                }
            else:
                return {'status': 'SSL_ERROR', 'risk': 'HIGH'}
                
        except Exception as e:
            return {'status': 'SSL_CHECK_FAILED', 'error': str(e), 'risk': 'MEDIUM'}
    
    def start_tcpdump(self, output_file):
        """Start tcpdump to capture network traffic"""
        try:
            # Check if running as root or with proper permissions
            cmd = f'timeout 60 tcpdump -i any -w {output_file} port 80 or port 443 2>/dev/null'
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # Let tcpdump start
            return process
        except Exception as e:
            print(f"      ⚠ tcpdump failed (may need root): {e}")
            return None
    
    def stop_tcpdump(self, process):
        """Stop tcpdump process"""
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
    
    def detonate_with_selenium(self, url, index):
        """Detonate URL using Selenium with comprehensive monitoring"""
        result = {
            'screenshot': None,
            'forms_detected': [],
            'javascript_analysis': {},
            'dom_analysis': {},
            'cookies_set': [],
            'storage_accessed': False,
            'page_title': '',
            'resources_loaded': []
        }
        
        driver = None
        
        try:
            # Try Firefox first
            options = FirefoxOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.set_preference('dom.webdriver.enabled', False)
            options.set_preference('useAutomationExtension', False)
            
            try:
                driver = webdriver.Firefox(options=options)
            except:
                # Fallback to Chrome
                options = ChromeOptions()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                driver = webdriver.Chrome(options=options)
            
            # Set timeout
            driver.set_page_load_timeout(30)
            
            # Navigate to URL
            driver.get(url)
            time.sleep(3)  # Let page load
            
            # Get page title
            result['page_title'] = driver.title
            
            # Take screenshot
            screenshot_file = f"{self.screenshots_dir}/url_{index}_screenshot.png"
            driver.save_screenshot(screenshot_file)
            result['screenshot'] = screenshot_file
            
            # Analyze forms
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                form_info = self.analyze_form(form)
                result['forms_detected'].append(form_info)
            
            # Check for credential harvesting indicators
            inputs = driver.find_elements(By.TAG_NAME, 'input')
            for inp in inputs:
                input_type = inp.get_attribute('type')
                if input_type in ['password', 'email', 'text']:
                    name = inp.get_attribute('name') or inp.get_attribute('id') or 'unknown'
                    result['forms_detected'].append({
                        'type': input_type,
                        'name': name,
                        'placeholder': inp.get_attribute('placeholder')
                    })
            
            # Get cookies
            cookies = driver.get_cookies()
            result['cookies_set'] = [c['name'] for c in cookies]
            
            # Execute JavaScript to check localStorage/sessionStorage
            try:
                local_storage = driver.execute_script("return window.localStorage.length")
                session_storage = driver.execute_script("return window.sessionStorage.length")
                result['storage_accessed'] = local_storage > 0 or session_storage > 0
            except:
                pass
            
            # Analyze DOM for suspicious patterns
            result['dom_analysis'] = self.analyze_dom(driver)
            
            # Get all links
            links = driver.find_elements(By.TAG_NAME, 'a')
            result['links_on_page'] = len(links)
            
        except TimeoutException:
            result['error'] = 'Page load timeout'
        except WebDriverException as e:
            result['error'] = f'WebDriver error: {str(e)}'
        except Exception as e:
            result['error'] = f'Detonation error: {str(e)}'
        finally:
            if driver:
                driver.quit()
        
        return result
    
    def analyze_form(self, form_element):
        """Analyze HTML form for suspicious patterns"""
        try:
            return {
                'action': form_element.get_attribute('action') or 'unknown',
                'method': form_element.get_attribute('method') or 'GET',
                'inputs': len(form_element.find_elements(By.TAG_NAME, 'input'))
            }
        except:
            return {'error': 'Could not analyze form'}
    
    def analyze_dom(self, driver):
        """Analyze DOM for suspicious patterns"""
        analysis = {
            'hidden_iframes': 0,
            'obfuscated_scripts': 0,
            'suspicious_keywords': []
        }
        
        try:
            # Check for hidden iframes
            iframes = driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframes:
                style = iframe.get_attribute('style') or ''
                if 'display:none' in style or 'visibility:hidden' in style:
                    analysis['hidden_iframes'] += 1
            
            # Check page source for suspicious patterns
            page_source = driver.page_source.lower()
            
            suspicious_words = ['eval(', 'unescape(', 'fromcharcode', 'atob(', 
                               'document.write', 'iframe', 'exec(']
            
            for word in suspicious_words:
                if word in page_source:
                    analysis['suspicious_keywords'].append(word)
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def analyze_pcap(self, pcap_file):
        """Analyze captured packet file"""
        analysis = {
            'domains': [],
            'resources': [],
            'total_packets': 0
        }
        
        if not os.path.exists(pcap_file):
            return analysis
        
        try:
            # Use tshark to analyze pcap
            cmd = f'tshark -r {pcap_file} -T fields -e dns.qry.name -e http.host 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            domains = set()
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    for part in parts:
                        if part and '.' in part:
                            domains.add(part)
            
            analysis['domains'] = sorted(list(domains))
            
            # Count packets
            cmd = f'capinfos -c {pcap_file} 2>/dev/null | grep "Number of packets" | awk \'{{print $4}}\''
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            try:
                analysis['total_packets'] = int(result.stdout.strip())
            except:
                pass
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def calculate_url_risk(self, result):
        """Calculate risk level based on collected data"""
        risk_score = 0
        risk_factors = []
        
        # Check redirects
        if result['redirect_count'] > 3:
            risk_score += 20
            risk_factors.append(f"Multiple redirects ({result['redirect_count']})")
        elif result['redirect_count'] > 0:
            risk_score += 10
        
        # Check SSL
        if result['ssl_info'].get('risk') == 'HIGH':
            risk_score += 30
            risk_factors.append("SSL issues detected")
        
        # Check forms
        if result.get('forms_detected'):
            if any('password' in str(f).lower() for f in result['forms_detected']):
                risk_score += 25
                risk_factors.append("Password input detected")
        
        # Check DOM analysis
        dom = result.get('dom_analysis', {})
        if dom.get('hidden_iframes', 0) > 0:
            risk_score += 15
            risk_factors.append(f"Hidden iframes ({dom['hidden_iframes']})")
        
        if dom.get('suspicious_keywords'):
            risk_score += 15
            risk_factors.append(f"Suspicious JavaScript patterns")
        
        # Check contacted domains
        if len(result.get('contacted_domains', [])) > 10:
            risk_score += 10
            risk_factors.append(f"Many domains contacted ({len(result['contacted_domains'])})")
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'CRITICAL'
        elif risk_score >= 40:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return risk_level, risk_factors

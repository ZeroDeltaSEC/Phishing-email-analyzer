"""
Traffic Monitor Module
Network traffic monitoring and analysis
"""

import subprocess
import os


class TrafficMonitor:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.traffic_dir = f"{output_dir}/traffic_dumps"
    
    def start_capture(self, interface='any', output_file=None):
        """
        Start packet capture
        Requires root/sudo privileges
        """
        if not output_file:
            output_file = f"{self.traffic_dir}/capture_{os.getpid()}.pcap"
        
        try:
            cmd = f'tcpdump -i {interface} -w {output_file} port 80 or port 443'
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            return process, output_file
        except Exception as e:
            return None, None
    
    def stop_capture(self, process):
        """Stop packet capture"""
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
    
    def analyze_traffic(self, pcap_file):
        """
        Analyze captured traffic
        """
        analysis = {
            'total_packets': 0,
            'domains_contacted': [],
            'ips_contacted': [],
            'protocols': {},
            'suspicious_patterns': []
        }
        
        if not os.path.exists(pcap_file):
            return analysis
        
        try:
            # Use tshark to analyze
            # DNS queries
            cmd = f'tshark -r {pcap_file} -T fields -e dns.qry.name 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            domains = set()
            for line in result.stdout.split('\n'):
                if line.strip():
                    domains.add(line.strip())
            
            analysis['domains_contacted'] = sorted(list(domains))
            
            # IP addresses
            cmd = f'tshark -r {pcap_file} -T fields -e ip.dst 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            ips = set()
            for line in result.stdout.split('\n'):
                if line.strip():
                    ips.add(line.strip())
            
            analysis['ips_contacted'] = sorted(list(ips))
            
            # Packet count
            cmd = f'capinfos -c {pcap_file} 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if 'Number of packets' in line:
                    try:
                        analysis['total_packets'] = int(line.split(':')[1].strip())
                    except:
                        pass
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

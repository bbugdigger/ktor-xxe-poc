#!/usr/bin/env python3
"""
Simple test to verify the Ktor server is running and accessible
"""

import requests
import sys

def test_server(url="http://localhost:8080"):
    try:
        print(f"Testing server at {url}")
        response = requests.get(url, timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("[+] Server is running and accessible!")
            return True
        else:
            print("[-] Server returned non-200 status")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Cannot connect to server: {e}")
        print("Make sure the Ktor server is running with: ./gradlew run")
        return False

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    success = test_server(url)
    sys.exit(0 if success else 1)

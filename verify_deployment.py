import requests
import json
import time
import sys

def test_analyze():
    url = "http://127.0.0.1:8080/analyze"
    payload = {"url": "http://example.com"}
    
    print(f"Testing {url} with payload {payload}...")
    
    max_retries = 5
    for i in range(max_retries):
        try:
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                print("[OK] Server responded with 200 OK")
                
                # Verify Keys
                required_keys = ['server_info', 'security_scan', 'final_url', 'network_summary', 'simple_analysis']
                missing = [k for k in required_keys if k not in data]
                
                if missing:
                    print(f"[FAIL] Missing keys in response: {missing}")
                    sys.exit(1)
                
                # Verify Deep Data
                if 'screenshot' not in data['security_scan']:
                    print("[FAIL] Screenshot missing from security_scan")
                    sys.exit(1)
                    
                if 'ssl' not in data['server_info']:
                    print("[FAIL] SSL info missing from server_info")
                    sys.exit(1)

                print("[SUCCESS] Payload verification successful! All features active.")
                return
            else:
                print(f"[FAIL] Server returned status {response.status_code}")
                print(response.text)
                sys.exit(1)
        except requests.exceptions.ConnectionError:
            print(f"Waiting for server... ({i+1}/{max_retries})")
            time.sleep(2)
        except Exception as e:
            print(f"[ERROR]: {e}")
            sys.exit(1)

    print("❌ Could not connect to server after multiple attempts.")
    sys.exit(1)

if __name__ == "__main__":
    test_analyze()

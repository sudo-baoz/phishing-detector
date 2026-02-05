import sys
import os
import json
import requests

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.config import settings
from app.services.external_intel import external_intel

def test_google_sb():
    print("🚀 Testing Google Safe Browsing Integration...")
    
    key = settings.GOOGLE_SAFE_BROWSING_KEY
    if not key:
        print("❌ Error: GOOGLE_SAFE_BROWSING_KEY is missing in .env")
        return

    print(f"🔑 API Key: {key[:5]}...{key[-5:]}")
    
    # Test URLs
    # testsafebrowsing.appspot.com is Google's test site
    unsafe_url = "http://testsafebrowsing.appspot.com/s/malware.html"
    safe_url = "https://www.google.com"
    
    print(f"\n🔍 Checking Unsafe URL: {unsafe_url}")
    res_unsafe = external_intel.check_google_safe_browsing(unsafe_url)
    print(json.dumps(res_unsafe, indent=2))
    
    if not res_unsafe['safe']:
        print("✅ PASSED: Detected Malware")
    else:
        print("⚠️ FAILED: Did not detect malware (Check API Quota/Key)")

    print(f"\n🔍 Checking Safe URL: {safe_url}")
    res_safe = external_intel.check_google_safe_browsing(safe_url)
    print(json.dumps(res_safe, indent=2))
    
    if res_safe['safe']:
        print("✅ PASSED: Confirmed Safe")
    else:
        print("⚠️ FAILED: Flagged safe URL as unsafe")

if __name__ == "__main__":
    test_google_sb()

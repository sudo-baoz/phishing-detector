
import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.chat_agent import sentinel_ai

def test_homograph():
    print("🚀 Initializing Homograph Attack Test...")
    
    from app.config import settings
    key = settings.GEMINI_API_KEY
    if key:
        print(f"🔑 API Key loaded: {key[:4]}...{key[-4:]} (Length: {len(key)})")
    else:
        print("❌ API Key is EMPTY")

    if not sentinel_ai.is_available():
        print("❌ Error: Sentinel AI is not available. Check GEMINI_API_KEY.")
        return

    test_cases = [
        "http://faceb00k.com/login",
        "http://paypal.verify-secure.com",
        "https://www.facebook.com",
        "http://googIe.com"
    ]
    
    for url in test_cases:
        print(f"\n🔍 Analyzing: {url}")
        print("-" * 40)
        
        result = sentinel_ai.analyze_homograph(url)
        
        print(json.dumps(result, indent=2))
        
        if result.get('verdict') == 'PHISHING':
            print("✅ PASSED: Detected Phishing")
        elif result.get('verdict') == 'SAFE' and 'facebook.com' in url:
             print("✅ PASSED: Detected Safe")
        else:
             print("⚠️  CHECK: Verdict might be unexpected")

if __name__ == "__main__":
    test_homograph()

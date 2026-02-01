"""
Test script for deep analysis features
Tests: Redirect chain, password field detection, bot API detection, SSL certificate checking
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_scan_with_deep_analysis(url: str, deep_analysis: bool = True):
    """Test URL scanning with deep analysis"""
    print(f"\n{'='*80}")
    print(f"Testing URL: {url}")
    print(f"Deep Analysis: {deep_analysis}")
    print(f"{'='*80}\n")
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json={
                "url": url,
                "include_osint": True,
                "deep_analysis": deep_analysis
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("✅ Scan completed successfully!\n")
            
            # Verdict
            print("📊 VERDICT:")
            print(f"   Score: {data['verdict']['score']}/100")
            print(f"   Level: {data['verdict']['level']}")
            print(f"   Target Brand: {data['verdict']['target_brand']}")
            print(f"   Threat Type: {data['verdict']['threat_type']}\n")
            
            # Network
            print("🌐 NETWORK:")
            print(f"   Domain Age: {data['network']['domain_age']}")
            print(f"   Registrar: {data['network']['registrar']}")
            print(f"   ISP: {data['network']['isp']}")
            print(f"   Country: {data['network']['country']}")
            print(f"   IP: {data['network']['ip']}\n")
            
            # Forensics
            print("🔍 FORENSICS:")
            print(f"   Typosquatting: {data['forensics']['typosquatting']}")
            print(f"   Redirect Chain: {data['forensics']['redirect_chain']}")
            print(f"   Obfuscation: {data['forensics']['obfuscation']}\n")
            
            # Content
            print("📄 CONTENT:")
            print(f"   Has Login Form: {data['content']['has_login_form']}")
            print(f"   Screenshot URL: {data['content']['screenshot_url']}")
            print(f"   External Resources: {data['content']['external_resources']}\n")
            
            # Advanced
            print("🔬 ADVANCED:")
            print(f"   Telegram Bot: {data['advanced']['telegram_bot_detected']}")
            print(f"   Discord Webhook: {data['advanced']['discord_webhook_detected']}")
            print(f"   SSL Issuer: {data['advanced']['ssl_issuer']}")
            print(f"   SSL Validity: {data['advanced']['ssl_validity']}\n")
            
            # Intelligence
            print("🛡️ INTELLIGENCE:")
            print(f"   VirusTotal Score: {data['intelligence']['virustotal_score']}")
            print(f"   Google Safe Browsing: {data['intelligence']['google_safebrowsing']}\n")
            
            return data
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None


if __name__ == "__main__":
    print("\n" + "="*80)
    print("DEEP ANALYSIS TEST SUITE")
    print("="*80)
    
    # Test 1: Legitimate site (Google)
    test_scan_with_deep_analysis("https://www.google.com", deep_analysis=True)
    
    # Test 2: Suspicious site (example phishing simulation)
    # Note: Use a safe test URL or real phishing test domain
    test_scan_with_deep_analysis("https://www.facebook-login-verify.com", deep_analysis=True)
    
    # Test 3: Quick scan without deep analysis
    print("\n\n" + "="*80)
    print("TESTING WITHOUT DEEP ANALYSIS (FASTER)")
    print("="*80)
    test_scan_with_deep_analysis("https://www.youtube.com", deep_analysis=False)
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETED")
    print("="*80 + "\n")

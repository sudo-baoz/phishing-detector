"""
Test script for Phishing Detector API
Tests all endpoints to ensure they work correctly
"""

import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:8000"
TEST_USER = {
    "username": f"testuser_{int(__import__('time').time())}",
    "password": "testpassword123"
}

def print_test(test_name: str):
    """Print test name"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print('='*60)

def print_success(message: str):
    """Print success message"""
    print(f"[OK] {message}")

def print_error(message: str):
    """Print error message"""
    print(f"[ERROR] {message}")

def test_health_check():
    """Test health check endpoint"""
    print_test("Health Check")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        assert response.status_code == 200
        data = response.json()
        print_success(f"Health check passed: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_database_health():
    """Test database health endpoint"""
    print_test("Database Health Check")
    
    try:
        response = requests.get(f"{BASE_URL}/health/db")
        assert response.status_code == 200
        data = response.json()
        print_success(f"Database health check passed: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print_error(f"Database health check failed: {e}")
        return False

def test_model_info():
    """Test ML model info endpoint"""
    print_test("ML Model Info")
    
    try:
        response = requests.get(f"{BASE_URL}/model/info")
        assert response.status_code == 200
        data = response.json()
        print_success(f"Model info retrieved: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print_error(f"Model info failed: {e}")
        return False

def test_user_registration():
    """Test user registration"""
    print_test("User Registration")
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json=TEST_USER
        )
        assert response.status_code == 201
        data = response.json()
        print_success(f"User registered: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print_error(f"User registration failed: {e}")
        return False

def test_user_login():
    """Test user login"""
    print_test("User Login")
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json=TEST_USER
        )
        assert response.status_code == 200
        data = response.json()
        print_success(f"User logged in: {json.dumps(data, indent=2)}")
        return True, data.get('access_token')
    except Exception as e:
        print_error(f"User login failed: {e}")
        return False, None

def test_scan_safe_url():
    """Test scanning a safe URL"""
    print_test("Scan Safe URL")
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json={"url": "https://www.google.com"}
        )
        assert response.status_code == 200
        data = response.json()
        print_success(f"Scan completed: {json.dumps(data, indent=2)}")
        print(f"   URL: {data['url']}")
        print(f"   Is Phishing: {data['is_phishing']}")
        print(f"   Confidence: {data['confidence_score']:.2f}%")
        return True, data['id']
    except Exception as e:
        print_error(f"Safe URL scan failed: {e}")
        return False, None

def test_scan_phishing_url():
    """Test scanning a potentially phishing URL"""
    print_test("Scan Phishing URL")
    
    try:
        # Use a suspicious-looking URL for testing
        response = requests.post(
            f"{BASE_URL}/scan",
            json={"url": "http://paypal-verify-account.tk/login.php?id=12345"}
        )
        assert response.status_code == 200
        data = response.json()
        print_success(f"Scan completed: {json.dumps(data, indent=2)}")
        print(f"   URL: {data['url']}")
        print(f"   Is Phishing: {data['is_phishing']}")
        print(f"   Confidence: {data['confidence_score']:.2f}%")
        print(f"   Threat Type: {data.get('threat_type', 'N/A')}")
        return True
    except Exception as e:
        print_error(f"Phishing URL scan failed: {e}")
        return False

def test_get_scan_history():
    """Test getting scan history"""
    print_test("Get Scan History")
    
    try:
        response = requests.get(f"{BASE_URL}/scan/history?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        print_success(f"Scan history retrieved: {data['total']} total scans")
        print(f"   Showing {len(data['scans'])} records")
        return True
    except Exception as e:
        print_error(f"Get scan history failed: {e}")
        return False

def test_get_scan_by_id(scan_id: int):
    """Test getting specific scan by ID"""
    print_test(f"Get Scan by ID ({scan_id})")
    
    try:
        response = requests.get(f"{BASE_URL}/scan/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        print_success(f"Scan retrieved: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print_error(f"Get scan by ID failed: {e}")
        return False

def test_invalid_url():
    """Test scanning an invalid URL"""
    print_test("Scan Invalid URL")
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json={"url": "not-a-valid-url"}
        )
        # Should return 422 (Validation Error)
        assert response.status_code == 422
        print_success("Invalid URL rejected as expected")
        return True
    except Exception as e:
        print_error(f"Invalid URL test failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("STARTING PHISHING DETECTOR API TESTS")
    print("="*60)
    print(f"Base URL: {BASE_URL}")
    
    results = []
    
    # Basic health checks
    results.append(("Health Check", test_health_check()))
    results.append(("Database Health", test_database_health()))
    results.append(("Model Info", test_model_info()))
    
    # Authentication tests
    results.append(("User Registration", test_user_registration()))
    login_success, token = test_user_login()
    results.append(("User Login", login_success))
    
    # Scanning tests
    safe_scan_success, scan_id = test_scan_safe_url()
    results.append(("Scan Safe URL", safe_scan_success))
    results.append(("Scan Phishing URL", test_scan_phishing_url()))
    
    # History tests
    results.append(("Get Scan History", test_get_scan_history()))
    if scan_id:
        results.append(("Get Scan by ID", test_get_scan_by_id(scan_id)))
    
    # Edge cases
    results.append(("Invalid URL", test_invalid_url()))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} - {test_name}")
    
    print("\n" + "="*60)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("="*60)
    
    return passed == total

if __name__ == "__main__":
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[WARNING] Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Fatal error: {e}")
        sys.exit(1)

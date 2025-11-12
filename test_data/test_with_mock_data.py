#!/usr/bin/env python3
"""
Test Script for PhishGuard AI Mock Data

This model has been trained from a dataset taken from 
NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data.

Usage: python test_with_mock_data.py
"""

import json
import sys
import os
import requests
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

try:
    from mongodb_manager import MongoDBManager
    from enhanced_mongodb_detector import EnhancedPhishingDetector
except ImportError:
    print("❌ Could not import project modules. Make sure you're running from project directory.")
    sys.exit(1)

class MockDataTester:
    def __init__(self):
        self.test_data_path = Path(__file__).parent / "mock_phishing_urls.json"
        self.load_test_data()
        
    def load_test_data(self):
        """Load mock test data from JSON file"""
        try:
            with open(self.test_data_path, 'r') as f:
                self.test_data = json.load(f)
            print(f"✅ Loaded test data: {self.test_data['description']}")
            print(f"📚 Attribution: {self.test_data['attribution']}")
        except FileNotFoundError:
            print(f"❌ Test data file not found: {self.test_data_path}")
            sys.exit(1)
    
    def test_phishing_detection(self):
        """Test phishing URL detection with mock data"""
        print("\n🔍 Testing Phishing URL Detection:")
        print("-" * 50)
        
        try:
            detector = EnhancedPhishingDetector()
            
            for test_case in self.test_data["test_phishing_urls"]:
                url = test_case["url"]
                expected = test_case["expected_result"]
                target_cse = test_case["target_cse"]
                
                result = detector.predict_url(url)
                status = "✅ PASS" if result["is_phishing"] else "❌ FAIL"
                
                print(f"{status} | {url}")
                print(f"      Target: {target_cse} | Expected: {expected}")
                print(f"      Result: {'phishing' if result['is_phishing'] else 'legitimate'}")
                print(f"      Confidence: {result['confidence']:.3f}")
                print()
                
        except Exception as e:
            print(f"❌ Error testing phishing detection: {str(e)}")
    
    def test_legitimate_detection(self):
        """Test legitimate URL detection with mock data"""
        print("\n✅ Testing Legitimate URL Detection:")
        print("-" * 50)
        
        try:
            detector = EnhancedPhishingDetector()
            
            for test_case in self.test_data["test_legitimate_urls"]:
                url = test_case["url"]
                expected = test_case["expected_result"]
                organization = test_case["organization"]
                
                result = detector.predict_url(url)
                status = "✅ PASS" if not result["is_phishing"] else "❌ FAIL"
                
                print(f"{status} | {url}")
                print(f"      Organization: {organization} | Expected: {expected}")
                print(f"      Result: {'phishing' if result['is_phishing'] else 'legitimate'}")
                print(f"      Confidence: {result['confidence']:.3f}")
                print()
                
        except Exception as e:
            print(f"❌ Error testing legitimate detection: {str(e)}")
    
    def test_dashboard_api(self, base_url="http://localhost:8080"):
        """Test dashboard API with mock data"""
        print(f"\n🌐 Testing Dashboard API at {base_url}:")
        print("-" * 50)
        
        endpoints = [
            "/api/stats",
            "/api/recent-threats", 
            "/api/threat-analysis"
        ]
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    print(f"✅ {endpoint} - Status: {response.status_code}")
                    data = response.json()
                    if 'top_targeted_cses' in data:
                        print(f"   CSE Data: {len(data['top_targeted_cses'])} organizations")
                else:
                    print(f"❌ {endpoint} - Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"❌ {endpoint} - Connection Error: {str(e)}")
    
    def display_test_scenarios(self):
        """Display test scenarios information"""
        print("\n📋 Test Scenarios Included:")
        print("-" * 50)
        
        for scenario in self.test_data["test_scenarios"]:
            print(f"🎯 {scenario['scenario']}")
            print(f"   Description: {scenario['description']}")
            print(f"   Common Patterns:")
            for pattern in scenario['common_patterns']:
                print(f"   • {pattern}")
            print()

def main():
    """Main test execution"""
    print("🚀 PhishGuard AI Mock Data Tester")
    print("=" * 50)
    print("This model has been trained from a dataset taken from")
    print("NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data")
    print("=" * 50)
    
    tester = MockDataTester()
    
    # Display test scenarios
    tester.display_test_scenarios()
    
    # Test phishing detection
    tester.test_phishing_detection()
    
    # Test legitimate detection  
    tester.test_legitimate_detection()
    
    # Test dashboard API (optional - only if server is running)
    print("\n❓ Testing Dashboard API (optional):")
    try:
        tester.test_dashboard_api()
    except Exception as e:
        print(f"ℹ️  Dashboard API test skipped - server may not be running")
    
    print("\n🎉 Mock data testing completed!")
    print("\nTo run the dashboard:")
    print("cd dashboard && python simple_app.py")

if __name__ == "__main__":
    main()
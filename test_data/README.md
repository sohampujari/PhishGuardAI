# Test Data and Mock Examples

This directory contains test data and mock examples for demonstrating PhishGuard AI functionality.

## Attribution

**This model has been trained from a dataset taken from NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data.**

## Contents

### `mock_phishing_urls.json`
Contains test cases for:
- **Phishing URLs**: Fake banking and telecom sites targeting Indian CSEs
- **Legitimate URLs**: Official websites of major Indian organizations
- **Test Scenarios**: Common attack patterns and fraud techniques

### `test_with_mock_data.py`
Automated test script that:
- Tests phishing detection accuracy
- Validates legitimate URL recognition
- Tests dashboard API endpoints
- Displays test scenarios and results

## Usage

### Run Mock Data Tests
```bash
cd test_data
python test_with_mock_data.py
```

### Test Individual URLs
```python
from enhanced_mongodb_detector import EnhancedPhishingDetector

detector = EnhancedPhishingDetector()
result = detector.predict_url("http://fake-sbi-bank.com/login")
print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']}")
```

## Test Cases Included

### Banking Phishing Examples
- State Bank of India impersonation
- ICICI Bank fake login pages
- HDFC Bank security scams
- Bank of Baroda urgent alerts

### Telecom Fraud Examples
- Airtel customer verification scams
- Fake recharge bonus offers
- KYC verification frauds

### Legitimate Baseline
- Official banking websites
- Authentic telecom portals
- Verified organization domains

## Expected Results

The model should correctly identify:
- ✅ Phishing attempts with high confidence (>0.7)
- ✅ Legitimate sites with high confidence (>0.7) 
- 🎯 Target CSE identification for known organizations
- 📊 Accurate threat categorization and severity assessment

## Dataset Information

This PhishGuard AI system was developed using training data from the **NCIIP Startup India AI GRAND CHALLENGE** initiative, focusing on protecting Indian Critical Sector Entities (CSEs) from phishing attacks.

The training dataset includes:
- Real phishing attempts targeting Indian organizations
- Legitimate website patterns from CSEs
- Attack vector classifications specific to Indian context
- Threat intelligence data for financial and telecom sectors
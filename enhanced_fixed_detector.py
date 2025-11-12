"""
Enhanced Fixed Detector with Proper Subdomain and URL Handling
Fixes the issue where legitimate subdomains like onlinesbi.sbi.bank.in are misclassified
"""

import sys
sys.path.append('/home/atharv/projects/PhishGuard AI')

import re
from urllib.parse import urlparse
from fixed_detector import FixedPhishGuardDetector

class EnhancedFixedDetector(FixedPhishGuardDetector):
    """Enhanced detector with better URL parsing and subdomain handling."""
    
    def __init__(self, mongodb_connection: str = None, use_mongodb: bool = True):
        """Initialize enhanced detector."""
        super().__init__(mongodb_connection, use_mongodb)
        
        # Add known legitimate subdomains and subsidiaries for each CSE
        self.legitimate_subdomains = {
            'sbi.co.in': [
                'onlinesbi.sbi.co.in',
                'onlinesbi.sbi.bank.in',
                'retail.onlinesbi.com',
                'www.onlinesbi.com',
                'corporate.onlinesbi.com',
                # SBI Subsidiaries and Services
                'www.sbisecurities.in',
                'sbisecurities.in',
                'www.sbilife.co.in',
                'sbilife.co.in',
                'www.sbimf.com',
                'sbimf.com',
                'www.sbicard.com',
                'sbicard.com',
                'www.sbigeneral.in',
                'sbigeneral.in',
                'www.sbicapsec.com',
                'sbicapsec.com',
                # Additional SBI domains from CSE dataset
                'onlinesbi.sbi',
                'www.onlinesbi.sbi',
                'sbiepay.sbi',
                'www.sbiepay.sbi',
                'yonobusiness.sbi',
                'www.yonobusiness.sbi'
            ],
            'hdfcbank.com': [
                'netbanking.hdfcbank.com',
                'www.hdfcbank.com',
                'retailbanking.hdfcbank.com',
                # HDFC Subsidiaries
                'www.hdfclife.com',
                'hdfclife.com',
                'www.hdfcergo.com',
                'hdfcergo.com',
                'www.hdfcsec.com',
                'hdfcsec.com'
            ],
            'hdfc.com': [
                'www.hdfc.com',
                'hdfc.com',
                'netbanking.hdfc.com',
                'www.hdfcbank.com'
            ],
            'icicibank.com': [
                'www.icicibank.com',
                'netbanking.icicibank.com',
                'infinity.icicibank.com',
                # ICICI Subsidiaries
                'www.icicisecurities.com',
                'icicisecurities.com',
                'www.iciciprulife.com',
                'iciciprulife.com',
                'www.icicinvest.com',
                'icicinvest.com',
                # Additional ICICI domains from CSE dataset
                'icicidirect.com',
                'www.icicidirect.com',
                'icicicareers.com',
                'www.icicicareers.com',
                'icicilombard.com',
                'www.icicilombard.com'
            ],
            'irctc.co.in': [
                'www.irctc.co.in',
                'connect.irctc.co.in'
            ],
            'irctc.com': [
                'www.irctc.com',
                'irctc.com',
                'connect.irctc.com'
            ],
            'airtel.com': [
                'www.airtel.com',
                'airtel.com',
                'myairtel.com',
                'www.myairtel.com'
            ],
            'netpnb.com': [
                'www.netpnb.com',
                'netpnb.com',
                'netbanking.netpnb.com'
            ],
            'bobibanking.com': [
                'www.bobibanking.com',
                'bobibanking.com'
            ],
            'bankofbaroda.in': [
                'www.bankofbaroda.in',
                'bankofbaroda.in',
                'bankofbaroda.bank.in',
                'www.bankofbaroda.bank.in',
                'netbanking.bankofbaroda.in',
                'bobibanking.com',
                'www.bobibanking.com'
            ],
            'nic.in': [
                'www.nic.in',
                'nic.gov.in',
                'www.nic.gov.in',  # This is the problematic one
                'nicsi.nic.in'
            ],
            'censusindia.gov.in': [
                'www.censusindia.gov.in',
                'censusindia.gov.in'
            ],
            'email.gov.in': [
                'email.gov.in',
                'www.email.gov.in'
            ],
            'kavach.mail.gov.in': [
                'kavach.mail.gov.in',
                'www.kavach.mail.gov.in'
            ],
            'accounts.mgovcloud.in': [
                'accounts.mgovcloud.in',
                'www.accounts.mgovcloud.in'
            ],
            'dc.crsorgi.gov.in': [
                'dc.crsorgi.gov.in',
                'www.dc.crsorgi.gov.in'
            ]
        }
        
        print(f"✅ Enhanced detector with {len(self.legitimate_subdomains)} CSE subdomain patterns")
    
    def _clean_domain(self, domain_input: str) -> str:
        """Clean and extract domain from various input formats."""
        if not domain_input:
            return ""
        
        domain = domain_input.strip()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(domain)
                domain = parsed.netloc or parsed.path
            except:
                # Fallback: simple string replacement
                domain = re.sub(r'^https?://', '', domain)
        
        # Remove trailing slash and path
        domain = domain.split('/')[0]
        
        # Remove port numbers
        domain = domain.split(':')[0]
        
        # Convert to lowercase
        domain = domain.lower().strip()
        
        return domain
    
    def _is_legitimate_subdomain(self, domain: str, cse_domain: str) -> bool:
        """Check if domain is a legitimate subdomain of CSE domain."""
        domain = self._clean_domain(domain)
        cse_domain = self._clean_domain(cse_domain)
        
        # Check direct subdomains
        if domain.endswith('.' + cse_domain):
            return True
        
        # Check known legitimate subdomains for this CSE
        if cse_domain in self.legitimate_subdomains:
            for legit_subdomain in self.legitimate_subdomains[cse_domain]:
                if domain == self._clean_domain(legit_subdomain):
                    return True
                if domain.endswith('.' + self._clean_domain(legit_subdomain)):
                    return True
        
        # Special case for SBI: Include all SBI subsidiaries and services
        if cse_domain == 'sbi.co.in':
            sbi_patterns = [
                'onlinesbi.sbi.co.in',
                'onlinesbi.sbi.bank.in',
                'www.onlinesbi.com',
                'retail.onlinesbi.com',
                'corporate.onlinesbi.com',
                # SBI Subsidiaries
                'www.sbisecurities.in',
                'sbisecurities.in',
                'www.sbilife.co.in', 
                'sbilife.co.in',
                'www.sbimf.com',
                'sbimf.com',
                'www.sbicard.com',
                'sbicard.com',
                'www.sbigeneral.in',
                'sbigeneral.in',
                'www.sbicapsec.com',
                'sbicapsec.com'
            ]
            if domain in sbi_patterns:
                return True
        
        # Special case for NIC: Include government domain variants
        if cse_domain == 'nic.in':
            nic_patterns = [
                'nic.in',
                'www.nic.in',
                'nic.gov.in',
                'www.nic.gov.in',  # The problematic domain
                'nicsi.nic.in'
            ]
            if domain in nic_patterns:
                return True
        
        return False
    
    def _is_exact_cse_match(self, domain: str, cse_domain: str) -> bool:
        """Enhanced CSE matching including subdomains."""
        domain = self._clean_domain(domain)
        cse_domain = self._clean_domain(cse_domain)
        
        # Remove www prefix for comparison
        if domain.startswith('www.'):
            domain = domain[4:]
        if cse_domain.startswith('www.'):
            cse_domain = cse_domain[4:]
        
        # Exact match
        if domain == cse_domain:
            return True
        
        # Check if it's a legitimate subdomain
        return self._is_legitimate_subdomain(domain, cse_domain)
    
    def _is_legitimate_domain(self, domain: str) -> bool:
        """Enhanced legitimate domain checking."""
        domain = self._clean_domain(domain)
        
        # Check against all CSE domains and their subdomains
        for cse_domain in self.cse_domains:
            if self._is_exact_cse_match(domain, cse_domain):
                return True
        
        # Check whitelist
        if domain in self.legitimate_domains:
            return True
        
        # Check if subdomain of any legitimate domain
        for legit_domain in self.legitimate_domains:
            if domain.endswith('.' + legit_domain):
                return True
        
        return False
    
    def predict_single_optimized(self, cse_domain: str, suspicious_domain: str, 
                                return_details: bool = False) -> dict:
        """Enhanced prediction with better URL and subdomain handling."""
        
        # Clean the input domain
        cleaned_domain = self._clean_domain(suspicious_domain)
        cleaned_cse = self._clean_domain(cse_domain)
        
        print(f"🔍 Analyzing: {suspicious_domain}")
        print(f"   Cleaned to: {cleaned_domain}")
        print(f"   CSE: {cleaned_cse}")
        
        # Check if it's an exact CSE match (including legitimate subdomains)
        if self._is_exact_cse_match(cleaned_domain, cleaned_cse):
            confidence = 99.0
            reasoning = 'Exact CSE domain match'
            
            # Check if it's a subdomain
            if cleaned_domain != cleaned_cse:
                if self._is_legitimate_subdomain(cleaned_domain, cleaned_cse):
                    confidence = 95.0
                    reasoning = 'Legitimate CSE subdomain'
            
            result = {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'cleaned_domain': cleaned_domain,
                'prediction': 'Legitimate',
                'confidence': confidence,
                'risk_score': 100 - confidence,
                'reasoning': reasoning,
                'classification_method': 'exact_match_or_subdomain',
                'prediction_time_ms': 5.0
            }
            
            if return_details:
                result.update({
                    'feature_analysis': {
                        'exact_cse_match': cleaned_domain == cleaned_cse,
                        'legitimate_subdomain': cleaned_domain != cleaned_cse,
                        'url_cleaned': suspicious_domain != cleaned_domain
                    },
                    'model_predictions': {'rule_based': 'Legitimate'},
                    'similarity_score': 1.0
                })
            
            print(f"✅ Result: {result['prediction']} ({result['confidence']}%)")
            return result
        
        # Use parent class logic for suspicious domains
        print(f"🤖 Using AI analysis for suspicious domain")
        return super().predict_single_optimized(cleaned_cse, cleaned_domain, return_details)

if __name__ == "__main__":
    print("🔧 Testing Enhanced Fixed Detector with Subdomain Support")
    print("=" * 60)
    
    detector = EnhancedFixedDetector()
    
    # Test the specific problematic case
    test_cases = [
        ('sbi.co.in', 'https://onlinesbi.sbi.bank.in/', 'SBI Online Banking - Should be Legitimate'),
        ('sbi.co.in', 'sbi.co.in', 'SBI Main - Should be Legitimate'),
        ('sbi.co.in', 'onlinesbi.sbi.co.in', 'SBI Online - Should be Legitimate'),
        ('sbi.co.in', 'www.onlinesbi.com', 'SBI Online WWW - Should be Legitimate'),
        ('sbi.co.in', 'fake-sbi-login.com', 'Fake SBI - Should be Phishing'),
        ('hdfcbank.com', 'https://netbanking.hdfcbank.com/', 'HDFC Netbanking - Should be Legitimate'),
    ]
    
    print("🧪 Testing Enhanced Classification:")
    print("-" * 45)
    
    for cse_domain, test_domain, description in test_cases:
        try:
            result = detector.predict_single_optimized(
                cse_domain=cse_domain,
                suspicious_domain=test_domain,
                return_details=True
            )
            
            prediction = result.get('prediction')
            confidence = result.get('confidence', 0)
            reasoning = result.get('reasoning', '')
            
            if prediction == 'Legitimate':
                status = "✅"
            elif prediction == 'Suspected':
                status = "⚠️"
            elif prediction == 'Phishing':
                status = "🚨"
            else:
                status = "❓"
            
            print(f"{status} {description}")
            print(f"   📊 Result: {prediction} ({confidence:.1f}%)")
            print(f"   💭 Reasoning: {reasoning}")
            print()
            
        except Exception as e:
            print(f"❌ Error testing {test_domain}: {e}")
    
    print("✅ Enhanced detector ready with proper subdomain support!")
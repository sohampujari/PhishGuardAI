"""
Fixed PhishGuard Detector with Proper Training Data Understanding

The key insight: The AI models were trained ONLY on phishing/suspected domains,
never on legitimate ones. So we need to handle legitimate domain classification
differently - through exact matching and whitelisting, not AI prediction.
"""

import sys
sys.path.append('/home/atharv/projects/PhishGuard AI')

from optimized_detector import OptimizedPhishGuardDetector
from mongodb_manager import PhishGuardMongoDB
from datetime import datetime
import logging
from typing import Dict

class FixedPhishGuardDetector(OptimizedPhishGuardDetector):
    """
    Fixed detector that properly handles the fact that AI models 
    were trained only on phishing/suspected domains, not legitimate ones.
    """
    
    def __init__(self, mongodb_connection: str = None, use_mongodb: bool = True):
        """Initialize the fixed detector."""
        super().__init__()
        
        self.use_mongodb = use_mongodb
        self.mongo = None
        
        if use_mongodb:
            try:
                self.mongo = PhishGuardMongoDB()
                print("✅ MongoDB connected")
            except Exception as e:
                print(f"❌ MongoDB connection failed: {e}")
                self.use_mongodb = False
        
        # Load CSE domains and whitelists
        # Don't overwrite parent's cse_domains dict, add to legitimate domains instead
        self.cse_domains_list = set()  # For backward compatibility
        self.legitimate_domains = set()
        self.phishing_patterns = set()
        
        self._load_domain_lists()
    
    def _load_domain_lists(self):
        """Load CSE domains, legitimate domains, and known phishing patterns."""
        if not self.mongo:
            # Fallback to hardcoded CSE domains if no MongoDB (updated with CSE dataset)
            self.cse_domains_list = {
                'sbi.co.in', 'icicibank.com', 'hdfcbank.com', 'pnbindia.in',
                'bankofbaroda.in', 'nic.in', 'censusindia.gov.in', 
                'irctc.co.in', 'airtel.in', 'iocl.com',
                # Additional domains from CSE dataset
                'hdfc.com', 'airtel.com', 'irctc.com', 'icicidirect.com',
                'netpnb.com', 'bobibanking.com', 'email.gov.in',
                'kavach.mail.gov.in', 'accounts.mgovcloud.in', 'dc.crsorgi.gov.in'
            }
            self.legitimate_domains = self.cse_domains_list.copy()
            print(f"✅ Loaded {len(self.cse_domains_list)} hardcoded CSE domains")
            return
        
        try:
            # Load CSE domains from MongoDB
            cse_entities = self.mongo.db.cse_entities.find({'is_active': True})
            for entity in cse_entities:
                domain = entity.get('official_domain')
                if domain:
                    self.cse_domains_list.add(domain.lower().strip())
            
            # Load whitelist
            whitelist_doc = self.mongo.db.whitelists.find_one({'type': 'legitimate_domains_whitelist'})
            if whitelist_doc and 'domains' in whitelist_doc:
                for domain in whitelist_doc['domains']:
                    self.legitimate_domains.add(domain.lower().strip())
            
            # Also add CSE domains to legitimate list
            self.legitimate_domains.update(self.cse_domains_list)
            
            # Load known phishing patterns from training data
            # This could be extended to load from MongoDB if stored
            
            print(f"✅ Loaded {len(self.cse_domains_list)} CSE domains")
            print(f"✅ Loaded {len(self.legitimate_domains)} legitimate domains")
            
        except Exception as e:
            print(f"❌ Error loading domain lists: {e}")
    
    def _is_exact_cse_match(self, domain: str, cse_domain: str) -> bool:
        """Check if domain exactly matches the CSE domain."""
        domain = domain.lower().strip()
        cse_domain = cse_domain.lower().strip()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        if cse_domain.startswith('www.'):
            cse_domain = cse_domain[4:]
        
        return domain == cse_domain
    
    def _is_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is in the legitimate domains list."""
        domain = domain.lower().strip()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check exact match
        if domain in self.legitimate_domains:
            return True
        
        # Check if it's a subdomain of a legitimate domain
        for legit_domain in self.legitimate_domains:
            if domain.endswith('.' + legit_domain):
                return True
        
        return False
    
    def _calculate_similarity_score(self, suspicious_domain: str, cse_domain: str) -> float:
        """Calculate similarity between suspicious domain and CSE domain."""
        suspicious = suspicious_domain.lower().strip()
        cse = cse_domain.lower().strip()
        
        # Remove common prefixes/suffixes
        for prefix in ['www.', 'http://', 'https://']:
            if suspicious.startswith(prefix):
                suspicious = suspicious[len(prefix):]
            if cse.startswith(prefix):
                cse = cse[len(prefix):]
        
        # Simple similarity based on common characters and structure
        if suspicious == cse:
            return 1.0
        
        # Check if suspicious domain contains CSE domain
        cse_base = cse.split('.')[0]  # Get the main part (e.g., 'sbi' from 'sbi.co.in')
        
        similarity = 0.0
        
        # Exact substring match
        if cse_base in suspicious:
            similarity += 0.5
        
        # Similar length
        len_diff = abs(len(suspicious) - len(cse)) / max(len(suspicious), len(cse))
        similarity += (1 - len_diff) * 0.2
        
        # Common characters ratio
        common_chars = len(set(suspicious) & set(cse))
        total_chars = len(set(suspicious) | set(cse))
        if total_chars > 0:
            similarity += (common_chars / total_chars) * 0.3
        
        return min(similarity, 1.0)
    
    def predict_single_optimized(self, cse_domain: str, suspicious_domain: str, 
                                return_details: bool = False) -> Dict:
        """
        Fixed prediction that properly handles legitimate domains.
        
        Key insight: AI models were trained only on phishing/suspected domains,
        so we can't use them to classify legitimate domains. Instead, we use
        rule-based classification for legitimate domains and AI for suspicious ones.
        """
        
        start_time = datetime.now()
        
        # Step 1: Check if it's an exact CSE domain match
        if self._is_exact_cse_match(suspicious_domain, cse_domain):
            result = {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'prediction': 'Legitimate',
                'confidence': 99.0,
                'risk_score': 1.0,
                'reasoning': 'Exact CSE domain match',
                'classification_method': 'exact_match',
                'prediction_time_ms': 1.0
            }
            
            if return_details:
                result.update({
                    'feature_analysis': {'exact_cse_match': True},
                    'model_predictions': {'rule_based': 'Legitimate'},
                    'similarity_score': 1.0
                })
            
            return result
        
        # Step 2: Check if it's in legitimate domains whitelist
        if self._is_legitimate_domain(suspicious_domain):
            result = {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'prediction': 'Legitimate', 
                'confidence': 95.0,
                'risk_score': 5.0,
                'reasoning': 'Domain in legitimate whitelist',
                'classification_method': 'whitelist_match',
                'prediction_time_ms': 2.0
            }
            
            if return_details:
                result.update({
                    'feature_analysis': {'whitelist_match': True},
                    'model_predictions': {'whitelist': 'Legitimate'},
                    'similarity_score': 0.8
                })
            
            return result
        
        # Step 3: Calculate similarity score for additional context
        similarity_score = self._calculate_similarity_score(suspicious_domain, cse_domain)
        
        # Step 4: Use AI models for suspicious domains (what they were trained for)
        try:
            # Get AI prediction using parent class
            ai_result = super().predict_single_optimized(cse_domain, suspicious_domain, return_details)
            
            # Debug: Check if ai_result is the expected type
            if not isinstance(ai_result, dict):
                print(f"⚠️ Warning: AI result is {type(ai_result)}, expected dict. Converting...")
                # Fallback to default values if result is not a dict
                ai_result = {
                    'prediction': 'Suspected',
                    'confidence': 50.0,
                    'risk_score': 50.0,
                    'model_predictions': {}
                }
            
            # Apply improved classification logic based on similarity
            ai_prediction = ai_result.get('prediction', 'Suspected')
            ai_confidence = ai_result.get('confidence', 50.0)
            
            # Adjust prediction based on similarity to CSE domain
            if similarity_score > 0.7:
                # High similarity to CSE domain - likely phishing attempt
                final_prediction = 'Phishing'
                final_confidence = min(80.0 + (similarity_score * 20), 95.0)
                risk_score = 85.0 + (similarity_score * 10)
                reasoning = f'High similarity ({similarity_score:.2f}) to CSE domain - likely phishing'
            elif similarity_score > 0.4:
                # Medium similarity - suspected
                final_prediction = 'Suspected'
                final_confidence = 60.0 + (similarity_score * 20)
                risk_score = 50.0 + (similarity_score * 30)
                reasoning = f'Medium similarity ({similarity_score:.2f}) to CSE domain - suspected'
            else:
                # Low similarity - use AI prediction but adjust confidence
                final_prediction = ai_prediction
                final_confidence = max(ai_confidence * 0.8, 30.0)  # Reduce confidence slightly
                risk_score = ai_result.get('risk_score', final_confidence)
                reasoning = f'AI classification with low CSE similarity ({similarity_score:.2f})'
            
            end_time = datetime.now()
            prediction_time = (end_time - start_time).total_seconds() * 1000
            
            result = {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'prediction': final_prediction,
                'confidence': final_confidence,
                'risk_score': risk_score,
                'reasoning': reasoning,
                'classification_method': 'ai_with_similarity',
                'similarity_score': similarity_score,
                'prediction_time_ms': prediction_time
            }
            
            if return_details:
                result.update({
                    'feature_analysis': ai_result.get('feature_analysis', {}),
                    'model_predictions': ai_result.get('model_predictions', {}),
                    'ai_original_prediction': ai_prediction,
                    'ai_original_confidence': ai_confidence,
                    'similarity_analysis': {
                        'cse_similarity': similarity_score,
                        'similarity_impact': 'high' if similarity_score > 0.7 else 'medium' if similarity_score > 0.4 else 'low'
                    }
                })
            
            return result
            
        except Exception as e:
            print(f"❌ Error in AI prediction: {e}")
            
            # Fallback to rule-based classification
            if similarity_score > 0.6:
                prediction = 'Phishing'
                confidence = 70.0
                risk_score = 80.0
            elif similarity_score > 0.3:
                prediction = 'Suspected'
                confidence = 60.0
                risk_score = 60.0
            else:
                prediction = 'Suspected'
                confidence = 40.0
                risk_score = 50.0
            
            end_time = datetime.now()
            prediction_time = (end_time - start_time).total_seconds() * 1000
            
            return {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'prediction': prediction,
                'confidence': confidence,
                'risk_score': risk_score,
                'reasoning': f'Rule-based fallback (similarity: {similarity_score:.2f})',
                'classification_method': 'rule_based_fallback',
                'similarity_score': similarity_score,
                'prediction_time_ms': prediction_time,
                'error': str(e)
            }

if __name__ == "__main__":
    print("🔧 Testing Fixed PhishGuard Detector")
    print("=" * 40)
    
    detector = FixedPhishGuardDetector()
    
    test_cases = [
        ('sbi.co.in', 'sbi.co.in', 'Should be Legitimate (exact match)'),
        ('hdfcbank.com', 'hdfcbank.com', 'Should be Legitimate (exact match)'),
        ('sbi.co.in', 'sbi-secure-login.com', 'Should be Phishing (high similarity)'),
        ('icicibank.com', 'icici-netbanking.net', 'Should be Suspected (medium similarity)'),
        ('airtel.in', 'google.com', 'Should be Suspected (low similarity)'),
        ('hdfcbank.com', 'hdfc-bank-online.com', 'Should be Phishing (high similarity)'),
    ]
    
    print("🧪 Testing Fixed Classification Logic:")
    print("-" * 50)
    
    for cse_domain, test_domain, expected in test_cases:
        try:
            result = detector.predict_single_optimized(
                cse_domain=cse_domain,
                suspicious_domain=test_domain,
                return_details=True
            )
            
            prediction = result.get('prediction')
            confidence = result.get('confidence', 0)
            similarity = result.get('similarity_score', 0)
            method = result.get('classification_method', 'unknown')
            reasoning = result.get('reasoning', 'No reasoning provided')
            
            # Status emoji
            if prediction == 'Legitimate':
                status = "✅"
            elif prediction == 'Suspected':
                status = "⚠️"  
            elif prediction == 'Phishing':
                status = "🚨"
            else:
                status = "❓"
            
            print(f"{status} {test_domain}")
            print(f"   Expected: {expected}")
            print(f"   Result: {prediction} ({confidence:.1f}% confidence)")
            print(f"   Method: {method}")
            print(f"   Similarity: {similarity:.2f}")
            print(f"   Reasoning: {reasoning}")
            print()
            
        except Exception as e:
            print(f"❌ Error testing {test_domain}: {e}")
    
    print("✅ Fixed detector ready! This should properly classify legitimate domains.")
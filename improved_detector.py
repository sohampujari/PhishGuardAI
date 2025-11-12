"""
Enhanced PhishGuard Detector with Proper Classification Logic
Fixes legitimate domain classification and implements whitelist checking
"""

from enhanced_mongodb_detector import EnhancedPhishGuardDetector
from mongodb_manager import PhishGuardMongoDB
from datetime import datetime
import logging

class ImprovedPhishGuardDetector(EnhancedPhishGuardDetector):
    """Enhanced detector with improved classification logic."""
    
    def __init__(self, mongodb_connection: str = None, use_mongodb: bool = True):
        """Initialize detector with whitelist support."""
        super().__init__(mongodb_connection, use_mongodb)
        
        self.legitimate_domains = set()
        self.cse_domains = set()
        self.load_whitelists()
        
    def load_whitelists(self):
        """Load legitimate domains and CSE domains from MongoDB."""
        if not self.mongo:
            return
            
        try:
            # Load legitimate domains whitelist
            whitelist_doc = self.mongo.db.whitelists.find_one({'type': 'legitimate_domains_whitelist'})
            if whitelist_doc and 'domains' in whitelist_doc:
                self.legitimate_domains = set(whitelist_doc['domains'])
                self.logger.info(f"✅ Loaded {len(self.legitimate_domains)} legitimate domains")
            
            # Load CSE domains
            cse_entities = self.mongo.db.cse_entities.find({'is_active': True})
            for cse in cse_entities:
                if cse.get('official_domain'):
                    self.cse_domains.add(cse['official_domain'].lower())
            
            self.logger.info(f"✅ Loaded {len(self.cse_domains)} CSE domains")
            
        except Exception as e:
            self.logger.error(f"❌ Error loading whitelists: {e}")
    
    def is_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is in legitimate whitelist or is a CSE domain."""
        domain = domain.lower().strip()
        
        # Remove www prefix for comparison
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check exact match in whitelists
        if domain in self.legitimate_domains or domain in self.cse_domains:
            return True
        
        # Check if domain is subdomain of a legitimate domain
        for legit_domain in self.legitimate_domains.union(self.cse_domains):
            if domain.endswith('.' + legit_domain):
                return True
        
        return False
    
    def classify_domain_result(self, prediction: str, confidence: float, domain: str, 
                              cse_domain: str) -> tuple:
        """Improved classification logic with whitelist checking."""
        
        # First check if domain is legitimate
        if self.is_legitimate_domain(domain):
            return 'Legitimate', 95.0  # High confidence for whitelisted domains
        
        # Check if domain exactly matches CSE domain
        if domain.lower().strip() == cse_domain.lower().strip():
            return 'Legitimate', 99.0  # Very high confidence for exact CSE match
        
        # Original AI prediction logic with improved thresholds
        if prediction == 'Phishing':
            # High confidence phishing
            if confidence >= 0.7:
                return 'Phishing', confidence * 100
            else:
                return 'Suspected', confidence * 100
        elif prediction == 'Suspected':
            # Adjust suspected classification
            if confidence >= 0.8:
                return 'Suspected', confidence * 100
            elif confidence >= 0.5:
                return 'Suspected', confidence * 100
            else:
                return 'Legitimate', (1 - confidence) * 100
        else:
            # Default case
            return 'Suspected', confidence * 100
    
    def predict_single_optimized(self, cse_domain: str, suspicious_domain: str, 
                                return_details: bool = False, store_result: bool = True) -> dict:
        """Enhanced prediction with improved classification."""
        
        # Get base prediction from parent class
        result = super().predict_single_optimized(
            cse_domain, suspicious_domain, return_details
        )
        
        # Apply improved classification logic
        original_prediction = result.get('prediction', 'Suspected')
        original_confidence = result.get('confidence', 0.5)
        
        # Get improved classification
        improved_classification, improved_confidence = self.classify_domain_result(
            original_prediction, original_confidence, suspicious_domain, cse_domain
        )
        
        # Update result
        result['prediction'] = improved_classification
        result['confidence'] = improved_confidence
        result['original_prediction'] = original_prediction
        result['original_confidence'] = original_confidence
        result['classification_improved'] = True
        
        # Calculate risk score based on improved classification
        if improved_classification == 'Legitimate':
            result['risk_score'] = max(10, 100 - improved_confidence)
        elif improved_classification == 'Suspected':
            result['risk_score'] = 50 + (improved_confidence * 0.4)
        elif improved_classification == 'Phishing':
            result['risk_score'] = 70 + (improved_confidence * 0.3)
        else:
            result['risk_score'] = improved_confidence
        
        # Store result in MongoDB if available and requested
        if self.use_mongodb and store_result and self.mongo:
            try:
                result['source'] = 'improved_detection'
                domain_id = self.mongo.store_detection_result(result)
                result['mongodb_id'] = str(domain_id)
                
                # Log performance metric
                self.mongo.log_performance_metric(
                    metric_type="detection_response_time",
                    value=result['prediction_time_ms'],
                    unit="milliseconds",
                    additional_info={
                        "classification": result['prediction'],
                        "confidence": result['confidence'],
                        "improved": True
                    }
                )
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store result: {e}")
        
        return result
    
    def get_classification_stats(self) -> dict:
        """Get statistics about classification improvements."""
        if not self.mongo:
            return {}
        
        try:
            # Get recent detections with improvement info
            pipeline = [
                {'$match': {'source': 'improved_detection'}},
                {'$group': {
                    '_id': '$classification',
                    'count': {'$sum': 1},
                    'avg_confidence': {'$avg': '$confidence'}
                }}
            ]
            
            stats = list(self.mongo.db.detected_domains.aggregate(pipeline))
            
            # Count improvements
            improved_count = self.mongo.db.detected_domains.count_documents({
                'source': 'improved_detection',
                'classification_improved': True
            })
            
            return {
                'classification_distribution': stats,
                'improved_classifications': improved_count,
                'legitimate_domains_count': len(self.legitimate_domains),
                'cse_domains_count': len(self.cse_domains)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error getting classification stats: {e}")
            return {}

if __name__ == "__main__":
    print("🚀 Testing Improved PhishGuard Detector")
    print("=" * 40)
    
    # Initialize detector
    detector = ImprovedPhishGuardDetector()
    
    # Test cases
    test_cases = [
        ('sbi.co.in', 'sbi.co.in'),  # Should be Legitimate (exact match)
        ('hdfcbank.com', 'hdfcbank.com'),  # Should be Legitimate (whitelist)
        ('sbi.co.in', 'sbi-fake-login.com'),  # Should be Phishing/Suspected
        ('icicibank.com', 'icici-secure.net'),  # Should be Suspected
        ('airtel.in', 'airtel.in'),  # Should be Legitimate (whitelist)
    ]
    
    print("🧪 Testing classification improvements:")
    for cse_domain, test_domain in test_cases:
        result = detector.predict_single_optimized(cse_domain, test_domain, return_details=True)
        
        print(f"\n🌐 Domain: {test_domain}")
        print(f"   📊 Classification: {result['prediction']} ({result['confidence']:.1f}%)")
        print(f"   🎯 Risk Score: {result.get('risk_score', 0):.1f}/100")
        print(f"   🔄 Original: {result.get('original_prediction')} ({result.get('original_confidence', 0):.1f}%)")
        print(f"   ✅ Improved: {result.get('classification_improved', False)}")
    
    # Get stats
    stats = detector.get_classification_stats()
    print(f"\n📊 Classification Statistics:")
    print(f"   🔍 Legitimate domains in whitelist: {stats.get('legitimate_domains_count', 0)}")
    print(f"   🏢 CSE domains loaded: {stats.get('cse_domains_count', 0)}")
    print(f"   ✅ Improved classifications: {stats.get('improved_classifications', 0)}")
    
    print("\n✅ Improved detector ready for dashboard integration!")
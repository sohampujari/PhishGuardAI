"""
Enhanced PhishGuard Detector with MongoDB Integration
Extends the optimized detector with database storage and analytics.

Dataset Attribution: This model has been trained from a dataset taken from 
NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data.
"""

from optimized_detector import OptimizedPhishGuardDetector
import logging
from datetime import datetime
from typing import Dict, List, Optional
import json
import os
from pathlib import Path

# MongoDB will be imported when available
try:
    from mongodb_manager import PhishGuardMongoDB
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("⚠️ MongoDB not available - install pymongo to enable database features")

class EnhancedPhishGuardDetector(OptimizedPhishGuardDetector):
    """PhishGuard detector with MongoDB integration."""
    
    def __init__(self, mongodb_connection: str = None, use_mongodb: bool = True,
                 classification_policy_path: str | None = None, disable_downgrade: bool | None = None):
        """Initialize detector with optional MongoDB support and policy control.

        Args:
            mongodb_connection: MongoDB connection string.
            use_mongodb: Enable Mongo integration if available.
            classification_policy_path: Path to JSON policy controlling downgrade/upgrade behavior.
            disable_downgrade: Explicit override to disable downgrade logic (for evaluation runs).
        """
        super().__init__()
        
        self.use_mongodb = use_mongodb and MONGODB_AVAILABLE
        self.mongo = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize MongoDB if available and requested
        if self.use_mongodb:
            try:
                self.mongo = PhishGuardMongoDB(mongodb_connection)
                self.load_cses_from_db()
                self.logger.info("✅ Enhanced detector with MongoDB integration ready")
            except Exception as e:
                self.logger.warning(f"⚠️ MongoDB initialization failed: {e}")
                self.use_mongodb = False
        
        if not self.use_mongodb:
            self.logger.info("✅ Enhanced detector ready (without MongoDB)")

        # Load classification policy (downgrade / upgrade tunables)
        self.classification_policy_path = classification_policy_path or 'classification_policy.json'
        self.classification_policy = self._load_classification_policy()

        # Determine downgrade disable flag (constructor param wins, then env)
        env_disable = os.getenv('PHISHGUARD_DISABLE_DOWNGRADE', '').strip().lower() in ('1', 'true', 'yes')
        self.disable_downgrade = bool(disable_downgrade if disable_downgrade is not None else env_disable)

        if self.disable_downgrade:
            self.logger.info("🛠️ Downgrade logic DISABLED (raw recall mode)")
        else:
            if self.classification_policy.get('enable_downgrade', True):
                self.logger.info("🛠️ Downgrade logic ENABLED (precision safety mode)")
            else:
                self.logger.info("🛠️ Policy disables downgrade even though global flag not set")

    def _load_classification_policy(self) -> dict:
        """Load downgrade/upgrade policy JSON, with safe defaults."""
        default_policy = {
            'enable_downgrade': True,
            'downgrade_margin': 0.05,           # absolute probability band above threshold
            'downgrade_confidence_norm': 0.60,  # confidence (0-1) below which to downgrade
            'enable_upgrade': True,
            'upgrade_confidence_threshold': 30.0  # confidence (0-100) below which to upgrade Suspected -> Legitimate
        }
        try:
            path = Path(self.classification_policy_path)
            if path.exists():
                loaded = json.loads(path.read_text())
                # Merge defaults
                for k,v in default_policy.items():
                    loaded.setdefault(k, v)
                return loaded
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to load classification policy '{self.classification_policy_path}': {e}. Using defaults.")
        return default_policy
    
    def load_cses_from_db(self):
        """Load CSE configurations from MongoDB."""
        if not self.mongo:
            return
            
        try:
            cses = self.mongo.get_all_active_cses()
            self.cse_domains = {}
            
            for cse in cses:
                keywords = cse.get('keywords', [])
                if keywords:
                    self.cse_domains[keywords[0]] = [cse['official_domain']] + keywords[1:]
            
            self.logger.info(f"✅ Loaded {len(cses)} CSEs from database")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load CSEs: {e}")
    
    def _load_legitimate_domains_whitelist(self) -> set:
        """Load legitimate domains whitelist from MongoDB."""
        if not self.mongo:
            return set()
        
        try:
            whitelist_doc = self.mongo.db.whitelists.find_one({'type': 'legitimate_domains_whitelist'})
            if whitelist_doc and 'domains' in whitelist_doc:
                return set(whitelist_doc['domains'])
        except Exception as e:
            self.logger.error(f"❌ Error loading whitelist: {e}")
        
        return set()
    
    def _is_legitimate_domain(self, domain: str, cse_domain: str) -> bool:
        """Check if domain is legitimate (whitelisted or exact CSE match)."""
        domain = domain.lower().strip()
        cse_domain = cse_domain.lower().strip()
        
        # Remove www prefix for comparison
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check if exact match with CSE domain
        if domain == cse_domain:
            return True
        
        # Load whitelist and check
        legitimate_domains = self._load_legitimate_domains_whitelist()
        
        if domain in legitimate_domains:
            return True
        
        # Check if subdomain of legitimate domain
        for legit_domain in legitimate_domains:
            if domain.endswith('.' + legit_domain):
                return True
        
        return False
    
    def _improve_classification(self, result: dict, suspicious_domain: str, cse_domain: str) -> dict:
        """Apply downgrade/upgrade logic based on classification policy.

        This function can be disabled entirely (raw recall mode) via:
          - constructor disable_downgrade=True
          - environment PHISHGUARD_DISABLE_DOWNGRADE=1
          - classification_policy.json with enable_downgrade=false
        """
        original_prediction = result.get('prediction', 'Suspected')
        confidence = float(result.get('confidence', 50.0))

        # Normalize confidence to 0-100 range if provided in 0-1
        if confidence <= 1.0:
            confidence *= 100.0
            result['confidence'] = confidence

        policy = self.classification_policy
        if self.disable_downgrade or not policy.get('enable_downgrade', True):
            # Still allow upgrade if enabled, to reduce false alarms on ultra-low confidence
            if policy.get('enable_upgrade', True) and original_prediction == 'Suspected' and confidence < policy.get('upgrade_confidence_threshold', 30.0):
                result['prediction'] = 'Legitimate'
                result['confidence'] = max(70.0, 100 - confidence)
                result['classification_improved'] = True
                result['classification_improvement_reason'] = 'low_conf_suspected_promoted_to_legitimate'
            return result

        # Upgrade branch (very low confidence suspected)
        if policy.get('enable_upgrade', True) and original_prediction == 'Suspected' and confidence < policy.get('upgrade_confidence_threshold', 30.0):
            result['prediction'] = 'Legitimate'
            result['confidence'] = max(70.0, 100 - confidence)
            result['classification_improved'] = True
            result['classification_improvement_reason'] = 'low_conf_suspected_promoted_to_legitimate'
            return result

        # Downgrade branch (near threshold, low confidence phishing)
        if original_prediction == 'Phishing':
            # result['probability'] is phishing probability now
            proba = float(result.get('probability', 0.0))
            # Prefer phishing threshold from model details or policy config
            md = result.get('model_details', {}) if isinstance(result.get('model_details', {}), dict) else {}
            threshold_used = float(md.get('threshold_used_phishing', getattr(self, 'threshold_cfg', {}).get('phishing_threshold', 0.18)))

            epsilon = float(policy.get('downgrade_margin', 0.05))
            conf_norm_cut = float(policy.get('downgrade_confidence_norm', 0.60))
            conf_norm = confidence / 100.0
            if (proba < (threshold_used + epsilon)) and (conf_norm < conf_norm_cut):
                result['prediction'] = 'Suspected'
                result['confidence'] = max(40.0, min(confidence, 60.0))
                result['classification_improved'] = True
                reason = 'near_threshold_low_conf_phishing_downgraded_to_suspected'
                result['classification_improvement_reason'] = reason
                result['classification_improvement_policy'] = {
                    'threshold_used_phishing': threshold_used,
                    'probability': proba,
                    'downgrade_margin': epsilon,
                    'downgrade_confidence_norm_cut': conf_norm_cut
                }
        return result
    
    def predict_single_optimized(self, cse_domain: str, suspicious_domain: str, 
                                return_details: bool = False, store_result: bool = True,
                                disable_downgrade: bool | None = None) -> Dict:
        """Enhanced prediction with automatic MongoDB storage."""
        
        # Check if domain is legitimate first
        if self._is_legitimate_domain(suspicious_domain, cse_domain):
            result = {
                'cse_domain': cse_domain,
                'suspicious_domain': suspicious_domain,
                'prediction': 'Legitimate',
                'confidence': 95.0,
                'risk_score': 5.0,
                'whitelisted': True,
                'prediction_time_ms': 1.0,
                'models_used': ['whitelist_check']
            }
            if return_details:
                result.update({
                    'feature_analysis': {'whitelist_match': True},
                    'model_predictions': {'whitelist': 'Legitimate'},
                    'classification_details': 'Domain found in legitimate whitelist or exact CSE match'
                })
        else:
            # Optionally override downgrade disable per-call
            previous_disable = self.disable_downgrade
            if disable_downgrade is not None:
                self.disable_downgrade = bool(disable_downgrade)

            # Get prediction from parent class
            result = super().predict_single_optimized(cse_domain, suspicious_domain, return_details)

            # Apply improved classification (policy aware)
            result = self._improve_classification(result, suspicious_domain, cse_domain)

            # Restore original disable flag if temporary override was used
            self.disable_downgrade = previous_disable
        
        # Store result in MongoDB if available and requested
        if self.use_mongodb and store_result and self.mongo:
            try:
                result['source'] = 'api_detection'
                domain_id = self.mongo.store_detection_result(result)
                result['mongodb_id'] = str(domain_id)
                
                # Log performance metric
                self.mongo.log_performance_metric(
                    metric_type="detection_response_time",
                    value=result['prediction_time_ms'],
                    unit="milliseconds",
                    additional_info={
                        "classification": result['prediction'],
                        "confidence": result['confidence']
                    }
                )
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store result: {e}")
        
        return result
    
    def predict_batch_optimized(self, domain_pairs: List, progress_callback=None, 
                               store_results: bool = True) -> List[Dict]:
        """Enhanced batch prediction with MongoDB storage."""
        
        results = super().predict_batch_optimized(domain_pairs, progress_callback)
        
        # Store all results in MongoDB if available
        if self.use_mongodb and store_results and self.mongo and isinstance(results, list):
            stored_count = 0
            for result in results:
                try:
                    result['source'] = 'batch_detection'
                    self.mongo.store_detection_result(result)
                    stored_count += 1
                except Exception as e:
                    self.logger.error(f"❌ Failed to store batch result: {e}")
            
            self.logger.info(f"✅ Stored {stored_count}/{len(results)} batch results")
            
            # Log batch performance
            if len(results) > 0:
                avg_response_time = sum(r.get('prediction_time_ms', 0) for r in results) / len(results)
                try:
                    self.mongo.log_performance_metric(
                        metric_type="batch_avg_response_time",
                        value=avg_response_time,
                        unit="milliseconds",
                        additional_info={
                            "batch_size": len(results),
                            "total_time": sum(r.get('prediction_time_ms', 0) for r in results)
                        }
                    )
                except Exception as e:
                    self.logger.error(f"❌ Failed to log performance: {e}")
        
        return results
    
    def get_detection_history(self, domain: str) -> List[Dict]:
        """Get detection history for a domain."""
        if not self.mongo:
            return []
            
        try:
            return list(self.mongo.db.detected_domains.find({
                "$or": [
                    {"domain_name": domain},
                    {"target_cse.official_domain": domain}
                ]
            }).sort("detected_at", -1))
        except Exception as e:
            self.logger.error(f"❌ Failed to get history: {e}")
            return []
    
    def get_dashboard_data(self) -> Dict:
        """Get data for dashboard display."""
        if not self.mongo:
            return {
                "error": "MongoDB not available",
                "recent_detections": [],
                "high_risk_domains": [],
                "statistics": {},
                "top_targeted_cses": [],
                "system_status": "operational_no_db"
            }
        
        try:
            recent_detections = self.mongo.get_recent_detections(hours=24)
            high_risk_domains = self.mongo.get_high_risk_domains(min_risk_score=70)
            stats = self.mongo.get_detection_statistics(days=7)
            top_targets = self.mongo.get_top_targeted_cses(limit=5)
            
            return {
                "recent_detections": recent_detections[:10],
                "high_risk_domains": high_risk_domains[:10],
                "statistics": stats,
                "top_targeted_cses": top_targets,
                "system_status": "operational"
            }
        except Exception as e:
            self.logger.error(f"❌ Failed to get dashboard data: {e}")
            return {
                "error": str(e),
                "recent_detections": [],
                "high_risk_domains": [],
                "statistics": {},
                "top_targeted_cses": [],
                "system_status": "error"
            }
    
    def mark_false_positive(self, domain_id: str, reason: str = None):
        """Mark a detection as false positive."""
        if not self.mongo:
            self.logger.warning("❌ MongoDB not available for false positive marking")
            return False
            
        try:
            from bson import ObjectId
            
            self.mongo.db.detected_domains.update_one(
                {"_id": ObjectId(domain_id)},
                {
                    "$set": {
                        "false_positive": True,
                        "false_positive_reason": reason,
                        "false_positive_marked_at": datetime.utcnow()
                    }
                }
            )
            
            self.logger.info(f"✅ Marked domain as false positive: {domain_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to mark false positive: {e}")
            return False
    
    def get_statistics_summary(self) -> Dict:
        """Get comprehensive system statistics."""
        
        base_stats = {
            "system_version": "2.0-enhanced",
            "mongodb_enabled": self.use_mongodb,
            "cache_enabled": self.enable_caching,
            "models_loaded": len(self.base_detector.feature_names) > 0,
        }
        
        if self.use_mongodb and self.mongo:
            try:
                db_stats = self.mongo.get_detection_statistics(days=30)
                performance_metrics = self.mongo.get_performance_trends("detection_response_time", hours=24)
                
                base_stats.update({
                    "database_stats": db_stats,
                    "avg_response_time_24h": sum(m['value'] for m in performance_metrics) / len(performance_metrics) if performance_metrics else 0,
                    "total_domains_tracked": db_stats.get('total_detections', 0)
                })
            except Exception as e:
                self.logger.error(f"❌ Failed to get DB statistics: {e}")
        
        return base_stats
    
    def export_report(self, start_date: datetime, end_date: datetime, 
                     format: str = 'json') -> Dict:
        """Export detection report for specified period."""
        
        if not self.mongo:
            return {"error": "MongoDB not available for reporting"}
        
        try:
            detections = self.mongo.export_detections_for_submission(start_date, end_date)
            
            report = {
                "report_period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "summary": {
                    "total_detections": len(detections),
                    "phishing_count": len([d for d in detections if d.get('Classification') == 'Phishing']),
                    "suspected_count": len([d for d in detections if d.get('Classification') == 'Suspected'])
                },
                "detections": detections,
                "generated_at": datetime.utcnow().isoformat(),
                "system_version": "PhishGuard AI v2.0"
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"❌ Failed to export report: {e}")
            return {"error": str(e)}


def demo_enhanced_detector():
    """Demonstrate enhanced detector capabilities."""
    
    print("🚀 PhishGuard AI Enhanced Detector Demo")
    print("=" * 50)
    
    # Initialize detector
    detector = EnhancedPhishGuardDetector()
    
    # Test detection with storage
    print("\n📊 Testing detection with MongoDB storage...")
    result = detector.predict_single_optimized("sbi.co.in", "sbi-fake-demo.com")
    
    print(f"   🌐 Domain: sbi-fake-demo.com")
    print(f"   📊 Classification: {result['prediction']}")
    print(f"   🎯 Confidence: {result['confidence']:.1%}")
    print(f"   🔥 Risk Score: {result['risk_score']:.1f}/100")
    
    if 'mongodb_id' in result:
        print(f"   💾 Stored with ID: {result['mongodb_id']}")
    
    # Get system statistics
    print("\n📈 System Statistics:")
    stats = detector.get_statistics_summary()
    print(f"   🔧 MongoDB Enabled: {stats['mongodb_enabled']}")
    print(f"   ⚡ Cache Enabled: {stats['cache_enabled']}")
    print(f"   🤖 Models Loaded: {stats['models_loaded']}")
    
    if detector.use_mongodb:
        # Get dashboard data
        print("\n📊 Dashboard Data:")
        dashboard = detector.get_dashboard_data()
        print(f"   🚨 Recent Detections: {len(dashboard['recent_detections'])}")
        print(f"   🔴 High Risk Domains: {len(dashboard['high_risk_domains'])}")
        print(f"   🎯 System Status: {dashboard['system_status']}")
    
    print("\n✅ Enhanced detector demo complete!")


if __name__ == "__main__":
    # Run demonstration
    demo_enhanced_detector()
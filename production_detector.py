#!/usr/bin/env python3
"""
PhishGuard AI - Production Model Deployment
===========================================

This script creates a production-ready phishing detection model
with proper evaluation and deployment capabilities.

Key Features:
1. Feature extraction from domain pairs
2. Ensemble model prediction
3. Confidence scoring
4. Batch processing
5. Real-time detection API ready

Author: PhishGuard AI Team
Date: October 2, 2025
"""

import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from pathlib import Path
import json
import time
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import our feature extractor
from training.feature_engineering import PhishGuardFeatureExtractor

class PhishGuardDetector:
    """
    Production-ready PhishGuard AI detector.
    Combines all trained models for optimal performance.
    """
    
    def __init__(self, model_dir="models"):
        """Initialize the detector with trained models."""
        
        self.model_path = Path(model_dir)
        self.feature_extractor = PhishGuardFeatureExtractor()
        
        print("🚀 Initializing PhishGuard AI Detector...")
        
        # Load models
        self.random_forest = joblib.load(self.model_path / "random_forest.pkl")
        self.xgboost = joblib.load(self.model_path / "xgboost.pkl")
        self.neural_network = tf.keras.models.load_model(self.model_path / "neural_network.h5")
        
        # Load preprocessing
        self.scaler = joblib.load(self.model_path / "scaler.pkl")
        self.label_encoder = joblib.load(self.model_path / "label_encoder.pkl")
        self.feature_names = joblib.load(self.model_path / "feature_names.pkl")
        self.ensemble_weights = joblib.load(self.model_path / "ensemble_weights.pkl")
        
        # Model parameters (can be optimized)
        self.classification_threshold = 0.5
        self.confidence_threshold = 0.7
        
        print("✅ PhishGuard AI Detector initialized successfully!")
        print(f"   Models loaded from: {self.model_path}")
        print(f"   Feature count: {len(self.feature_names)}")
        print(f"   Classes: {self.label_encoder.classes_}")
    
    def extract_features_from_domains(self, cse_domain, suspicious_domain):
        """Extract features from a domain pair."""
        
        try:
            features = self.feature_extractor.extract_all_features(cse_domain, suspicious_domain)
            
            # Ensure all expected features are present
            feature_vector = []
            for feature_name in self.feature_names:
                value = features.get(feature_name, 0)
                
                # Handle infinite and NaN values
                if np.isinf(value) or np.isnan(value):
                    value = 0
                
                feature_vector.append(value)
            
            return np.array(feature_vector).reshape(1, -1)
            
        except Exception as e:
            print(f"❌ Error extracting features: {e}")
            return np.zeros((1, len(self.feature_names)))
    
    def predict_single(self, cse_domain, suspicious_domain, return_details=False):
        """
        Predict if a suspicious domain is phishing/suspected.
        
        Args:
            cse_domain (str): Legitimate CSE domain (e.g., 'airtel.in')
            suspicious_domain (str): Domain to analyze (e.g., 'airtel-secure.tk')
            return_details (bool): Return detailed prediction info
            
        Returns:
            dict: Prediction results
        """
        
        start_time = time.time()
        
        # Extract features
        X = self.extract_features_from_domains(cse_domain, suspicious_domain)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from all models
        rf_proba = self.random_forest.predict_proba(X_scaled)[0, 1]
        xgb_proba = self.xgboost.predict_proba(X_scaled)[0, 1]
        nn_proba = self.neural_network.predict(X_scaled, verbose=0)[0, 0]
        
        # Rule engine
        rule_proba = self._apply_rules(X_scaled[0], suspicious_domain)
        
        # Ensemble prediction
        ensemble_proba = (
            self.ensemble_weights['random_forest'] * rf_proba +
            self.ensemble_weights['xgboost'] * xgb_proba +
            self.ensemble_weights['neural_network'] * nn_proba +
            self.ensemble_weights['rule_engine'] * rule_proba
        )
        
        # Final prediction
        prediction = 1 if ensemble_proba >= self.classification_threshold else 0
        predicted_class = self.label_encoder.classes_[prediction]
        
        # Confidence calculation
        confidence = abs(ensemble_proba - 0.5) * 2  # Scale to [0, 1]
        confidence_level = self._get_confidence_level(confidence)
        
        prediction_time = time.time() - start_time
        
        result = {
            'cse_domain': cse_domain,
            'suspicious_domain': suspicious_domain,
            'prediction': predicted_class,
            'probability': float(ensemble_proba),
            'confidence': float(confidence),
            'confidence_level': confidence_level,
            'risk_score': float(ensemble_proba * 100),
            'prediction_time_ms': float(prediction_time * 1000),
            'timestamp': datetime.now().isoformat()
        }
        
        if return_details:
            result['model_details'] = {
                'random_forest_proba': float(rf_proba),
                'xgboost_proba': float(xgb_proba),
                'neural_network_proba': float(nn_proba),
                'rule_engine_proba': float(rule_proba),
                'ensemble_weights': self.ensemble_weights,
                'threshold_used': self.classification_threshold,
                'feature_count': len(self.feature_names)
            }
        
        return result
    
    def predict_batch(self, domain_pairs, progress_callback=None):
        """
        Predict multiple domain pairs efficiently.
        
        Args:
            domain_pairs (list): List of (cse_domain, suspicious_domain) tuples
            progress_callback (callable): Optional progress callback function
            
        Returns:
            list: List of prediction results
        """
        
        print(f"🔍 Processing {len(domain_pairs)} domain pairs...")
        start_time = time.time()
        
        results = []
        
        for i, (cse_domain, suspicious_domain) in enumerate(domain_pairs):
            try:
                result = self.predict_single(cse_domain, suspicious_domain)
                results.append(result)
                
                if progress_callback:
                    progress_callback(i + 1, len(domain_pairs))
                elif (i + 1) % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed
                    eta = (len(domain_pairs) - i - 1) / rate
                    print(f"   Progress: {i+1}/{len(domain_pairs)} ({rate:.1f}/sec, ETA: {eta:.1f}s)")
                    
            except Exception as e:
                print(f"❌ Error processing {suspicious_domain}: {e}")
                results.append({
                    'cse_domain': cse_domain,
                    'suspicious_domain': suspicious_domain,
                    'prediction': 'Error',
                    'error': str(e)
                })
        
        total_time = time.time() - start_time
        avg_time = total_time / len(domain_pairs) * 1000
        
        print(f"✅ Batch processing completed:")
        print(f"   Total time: {total_time:.2f}s")
        print(f"   Average time per domain: {avg_time:.1f}ms")
        print(f"   Processing rate: {len(domain_pairs)/total_time:.1f} domains/sec")
        
        return results
    
    def _apply_rules(self, feature_vector, suspicious_domain):
        """Apply rule-based logic for additional signals."""
        
        base_score = 0.3
        
        # Rule 1: Very suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top']
        if any(suspicious_domain.lower().endswith(tld) for tld in suspicious_tlds):
            base_score += 0.2
        
        # Rule 2: Contains common phishing keywords
        phishing_keywords = ['secure', 'login', 'verify', 'update', 'confirm']
        domain_lower = suspicious_domain.lower()
        keyword_count = sum(1 for keyword in phishing_keywords if keyword in domain_lower)
        base_score += min(keyword_count * 0.1, 0.3)
        
        # Rule 3: Unusual length
        if len(suspicious_domain) > 30:
            base_score += 0.1
        
        # Rule 4: Many hyphens or numbers
        if suspicious_domain.count('-') > 2 or sum(c.isdigit() for c in suspicious_domain) > 3:
            base_score += 0.1
        
        return min(base_score, 1.0)
    
    def _get_confidence_level(self, confidence_score):
        """Convert confidence score to human-readable level."""
        
        if confidence_score >= 0.8:
            return "Very High"
        elif confidence_score >= 0.6:
            return "High"
        elif confidence_score >= 0.4:
            return "Medium"
        elif confidence_score >= 0.2:
            return "Low"
        else:
            return "Very Low"
    
    def analyze_domain_features(self, cse_domain, suspicious_domain):
        """
        Detailed analysis of domain features for investigation.
        
        Returns:
            dict: Detailed feature analysis
        """
        
        print(f"🔍 Analyzing features for: {suspicious_domain}")
        print(f"   Compared to CSE domain: {cse_domain}")
        
        # Extract features
        X = self.extract_features_from_domains(cse_domain, suspicious_domain)
        feature_dict = {name: X[0, i] for i, name in enumerate(self.feature_names)}
        
        # Get feature importance from Random Forest
        feature_importance = self.random_forest.feature_importances_
        
        # Combine features with importance
        feature_analysis = []
        for i, (name, value) in enumerate(feature_dict.items()):
            feature_analysis.append({
                'feature': name,
                'value': float(value),
                'importance': float(feature_importance[i]),
                'category': self._categorize_feature(name)
            })
        
        # Sort by importance
        feature_analysis.sort(key=lambda x: x['importance'], reverse=True)
        
        # Get top suspicious features
        suspicious_features = []
        for feature in feature_analysis[:20]:
            if self._is_suspicious_feature_value(feature['feature'], feature['value']):
                suspicious_features.append(feature)
        
        return {
            'domain_pair': f"{cse_domain} vs {suspicious_domain}",
            'top_features': feature_analysis[:10],
            'suspicious_features': suspicious_features[:5],
            'feature_categories': self._get_feature_category_summary(feature_analysis)
        }
    
    def _categorize_feature(self, feature_name):
        """Categorize feature by type."""
        
        if feature_name.startswith('url_'):
            return 'URL Structure'
        elif feature_name.startswith('domain_'):
            return 'Domain Analysis'
        elif feature_name.startswith('lexical_'):
            return 'Text Similarity'
        elif feature_name.startswith('typo_'):
            return 'Typosquatting'
        elif feature_name.startswith('idn_'):
            return 'IDN/Homograph'
        elif feature_name.startswith('struct_'):
            return 'Structural'
        elif feature_name.startswith('risk_'):
            return 'Risk Assessment'
        elif feature_name.startswith('brand_'):
            return 'Brand Similarity'
        else:
            return 'Other'
    
    def _is_suspicious_feature_value(self, feature_name, value):
        """Determine if a feature value indicates suspicion."""
        
        # High similarity features (suspicious when high)
        if any(keyword in feature_name for keyword in ['similarity', 'ratio', 'jaro_winkler']):
            return value > 0.7
        
        # Distance features (suspicious when low)
        if 'distance' in feature_name:
            return value < 3
        
        # Count features (suspicious when high)
        if any(keyword in feature_name for keyword in ['count', 'suspicious', 'typo']):
            return value > 2
        
        # Length features (suspicious when very high or very low)
        if 'length' in feature_name:
            return value > 20 or value < 3
        
        return False
    
    def _get_feature_category_summary(self, feature_analysis):
        """Get summary statistics by feature category."""
        
        categories = {}
        for feature in feature_analysis:
            category = feature['category']
            if category not in categories:
                categories[category] = {
                    'count': 0,
                    'avg_importance': 0,
                    'suspicious_count': 0
                }
            
            categories[category]['count'] += 1
            categories[category]['avg_importance'] += feature['importance']
            
            if self._is_suspicious_feature_value(feature['feature'], feature['value']):
                categories[category]['suspicious_count'] += 1
        
        # Calculate averages
        for category in categories:
            if categories[category]['count'] > 0:
                categories[category]['avg_importance'] /= categories[category]['count']
        
        return categories
    
    def generate_report(self, results, output_file="detection_report.json"):
        """Generate a comprehensive detection report."""
        
        print(f"📊 Generating detection report...")
        
        # Summary statistics
        total_domains = len(results)
        phishing_count = sum(1 for r in results if r.get('prediction') == 'Phishing')
        suspected_count = sum(1 for r in results if r.get('prediction') == 'Suspected')
        
        high_confidence = sum(1 for r in results if r.get('confidence', 0) > 0.7)
        avg_confidence = np.mean([r.get('confidence', 0) for r in results])
        avg_risk_score = np.mean([r.get('risk_score', 0) for r in results])
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_domains_analyzed': total_domains,
                'phishguard_version': '1.0.0'
            },
            'summary_statistics': {
                'phishing_domains': phishing_count,
                'suspected_domains': suspected_count,
                'phishing_percentage': (phishing_count / total_domains * 100) if total_domains > 0 else 0,
                'suspected_percentage': (suspected_count / total_domains * 100) if total_domains > 0 else 0,
                'high_confidence_detections': high_confidence,
                'average_confidence': float(avg_confidence),
                'average_risk_score': float(avg_risk_score)
            },
            'detection_results': results
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Report saved to: {output_file}")
        print(f"📊 Summary:")
        print(f"   Total domains: {total_domains}")
        print(f"   Phishing: {phishing_count} ({phishing_count/total_domains*100:.1f}%)")
        print(f"   Suspected: {suspected_count} ({suspected_count/total_domains*100:.1f}%)")
        print(f"   High confidence: {high_confidence} ({high_confidence/total_domains*100:.1f}%)")
        
        return report


def demo_detection():
    """Demonstrate the PhishGuard detector capabilities."""
    
    print("🎯 PHISHGUARD AI - PRODUCTION DETECTOR DEMO")
    print("=" * 70)
    
    # Initialize detector
    detector = PhishGuardDetector()
    
    # Test cases from our training data
    test_cases = [
        ("airtel.in", "airtel-merchants.in"),
        ("airtel.in", "airtelrecharge.co.in"),
        ("airtel.in", "airtela.sbs"),
        ("sbi.co.in", "sbi-secure.tk"),
        ("hdfc.com", "hdfcbank-login.ml"),
        ("icici.com", "icicibank.com"),  # Legitimate example
        ("axis.com", "axis-bank-verify.top"),
        ("kotak.com", "kotakbank123.ga")
    ]
    
    print(f"\n🔍 Testing {len(test_cases)} domain pairs...")
    print("-" * 70)
    
    results = []
    
    for i, (cse_domain, suspicious_domain) in enumerate(test_cases, 1):
        print(f"\n{i}. Analyzing: {suspicious_domain}")
        print(f"   CSE Domain: {cse_domain}")
        
        # Get prediction
        result = detector.predict_single(cse_domain, suspicious_domain, return_details=True)
        results.append(result)
        
        # Display result
        prediction = result['prediction']
        probability = result['probability']
        confidence = result['confidence']
        risk_score = result['risk_score']
        
        # Color coding for terminal output
        if prediction == 'Phishing':
            status_icon = "🚨"
            status_color = "HIGH RISK"
        elif prediction == 'Suspected':
            status_icon = "⚠️"
            status_color = "MEDIUM RISK"
        else:
            status_icon = "✅"
            status_color = "LOW RISK"
        
        print(f"   {status_icon} Prediction: {prediction} ({status_color})")
        print(f"   📊 Risk Score: {risk_score:.1f}%")
        print(f"   🎯 Confidence: {confidence:.1%} ({result['confidence_level']})")
        print(f"   ⏱️  Processing Time: {result['prediction_time_ms']:.1f}ms")
        
        # Show model breakdown for first few cases
        if i <= 3 and 'model_details' in result:
            details = result['model_details']
            print(f"   🔍 Model Breakdown:")
            print(f"      Random Forest: {details['random_forest_proba']:.3f}")
            print(f"      XGBoost: {details['xgboost_proba']:.3f}")
            print(f"      Neural Network: {details['neural_network_proba']:.3f}")
            print(f"      Rule Engine: {details['rule_engine_proba']:.3f}")
    
    # Generate report
    print(f"\n📊 Generating comprehensive report...")
    report = detector.generate_report(results, "demo_detection_report.json")
    
    # Feature analysis for most suspicious domain
    most_suspicious = max(results, key=lambda x: x.get('risk_score', 0))
    print(f"\n🔬 Detailed feature analysis for most suspicious domain:")
    print(f"   Domain: {most_suspicious['suspicious_domain']}")
    
    analysis = detector.analyze_domain_features(
        most_suspicious['cse_domain'], 
        most_suspicious['suspicious_domain']
    )
    
    print(f"\n🔥 Top 5 suspicious features:")
    for i, feature in enumerate(analysis['suspicious_features'], 1):
        print(f"   {i}. {feature['feature']}: {feature['value']:.3f} (importance: {feature['importance']:.3f})")
    
    print(f"\n✅ Demo completed successfully!")
    print(f"📄 Full report saved to: demo_detection_report.json")


if __name__ == "__main__":
    demo_detection()
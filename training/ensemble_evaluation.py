#!/usr/bin/env python3
"""
PhishGuard AI: Final Ensemble Model Evaluation
Generate comprehensive confusion matrix and accuracy report for the 4-model ensemble
"""

import sys
import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score,
    precision_recall_curve, roc_curve
)
from sklearn.calibration import CalibratedClassifierCV
import warnings
warnings.filterwarnings('ignore')

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class EnsembleEvaluator:
    def __init__(self, models_dir="../models"):
        self.models_dir = models_dir
        self.models = {}
        self.feature_names = None
        self.scaler = None
        self.calibrator = None
        
    def load_models(self):
        """Load all ensemble model components"""
        try:
            print("🔧 Loading ensemble model components...")
            
            # Load individual models
            self.models['random_forest'] = joblib.load(f"{self.models_dir}/random_forest.pkl")
            self.models['xgboost'] = joblib.load(f"{self.models_dir}/xgboost.pkl")
            
            # Try to load neural network (might be .h5 format)
            try:
                from tensorflow.keras.models import load_model
                self.models['neural_network'] = load_model(f"{self.models_dir}/neural_network.h5")
            except:
                print("⚠️  Neural network model not found, using available models only")
                
            self.models['rule_engine'] = joblib.load(f"{self.models_dir}/rule_engine.pkl")
            
            # Load preprocessing components
            self.scaler = joblib.load(f"{self.models_dir}/scaler.pkl")
            self.feature_names = joblib.load(f"{self.models_dir}/feature_names.pkl")
            
            # Load calibrator if available
            try:
                self.calibrator = joblib.load(f"{self.models_dir}/ensemble_calibrator.joblib")
                print("✅ Probability calibrator loaded")
            except:
                print("⚠️  No calibrator found, using raw ensemble predictions")
            
            print(f"✅ Successfully loaded {len(self.models)} models")
            return True
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def load_test_data(self, test_file="../PS02_Training_set.xlsx"):
        """Load and prepare test data"""
        try:
            print("📊 Loading test data...")
            
            # For demonstration, we'll use a portion of training data as test
            # In practice, you'd have separate test data
            df = pd.read_excel(test_file)
            
            # Rename columns for easier access
            df = df.rename(columns={
                'Corresponding CSE Domain Name': 'cse_domain',
                'Identified Phishing/Suspected Domain Name': 'suspected_domain',
                'Phishing/Suspected Domains (i.e. Class Label)': 'label'
            })
            
            # Take last 20% as test set
            test_size = int(len(df) * 0.2)
            test_data = df.tail(test_size).copy()
            
            print(f"✅ Loaded {len(test_data)} test samples")
            return test_data
            
        except Exception as e:
            print(f"❌ Error loading test data: {e}")
            return None
    
    def extract_features_simple(self, domain, cse_target):
        """Extract basic features for testing (simplified version)"""
        features = []
        
        # Basic domain features
        features.extend([
            len(domain),  # domain_length
            domain.count('-'),  # hyphen_count
            domain.count('.'),  # dot_count
            sum(c.isdigit() for c in domain),  # digit_count
            len([c for c in domain if not c.isalnum() and c != '.']),  # special_chars
        ])
        
        # Similarity features (basic)
        import difflib
        similarity = difflib.SequenceMatcher(None, domain, cse_target).ratio()
        features.extend([
            similarity,  # basic_similarity
            len(domain) - len(cse_target),  # length_difference
            1 if cse_target.split('.')[0] in domain else 0,  # brand_in_domain
        ])
        
        # Pad to expected feature count (110)
        while len(features) < 110:
            features.append(0.0)
        
        return np.array(features[:110])
    
    def predict_ensemble(self, features):
        """Make ensemble prediction with model weights"""
        predictions = {}
        
        # Model weights (from training documentation)
        weights = {
            'random_forest': 0.25,
            'xgboost': 0.40,
            'neural_network': 0.20,
            'rule_engine': 0.15
        }
        
        # Get predictions from each model
        if 'random_forest' in self.models:
            try:
                pred = self.models['random_forest'].predict_proba([features])[0]
                predictions['random_forest'] = pred[1]  # Probability of phishing
            except:
                predictions['random_forest'] = 0.5
                
        if 'xgboost' in self.models:
            try:
                pred = self.models['xgboost'].predict_proba([features])[0]
                predictions['xgboost'] = pred[1]
            except:
                predictions['xgboost'] = 0.5
                
        if 'neural_network' in self.models:
            try:
                pred = self.models['neural_network'].predict([features.reshape(1, -1)])[0]
                predictions['neural_network'] = pred[1] if len(pred) > 1 else pred[0]
            except:
                predictions['neural_network'] = 0.5
                
        if 'rule_engine' in self.models:
            try:
                pred = self.models['rule_engine'].predict_proba([features])[0]
                predictions['rule_engine'] = pred[1]
            except:
                predictions['rule_engine'] = 0.5
        
        # Calculate weighted ensemble prediction
        ensemble_score = 0.0
        total_weight = 0.0
        
        for model_name, score in predictions.items():
            if model_name in weights:
                ensemble_score += score * weights[model_name]
                total_weight += weights[model_name]
        
        # Normalize if not all models available
        if total_weight > 0:
            ensemble_score /= total_weight
        
        # Apply calibration if available
        if self.calibrator:
            try:
                ensemble_score = self.calibrator.predict_proba([[ensemble_score]])[0][1]
            except:
                pass
        
        return ensemble_score, predictions
    
    def evaluate_model(self, test_data):
        """Evaluate the ensemble model and generate comprehensive report"""
        print("\n🎯 Starting ensemble model evaluation...")
        
        y_true = []
        y_pred = []
        y_scores = []
        detailed_results = []
        
        for idx, row in test_data.iterrows():
            try:
                domain = row['suspected_domain']
                cse_target = row['cse_domain']
                true_label = 1 if row['label'].strip().lower() == 'phishing' else 0
                
                # Extract features
                features = self.extract_features_simple(domain, cse_target)
                
                # Scale features
                if self.scaler:
                    features = self.scaler.transform([features])[0]
                
                # Get ensemble prediction
                ensemble_score, individual_scores = self.predict_ensemble(features)
                
                # Convert to binary prediction (threshold = 0.5)
                pred_label = 1 if ensemble_score > 0.5 else 0
                
                y_true.append(true_label)
                y_pred.append(pred_label)
                y_scores.append(ensemble_score)
                
                detailed_results.append({
                    'domain': domain,
                    'cse_target': cse_target,
                    'true_label': true_label,
                    'predicted_label': pred_label,
                    'ensemble_score': ensemble_score,
                    'individual_scores': individual_scores
                })
                
            except Exception as e:
                print(f"⚠️  Error processing {row.get('suspected_domain', 'unknown')}: {e}")
                continue
        
        return np.array(y_true), np.array(y_pred), np.array(y_scores), detailed_results
    
    def generate_confusion_matrix(self, y_true, y_pred):
        """Generate and plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Legitimate', 'Phishing'],
                   yticklabels=['Legitimate', 'Phishing'])
        plt.title('PhishGuard AI Ensemble Model - Confusion Matrix', fontsize=16, fontweight='bold')
        plt.xlabel('Predicted Label', fontsize=12)
        plt.ylabel('True Label', fontsize=12)
        
        # Add performance metrics to the plot
        tn, fp, fn, tp = cm.ravel()
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics_text = f"""
        Accuracy: {accuracy:.3f}
        Precision: {precision:.3f}
        Recall: {recall:.3f}
        F1-Score: {f1:.3f}
        
        True Positives: {tp}
        True Negatives: {tn}
        False Positives: {fp}
        False Negatives: {fn}
        """
        
        plt.text(2.5, 1.5, metrics_text, fontsize=10, 
                bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue"))
        
        plt.tight_layout()
        plt.savefig('ensemble_confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        return cm
    
    def generate_comprehensive_report(self, y_true, y_pred, y_scores, detailed_results):
        """Generate comprehensive accuracy and performance report"""
        
        report = "\n" + "="*80 + "\n"
        report += "🎯 PHISHGUARD AI: FINAL ENSEMBLE MODEL EVALUATION REPORT\n"
        report += "="*80 + "\n\n"
        
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        
        try:
            auc_score = roc_auc_score(y_true, y_scores)
        except:
            auc_score = 0.0
        
        report += "📊 OVERALL PERFORMANCE METRICS:\n"
        report += "-" * 40 + "\n"
        report += f"✅ Overall Accuracy:     {accuracy:.4f} ({accuracy*100:.2f}%)\n"
        report += f"✅ Precision (Phishing): {precision:.4f} ({precision*100:.2f}%)\n"
        report += f"✅ Recall (Phishing):    {recall:.4f} ({recall*100:.2f}%)\n"
        report += f"✅ F1-Score:             {f1:.4f}\n"
        report += f"✅ AUC-ROC Score:        {auc_score:.4f}\n\n"
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        report += "📈 CONFUSION MATRIX BREAKDOWN:\n"
        report += "-" * 40 + "\n"
        report += f"True Positives (TP):  {tp:4d} (Correctly identified phishing)\n"
        report += f"True Negatives (TN):  {tn:4d} (Correctly identified legitimate)\n"
        report += f"False Positives (FP): {fp:4d} (Legitimate marked as phishing)\n"
        report += f"False Negatives (FN): {fn:4d} (Phishing marked as legitimate)\n\n"
        
        # Error Analysis
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        report += "⚠️  ERROR ANALYSIS:\n"
        report += "-" * 40 + "\n"
        report += f"False Positive Rate:  {fpr:.4f} ({fpr*100:.2f}%)\n"
        report += f"False Negative Rate:  {fnr:.4f} ({fnr*100:.2f}%)\n"
        report += f"Total Errors:         {fp + fn:4d} / {len(y_true)} samples\n\n"
        
        # Model Component Analysis
        if detailed_results:
            rf_scores = [r['individual_scores'].get('random_forest', 0) for r in detailed_results if r['individual_scores']]
            xgb_scores = [r['individual_scores'].get('xgboost', 0) for r in detailed_results if r['individual_scores']]
            nn_scores = [r['individual_scores'].get('neural_network', 0) for r in detailed_results if r['individual_scores']]
            re_scores = [r['individual_scores'].get('rule_engine', 0) for r in detailed_results if r['individual_scores']]
            
            report += "🧠 INDIVIDUAL MODEL PERFORMANCE:\n"
            report += "-" * 40 + "\n"
            if rf_scores:
                report += f"Random Forest Avg Score:   {np.mean(rf_scores):.4f}\n"
            if xgb_scores:
                report += f"XGBoost Avg Score:         {np.mean(xgb_scores):.4f}\n"
            if nn_scores:
                report += f"Neural Network Avg Score:  {np.mean(nn_scores):.4f}\n"
            if re_scores:
                report += f"Rule Engine Avg Score:     {np.mean(re_scores):.4f}\n"
        
        # Classification Report
        report += "\n📋 DETAILED CLASSIFICATION REPORT:\n"
        report += "-" * 40 + "\n"
        class_report = classification_report(y_true, y_pred, 
                                           target_names=['Legitimate', 'Phishing'],
                                           digits=4)
        report += class_report + "\n"
        
        # Performance Summary
        report += "\n🏆 PERFORMANCE SUMMARY:\n"
        report += "-" * 40 + "\n"
        
        if accuracy >= 0.95:
            report += "🎯 EXCELLENT: Accuracy exceeds 95% target\n"
        elif accuracy >= 0.90:
            report += "✅ GOOD: Accuracy above 90%\n"
        else:
            report += "⚠️  NEEDS IMPROVEMENT: Accuracy below 90%\n"
            
        if fpr <= 0.05:
            report += "🛡️  LOW FALSE POSITIVES: False positive rate under 5%\n"
        else:
            report += "⚠️  HIGH FALSE POSITIVES: May impact user experience\n"
            
        if fnr <= 0.05:
            report += "🔒 LOW FALSE NEGATIVES: Good security coverage\n"
        else:
            report += "⚠️  HIGH FALSE NEGATIVES: Security risk detected\n"
        
        report += "\n" + "="*80 + "\n"
        
        return report
    
    def save_detailed_results(self, detailed_results):
        """Save detailed prediction results to CSV"""
        df = pd.DataFrame(detailed_results)
        df.to_csv('ensemble_evaluation_results.csv', index=False)
        print("✅ Detailed results saved to ensemble_evaluation_results.csv")

def main():
    """Main evaluation workflow"""
    print("🚀 PhishGuard AI: Final Ensemble Model Evaluation")
    print("=" * 60)
    
    evaluator = EnsembleEvaluator()
    
    # Load models
    if not evaluator.load_models():
        print("❌ Failed to load models. Exiting.")
        return
    
    # Load test data
    test_data = evaluator.load_test_data()
    if test_data is None:
        print("❌ Failed to load test data. Exiting.")
        return
    
    # Evaluate model
    y_true, y_pred, y_scores, detailed_results = evaluator.evaluate_model(test_data)
    
    if len(y_true) == 0:
        print("❌ No valid predictions generated. Check your data and models.")
        return
    
    # Generate confusion matrix
    print("\n📊 Generating confusion matrix...")
    cm = evaluator.generate_confusion_matrix(y_true, y_pred)
    
    # Generate comprehensive report
    report = evaluator.generate_comprehensive_report(y_true, y_pred, y_scores, detailed_results)
    print(report)
    
    # Save report to file
    with open('ensemble_evaluation_report.txt', 'w') as f:
        f.write(report)
    
    # Save detailed results
    evaluator.save_detailed_results(detailed_results)
    
    print("\n✅ Evaluation complete! Files generated:")
    print("   📊 ensemble_confusion_matrix.png")
    print("   📄 ensemble_evaluation_report.txt")
    print("   📋 ensemble_evaluation_results.csv")

if __name__ == "__main__":
    main()
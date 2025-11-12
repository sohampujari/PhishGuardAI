"""
Investigate Training Data Classification Issues
Check if the AI models are correctly classifying domains from their own training dataset
"""

import sys
sys.path.append('/home/atharv/projects/PhishGuard AI')

import pandas as pd
from enhanced_mongodb_detector import EnhancedPhishGuardDetector
import numpy as np

def test_training_data_classification():
    """Test how the AI models perform on their own training data."""
    print("🔍 Investigating Training Data Classification Issues")
    print("=" * 55)
    
    # Load the training dataset
    try:
        print("📂 Loading training dataset...")
        df = pd.read_excel('/home/atharv/projects/PhishGuard AI/PS02_Training_set.xlsx')
        print(f"✅ Loaded {len(df)} training samples")
        
        # Show dataset structure
        print(f"\n📊 Dataset columns: {list(df.columns)}")
        print(f"📊 Dataset shape: {df.shape}")
        
        if 'classification' in df.columns:
            print(f"📊 Original classifications:")
            print(df['classification'].value_counts())
        elif 'label' in df.columns:
            print(f"📊 Original labels:")
            print(df['label'].value_counts())
        
    except Exception as e:
        print(f"❌ Error loading training data: {e}")
        return
    
    # Initialize detector
    print(f"\n🤖 Initializing AI detector...")
    try:
        detector = EnhancedPhishGuardDetector()
        print("✅ Detector initialized")
    except Exception as e:
        print(f"❌ Error initializing detector: {e}")
        return
    
    # Test a sample of training data
    print(f"\n🧪 Testing AI predictions on training data...")
    
    # Get domain columns - try different possible column names
    domain_col = None
    for col in ['domain', 'url', 'website', 'Domain']:
        if col in df.columns:
            domain_col = col
            break
    
    if not domain_col:
        print("❌ Could not find domain column in training data")
        return
    
    # Get classification column
    class_col = None
    for col in ['classification', 'label', 'class', 'Classification']:
        if col in df.columns:
            class_col = col
            break
    
    if not class_col:
        print("❌ Could not find classification column in training data")
        return
    
    print(f"📊 Using domain column: '{domain_col}'")
    print(f"📊 Using classification column: '{class_col}'")
    
    # Test sample of training data
    sample_size = min(50, len(df))
    test_sample = df.sample(n=sample_size, random_state=42)
    
    print(f"\n🔬 Testing {sample_size} random samples from training data:")
    print("-" * 60)
    
    correct_predictions = 0
    total_predictions = 0
    misclassifications = []
    
    for idx, row in test_sample.iterrows():
        try:
            domain = str(row[domain_col]).strip()
            original_class = str(row[class_col]).strip().lower()
            
            # Skip if domain is invalid
            if not domain or domain in ['nan', 'None', '']:
                continue
            
            # Use a generic CSE domain for testing
            cse_domain = 'sbi.co.in'  # Generic CSE for testing
            
            # Get AI prediction
            result = detector.predict_single_optimized(
                cse_domain=cse_domain,
                suspicious_domain=domain,
                return_details=False,
                store_result=False
            )
            
            ai_prediction = result.get('prediction', 'Unknown').lower()
            confidence = result.get('confidence', 0)
            
            # Map original classifications to our system
            if 'phish' in original_class or 'malicious' in original_class:
                expected = 'phishing'
            elif 'legit' in original_class or 'benign' in original_class or 'legitimate' in original_class:
                expected = 'legitimate'
            else:
                expected = 'suspected'
            
            # Check if prediction is correct
            is_correct = False
            if expected == 'phishing' and ai_prediction in ['phishing', 'suspected']:
                is_correct = True
            elif expected == 'legitimate' and ai_prediction == 'legitimate':
                is_correct = True
            elif expected == 'suspected':
                is_correct = True  # Any prediction acceptable for suspected
            
            # Status icon
            status = "✅" if is_correct else "❌"
            
            print(f"{status} {domain[:40]:<40}")
            print(f"   📚 Training label: {original_class:<15} → Expected: {expected}")
            print(f"   🤖 AI prediction: {ai_prediction:<15} → Confidence: {confidence:.1f}%")
            
            if not is_correct:
                misclassifications.append({
                    'domain': domain,
                    'expected': expected,
                    'predicted': ai_prediction,
                    'confidence': confidence,
                    'original': original_class
                })
            else:
                correct_predictions += 1
            
            total_predictions += 1
            print()
            
        except Exception as e:
            print(f"❌ Error testing {domain}: {e}")
            continue
    
    # Summary
    accuracy = (correct_predictions / total_predictions * 100) if total_predictions > 0 else 0
    
    print(f"\n📊 TRAINING DATA CLASSIFICATION RESULTS:")
    print("=" * 50)
    print(f"✅ Correct predictions: {correct_predictions}/{total_predictions}")
    print(f"📈 Accuracy: {accuracy:.1f}%")
    print(f"❌ Misclassifications: {len(misclassifications)}")
    
    if misclassifications:
        print(f"\n🚨 CRITICAL MISCLASSIFICATIONS:")
        print("-" * 40)
        for misc in misclassifications[:10]:  # Show first 10
            print(f"❌ {misc['domain']}")
            print(f"   Expected: {misc['expected']} | Got: {misc['predicted']} ({misc['confidence']:.1f}%)")
    
    # Identify the root problem
    print(f"\n🔍 ROOT CAUSE ANALYSIS:")
    if accuracy < 50:
        print("🚨 CRITICAL: AI models are performing worse than random chance!")
        print("   Possible causes:")
        print("   1. Models were trained on different data format")
        print("   2. Feature extraction is incorrect")
        print("   3. Models are corrupted or incorrectly loaded")
        print("   4. Domain preprocessing is inconsistent")
        
    elif accuracy < 70:
        print("⚠️  WARNING: AI models have poor accuracy on training data")
        print("   Possible causes:")
        print("   1. Overfitting during training")
        print("   2. Classification thresholds need adjustment")
        print("   3. Feature extraction differences")
        
    else:
        print("✅ AI models are performing reasonably on training data")
        print("   The issue might be in the classification logic or thresholds")
    
    return misclassifications, accuracy

if __name__ == "__main__":
    misclassifications, accuracy = test_training_data_classification()
    
    if accuracy < 70:
        print(f"\n🔧 IMMEDIATE ACTION REQUIRED:")
        print(f"   The AI models need to be retrained or fixed!")
        print(f"   Current accuracy on training data: {accuracy:.1f}%")
    else:
        print(f"\n✅ Models are working, classification logic might need adjustment")
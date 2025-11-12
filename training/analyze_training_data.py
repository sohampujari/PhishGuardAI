"""
Simple Training Data Analysis
Just check what the training data looks like without loading AI models
"""

import sys
sys.path.append('/home/atharv/projects/PhishGuard AI')

import pandas as pd
import numpy as np

def analyze_training_data():
    """Analyze the training dataset structure and content."""
    print("🔍 Analyzing Training Dataset")
    print("=" * 35)
    
    try:
        # Load the training dataset
        print("📂 Loading training dataset...")
        df = pd.read_excel('/home/atharv/projects/PhishGuard AI/PS02_Training_set.xlsx')
        print(f"✅ Loaded {len(df)} training samples")
        
        # Show basic info
        print(f"\n📊 Dataset Structure:")
        print(f"   Shape: {df.shape}")
        print(f"   Columns: {list(df.columns)}")
        
        # Show first few rows
        print(f"\n📋 First 5 rows:")
        print(df.head())
        
        # Check for classification column
        class_columns = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['class', 'label', 'target', 'phish']):
                class_columns.append(col)
        
        print(f"\n🎯 Potential classification columns: {class_columns}")
        
        # Check for domain columns
        domain_columns = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['domain', 'url', 'website', 'link']):
                domain_columns.append(col)
        
        print(f"🌐 Potential domain columns: {domain_columns}")
        
        # Analyze each potential classification column
        for col in class_columns:
            print(f"\n📊 Analysis of '{col}':")
            print(df[col].value_counts())
            
            # Check unique values
            unique_vals = df[col].unique()
            print(f"   Unique values: {unique_vals}")
        
        # Sample some domains if found
        for col in domain_columns:
            print(f"\n🌐 Sample domains from '{col}':")
            sample_domains = df[col].dropna().sample(min(10, len(df))).tolist()
            for domain in sample_domains:
                print(f"   • {domain}")
        
        # Check for legitimate vs phishing distribution
        if class_columns:
            main_class_col = class_columns[0]
            print(f"\n🎯 Classification Distribution (using '{main_class_col}'):")
            
            # Count different types
            legitimate_count = 0
            phishing_count = 0
            other_count = 0
            
            for value in df[main_class_col]:
                value_str = str(value).lower()
                if any(keyword in value_str for keyword in ['legit', 'benign', 'legitimate', 'good']):
                    legitimate_count += 1
                elif any(keyword in value_str for keyword in ['phish', 'malicious', 'bad', 'fraud']):
                    phishing_count += 1
                else:
                    other_count += 1
            
            total = len(df)
            print(f"   ✅ Legitimate: {legitimate_count} ({legitimate_count/total*100:.1f}%)")
            print(f"   🚨 Phishing: {phishing_count} ({phishing_count/total*100:.1f}%)")
            print(f"   ❓ Other/Unknown: {other_count} ({other_count/total*100:.1f}%)")
            
            # Check if dataset is balanced
            if abs(legitimate_count - phishing_count) / total > 0.3:
                print(f"\n⚠️  WARNING: Dataset is imbalanced!")
                print(f"   This could cause the AI to be biased towards the majority class")
            else:
                print(f"\n✅ Dataset appears reasonably balanced")
        
        return df
        
    except FileNotFoundError:
        print("❌ Training dataset not found at expected location")
        print("   Expected: /home/atharv/projects/PhishGuard AI/PS02_Training_set.xlsx")
        return None
    except Exception as e:
        print(f"❌ Error analyzing training data: {e}")
        return None

def check_model_files():
    """Check if AI model files exist and their dates."""
    print(f"\n🤖 Checking AI Model Files:")
    print("-" * 30)
    
    import os
    from datetime import datetime
    
    model_dir = '/home/atharv/projects/PhishGuard AI/models'
    
    if not os.path.exists(model_dir):
        print("❌ Models directory not found!")
        return
    
    model_files = []
    for file in os.listdir(model_dir):
        if file.endswith(('.pkl', '.joblib', '.h5', '.json')):
            file_path = os.path.join(model_dir, file)
            mod_time = os.path.getmtime(file_path)
            mod_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
            file_size = os.path.getsize(file_path)
            model_files.append((file, mod_date, file_size))
    
    if model_files:
        print("📁 Found model files:")
        for file, date, size in model_files:
            print(f"   • {file:<25} | {date} | {size:,} bytes")
    else:
        print("❌ No model files found!")
    
    return model_files

if __name__ == "__main__":
    # Analyze training data
    df = analyze_training_data()
    
    # Check model files
    model_files = check_model_files()
    
    print(f"\n🔍 DIAGNOSIS SUMMARY:")
    print("=" * 25)
    
    if df is not None:
        print("✅ Training data is accessible")
        if len(df) < 100:
            print("⚠️  WARNING: Training dataset is very small")
        elif len(df) < 1000:
            print("⚠️  WARNING: Training dataset might be too small for good AI performance")
        else:
            print("✅ Training dataset size appears adequate")
    else:
        print("❌ Training data is not accessible")
    
    if model_files:
        print("✅ AI model files exist")
        # Check if models are recent
        import os
        newest_model = max(model_files, key=lambda x: os.path.getmtime(f'/home/atharv/projects/PhishGuard AI/models/{x[0]}'))
        print(f"   Newest model: {newest_model[0]} ({newest_model[1]})")
    else:
        print("❌ AI model files are missing")
    
    print(f"\n🎯 NEXT STEPS:")
    if df is not None and model_files:
        print("1. ✅ Data and models exist - issue is likely in classification logic")
        print("2. 🔧 Need to test actual AI predictions vs training labels")
        print("3. 🔍 May need to adjust classification thresholds")
    elif df is None:
        print("1. ❌ Fix training data loading first")
        print("2. 🔧 Retrain models with correct data")
    elif not model_files:
        print("1. ❌ Models are missing - need to retrain")
        print("2. 🔧 Use training data to create new models")

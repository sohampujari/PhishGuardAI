"""
PhishGuard AI Training Module

This package contains all the machine learning training and evaluation components:
- Feature engineering and extraction
- Model training and calibration
- Accuracy optimization
- Ensemble evaluation
- Performance analysis

All training-related functionality is centralized in this module.
"""

__version__ = "1.0.0"
__author__ = "PhishGuard AI Team"

# Import key components for easy access
try:
    from .feature_engineering import PhishGuardFeatureExtractor
    from .ensemble_evaluation import EnsembleEvaluator
    from .accuracy_optimizer import AccuracyTestSuite
except ImportError:
    # Handle cases where dependencies might not be available
    pass

__all__ = [
    'PhishGuardFeatureExtractor',
    'EnsembleEvaluator', 
    'AccuracyTestSuite'
]
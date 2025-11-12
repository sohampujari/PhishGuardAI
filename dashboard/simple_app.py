"""
PhishGuard AI Simple Dashboard
Beautiful web interface without WebSocket (for compatibility).

Dataset Attribution: This model has been trained from a dataset taken from 
NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data.
"""

from flask import Flask, render_template, jsonify, request, redirect
import sys
import os
from dotenv import load_dotenv

# Add parent directory to path and change to project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)
os.chdir(project_root)  # Change to project root so models can be found

# Load environment variables from project root
load_dotenv(os.path.join(project_root, '.env'))

from mongodb_manager import PhishGuardMongoDB
from enhanced_fixed_detector import EnhancedFixedDetector
from datetime import datetime, timedelta
import json
import time
import re
import random
from typing import Dict, List
from pathlib import Path

# Configure Flask app with correct template folder
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Global instances
mongo_db = None
detector = None

def initialize_components():
    """Initialize MongoDB and detector components."""
    global mongo_db, detector
    try:
        # Try to initialize MongoDB
        try:
            mongo_db = PhishGuardMongoDB()
            print("✅ MongoDB connected successfully")
        except Exception as mongo_error:
            print(f"⚠️  MongoDB connection failed: {mongo_error}")
            print("📋 App will continue without database features")
            mongo_db = None
        
        # Initialize the enhanced detector (works without MongoDB)
        detector = EnhancedFixedDetector(use_mongodb=(mongo_db is not None))
        print("✅ Dashboard components initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize components: {e}")
        # Set defaults to allow app to start
        mongo_db = None
        detector = None

@app.route('/')
def landing():
    """Product landing/marketing page as default."""
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    """Main operational dashboard page with CSE entities."""
    try:
        # Get CSE entities from database
        cse_entities = []
        if mongo_db:
            entities = mongo_db.db.cse_entities.find({'is_active': True}).sort('name', 1)
            for entity in entities:
                cse_entities.append({
                    'name': f"{entity['name']} ({entity['abbreviation']})",
                    'domain': entity['official_domain'],
                    'category': entity.get('category', 'Other')
                })
        return render_template('dashboard_comprehensive.html', cse_entities=cse_entities)
    except Exception as e:
        print(f"❌ Error loading CSE entities: {e}")
        return render_template('dashboard_comprehensive.html', cse_entities=[])

@app.route('/home')
def home_redirect():
    """Redirect old /home to new root route."""
    return landing()

@app.route('/api/stats')
def get_stats():
    """Get system statistics."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
            
        # Collection counts
        stats = {}
        collections = ['cse_entities', 'detected_domains', 'performance_metrics', 'monitoring_logs']
        for col in collections:
            stats[col] = mongo_db.db[col].count_documents({})
        
        # Recent activity (last 24 hours)
        yesterday = datetime.now() - timedelta(hours=24)
        recent_detections = mongo_db.db.detected_domains.count_documents({
            'detected_at': {'$gte': yesterday}
        })
        
        # Classification breakdown
        pipeline = [
            {'$group': {
                '_id': '$classification',
                'count': {'$sum': 1}
            }}
        ]
        classification_data = list(mongo_db.db.detected_domains.aggregate(pipeline))
        
        # Average risk score
        avg_risk_pipeline = [
            {'$group': {
                '_id': None,
                'avg_risk': {'$avg': '$risk_score'},
                'max_risk': {'$max': '$risk_score'},
                'min_risk': {'$min': '$risk_score'}
            }}
        ]
        risk_stats = list(mongo_db.db.detected_domains.aggregate(avg_risk_pipeline))
        
        # Get top targeted CSEs
        top_targeted_cses = mongo_db.get_top_targeted_cses(limit=8)
        
        # Get average response time from performance metrics
        avg_response_time = 89  # Default fallback
        try:
            # Calculate average response time from recent performance metrics
            perf_metrics = list(mongo_db.db.performance_metrics.find({
                'metric_type': 'detection_time',
                'timestamp': {'$gte': datetime.now() - timedelta(hours=24)}
            }).limit(10))
            
            if perf_metrics:
                total_time = sum(metric.get('value', 89) for metric in perf_metrics)
                avg_response_time = round(total_time / len(perf_metrics))
        except Exception as e:
            print(f"Error calculating response time: {e}")
        
        return jsonify({
            'total_detections': stats.get('detected_domains', 0),
            'high_risk_count': len([d for d in classification_data if d.get('_id') in ['Phishing', 'Suspected']]),
            'cse_count': stats.get('cse_entities', 0),
            'avg_response_time': avg_response_time,
            'recent_detections_24h': recent_detections,
            'classification_breakdown': classification_data,
            'risk_statistics': risk_stats[0] if risk_stats else {},
            'top_targeted_cses': top_targeted_cses,
            'system_status': 'operational',
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cse-entities')
def get_cse_entities():
    """Get all CSE entities."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
        
        # Get CSE entities from database
        entities = []
        cse_docs = mongo_db.db.cse_entities.find({'is_active': True}).sort('name', 1)
        
        for entity in cse_docs:
            entities.append({
                'id': str(entity['_id']),
                'name': entity['name'],
                'abbreviation': entity['abbreviation'],
                'domain': entity['official_domain'],
                'category': entity.get('category', 'Other'),
                'description': entity.get('description', ''),
                'display_name': f"{entity['name']} ({entity['abbreviation']})"
            })
        
        return jsonify({
            'entities': entities,
            'count': len(entities),
            'categories': list(set(entity['category'] for entity in entities))
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-detections')
def get_recent_detections():
    """Get recent detection results."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
            
        limit = request.args.get('limit', 20, type=int)
        
        detections = mongo_db.db.detected_domains.find().sort('detected_at', -1).limit(limit)
        
        results = []
        for detection in detections:
            results.append({
                'id': str(detection.get('_id')),
                'domain_name': detection.get('domain_name'),
                'classification': detection.get('classification'),
                'confidence': detection.get('confidence', 0),
                'risk_score': detection.get('risk_score', 0),
                'detected_at': detection.get('detected_at').isoformat() if detection.get('detected_at') else None,
                'target_cse': detection.get('target_cse', {}).get('name', 'Unknown'),
                'source': detection.get('source', 'unknown')
            })
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/performance-metrics')
def get_performance_metrics():
    """Get performance metrics over time."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
            
        # Get last 50 performance metrics
        metrics = mongo_db.db.performance_metrics.find().sort('timestamp', -1).limit(50)
        
        response_times = []
        timestamps = []
        
        for metric in metrics:
            if metric.get('metric_type') == 'detection_response_time':
                response_times.append(metric.get('value', 0))
                timestamps.append(metric.get('timestamp').isoformat() if metric.get('timestamp') else None)
        
        return jsonify({
            'response_times': response_times,
            'timestamps': timestamps
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/model-metrics')
def get_model_metrics():
    """Return model-related configuration/metrics for UI (non-sensitive)."""
    try:
        # Defaults
        result = {
            'model_layers': 4,
            'phishing_threshold': None,
            'pilot_recall': None,
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        # Try to read threshold config if available
        tc_path = Path('models/threshold_config.json')
        if tc_path.exists():
            with open(tc_path, 'r') as f:
                cfg = json.load(f)
                result['phishing_threshold'] = cfg.get('phishing_threshold')
        # Try to read recent evaluation snapshot if present
        # e.g., metrics_tri_band_pass1.json produced by evaluation script
        for cand in ['metrics_tri_band_pass1.json', 'metrics.json', 'reports/metrics_latest.json']:
            p = Path(cand)
            if p.exists():
                try:
                    with open(p, 'r') as f:
                        m = json.load(f)
                        # Expect phishing class metrics
                        ph = m.get('per_class', {}).get('Phishing') or m.get('phishing')
                        if ph and isinstance(ph, dict):
                            # recall expected 0..1
                            rec = ph.get('recall')
                            if rec is not None:
                                result['pilot_recall'] = rec if rec <= 1 else rec / 100.0
                        break
                except Exception:
                    pass
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/risk-trends')
def get_risk_trends():
    """Return 7-day risk score trends (average per day + counts)."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
        today = datetime.utcnow().date()
        start = today - timedelta(days=6)
        pipeline = [
            {'$match': {'detected_at': {'$gte': datetime.combine(start, datetime.min.time())}}},
            {'$project': {
                'risk_score': 1,
                'classification': 1,
                'day': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$detected_at'}}
            }},
            {'$group': {
                '_id': '$day',
                'avg_risk': {'$avg': '$risk_score'},
                'count': {'$sum': 1},
                'phishing': {'$sum': {'$cond': [{'$eq': ['$classification', 'Phishing']}, 1, 0]}},
                'suspected': {'$sum': {'$cond': [{'$eq': ['$classification', 'Suspected']}, 1, 0]}},
                'legitimate': {'$sum': {'$cond': [{'$eq': ['$classification', 'Legitimate']}, 1, 0]}}
            }},
            {'$sort': {'_id': 1}}
        ]
        data = list(mongo_db.db.detected_domains.aggregate(pipeline))
        day_map = {d['_id']: d for d in data}
        result = []
        for i in range(7):
            day = (start + timedelta(days=i)).strftime('%Y-%m-%d')
            if day in day_map:
                d = day_map[day]
                result.append({
                    'date': day,
                    'avg_risk': round(d.get('avg_risk', 0), 2),
                    'count': d.get('count', 0),
                    'phishing': d.get('phishing', 0),
                    'suspected': d.get('suspected', 0),
                    'legitimate': d.get('legitimate', 0)
                })
            else:
                result.append({'date': day, 'avg_risk': 0, 'count': 0, 'phishing': 0, 'suspected': 0, 'legitimate': 0})
        return jsonify({'days': result, 'generated_at': datetime.utcnow().isoformat() + 'Z'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/detect', methods=['POST'])
def detect_phishing():
    """Perform live phishing detection."""
    try:
        if not detector:
            return jsonify({'error': 'Detector not available - models not loaded'}), 500
            
        # Get form data instead of JSON
        suspicious_domain = request.form.get('suspicious_domain')
        cse_domain = request.form.get('cse_domain', 'sbi.co.in')  # Default CSE
        
        if not suspicious_domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Perform detection
        start_time = time.time()
        result = detector.predict_single_optimized(cse_domain, suspicious_domain, return_details=True)
        detection_time = (time.time() - start_time) * 1000  # Convert to ms

        # Optionally store result in MongoDB if detector provides DB integration
        mongodb_id = None
        try:
            if getattr(detector, 'use_mongodb', False) and getattr(detector, 'mongo', None):
                # Ensure result contains a timestamp acceptable to mongodb_manager
                if 'timestamp' not in result:
                    result['timestamp'] = datetime.utcnow().isoformat() + 'Z'
                domain_obj_id = detector.mongo.store_detection_result(result)
                mongodb_id = str(domain_obj_id)
        except Exception as e:
            # Log and continue returning detection result even if DB write fails
            print(f"❌ Failed to store detection in MongoDB: {e}")

        return jsonify({
            'domain': suspicious_domain,
            'classification': result['prediction'],
            'confidence': result['confidence'],
            'risk_score': result.get('risk_score', 0),
            'detection_time_ms': detection_time,
            'features_used': result.get('features_count', 110),
            'mongodb_stored': mongodb_id is not None,
            'mongodb_id': mongodb_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Check if MongoDB connection is working
        if mongo_db and mongo_db.db:
            # Try to ping the database
            mongo_db.db.admin.command('ping')
            db_status = "connected"
        else:
            db_status = "disconnected"
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "database": db_status,
            "version": "2.1.0"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }), 503

@app.route('/debug/templates')
def debug_templates():
    """Debug endpoint to check template availability."""
    import os
    template_folder = app.template_folder
    templates_found = []
    
    if os.path.exists(template_folder):
        templates_found = os.listdir(template_folder)
    
    return jsonify({
        "template_folder": template_folder,
        "templates_found": templates_found,
        "current_dir": os.getcwd(),
        "dashboard_dir": os.path.dirname(os.path.abspath(__file__))
    })

if __name__ == '__main__':
    print("🚀 Initializing PhishGuard AI Simple Dashboard...")
    
    # Initialize components
    initialize_components()
    
    print("✅ PhishGuard AI Dashboard ready!")
    print("🌐 Access dashboard at: http://localhost:8080")
    
    # Run the Flask app
    app.run(debug=False, host='0.0.0.0', port=8080)
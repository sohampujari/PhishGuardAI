"""
PhishGuard AI Web Dashboard
Beautiful and responsive web interface for monitoring phishing detection system.
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import sys
import os

# Add parent directory to path and get project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from mongodb_manager import PhishGuardMongoDB
from enhanced_mongodb_detector import EnhancedPhishGuardDetector
from datetime import datetime, timedelta
import json
import threading
import time
from typing import Dict, List
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(os.path.join(project_root, '.env'))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'phishguard_ai_dashboard_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
mongo_db = None
detector = None

def initialize_components():
    """Initialize MongoDB and detector components."""
    global mongo_db, detector
    try:
        mongo_db = PhishGuardMongoDB()
        detector = EnhancedPhishGuardDetector()
        print("✅ Dashboard components initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize components: {e}")

@app.route('/')
def landing():
    """Product landing/marketing page as default."""
    return render_template('landing.html')

@app.route('/')
def dashboard():
    """Main dashboard page with comprehensive analytics"""
    try:
        # Get current statistics from MongoDB
        stats = get_current_stats()
        recent_detections = get_recent_detections_data()
        performance_metrics = get_performance_metrics_data()
        
        return render_template('dashboard_comprehensive.html', 
                             stats=stats,
                             recent_detections=recent_detections,
                             performance_metrics=performance_metrics)
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        # Return template with empty data if there's an error
        return render_template('dashboard_comprehensive.html', 
                             stats={}, 
                             recent_detections=[], 
                             performance_metrics={})

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
        
        return jsonify({
            'collection_counts': stats,
            'recent_detections_24h': recent_detections,
            'classification_breakdown': classification_data,
            'risk_statistics': risk_stats[0] if risk_stats else {},
            'system_status': 'operational',
            'last_updated': datetime.now().isoformat()
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
        # Normalize to ensure all days present
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

@app.route('/api/model-metrics')
def get_model_metrics():
    """Return model configuration and pilot evaluation snapshot for landing/dashboard UI."""
    try:
        info = {
            'model_layers': 4,
            'weights': {
                'random_forest': 0.25,
                'xgboost': 0.40,
                'neural_net': 0.20,
                'rule_engine': 0.15
            },
            'phishing_threshold': None,
            'suspected_threshold_base': None,
            'pilot_precision_phishing': None,
            'pilot_recall_phishing': None,
            'pilot_f1_phishing': None,
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        tc_path = Path('models/threshold_config.json')
        if tc_path.exists():
            try:
                with open(tc_path, 'r') as f:
                    cfg = json.load(f)
                info['phishing_threshold'] = cfg.get('phishing_threshold')
                info['suspected_threshold_base'] = cfg.get('suspected_threshold_base') or cfg.get('suspected_base')
            except Exception:
                pass
        # Attempt to read evaluation metrics file
        for cand in ['metrics_tri_band_pass1.json', 'metrics.json', 'reports/metrics_latest.json']:
            p = Path(cand)
            if p.exists():
                try:
                    with open(p, 'r') as f:
                        m = json.load(f)
                    ph = m.get('per_class', {}).get('Phishing') or m.get('phishing')
                    if ph:
                        prec = ph.get('precision')
                        rec = ph.get('recall')
                        f1 = ph.get('f1') or ph.get('f1_score')
                        if prec is not None: info['pilot_precision_phishing'] = prec if prec <= 1 else prec/100.0
                        if rec is not None: info['pilot_recall_phishing'] = rec if rec <= 1 else rec/100.0
                        if f1 is not None: info['pilot_f1_phishing'] = f1 if f1 <= 1 else f1/100.0
                except Exception:
                    pass
                break
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/detect', methods=['POST'])
def detect_phishing():
    """Perform live phishing detection."""
    try:
        if not detector:
            return jsonify({'error': 'Detector not available'}), 500
            
        data = request.get_json()
        suspicious_domain = data.get('domain')
        cse_domain = data.get('cse_domain', 'sbi.co.in')  # Default CSE
        
        if not suspicious_domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Perform detection
        start_time = time.time()
        result = detector.predict_single_optimized(cse_domain, suspicious_domain, return_details=True)
        detection_time = (time.time() - start_time) * 1000  # Convert to ms
        
        # Emit real-time update to all connected clients
        socketio.emit('new_detection', {
            'domain': suspicious_domain,
            'classification': result['prediction'],
            'confidence': result['confidence'],
            'risk_score': result.get('risk_score', 0),
            'detection_time': detection_time,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'domain': suspicious_domain,
            'classification': result['prediction'],
            'confidence': result['confidence'],
            'risk_score': result.get('risk_score', 0),
            'detection_time_ms': detection_time,
            'features_used': result.get('features_count', 0),
            'mongodb_stored': result.get('mongodb_id') is not None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cse-entities')
def get_cse_entities():
    """Get all CSE entities."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
            
        entities = mongo_db.db.cse_entities.find()
        
        results = []
        for entity in entities:
            results.append({
                'id': str(entity.get('_id')),
                'name': entity.get('name'),
                'official_domain': entity.get('official_domain'),
                'sector': entity.get('sector'),
                'country': entity.get('country'),
                'is_active': entity.get('is_active', True)
            })
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/risk-trends')
def get_risk_trends():
    """Get risk score trends over time."""
    try:
        if not mongo_db:
            return jsonify({'error': 'Database not available'}), 500
            
        # Get detections from last 7 days grouped by day
        week_ago = datetime.now() - timedelta(days=7)
        
        pipeline = [
            {'$match': {'detected_at': {'$gte': week_ago}}},
            {'$group': {
                '_id': {
                    'year': {'$year': '$detected_at'},
                    'month': {'$month': '$detected_at'},
                    'day': {'$dayOfMonth': '$detected_at'}
                },
                'avg_risk': {'$avg': '$risk_score'},
                'count': {'$sum': 1},
                'max_risk': {'$max': '$risk_score'}
            }},
            {'$sort': {'_id': 1}}
        ]
        
        trends = list(mongo_db.db.detected_domains.aggregate(pipeline))
        
        dates = []
        avg_risks = []
        counts = []
        
        for trend in trends:
            date_obj = datetime(trend['_id']['year'], trend['_id']['month'], trend['_id']['day'])
            dates.append(date_obj.strftime('%Y-%m-%d'))
            avg_risks.append(round(trend['avg_risk'], 2))
            counts.append(trend['count'])
        
        return jsonify({
            'dates': dates,
            'average_risk_scores': avg_risks,
            'detection_counts': counts
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print('Client connected to real-time dashboard')
    emit('status', {'message': 'Connected to PhishGuard AI Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print('Client disconnected from dashboard')

def background_monitoring():
    """Background task to monitor system health and send updates."""
    while True:
        try:
            if mongo_db:
                # Send periodic updates every 30 seconds
                stats = {}
                collections = ['detected_domains', 'performance_metrics']
                for col in collections:
                    stats[col] = mongo_db.db[col].count_documents({})
                
                socketio.emit('stats_update', {
                    'collection_counts': stats,
                    'timestamp': datetime.now().isoformat()
                })
            
            time.sleep(30)  # Update every 30 seconds
            
        except Exception as e:
            print(f"Background monitoring error: {e}")
            time.sleep(60)  # Wait longer on error

if __name__ == '__main__':
    print("🚀 Initializing PhishGuard AI Dashboard...")
    
    # Initialize components
    initialize_components()
    
    # Start background monitoring thread
    monitoring_thread = threading.Thread(target=background_monitoring, daemon=True)
    monitoring_thread.start()
    
    print("✅ PhishGuard AI Dashboard ready!")
    print("🌐 Access dashboard at: http://localhost:5000")
    
    # Run the Flask-SocketIO app without eventlet
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, 
                 allow_unsafe_werkzeug=True, async_mode='threading')
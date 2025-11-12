"""
MongoDB Integration Manager for PhishGuard AI
Provides comprehensive database operations for phishing detection system.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from bson import ObjectId
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class PhishGuardMongoDB:
    """MongoDB integration for PhishGuard AI system."""
    
    def __init__(self, connection_string: str = None):
        """Initialize MongoDB connection."""
        # Use MongoDB Atlas URI from environment variables only
        self.connection_string = connection_string or os.getenv('MONGODB_URI')
        
        if not self.connection_string:
            raise ValueError("MONGODB_URI environment variable is required")
            
        self.database_name = os.getenv('DATABASE_NAME', 'phishguard_ai')
        self.client = None
        self.db = None
        self.logger = logging.getLogger(__name__)
        
        # Debug: Log which connection is being used (mask password)
        if "mongodb+srv://" in self.connection_string:
            masked_conn = self.connection_string.split('@')[1] if '@' in self.connection_string else "Atlas"
            self.logger.info(f"🔧 MongoDB URI: Atlas @ {masked_conn}")
        else:
            self.logger.info(f"🔧 MongoDB URI: {self.connection_string}")
        
        self.logger.info(f"🔧 Database: {self.database_name}")
        
        # Collection names
        self.COLLECTIONS = {
            'cse_entities': 'cse_entities',
            'detected_domains': 'detected_domains', 
            'monitoring_logs': 'monitoring_logs',
            'performance_metrics': 'performance_metrics',
            'system_config': 'system_config',
            'whitelists': 'whitelists'
        }
        
        self.connect()
        self.setup_indexes()
    
    def connect(self, database_name: str = None):
        """Connect to MongoDB database."""
        try:
            # Simple connection without SSL complications for Docker
            self.client = MongoClient(self.connection_string)
            db_name = database_name or self.database_name
            self.db = self.client[db_name]
            
            # Test connection with timeout
            self.client.admin.command('ping')
            
            # Log connection details (without password)
            if "mongodb+srv://" in self.connection_string:
                # Atlas connection
                masked_uri = self.connection_string.split('@')[1].split('?')[0] if '@' in self.connection_string else "Atlas"
                self.logger.info(f"✅ Connected to MongoDB Atlas: {db_name} @ {masked_uri}")
            else:
                # Local connection
                self.logger.info(f"✅ Connected to Local MongoDB: {db_name}")
            
        except Exception as e:
            self.logger.error(f"❌ MongoDB connection failed: {e}")
            # Don't raise exception to allow app to start without DB
            self.client = None
            self.db = None
    
    def setup_indexes(self):
        """Create optimized indexes for fast queries."""
        try:
            # CSE Entities indexes
            self.db.cse_entities.create_index("official_domain", unique=True)
            self.db.cse_entities.create_index("sector")
            
            # Detected Domains indexes
            self.db.detected_domains.create_index("domain_name", unique=True)
            self.db.detected_domains.create_index("classification")
            self.db.detected_domains.create_index("risk_score")
            self.db.detected_domains.create_index("detected_at")
            self.db.detected_domains.create_index("target_cse.official_domain")
            self.db.detected_domains.create_index([
                ("classification", ASCENDING),
                ("risk_score", DESCENDING)
            ])
            
            # Monitoring Logs indexes
            self.db.monitoring_logs.create_index("domain_id")
            self.db.monitoring_logs.create_index("checked_at")
            self.db.monitoring_logs.create_index("content_changed")
            
            # Performance Metrics indexes
            self.db.performance_metrics.create_index("timestamp")
            self.db.performance_metrics.create_index("metric_type")
            
            self.logger.info("✅ Database indexes created successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Index creation failed: {e}")
    
    # CSE Management Methods
    def add_cse(self, name: str, official_domain: str, sector: str, 
                keywords: List[str] = None) -> ObjectId:
        """Add a new CSE entity."""
        cse_doc = {
            "name": name,
            "official_domain": official_domain,
            "sector": sector,
            "keywords": keywords or [],
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        result = self.db.cse_entities.insert_one(cse_doc)
        self.logger.info(f"✅ Added CSE: {name} ({official_domain})")
        return result.inserted_id
    
    def get_cse_by_domain(self, domain: str) -> Optional[Dict]:
        """Get CSE by official domain."""
        return self.db.cse_entities.find_one({"official_domain": domain})
    
    def get_all_active_cses(self) -> List[Dict]:
        """Get all active CSE entities."""
        return list(self.db.cse_entities.find({"is_active": True}))
    
    # Detection Results Methods
    def store_detection_result(self, detection_result: Dict) -> ObjectId:
        """Store phishing detection result."""
        
        # Get CSE information
        cse_info = self.get_cse_by_domain(detection_result.get('cse_domain'))
        
        domain_doc = {
            "domain_name": detection_result['suspicious_domain'],
            "target_cse": {
                "id": cse_info['_id'] if cse_info else None,
                "name": cse_info['name'] if cse_info else "Unknown",
                "official_domain": detection_result['cse_domain']
            },
            "classification": detection_result['prediction'],
            "confidence_score": detection_result['confidence'],
            "risk_score": detection_result['risk_score'],
            "detection_result": {
                k: v for k, v in detection_result.items() 
                if k not in ['suspicious_domain', 'cse_domain']
            },
            "detection_source": detection_result.get('source', 'api'),
            "detected_at": datetime.fromisoformat(detection_result['timestamp'].replace('Z', '+00:00')),
            "updated_at": datetime.utcnow(),
            "is_active": True,
            "false_positive": False,
            "monitoring": {
                "is_monitored": detection_result['prediction'] == 'Suspected',
                "monitor_until": datetime.utcnow() + timedelta(days=90),
                "last_checked": None,
                "check_count": 0
            }
        }
        
        # Upsert (update if exists, insert if new)
        result = self.db.detected_domains.update_one(
            {"domain_name": detection_result['suspicious_domain']},
            {"$set": domain_doc},
            upsert=True
        )
        
        domain_id = result.upserted_id or self.db.detected_domains.find_one(
            {"domain_name": detection_result['suspicious_domain']}
        )['_id']
        
        self.logger.info(f"✅ Stored detection: {detection_result['suspicious_domain']} -> {detection_result['prediction']}")
        return domain_id
    
    def get_recent_detections(self, hours: int = 24, classification: str = None) -> List[Dict]:
        """Get recent detections within specified hours."""
        
        since = datetime.utcnow() - timedelta(hours=hours)
        query = {"detected_at": {"$gte": since}}
        
        if classification:
            query["classification"] = classification
            
        return list(self.db.detected_domains.find(query).sort("detected_at", -1))
    
    def get_high_risk_domains(self, min_risk_score: float = 70.0) -> List[Dict]:
        """Get high-risk domains above threshold."""
        
        query = {
            "risk_score": {"$gte": min_risk_score},
            "is_active": True
        }
        
        return list(self.db.detected_domains.find(query).sort("risk_score", -1))
    
    def search_domains_by_cse(self, cse_domain: str) -> List[Dict]:
        """Get all detected domains targeting specific CSE."""
        
        return list(self.db.detected_domains.find({
            "target_cse.official_domain": cse_domain
        }).sort("detected_at", -1))
    
    # Monitoring Methods
    def add_monitoring_log(self, domain_id: ObjectId, check_result: Dict) -> ObjectId:
        """Add monitoring check log."""
        
        log_doc = {
            "domain_id": domain_id,
            "domain_name": check_result.get('domain_name'),
            "checked_at": datetime.utcnow(),
            "status": check_result.get('status', 'unknown'),
            "content_changed": check_result.get('content_changed', False),
            "change_description": check_result.get('change_description'),
            "screenshot_path": check_result.get('screenshot_path'),
            "similarity_score": check_result.get('similarity_score'),
            "response_time_ms": check_result.get('response_time_ms'),
            "http_status": check_result.get('http_status'),
            "content_hash": check_result.get('content_hash')
        }
        
        result = self.db.monitoring_logs.insert_one(log_doc)
        
        # Update domain's last_checked timestamp
        self.db.detected_domains.update_one(
            {"_id": domain_id},
            {
                "$set": {"monitoring.last_checked": datetime.utcnow()},
                "$inc": {"monitoring.check_count": 1}
            }
        )
        
        return result.inserted_id
    
    def get_domains_for_monitoring(self) -> List[Dict]:
        """Get domains that need monitoring."""
        
        return list(self.db.detected_domains.find({
            "monitoring.is_monitored": True,
            "monitoring.monitor_until": {"$gte": datetime.utcnow()},
            "is_active": True
        }))
    
    # Analytics & Reporting Methods
    def get_detection_statistics(self, days: int = 30) -> Dict:
        """Get detection statistics for specified period."""
        
        since = datetime.utcnow() - timedelta(days=days)
        
        pipeline = [
            {"$match": {"detected_at": {"$gte": since}}},
            {"$group": {
                "_id": "$classification",
                "count": {"$sum": 1},
                "avg_risk_score": {"$avg": "$risk_score"},
                "avg_confidence": {"$avg": "$confidence_score"}
            }}
        ]
        
        results = list(self.db.detected_domains.aggregate(pipeline))
        
        stats = {
            "total_detections": sum(r['count'] for r in results),
            "by_classification": {r['_id']: r for r in results},
            "period_days": days
        }
        
        return stats
    
    def get_top_targeted_cses(self, limit: int = 10) -> List[Dict]:
        """Get most targeted CSEs."""
        
        pipeline = [
            {"$match": {"is_active": True}},
            {"$group": {
                "_id": "$target_cse.official_domain",
                "cse_name": {"$first": "$target_cse.name"},
                "threat_count": {"$sum": 1},
                "avg_risk_score": {"$avg": "$risk_score"},
                "latest_detection": {"$max": "$detected_at"}
            }},
            {"$sort": {"threat_count": -1}},
            {"$limit": limit}
        ]
        
        return list(self.db.detected_domains.aggregate(pipeline))
    
    # Performance Tracking
    def log_performance_metric(self, metric_type: str, value: float, 
                              unit: str, additional_info: Dict = None):
        """Log system performance metric."""
        
        metric_doc = {
            "timestamp": datetime.utcnow(),
            "metric_type": metric_type,
            "value": value,
            "unit": unit,
            "system_info": additional_info or {}
        }
        
        self.db.performance_metrics.insert_one(metric_doc)
    
    def get_performance_trends(self, metric_type: str, hours: int = 24) -> List[Dict]:
        """Get performance trends for specific metric."""
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        return list(self.db.performance_metrics.find({
            "metric_type": metric_type,
            "timestamp": {"$gte": since}
        }).sort("timestamp", 1))
    
    # Export & Reporting
    def export_detections_for_submission(self, start_date: datetime, 
                                        end_date: datetime) -> List[Dict]:
        """Export detections in submission format."""
        
        pipeline = [
            {"$match": {
                "detected_at": {"$gte": start_date, "$lte": end_date},
                "is_active": True
            }},
            {"$project": {
                "Application_ID": "PHISHGUARD-AI",
                "Source_of_detection": "$detection_source",
                "Identified_Domain": "$domain_name",
                "Corresponding_CSE_Domain": "$target_cse.official_domain", 
                "CSE_Name": "$target_cse.name",
                "Classification": "$classification",
                "Domain_Registration_Date": "$domain_info.registration_date",
                "Registrar_Name": "$domain_info.registrar_name",
                "Registrant_Country": "$domain_info.registrant_country",
                "Hosting_IP": "$domain_info.hosting_ip",
                "Risk_Score": "$risk_score",
                "Confidence": "$confidence_score",
                "Detection_Date": {"$dateToString": {
                    "format": "%d-%m-%Y", 
                    "date": "$detected_at"
                }},
                "Detection_Time": {"$dateToString": {
                    "format": "%H-%M-%S",
                    "date": "$detected_at"
                }},
                "Evidence_File": "$evidence.screenshot_path"
            }}
        ]
        
        return list(self.db.detected_domains.aggregate(pipeline))
    
    def close_connection(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            self.logger.info("✅ MongoDB connection closed")


# Initialize default CSEs
def setup_default_cses(mongo: PhishGuardMongoDB):
    """Setup default CSE entities."""
    
    default_cses = [
        {
            "name": "State Bank of India",
            "official_domain": "sbi.co.in",
            "sector": "Banking",
            "keywords": ["sbi", "statebank", "yono", "onlinesbi"]
        },
        {
            "name": "ICICI Bank",
            "official_domain": "icicibank.com",
            "sector": "Banking", 
            "keywords": ["icici", "icicidirect", "icicibank"]
        },
        {
            "name": "HDFC Bank",
            "official_domain": "hdfcbank.com",
            "sector": "Banking",
            "keywords": ["hdfc", "hdfcbank", "netbanking"]
        },
        {
            "name": "Bharti Airtel",
            "official_domain": "airtel.in", 
            "sector": "Telecom",
            "keywords": ["airtel", "bhartiairtel", "myairtel"]
        },
        {
            "name": "Reliance Jio",
            "official_domain": "jio.com",
            "sector": "Telecom",
            "keywords": ["jio", "reliancejio", "myjio"]
        },
        {
            "name": "Indian Railway Catering and Tourism Corporation",
            "official_domain": "irctc.co.in",
            "sector": "Transportation", 
            "keywords": ["irctc", "indianrail", "railwayreservation"]
        }
    ]
    
    for cse_data in default_cses:
        try:
            # Check if CSE already exists
            existing = mongo.get_cse_by_domain(cse_data["official_domain"])
            if not existing:
                mongo.add_cse(**cse_data)
                print(f"✅ Added CSE: {cse_data['name']}")
            else:
                print(f"📋 CSE already exists: {cse_data['name']}")
        except Exception as e:
            print(f"❌ Failed to add CSE {cse_data['name']}: {e}")


if __name__ == "__main__":
    # Initialize MongoDB
    mongo = PhishGuardMongoDB()
    
    # Setup default CSEs
    setup_default_cses(mongo)
    
    # Test functionality
    print("\n🧪 Testing MongoDB functionality...")
    
    # Get statistics
    stats = mongo.get_detection_statistics(days=7)
    print(f"📊 Detection stats: {stats}")
    
    # Close connection
    mongo.close_connection()
# 🛡️ PhishGuard AI - Advanced Phishing Detection System

![PhishGuard AI](https://img.shields.io/badge/AI-Powered-blue) ![MongoDB](https://img.shields.io/badge/Database-MongoDB%20Atlas-green) ![Flask](https://img.shields.io/badge/Framework-Flask-red) ![Python](https://img.shields.io/badge/Language-Python-yellow)

## 🎯 Overview

PhishGuard AI is an advanced machine learning-powered phishing detection system specifically designed for **Indian Critical Sector Entities (CSEs)**. It provides real-time threat detection with comprehensive analytics through a modern web dashboard.

**🏆 Dataset Attribution**: This model has been trained from a dataset taken from **NCIIP Startup India AI GRAND CHALLENGE's Problem Statement data**, ensuring high-quality training data specifically focused on Indian cybersecurity threats.

## ✨ Key Features

### 🔍 **AI-Powered Detection**
- **Multi-Algorithm Ensemble**: Random Forest, XGBoost, Neural Networks
- **Advanced Feature Engineering**: 110+ domain characteristics
- **Real-time Analysis**: 1000+ domains per minute capability
- **CSE-Specific Intelligence**: Tailored for Indian banking, government, and telecom

### 📊 **Comprehensive Dashboard**
- **Real-time Analytics**: Live threat monitoring and statistics
- **Interactive Charts**: Classification breakdown, risk trends, geographic distribution
- **CSE Targeting Analysis**: Track which organizations are being targeted
- **Performance Metrics**: System health and response times

### 🗄️ **MongoDB Atlas Integration**
- **Cloud Database**: Scalable MongoDB Atlas deployment
- **Real-time Data**: Live threat intelligence and historical analysis
- **Secure Storage**: Encrypted connections and data protection

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │  Detection API  │    │  MongoDB Atlas  │
│     (Flask)     │◄──►│   (ML Models)   │◄──►│   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         │                        │                        │
    ┌──────────┐            ┌──────────┐            ┌──────────┐
    │   HTML   │            │ AI Models│            │   CSE    │
    │ Charts.js│            │ Ensemble │            │ Entities │
    │   CSS    │            │ Detector │            │Whitelist │
    └──────────┘            └──────────┘            └──────────┘
```

## 🚀 Quick Start

### Prerequisites
```bash
- Python 3.8+
- MongoDB Atlas account
- Virtual environment (recommended)
```

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd "PhishGuard AI"
```

2. **Set up virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your MongoDB Atlas URI
```

5. **Run the dashboard**
```bash
cd dashboard
python simple_app.py
```

6. **Access the dashboard**
```
http://localhost:8080
```

## 🔧 Configuration

### Environment Variables (.env)
```bash
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/
DATABASE_NAME=phishguard_ai
FLASK_ENV=development
```

### CSE Entities
The system includes pre-configured CSE entities:
- State Bank of India
- ICICI Bank, HDFC Bank
- Airtel, BSNL
- National Informatics Centre
- Indian Railways (IRCTC)
- And more...

## 📈 Dashboard Features

### 🎯 **Performance Analytics**
- Detection accuracy metrics
- Response time monitoring  
- System uptime tracking
- Precision and recall rates

### 🏢 **CSE Targeting Analysis**
- Real-time targeted organization tracking
- Threat volume per CSE
- Risk score analysis
- Historical targeting patterns

### 🗺️ **Geographic Intelligence**
- Threat origin mapping
- Geographic distribution analysis
- Regional threat patterns
- Country-wise threat statistics

### 📊 **Classification Breakdown**
- Phishing vs Suspected vs Legitimate
- Risk severity heatmaps
- Attack vector analysis
- Time-based trend analysis

## 🔬 ML Model Details

### **Ensemble Architecture**
```python
Models:
├── Random Forest (25% weight)
├── XGBoost (40% weight)  
├── Neural Network (20% weight)
└── Rule Engine (15% weight)
```

### **Feature Engineering** (110+ features)
- Domain characteristics (length, subdomains, TLD)
- URL patterns (suspicious keywords, encoding)
- Certificate analysis (SSL/TLS validation)
- DNS intelligence (resolution patterns)
- Content analysis (title, body inspection)

### **Performance Metrics**
- **Accuracy**: 94.7%+
- **Precision**: 96.2%+
- **Recall**: 93.8%+
- **F1-Score**: 95.0%+
- **Response Time**: <127ms average

## 🗃️ Database Schema

### Collections
```javascript
// CSE Entities
{
  "_id": ObjectId,
  "name": "State Bank of India",
  "abbreviation": "SBI",
  "official_domain": "sbi.co.in",
  "category": "Banking",
  "is_active": true
}

// Detected Domains
{
  "_id": ObjectId,
  "domain_name": "sbi-fake-demo.com",
  "classification": "Suspected",
  "confidence_score": 0.7045,
  "risk_score": 86.62,
  "target_cse": {
    "name": "State Bank of India",
    "official_domain": "sbi.co.in"
  },
  "detected_at": ISODate,
  "is_active": true
}
```

## 🛠️ API Endpoints

### Detection API
```http
POST /api/detect
Content-Type: application/json

{
  "domain": "suspicious-bank.com",
  "cse_domain": "sbi.co.in"
}
```

### Statistics API
```http
GET /api/stats
Response: {
  "total_detections": 44,
  "high_risk_count": 23,
  "top_targeted_cses": [...],
  "classification_breakdown": [...]
}
```

## 📁 Project Structure

```
PhishGuard AI/
├── dashboard/                 # Web dashboard
│   ├── templates/            # HTML templates
│   ├── static/              # CSS, JS, assets
│   └── simple_app.py        # Flask application
├── models/                   # ML model files
├── whitelists/              # CSE whitelist data
├── mongodb_manager.py       # Database operations
├── enhanced_mongodb_detector.py  # ML detection engine
├── optimized_detector.py    # Performance-optimized detector
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
└── README.md               # This file
```

## 🔒 Security Features

- **Input Validation**: Comprehensive URL and domain validation
- **Rate Limiting**: API request throttling
- **Encrypted Connections**: MongoDB Atlas TLS/SSL
- **Environment Variables**: Sensitive data protection
- **CSE Whitelisting**: Legitimate domain protection

## 📊 Monitoring & Analytics

### Real-time Metrics
- Detection volume and patterns
- System performance indicators
- Database connection health
- API response times

### Historical Analysis
- Threat trend analysis
- CSE targeting patterns
- Geographic threat distribution
- Attack vector evolution

## 🚧 Deployment

### Development
```bash
cd dashboard
python simple_app.py
```

### Production (Coming Soon)
- Docker containerization
- AWS EC2 deployment
- Load balancing
- Auto-scaling

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting guide

## 🙏 Acknowledgments

- Indian Critical Sector Entities for threat intelligence
- MongoDB Atlas for cloud database services
- TensorFlow and scikit-learn communities
- Chart.js for visualization components

---

**🛡️ Built with ❤️ for Indian Cybersecurity**
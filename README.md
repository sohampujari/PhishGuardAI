# 🛡️ PhishGuard AI - Advanced Phishing Detection System

![PhishGuard AI](https://img.shields.io/badge/AI-Powered-blue) ![MongoDB](https://img.shields.io/badge/Database-MongoDB%20Atlas-green) ![Flask](https://img.shields.io/badge/Framework-Flask-red) ![Python](https://img.shields.io/badge/Language-Python-yellow) ![License](https://img.shields.io/badge/License-MIT-orange)

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
- **Attack Vector Insights**: Identify common phishing techniques

### 🛡️ **Production-Ready Architecture**
- **MongoDB Atlas Integration**: Cloud-based data storage and analytics
- **Flask Web Application**: Modern, responsive web interface
- **API Endpoints**: RESTful APIs for integration with other systems
- **Automated Testing**: Comprehensive test suite with mock data

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MongoDB Atlas account (or local MongoDB)
- Git

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Atharv5873/PhishGuard-AI.git
cd PhishGuard-AI
```

2. **Set up Python environment**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements_deploy.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your MongoDB Atlas credentials
```

4. **Run the dashboard**
```bash
cd dashboard
python simple_app.py
```

5. **Access the application**
- Dashboard: http://localhost:8080
- API Documentation: http://localhost:8080/api/stats

## 🧪 Testing with Mock Data

### Run Automated Tests
```bash
cd test_data
python test_with_mock_data.py
```

### Test Individual URLs
```python
from enhanced_mongodb_detector import EnhancedPhishingDetector

detector = EnhancedPhishingDetector()
result = detector.predict_url("http://example-phishing-site.com")
print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']:.3f}")
```

## 📊 Dashboard Features

### Real-Time Analytics
- **Threat Statistics**: Total threats detected, success rate, response times
- **CSE Targeting**: Which Indian organizations are being targeted most
- **Geographic Distribution**: Threat origins and target locations
- **Attack Vectors**: Common phishing techniques and patterns

### Interactive Visualizations
- **Classification Breakdown**: Pie chart of threat categories
- **Risk Trends**: Timeline of threat detection over time
- **Severity Heatmap**: Color-coded threat intensity mapping
- **Response Performance**: System performance metrics

## 🏢 Supported CSEs (Critical Sector Entities)

### Banking & Financial
- State Bank of India (SBI)
- ICICI Bank
- HDFC Bank
- Bank of Baroda
- Axis Bank

### Telecommunications
- Bharti Airtel
- Reliance Jio
- Vodafone Idea

### Government & Public Sector
- And many more...

## 📁 Project Structure

```
PhishGuard-AI/
├── 📱 dashboard/
│   ├── app.py                    # Alternative Flask app
│   ├── simple_app.py            # Main dashboard application
│   ├── templates/               # HTML templates
│   │   └── dashboard_comprehensive.html
│   └── static/                  # CSS, JS, assets
├── 🤖 models/
│   ├── neural_network.h5        # Trained neural network
│   └── threshold_config.json    # Model configuration
├── 🧪 test_data/
│   ├── mock_phishing_urls.json  # Test cases
│   ├── test_with_mock_data.py   # Test automation
│   └── README.md                # Test documentation
├── 🗃️ whitelists/
│   └── legitimate_whitelist.json # Verified legitimate domains
├── ⚙️ Configuration Files
│   ├── .env.example             # Environment template
│   ├── .gitignore              # Git ignore rules
│   ├── requirements_deploy.txt  # Python dependencies
│   └── cse_whitelist.json      # CSE organization data
├── 🔧 Core Application
│   ├── mongodb_manager.py       # Database operations
│   ├── enhanced_mongodb_detector.py # ML detection engine
│   └── README_DEPLOY.md         # Deployment guide
└── 📄 README.md                 # This file
```

## 🛠️ API Endpoints

### Statistics API
```
GET /api/stats
```
Returns comprehensive threat statistics including:
- Total threats detected
- Success rate and performance metrics
- Top targeted CSEs
- Recent threat summary

### Health Check
```
GET /health
```
Returns system health status and database connectivity.

## 🚀 Deployment

### Docker Deployment (Recommended)
```bash
# Build Docker image
docker build -t phishguard-ai .

# Run with environment variables
docker run -p 8080:8080 --env-file .env phishguard-ai
```

### Cloud Deployment
1. **AWS EC2**: Deploy using Docker or direct installation
2. **Google Cloud**: Use Cloud Run or Compute Engine
3. **Azure**: Deploy via Container Instances or App Service

See `README_DEPLOY.md` for detailed deployment instructions.

## 📈 Performance Metrics

- **Detection Accuracy**: >95% on test dataset
- **Processing Speed**: 1000+ domains per minute
- **Response Time**: <100ms average API response
- **Uptime**: 99.9% availability target

## 🧠 Machine Learning Models

### Ensemble Architecture
- **Random Forest**: 25% weight - Feature importance analysis
- **XGBoost**: 40% weight - Gradient boosting optimization  
- **Neural Network**: 20% weight - Deep learning patterns
- **Rule-based Engine**: 15% weight - Domain-specific rules

### Feature Engineering (110+ features)
- Domain characteristics (length, entropy, special characters)
- URL structure analysis (subdomains, path complexity)
- Lexical analysis (suspicious keywords, patterns)
- Network metadata (whois, DNS records)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NCIIP Startup India AI GRAND CHALLENGE** for providing the training dataset
- Indian Critical Sector Entities for cybersecurity collaboration
- Open-source community for tools and frameworks

## 📞 Support

For support, email atharv5873@gmail.com or create an issue on GitHub.

---

**⭐ If you find PhishGuard AI helpful, please give it a star on GitHub!**
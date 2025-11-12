# 🚀 AWS EC2 Deployment Guide - PhishGuard AI

Complete step-by-step guide to deploy PhishGuard AI on AWS EC2 using Docker.

## 📋 **Prerequisites**
- AWS Account with free tier access
- Domain names for CSEs (optional)
- MongoDB Atlas account and cluster

---

## 🎯 **Step 1: Launch EC2 Instance**

### **1.1 EC2 Configuration**
```
Instance Details:
├── AMI: Ubuntu Server 22.04 LTS (Free Tier)
├── Instance Type: t2.micro (1 vCPU, 1 GB RAM)
├── Storage: 30 GB gp2 SSD (Free Tier Maximum)
├── Key Pair: Create new → "phishguard-ec2-key.pem"
└── Security Group: Create new → "phishguard-security-group"
```

### **1.2 Security Group Rules**
```bash
Inbound Rules:
┌──────────────┬────────┬─────────────┬─────────────────────┐
│ Type         │ Port   │ Source      │ Description         │
├──────────────┼────────┼─────────────┼─────────────────────┤
│ SSH          │ 22     │ Your IP     │ SSH access          │
│ HTTP         │ 80     │ 0.0.0.0/0   │ Web traffic         │
│ HTTPS        │ 443    │ 0.0.0.0/0   │ Secure web traffic  │
│ Custom TCP   │ 8080   │ 0.0.0.0/0   │ PhishGuard Dashboard│
└──────────────┴────────┴─────────────┴─────────────────────┘

Outbound Rules: All traffic (0.0.0.0/0) - Default
```

### **1.3 Launch Instance**
1. Review and Launch
2. Download key pair: `phishguard-ec2-key.pem`
3. Set key permissions: `chmod 400 phishguard-ec2-key.pem`
4. Note your **Public IP** address

---

## 🔧 **Step 2: Connect to EC2 Instance**

### **SSH Connection**
```bash
ssh -i phishguard-ec2-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

---

## 🐳 **Step 3: Run Automated Setup**

### **Download and Execute Setup Script**
```bash
# Download the setup script
wget https://raw.githubusercontent.com/Atharv5873/PhishGuard-AI/main/ec2-setup.sh

# Make it executable
chmod +x ec2-setup.sh

# Run the setup (this takes 5-10 minutes)
./ec2-setup.sh
```

### **What the Script Does:**
- ✅ Updates system packages
- ✅ Installs Docker and Docker Compose
- ✅ Clones PhishGuard AI repository
- ✅ Sets up firewall rules
- ✅ Creates deployment scripts
- ✅ Configures systemd service for auto-start

---

## ⚙️ **Step 4: Configure Environment**

### **Edit Environment File**
```bash
cd /home/ubuntu/PhishGuard-AI
sudo nano .env
```

### **Update MongoDB Credentials**
```bash
# MongoDB Atlas Configuration
MONGODB_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@your-cluster.mongodb.net/?retryWrites=true&w=majority
DATABASE_NAME=phishguard_ai

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
```

**Replace:**
- `YOUR_USERNAME` → Your MongoDB Atlas username
- `YOUR_PASSWORD` → Your MongoDB Atlas password  
- `your-cluster.mongodb.net` → Your cluster URL

---

## 🚀 **Step 5: Deploy Application**

### **Deploy PhishGuard AI**
```bash
# Apply docker group membership
newgrp docker

# Deploy the application
./deploy.sh
```

### **Monitor Deployment**
```bash
# Check status
./monitor.sh

# View logs
docker-compose logs -f

# Check containers
docker-compose ps
```

---

## 🌐 **Step 6: Access Your Application**

### **URLs**
```bash
🌐 Dashboard: http://YOUR_EC2_PUBLIC_IP:8080
📊 Health Check: http://YOUR_EC2_PUBLIC_IP:8080/health
🔍 API Stats: http://YOUR_EC2_PUBLIC_IP:8080/api/stats
```

### **Verify Deployment**
```bash
# Test health endpoint
curl http://localhost:8080/health

# Test dashboard access
curl -I http://localhost:8080
```

---

## 🔧 **Step 7: Optional - Domain Setup**

### **If you have a domain name:**

#### **1. Point Domain to EC2**
```bash
# Create A record in your DNS:
phishguard.yourdomain.com → YOUR_EC2_PUBLIC_IP
```

#### **2. Install SSL Certificate (Let's Encrypt)**
```bash
# Install Certbot
sudo apt install certbot

# Get SSL certificate
sudo certbot certonly --standalone -d phishguard.yourdomain.com

# Update docker-compose.yml to include SSL
```

---

## 📊 **Management Commands**

### **Deployment Management**
```bash
# Update application
git pull origin main
./deploy.sh

# Stop application
docker-compose down

# Start application
docker-compose up -d

# View logs
docker-compose logs -f phishguard-ai

# Restart application
docker-compose restart
```

### **System Monitoring**
```bash
# Full system status
./monitor.sh

# Check disk space
df -h

# Check memory usage
free -h

# Check Docker status
docker system df
```

### **Troubleshooting**
```bash
# Check container status
docker-compose ps

# View application logs
docker-compose logs phishguard-ai

# Check MongoDB connectivity
docker-compose exec phishguard-ai python -c "from mongodb_manager import PhishGuardMongoDB; print('MongoDB OK')"

# Restart with fresh build
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## ⚠️ **Important Notes**

### **Security**
- ✅ Keep your EC2 key pair secure
- ✅ Regularly update security patches: `sudo apt update && sudo apt upgrade`
- ✅ Monitor access logs
- ✅ Use strong MongoDB passwords

### **Performance**
- 🔧 t2.micro has 1GB RAM - suitable for demo/testing
- 🔧 For production, consider t3.small or larger
- 🔧 Monitor CPU and memory usage

### **Costs**
- 💰 t2.micro is free tier eligible (750 hours/month)
- 💰 30GB storage is free tier maximum
- 💰 Data transfer costs may apply

### **Backup**
```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker run --rm -v phishguard-ai_logs:/backup alpine tar czf - /backup > backup_$DATE.tar.gz
aws s3 cp backup_$DATE.tar.gz s3://your-backup-bucket/
EOF
```

---

## 🎉 **Success Criteria**

### **✅ Deployment Complete When:**
- Dashboard loads at `http://YOUR_EC2_IP:8080`
- Health check returns status 200
- MongoDB connection successful
- ML models loaded correctly
- CSE data displaying properly

### **📞 Support**
- Email: atharv5873@gmail.com
- GitHub Issues: https://github.com/Atharv5873/PhishGuard-AI/issues

---

**🚀 Your PhishGuard AI is now deployed on AWS EC2 with Docker!**
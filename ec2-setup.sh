#!/bin/bash

# PhishGuard AI - AWS EC2 Setup Script
# This script installs Docker, clones the repository, and deploys the application

set -e  # Exit on any error

echo "🚀 PhishGuard AI - AWS EC2 Deployment Script"
echo "============================================"

# Update system packages
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "📦 Installing required packages..."
sudo apt install -y \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add current user to docker group
echo "👤 Adding user to docker group..."
sudo usermod -aG docker $USER

# Start and enable Docker
echo "🔄 Starting Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Clone PhishGuard AI repository
echo "📥 Cloning PhishGuard AI repository..."
cd /home/ubuntu
git clone https://github.com/Atharv5873/PhishGuard-AI.git
cd PhishGuard-AI

# Create environment file
echo "⚙️ Creating environment configuration..."
cat > .env << 'EOF'
# MongoDB Atlas Configuration
MONGODB_URI=mongodb+srv://atharv5873:your-password@your-cluster.mongodb.net/?retryWrites=true&w=majority
DATABASE_NAME=phishguard_ai

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False

# Optional: API Keys (if needed)
# API_KEY=your-api-key-here
EOF

echo "📝 IMPORTANT: Edit .env file with your MongoDB Atlas credentials!"
echo "   sudo nano /home/ubuntu/PhishGuard-AI/.env"

# Create logs directory
mkdir -p logs

# Test Docker installation (using sudo since group membership not active yet)
echo "🧪 Testing Docker installation..."
sudo docker run hello-world

# Note: Docker buildx setup will be done in deploy.sh after group membership is active

# Create systemd service for auto-start
echo "🔄 Creating systemd service..."
sudo tee /etc/systemd/system/phishguard-ai.service > /dev/null << 'EOF'
[Unit]
Description=PhishGuard AI Application
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ubuntu/PhishGuard-AI
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
sudo systemctl daemon-reload
sudo systemctl enable phishguard-ai.service

# Setup firewall (UFW)
echo "🔒 Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 8080

# Create deployment script
echo "📝 Creating deployment script..."
cat > deploy.sh << 'EOF'
#!/bin/bash
echo "🚀 Deploying PhishGuard AI..."

# Setup Docker buildx if not already done (now that docker group membership is active)
if ! docker buildx version >/dev/null 2>&1; then
    echo "🔧 Setting up Docker buildx..."
    docker buildx install
    docker buildx create --use --name phishguard-builder 2>/dev/null || echo "Builder already exists"
    docker buildx use phishguard-builder
fi

# Pull latest changes
git pull origin main

# Build and start services
docker-compose down
docker-compose build --no-cache
docker-compose up -d

echo "✅ PhishGuard AI deployed successfully!"
echo "🌐 Access dashboard at: http://$(curl -s http://checkip.amazonaws.com):8080"
echo "📊 Health check: http://$(curl -s http://checkip.amazonaws.com):8080/health"
EOF

chmod +x deploy.sh

# Create monitoring script
echo "📊 Creating monitoring script..."
cat > monitor.sh << 'EOF'
#!/bin/bash
echo "📊 PhishGuard AI System Status"
echo "============================="

echo "🐳 Docker Status:"
sudo systemctl status docker --no-pager -l

echo -e "\n📦 Container Status:"
docker-compose ps

echo -e "\n📈 Resource Usage:"
docker stats --no-stream

echo -e "\n🔍 Recent Logs (last 20 lines):"
docker-compose logs --tail=20

echo -e "\n🌐 Public IP:"
curl -s http://checkip.amazonaws.com

echo -e "\n🔗 Access URLs:"
echo "   Dashboard: http://$(curl -s http://checkip.amazonaws.com):8080"
echo "   Health Check: http://$(curl -s http://checkip.amazonaws.com):8080/health"
EOF

chmod +x monitor.sh

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "🎯 Next Steps:"
echo "1. Edit environment file: sudo nano .env"
echo "2. Add your MongoDB Atlas credentials"
echo "3. Deploy: ./deploy.sh"
echo "4. Monitor: ./monitor.sh"
echo ""
echo "🌐 Your EC2 public IP: $(curl -s http://checkip.amazonaws.com)"
echo "📊 Dashboard will be available at: http://$(curl -s http://checkip.amazonaws.com):8080"
echo ""
echo "⚠️  IMPORTANT: Make sure to:"
echo "   - Update .env with real MongoDB credentials"
echo "   - Check security group allows port 8080"
echo "   - Save your EC2 key pair securely"

# Log out and back in to apply docker group membership
echo ""
echo "🔄 Please run: newgrp docker (or logout and login again)"
echo "   Then run: ./deploy.sh"
#!/bin/bash

# PhishGuard AI - Simple EC2 Setup Script (Fixed Docker Permissions)
# This script installs Docker, clones the repository, and deploys the application

set -e  # Exit on any error

echo "🚀 PhishGuard AI - AWS EC2 Deployment Script (v2)"
echo "================================================="

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
if [ -d "PhishGuard-AI" ]; then
    echo "Repository already exists, updating..."
    cd PhishGuard-AI
    git pull origin main
else
    git clone https://github.com/Atharv5873/PhishGuard-AI.git
    cd PhishGuard-AI
fi

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
echo "   nano .env"

# Create logs directory
mkdir -p logs

# Test Docker installation (using sudo since group membership not active yet)
echo "🧪 Testing Docker installation..."
sudo docker run hello-world

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
User=ubuntu
Group=ubuntu

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

# Create simple deployment script (no buildx required)
echo "📝 Creating deployment script..."
cat > deploy.sh << 'EOF'
#!/bin/bash
echo "🚀 Deploying PhishGuard AI..."

# Ensure we have docker group permissions
if ! docker ps >/dev/null 2>&1; then
    echo "⚠️  Docker permission issue. Running with sudo..."
    DOCKER_CMD="sudo docker-compose"
else
    DOCKER_CMD="docker-compose"
fi

# Pull latest changes
echo "📥 Pulling latest code..."
git pull origin main

# Stop existing containers
echo "🛑 Stopping existing containers..."
$DOCKER_CMD down

# Build new images
echo "🔨 Building new images..."
$DOCKER_CMD build --no-cache

# Start services
echo "🚀 Starting services..."
$DOCKER_CMD up -d

echo ""
echo "✅ PhishGuard AI deployed successfully!"
echo "🌐 Access dashboard at: http://$(curl -s http://checkip.amazonaws.com):8080"
echo "📊 Health check: http://$(curl -s http://checkip.amazonaws.com):8080/health"
echo ""

# Show container status
echo "📦 Container Status:"
$DOCKER_CMD ps
EOF

chmod +x deploy.sh

# Create monitoring script
echo "📊 Creating monitoring script..."
cat > monitor.sh << 'EOF'
#!/bin/bash
echo "📊 PhishGuard AI System Status"
echo "============================="

# Check if we can run docker without sudo
if docker ps >/dev/null 2>&1; then
    DOCKER_CMD="docker-compose"
else
    DOCKER_CMD="sudo docker-compose"
fi

echo "🐳 Docker Status:"
sudo systemctl status docker --no-pager -l

echo -e "\n📦 Container Status:"
$DOCKER_CMD ps

echo -e "\n📈 Resource Usage:"
if docker ps >/dev/null 2>&1; then
    docker stats --no-stream
else
    echo "   (Run with docker permissions for detailed stats)"
fi

echo -e "\n🔍 Recent Logs (last 20 lines):"
$DOCKER_CMD logs --tail=20 phishguard-ai 2>/dev/null || echo "   Container logs not available"

echo -e "\n💾 Disk Usage:"
df -h /

echo -e "\n🧠 Memory Usage:"
free -h

echo -e "\n🌐 Public IP:"
curl -s http://checkip.amazonaws.com

echo -e "\n🔗 Access URLs:"
echo "   Dashboard: http://$(curl -s http://checkip.amazonaws.com):8080"
echo "   Health Check: http://$(curl -s http://checkip.amazonaws.com):8080/health"
EOF

chmod +x monitor.sh

# Create quick fix script for Docker permissions
echo "🔧 Creating Docker permission fix script..."
cat > fix-docker-permissions.sh << 'EOF'
#!/bin/bash
echo "🔧 Fixing Docker permissions..."

# Re-add user to docker group
sudo usermod -aG docker $USER

# Restart Docker service
sudo systemctl restart docker

# Apply group membership immediately
newgrp docker

echo "✅ Docker permissions fixed!"
echo "   You can now run: ./deploy.sh"
EOF

chmod +x fix-docker-permissions.sh

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "🎯 Next Steps:"
echo "1. Edit environment file: nano .env"
echo "2. Add your MongoDB Atlas credentials"
echo "3. Fix Docker permissions: ./fix-docker-permissions.sh"
echo "4. Deploy: ./deploy.sh"
echo "5. Monitor: ./monitor.sh"
echo ""
echo "🌐 Your EC2 public IP: $(curl -s http://checkip.amazonaws.com)"
echo "📊 Dashboard will be available at: http://$(curl -s http://checkip.amazonaws.com):8080"
echo ""
echo "⚠️  IMPORTANT: Make sure to:"
echo "   - Update .env with real MongoDB credentials"
echo "   - Check security group allows port 8080"
echo "   - Save your EC2 key pair securely"

echo ""
echo "🔄 Docker Group Fix Required:"
echo "   Run: ./fix-docker-permissions.sh"
echo "   Then: ./deploy.sh"
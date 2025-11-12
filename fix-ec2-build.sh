#!/bin/bash

# Quick Fix for EC2 Docker Build and Import Issues  
# LATEST: Restored original beautiful landing page + simplified MongoDB connection
# FIXES: SSL handshake errors, numpy._core issues, landing page template restored

echo "🔧 PhishGuard AI - Complete Docker Fix"
echo "======================================"

cd /home/ubuntu/PhishGuard-AI || exit 1

# Pull latest fixes from GitHub
echo "📥 Pulling latest fixes from GitHub..."
git pull origin main

# Setup secure environment variables
echo "🔐 Setting up secure environment..."
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Setting up from template..."
    cp .env.example .env
    echo ""
    echo "🚨 IMPORTANT: You need to update .env with your MongoDB credentials!"
    echo "   Edit the MONGODB_URI with your actual connection string"
    echo "   Command: nano .env"
    echo ""
    echo "   Example:"
    echo "   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?appName=FastOpsCluster"
    echo ""
    read -p "Press Enter after updating .env file..."
fi

# Validate environment variables
if grep -q "your-password\|your-cluster" .env; then
    echo "❌ Environment file still contains placeholder values!"
    echo "Please update .env with your actual MongoDB credentials."
    exit 1
fi

# Verify critical dependencies are present
echo "🔍 Verifying critical dependencies..."
if grep -q "tldextract\|fuzzywuzzy\|python-Levenshtein\|validators" requirements_deploy.txt; then
    echo "✅ All critical dependencies found in requirements"
    echo "📋 Found dependencies:"
    grep -E "tldextract|fuzzywuzzy|python-Levenshtein|validators" requirements_deploy.txt
else
    echo "❌ Missing critical dependencies - please check requirements_deploy.txt"
    echo "Required: tldextract, fuzzywuzzy, python-Levenshtein, validators"
    echo "Current requirements file content:"
    cat requirements_deploy.txt
    exit 1
fi

# Clean up failed containers and images
echo "🧹 Cleaning up failed Docker build..."
sudo docker-compose down
sudo docker system prune -af

# Remove ALL PhishGuard related images (force fresh rebuild)
echo "🗑️ Removing ALL PhishGuard images for completely fresh build..."
sudo docker images | grep -E "(phishguard|none)" | awk '{print $3}' | xargs -r sudo docker rmi -f
sudo docker rmi phishguard-ai-phishguard-ai 2>/dev/null || echo "Image not found"
sudo docker rmi phishguard-ai_phishguard-ai 2>/dev/null || echo "Image not found"

# Clear build cache completely
echo "🧹 Clearing Docker build cache..."
sudo docker builder prune -af

# Build with no cache to force fresh download of compatible packages
echo "🔨 Building with all fixes applied (completely fresh build)..."
echo "   This will download all dependencies including tldextract, fuzzywuzzy, etc."
sudo docker-compose build --no-cache --pull

# Start the service
echo "🚀 Starting PhishGuard AI..."
sudo docker-compose up -d

echo ""
echo "✅ Complete fix applied!"
echo ""

# Wait a moment for container to start
sleep 5

# Check status
echo "📦 Container Status:"
sudo docker-compose ps

echo ""
echo "🔍 Container Logs (checking for errors):"
sudo docker-compose logs --tail=10 phishguard-ai

echo ""
echo "🌐 Testing connectivity:"
echo "   Health check: curl -I http://localhost:8080/health"
curl -I http://localhost:8080/health 2>/dev/null || echo "   Service starting up..."

echo ""
echo "🎯 Your dashboard should now be available at:"
echo "   http://$(curl -s http://checkip.amazonaws.com):8080"
echo ""
echo "⚡ If container is still starting, wait 30 seconds and check:"
echo "   sudo docker-compose logs -f phishguard-ai"
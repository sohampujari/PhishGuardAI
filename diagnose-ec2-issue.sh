#!/bin/bash
# Quick verification script for EC2 Docker dependency issue
# Run this to confirm the problem and solution

echo "🔍 PhishGuard AI - Dependency Issue Diagnosis"
echo "=============================================="

cd /home/ubuntu/PhishGuard-AI || exit 1

echo ""
echo "📁 Current requirements_deploy.txt content:"
echo "-------------------------------------------"
if [ -f "requirements_deploy.txt" ]; then
    grep -E "tldextract|fuzzywuzzy|python-Levenshtein|validators" requirements_deploy.txt || echo "❌ Missing dependencies!"
else
    echo "❌ requirements_deploy.txt not found!"
fi

echo ""
echo "🐳 Current Docker images (looking for cached ones):"
echo "---------------------------------------------------"
sudo docker images | head -10

echo ""
echo "📦 Current container status:"
echo "----------------------------"
sudo docker-compose ps

echo ""
echo "🔧 Recommendation:"
echo "=================="
echo "The issue is cached Docker layers. Run ./fix-ec2-build.sh to:"
echo "1. Pull latest dependencies from GitHub" 
echo "2. Completely remove all Docker cache"
echo "3. Force fresh rebuild with all packages"
echo "4. Start clean container"
echo ""
echo "This will download tldextract, fuzzywuzzy, python-Levenshtein, validators"
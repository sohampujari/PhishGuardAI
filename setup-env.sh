#!/bin/bash

# PhishGuard AI - Secure Environment Setup for Production Deployment
# Run this script on your EC2 instance to set up environment variables securely

echo "🔐 PhishGuard AI - Secure Environment Setup"
echo "=========================================="

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  Creating .env file from template..."
    cp .env.example .env
    
    echo ""
    echo "🔧 Please update the .env file with your actual credentials:"
    echo "   - MONGODB_URI: Your MongoDB Atlas connection string"
    echo "   - DATABASE_NAME: Your database name"
    echo ""
    echo "📝 Edit command: nano .env"
    echo ""
    read -p "Press Enter after updating .env file..."
fi

# Validate .env file
echo "🔍 Validating environment configuration..."

if grep -q "your-password\|your-cluster" .env; then
    echo "❌ Environment file still contains placeholder values!"
    echo "Please update .env with your actual MongoDB credentials."
    exit 1
fi

if ! grep -q "MONGODB_URI=" .env; then
    echo "❌ MONGODB_URI not found in .env file!"
    exit 1
fi

echo "✅ Environment configuration validated"

# Load environment variables for current session
if [ -f .env ]; then
    export $(cat .env | grep -v ^# | xargs)
    echo "✅ Environment variables loaded"
fi

echo ""
echo "🔒 Security Notice:"
echo "   - .env file contains sensitive credentials"
echo "   - This file is in .gitignore and won't be committed"
echo "   - Keep your MongoDB credentials secure"
echo ""
echo "✅ Ready for secure deployment!"
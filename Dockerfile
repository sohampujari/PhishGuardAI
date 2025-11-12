# Use Python 3.9 slim image for smaller size
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --upgrade pip

# Copy requirements first for better caching
COPY requirements_deploy.txt requirements_flexible.txt ./

# Install Python dependencies with fallback
RUN pip install --no-cache-dir -r requirements_deploy.txt || \
    pip install --no-cache-dir -r requirements_flexible.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p models whitelists test_data

# Expose port
EXPOSE 8080

# Set environment variables for production
ENV FLASK_ENV=production
ENV FLASK_DEBUG=False

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "dashboard/simple_app.py"]
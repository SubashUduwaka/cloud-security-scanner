# Use an official Python 3.13 slim runtime as a parent image for a smaller footprint
FROM python:3.13-slim-bookworm

# Set environment variables to prevent Python from writing .pyc files and to run in unbuffered mode
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies needed by Python packages like cryptography and psycopg2-binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage Docker's layer caching
COPY requirements.txt .

# Upgrade pip and install the Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application's source code into the container
COPY . .

# Create necessary directories for logs and user data
RUN mkdir -p /root/.aegisscanner/logs && \
    mkdir -p /app/instance

# Create a non-root user for better security (optional but recommended)
RUN useradd -m -u 1000 aegis && \
    chown -R aegis:aegis /app /root/.aegisscanner
USER aegis

# Expose port 5000 to allow communication to the Gunicorn server
EXPOSE 5000

# Health check to ensure the application is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Define the command to run your application using the Gunicorn production server
# Use more workers and threads for better performance
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "wsgi:application"]
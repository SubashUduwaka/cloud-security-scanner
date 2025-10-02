# Aegis Cloud Scanner - Amazon Lightsail Deployment Guide

## 🚀 **Complete Cloud Deployment Solution**

This guide provides step-by-step instructions for deploying Aegis Cloud Scanner to Amazon Lightsail with Ubuntu, custom domain, and SSL certificates.

## 📋 **Prerequisites**

### **1. Amazon Lightsail Instance**
- **Recommended**: 2 GB RAM, 1 vCPU, 60 GB SSD
- **OS**: Ubuntu 22.04 LTS
- **Network**: Static IP address assigned

### **2. Domain Configuration**
- Registered domain name
- DNS access to configure A records
- Domain pointing to Lightsail static IP

### **3. Required Information**
- Domain name (e.g., `yourdomain.com`)
- Email address for SSL certificates
- SMTP credentials (for email features)
- Cloud provider API keys (AWS, Azure, GCP)

## 🛠️ **Deployment Methods**

### **Method 1: Automated Deployment (Recommended)**

#### **Step 1: Connect to Your Lightsail Instance**
```bash
ssh ubuntu@your-lightsail-ip
```

#### **Step 2: Download Application**
```bash
# Clone or upload your application files
cd /home/ubuntu
# Transfer your application files here
```

#### **Step 3: Run Automated Deployment**
```bash
chmod +x deployment/deploy.sh
./deployment/deploy.sh
```

The script will:
- ✅ Update Ubuntu packages
- ✅ Install Python 3.11 and dependencies
- ✅ Install and configure Nginx
- ✅ Install PostgreSQL database
- ✅ Set up SSL certificates (Let's Encrypt)
- ✅ Configure systemd services
- ✅ Start the application

### **Method 2: Manual Deployment**

#### **Step 1: System Preparation**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y software-properties-common curl wget git
```

#### **Step 2: Install Python**
```bash
# Install Python 3.11
sudo apt install -y python3.11 python3.11-dev python3.11-venv
sudo apt install -y python3-pip build-essential

# Install system dependencies
sudo apt install -y libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev
sudo apt install -y libjpeg-dev libpng-dev libfreetype6-dev
```

#### **Step 3: Install Web Server**
```bash
# Install Nginx
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

#### **Step 4: Setup Application**
```bash
# Create application directory
sudo mkdir -p /var/www/aegis-scanner
cd /var/www/aegis-scanner

# Copy application files (upload your files here)
sudo chown -R www-data:www-data /var/www/aegis-scanner

# Create Python virtual environment
sudo -u www-data python3.11 -m venv venv
sudo -u www-data bash -c "source venv/bin/activate && pip install -r requirements.txt"
```

#### **Step 5: Configure Database**
```bash
# Create database and user
sudo -u postgres psql -c "CREATE DATABASE aegis_scanner_prod;"
sudo -u postgres psql -c "CREATE USER aegis_user WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE aegis_scanner_prod TO aegis_user;"
```

#### **Step 6: Configure Environment**
```bash
# Create environment file
sudo nano /var/www/aegis-scanner/.env
```

Add the following configuration:
```bash
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://aegis_user:secure_password@localhost/aegis_scanner_prod
PREFERRED_URL_SCHEME=https

# Mail Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Cloud Provider Settings
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AZURE_CLIENT_ID=your-azure-client
AZURE_CLIENT_SECRET=your-azure-secret
AZURE_TENANT_ID=your-azure-tenant
```

#### **Step 7: Configure Nginx**
```bash
# Copy nginx configuration
sudo cp deployment/nginx/aegis-scanner /etc/nginx/sites-available/
sudo sed -i 's/yourdomain.com/your-actual-domain.com/g' /etc/nginx/sites-available/aegis-scanner
sudo ln -s /etc/nginx/sites-available/aegis-scanner /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

#### **Step 8: Setup SSL Certificate**
```bash
# Run SSL setup script
chmod +x deployment/ssl_setup.sh
./deployment/ssl_setup.sh
```

#### **Step 9: Configure Systemd Service**
```bash
# Copy service file
sudo cp deployment/systemd/aegis-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegis-scanner
sudo systemctl start aegis-scanner
```

## 🔐 **SSL Certificate Setup**

### **Automatic Setup (Included in deployment script)**
The deployment script automatically configures SSL certificates using Let's Encrypt.

### **Manual SSL Setup**
```bash
# Install Certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Get certificate
sudo systemctl stop nginx
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
sudo systemctl start nginx
```

## 🌐 **Domain Configuration**

### **DNS Settings**
Configure your domain's DNS records:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A    | @    | Your Lightsail IP | 300 |
| A    | www  | Your Lightsail IP | 300 |

### **Lightsail Networking**
1. **Static IP**: Assign a static IP to your instance
2. **Firewall**: Open ports 80 (HTTP) and 443 (HTTPS)

## 📊 **Post-Deployment Configuration**

### **1. Generate License Keys**
```bash
cd /var/www/aegis-scanner
sudo -u www-data bash -c "source venv/bin/activate && python licenses/simple_license_generator.py"
```

### **2. Configure Cloud Providers**

#### **AWS Configuration**
```bash
# Add to .env file
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1
```

#### **Azure Configuration**
```bash
# Add to .env file
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id
```

#### **Google Cloud Configuration**
```bash
# Upload service account JSON file
GOOGLE_APPLICATION_CREDENTIALS=/var/www/aegis-scanner/gcp-service-account.json
```

### **3. Test Application**
```bash
# Check service status
sudo systemctl status aegis-scanner

# View logs
sudo journalctl -u aegis-scanner -f

# Test HTTPS access
curl -I https://yourdomain.com
```

## 🔧 **Troubleshooting**

### **Common Issues**

#### **Application Won't Start**
```bash
# Check logs
sudo journalctl -u aegis-scanner -f

# Check configuration
sudo -u www-data bash -c "source /var/www/aegis-scanner/venv/bin/activate && python /var/www/aegis-scanner/wsgi.py"
```

#### **SSL Certificate Issues**
```bash
# Check certificate status
sudo certbot certificates

# Renew certificate
sudo certbot renew

# Test renewal
sudo certbot renew --dry-run
```

#### **Database Connection Issues**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test database connection
sudo -u postgres psql -c "\\l"
```

#### **Nginx Configuration Issues**
```bash
# Test configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/error.log
```

### **Performance Optimization**

#### **1. Enable Caching**
```bash
# Install Redis (optional)
sudo apt install -y redis-server
sudo systemctl enable redis-server

# Update .env
CACHE_TYPE=redis
CACHE_REDIS_URL=redis://localhost:6379/0
```

#### **2. Database Optimization**
```bash
# PostgreSQL configuration
sudo nano /etc/postgresql/14/main/postgresql.conf

# Increase shared_buffers, work_mem, etc.
```

#### **3. Monitoring**
```bash
# Install monitoring tools
sudo apt install -y htop iotop nethogs

# Monitor application
htop
sudo journalctl -u aegis-scanner -f
```

## 🛡️ **Security Hardening**

### **1. Firewall Configuration**
```bash
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

### **2. System Updates**
```bash
# Enable automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### **3. Application Security**
- Change default database passwords
- Use strong secret keys
- Regularly update dependencies
- Monitor application logs
- Implement rate limiting

## 📈 **Maintenance**

### **Daily Tasks**
```bash
# Check system resources
htop

# View application logs
sudo journalctl -u aegis-scanner --since "24 hours ago"
```

### **Weekly Tasks**
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Check SSL certificate expiry
sudo certbot certificates
```

### **Monthly Tasks**
```bash
# Update Python dependencies
sudo -u www-data bash -c "source /var/www/aegis-scanner/venv/bin/activate && pip list --outdated"

# Backup database
sudo -u postgres pg_dump aegis_scanner_prod > backup_$(date +%Y%m%d).sql
```

## 📞 **Support & Monitoring**

### **Log Locations**
- **Application**: `/var/www/aegis-scanner/logs/`
- **Nginx**: `/var/log/nginx/`
- **System**: `journalctl -u aegis-scanner`

### **Service Management**
```bash
# Restart application
sudo systemctl restart aegis-scanner

# Restart web server
sudo systemctl restart nginx

# View service status
sudo systemctl status aegis-scanner nginx postgresql
```

### **Health Checks**
- Application: `https://yourdomain.com/health`
- SSL Certificate: `https://www.ssllabs.com/ssltest/`
- DNS: `dig yourdomain.com`

---

## 🎯 **Quick Start Summary**

1. **Create Lightsail Instance** (Ubuntu 22.04)
2. **Assign Static IP** and configure DNS
3. **Upload Application Files** to server
4. **Run Deployment Script**: `./deployment/deploy.sh`
5. **Configure Domain** in script prompts
6. **Test Application**: Visit `https://yourdomain.com`
7. **Generate License Key** for testing
8. **Configure Cloud Provider** credentials

Your Aegis Cloud Scanner is now ready for production use! 🚀
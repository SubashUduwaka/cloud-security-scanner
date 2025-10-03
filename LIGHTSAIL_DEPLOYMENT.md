# 🚀 Amazon Lightsail Deployment Guide

## Deploy Aegis Cloud Security Scanner to Amazon Lightsail

### Prerequisites
- Amazon AWS Account
- Domain: `aegis-scanner.ink` (registered)
- Docker installed locally (for testing)

---

## 📋 Deployment Options

### **Option 1: Container Deployment (Recommended)**

#### Step 1: Create Lightsail Container Service

```bash
# Install AWS CLI
pip install awscli

# Configure AWS credentials
aws configure

# Create container service (Nano: $7/month, Micro: $10/month, Small: $40/month)
aws lightsail create-container-service \
  --service-name aegis-scanner \
  --power small \
  --scale 1
```

#### Step 2: Push Docker Image

```bash
# Build Docker image
docker build -t aegis-scanner:latest .

# Get Lightsail push commands
aws lightsail push-container-image \
  --service-name aegis-scanner \
  --label aegis-scanner \
  --image aegis-scanner:latest
```

#### Step 3: Deploy Container

Create `lightsail-deployment.json`:

```json
{
  "containers": {
    "aegis-app": {
      "image": ":aegis-scanner.latest",
      "environment": {
        "FLASK_ENV": "production",
        "SECRET_KEY": "your-secret-key-here",
        "DATABASE_URL": "sqlite:////root/.aegisscanner/aegis.db"
      },
      "ports": {
        "5000": "HTTP"
      }
    }
  },
  "publicEndpoint": {
    "containerName": "aegis-app",
    "containerPort": 5000,
    "healthCheck": {
      "path": "/",
      "intervalSeconds": 30
    }
  }
}
```

Deploy:
```bash
aws lightsail create-container-service-deployment \
  --service-name aegis-scanner \
  --cli-input-json file://lightsail-deployment.json
```

---

### **Option 2: Virtual Private Server (VPS)**

#### Step 1: Create Lightsail Instance

1. Go to [AWS Lightsail Console](https://lightsail.aws.amazon.com/)
2. Click **Create Instance**
3. Choose:
   - **Platform**: Linux/Unix
   - **Blueprint**: Ubuntu 22.04 LTS
   - **Plan**: $10/month (2GB RAM, 1 vCPU) - Minimum recommended
4. Name it: `aegis-scanner`
5. Click **Create Instance**

#### Step 2: Connect and Setup

```bash
# Connect via SSH (use Lightsail browser SSH or download key)
ssh ubuntu@<your-lightsail-ip>

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11+
sudo apt install python3.11 python3.11-venv python3-pip -y

# Install dependencies
sudo apt install build-essential libpq-dev libssl-dev libffi-dev -y

# Install Nginx (reverse proxy)
sudo apt install nginx -y

# Install Supervisor (process manager)
sudo apt install supervisor -y
```

#### Step 3: Deploy Application

```bash
# Create application directory
sudo mkdir -p /var/www/aegis-scanner
cd /var/www/aegis-scanner

# Clone your repository
sudo git clone https://github.com/SubashUduwaka/cloud-security-scanner.git .

# Create virtual environment
sudo python3.11 -m venv venv
sudo chown -R ubuntu:ubuntu /var/www/aegis-scanner

# Activate and install dependencies
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn

# Create .env file
sudo nano .env
```

Add to `.env`:
```env
FLASK_ENV=production
SECRET_KEY=your-super-secret-key-change-this
DATABASE_URL=sqlite:////var/www/aegis-scanner/instance/aegis.db
```

#### Step 4: Configure Gunicorn with Supervisor

Create `/etc/supervisor/conf.d/aegis.conf`:

```ini
[program:aegis]
directory=/var/www/aegis-scanner
command=/var/www/aegis-scanner/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --threads 2 --timeout 120 wsgi:application
user=ubuntu
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
stderr_logfile=/var/log/aegis/aegis.err.log
stdout_logfile=/var/log/aegis/aegis.out.log
```

Create log directory:
```bash
sudo mkdir -p /var/log/aegis
sudo chown ubuntu:ubuntu /var/log/aegis
```

Start Supervisor:
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start aegis
sudo supervisorctl status aegis
```

#### Step 5: Configure Nginx Reverse Proxy

Create `/etc/nginx/sites-available/aegis-scanner`:

```nginx
server {
    listen 80;
    server_name aegis-scanner.ink www.aegis-scanner.ink;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # File upload size limit
    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static {
        alias /var/www/aegis-scanner/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/aegis-scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🌐 Configure Domain (aegis-scanner.ink)

### Step 1: Get Lightsail Static IP

```bash
# Allocate static IP
aws lightsail allocate-static-ip --static-ip-name aegis-ip

# Attach to instance
aws lightsail attach-static-ip \
  --static-ip-name aegis-ip \
  --instance-name aegis-scanner

# Get IP address
aws lightsail get-static-ip --static-ip-name aegis-ip
```

Or via console:
1. Go to Lightsail → Networking → Create Static IP
2. Attach to `aegis-scanner` instance
3. Note the IP address (e.g., `54.123.45.67`)

### Step 2: Configure DNS Records

Go to your domain registrar (where you bought `aegis-scanner.ink`) and add:

**A Records:**
```
Type: A
Name: @
Value: 54.123.45.67 (your Lightsail IP)
TTL: 3600

Type: A
Name: www
Value: 54.123.45.67 (your Lightsail IP)
TTL: 3600
```

Wait 5-30 minutes for DNS propagation.

---

## 🔒 Enable HTTPS with Let's Encrypt

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate
sudo certbot --nginx -d aegis-scanner.ink -d www.aegis-scanner.ink

# Follow prompts (enter email, agree to terms)
# Choose: Redirect HTTP to HTTPS (option 2)

# Auto-renewal (Certbot sets this up automatically)
sudo certbot renew --dry-run
```

Your site is now accessible at:
- ✅ `https://aegis-scanner.ink`
- ✅ `https://www.aegis-scanner.ink`

---

## 📊 Configure Firewall

```bash
# Open required ports in Lightsail console
# Or via CLI:
aws lightsail open-instance-public-ports \
  --instance-name aegis-scanner \
  --port-info fromPort=80,toPort=80,protocol=TCP

aws lightsail open-instance-public-ports \
  --instance-name aegis-scanner \
  --port-info fromPort=443,toPort=443,protocol=TCP

# On server, configure UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

---

## 🔧 Application Management

### Start/Stop/Restart

```bash
# Check status
sudo supervisorctl status aegis

# Restart application
sudo supervisorctl restart aegis

# View logs
sudo tail -f /var/log/aegis/aegis.out.log
sudo tail -f /var/log/aegis/aegis.err.log

# Restart Nginx
sudo systemctl restart nginx

# Check Nginx status
sudo systemctl status nginx
```

### Update Application

```bash
cd /var/www/aegis-scanner
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade
sudo supervisorctl restart aegis
```

---

## 💰 Cost Estimate

### Container Service
- **Nano**: $7/month (512MB RAM, 0.25 vCPU) - Not recommended
- **Micro**: $10/month (1GB RAM, 0.25 vCPU) - Minimum
- **Small**: $40/month (2GB RAM, 1 vCPU) - **Recommended**

### VPS Instance
- **$5/month**: 512MB RAM, 1 vCPU - Too small
- **$10/month**: 2GB RAM, 1 vCPU - **Recommended minimum**
- **$20/month**: 4GB RAM, 2 vCPU - Better performance

### Additional Costs
- **Static IP**: FREE (included)
- **SSL Certificate**: FREE (Let's Encrypt)
- **Domain**: ~$10-15/year (already have aegis-scanner.ink)

**Recommended Total**: **$10-20/month**

---

## ✅ Post-Deployment Checklist

- [ ] Application accessible at `https://aegis-scanner.ink`
- [ ] SSL certificate installed and working
- [ ] HTTP redirects to HTTPS
- [ ] Database initialized and working
- [ ] Admin account created
- [ ] Logs rotating properly
- [ ] Supervisor auto-restart working
- [ ] Firewall configured
- [ ] Backups configured (see below)

---

## 💾 Database Backup

```bash
# Create backup script
sudo nano /usr/local/bin/backup-aegis.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/aegis"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
cp /var/www/aegis-scanner/instance/aegis.db $BACKUP_DIR/aegis_$TIMESTAMP.db

# Keep only last 7 days
find $BACKUP_DIR -name "aegis_*.db" -mtime +7 -delete

echo "Backup completed: $TIMESTAMP"
```

Make executable and schedule:
```bash
sudo chmod +x /usr/local/bin/backup-aegis.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
# Add line:
0 2 * * * /usr/local/bin/backup-aegis.sh >> /var/log/aegis/backup.log 2>&1
```

---

## 🐛 Troubleshooting

### Application Not Starting
```bash
# Check logs
sudo supervisorctl tail -f aegis stderr
sudo tail -f /var/log/aegis/aegis.err.log

# Check Python errors
cd /var/www/aegis-scanner
source venv/bin/activate
python wsgi.py
```

### 502 Bad Gateway
```bash
# Check if Gunicorn is running
sudo supervisorctl status aegis

# Check Nginx error logs
sudo tail -f /var/nginx/error.log

# Restart services
sudo supervisorctl restart aegis
sudo systemctl restart nginx
```

### Database Errors
```bash
# Check permissions
ls -la /var/www/aegis-scanner/instance/

# Fix permissions
sudo chown -R ubuntu:ubuntu /var/www/aegis-scanner
```

### SSL Certificate Issues
```bash
# Renew manually
sudo certbot renew --force-renewal

# Check certificate status
sudo certbot certificates
```

---

## 📞 Support

**Developer**: Subash Dananjaya Uduwaka
**Email**: aegis.aws.scanner@gmail.com
**Phone**: +94 77 962 6608
**GitHub**: https://github.com/SubashUduwaka/cloud-security-scanner

---

## 🔗 Quick Links

- **AWS Lightsail Console**: https://lightsail.aws.amazon.com/
- **Certbot Documentation**: https://certbot.eff.org/
- **Nginx Documentation**: https://nginx.org/en/docs/
- **Supervisor Documentation**: http://supervisord.org/

---

**Ready to Deploy!** 🚀

Choose either Container Service (easier) or VPS (more control) and follow the steps above.

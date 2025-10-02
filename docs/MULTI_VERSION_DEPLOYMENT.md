# Aegis Cloud Scanner - Multi-Version Deployment Guide

## 🚀 **Complete A-Z Deployment Guide for Amazon Lightsail**

Deploy both minimal and advanced versions of Aegis Cloud Scanner with a professional landing page for version selection.

## 🎯 **Architecture Overview**

```
yourdomain.com
├── Landing Page (Port 5000) - Version selector with beautiful UI
├── /advanced (Port 5001) - Full-featured version (your current app)
└── /minimal (Port 5002) - Lightweight version
```

### **User Flow:**
1. User visits `https://yourdomain.com`
2. Beautiful landing page shows version options
3. User selects preferred version
4. Redirected to chosen application

## 📋 **Pre-Deployment Checklist**

### **✅ What You Need:**
- [ ] Amazon Lightsail instance (Ubuntu 22.04)
- [ ] Domain name configured
- [ ] Current advanced version (✓ Ready)
- [ ] Minimal version files
- [ ] Email for SSL certificates

### **💰 Recommended Lightsail Setup:**
```bash
Instance: $20/month (4GB RAM, 2 vCPU, 80GB SSD)
Static IP: $3.50/month
Total: $23.50/month
```
*Note: Higher specs needed for dual version deployment*

## 🏗️ **Step-by-Step Deployment**

### **Phase 1: Prepare Your Files**

#### **1. Organize Your Application Structure**
```bash
# Current structure should be:
your-project/
├── landing/                 # ✓ Created (version selector)
├── advanced/               # Your current application
├── minimal/                # You need to provide this
├── deployment/             # ✓ Created (all configs)
└── shared/                 # Common assets
```

#### **2. Create Your Minimal Version**
You need to provide the minimal version files. Options:

**Option A: Simplified Current App**
```bash
# Copy current app and remove heavy features
cp -r . minimal/
# Then manually remove/simplify:
# - AI analysis features
# - Complex cloud integrations
# - Advanced reporting
# - Heavy dependencies
```

**Option B: Start Fresh**
Create a lightweight Flask app with basic features:
- Basic security scanning
- Simple UI
- Essential compliance checks
- Minimal dependencies

### **Phase 2: Amazon Lightsail Setup**

#### **1. Create Lightsail Instance**
```bash
# In AWS Lightsail Console:
1. Click "Create Instance"
2. Select "Linux/Unix"
3. Choose "Ubuntu 22.04 LTS"
4. Select $20/month plan (4GB RAM, 2 vCPU)
5. Name: "aegis-scanner-multi"
6. Create instance
```

#### **2. Configure Networking**
```bash
# Assign static IP
1. Go to "Networking" tab
2. Click "Create static IP"
3. Attach to your instance
4. Note the IP address
```

#### **3. Configure Firewall**
```bash
# In Lightsail firewall settings:
- SSH (22) - ✓ Already enabled
- HTTP (80) - Add this
- HTTPS (443) - Add this
```

### **Phase 3: DNS Configuration**

#### **Configure Your Domain**
```bash
# In your domain registrar (GoDaddy, Namecheap, etc.):
Type    Name    Value
A       @       YOUR_LIGHTSAIL_IP
A       www     YOUR_LIGHTSAIL_IP
```

### **Phase 4: Upload and Deploy**

#### **1. Upload Your Files**
```bash
# From your local machine:
scp -r . ubuntu@YOUR_IP:/home/ubuntu/aegis-scanner
```

#### **2. Connect to Instance**
```bash
ssh ubuntu@YOUR_IP
cd aegis-scanner
```

#### **3. Run Multi-Version Deployment**
```bash
# Make script executable
chmod +x deployment/deploy_multi_version.sh

# Run deployment (will prompt for domain and email)
./deployment/deploy_multi_version.sh
```

The script will automatically:
- ✅ Install all dependencies
- ✅ Configure Nginx for 3 applications
- ✅ Set up SSL certificates
- ✅ Create systemd services
- ✅ Initialize databases
- ✅ Start all services

## 🎨 **Landing Page Features**

Your users will see a beautiful landing page with:

### **Design Elements:**
- **Aegis Blue Theme** - Professional gradient background
- **Shield Logo** - 🛡️ Branded security imagery
- **Modern Cards** - Glass-morphism design for each version
- **Hover Effects** - Interactive animations
- **Responsive Design** - Works on all devices

### **Version Cards:**
```
┌─────────────────────────────────┐  ┌─────────────────────────────────┐
│ ⚡ Minimal Version              │  │ 🚀 Advanced Version            │
│ ┌─────────────────────────────┐ │  │ ┌─────────────────────────────┐ │
│ │ Simple                      │ │  │ │ Full Featured               │ │
│ └─────────────────────────────┘ │  │ └─────────────────────────────┘ │
│                                 │  │                                 │
│ ✓ Basic security scanning       │  │ ✓ AI-powered analysis          │
│ ✓ Essential checks              │  │ ✓ Multi-cloud support          │
│ ✓ Simple reporting              │  │ ✓ Advanced reporting            │
│ ✓ Fast deployment               │  │ ✓ Enterprise features           │
│                                 │  │                                 │
│ [Launch Minimal Version]        │  │ [Launch Advanced Version]       │
└─────────────────────────────────┘  └─────────────────────────────────┘
```

## 🔧 **Post-Deployment Configuration**

### **1. Verify All Services**
```bash
# Check service status
sudo systemctl status aegis-router aegis-advanced aegis-minimal

# Check logs if needed
sudo journalctl -u aegis-router -f
sudo journalctl -u aegis-advanced -f
sudo journalctl -u aegis-minimal -f
```

### **2. Test All URLs**
```bash
# Main landing page
curl -I https://yourdomain.com

# Advanced version
curl -I https://yourdomain.com/advanced

# Minimal version
curl -I https://yourdomain.com/minimal
```

### **3. Configure Cloud Credentials**
```bash
# Edit advanced version environment
sudo nano /var/www/aegis-scanner/advanced/.env

# Add your cloud provider credentials:
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AZURE_CLIENT_ID=your-client-id
# etc.
```

### **4. Generate License Keys**
```bash
# Use your GUI license generator
cd /var/www/aegis-scanner/advanced
sudo -u www-data python licenses/simple_license_generator.py
```

## 📊 **Resource Usage**

### **Expected Usage:**
```bash
# Memory allocation:
Landing Page:    ~100MB
Advanced App:    ~400MB
Minimal App:     ~150MB
System/Nginx:    ~200MB
Total:          ~850MB (within 4GB limit)

# CPU usage:
Low traffic:     10-20%
Medium traffic:  30-50%
High traffic:    60-80%
```

## 🔍 **Monitoring & Maintenance**

### **Daily Monitoring:**
```bash
# Check all services
sudo systemctl status aegis-*

# Monitor resources
htop
df -h
```

### **Log Monitoring:**
```bash
# Real-time logs for all services
sudo journalctl -u aegis-router -u aegis-advanced -u aegis-minimal -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### **Service Management:**
```bash
# Restart individual service
sudo systemctl restart aegis-advanced

# Restart all services
sudo systemctl restart aegis-*

# Update application
cd /var/www/aegis-scanner
# Upload new files
sudo systemctl restart aegis-*
```

## 🛡️ **Security Considerations**

### **Firewall Configuration:**
```bash
# Ubuntu firewall
sudo ufw status

# Should show:
# 22/tcp (SSH)
# 80/tcp (HTTP)
# 443/tcp (HTTPS)
```

### **SSL Certificate Management:**
```bash
# Check certificate status
sudo certbot certificates

# Test renewal
sudo certbot renew --dry-run

# Manual renewal if needed
sudo certbot renew
```

## 🚨 **Troubleshooting**

### **Common Issues:**

#### **Services Won't Start**
```bash
# Check service logs
sudo journalctl -u aegis-router -n 50

# Check port conflicts
sudo netstat -tlnp | grep :500

# Restart in order
sudo systemctl restart aegis-router
sudo systemctl restart aegis-advanced
sudo systemctl restart aegis-minimal
```

#### **Nginx Configuration Issues**
```bash
# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx

# Check nginx logs
sudo tail -f /var/log/nginx/error.log
```

#### **SSL Certificate Problems**
```bash
# Stop nginx temporarily
sudo systemctl stop nginx

# Renew certificate
sudo certbot renew

# Start nginx
sudo systemctl start nginx
```

## 💡 **Optimization Tips**

### **Performance Optimization:**
```bash
# Enable Redis for caching (optional)
sudo apt install redis-server
# Update .env files to use Redis

# Configure log rotation
sudo nano /etc/logrotate.d/aegis-scanner
```

### **Cost Optimization:**
```bash
# Monitor bandwidth usage
# Consider CloudFlare for CDN (free tier)
# Optimize images and static files
```

## ✅ **Deployment Checklist**

- [ ] Lightsail instance created ($20/month)
- [ ] Static IP assigned ($3.50/month)
- [ ] Domain DNS configured
- [ ] Application files uploaded
- [ ] Multi-version deployment script executed
- [ ] All services started successfully
- [ ] SSL certificates installed
- [ ] Landing page accessible
- [ ] Advanced version working
- [ ] Minimal version working
- [ ] Cloud credentials configured
- [ ] License keys generated
- [ ] Monitoring set up

## 🎯 **Success Criteria**

Your deployment is successful when:

1. **Landing page loads** at `https://yourdomain.com`
2. **Version selection works** - users can choose versions
3. **Advanced version accessible** at `https://yourdomain.com/advanced`
4. **Minimal version accessible** at `https://yourdomain.com/minimal`
5. **SSL certificates valid** - green lock in browser
6. **All services running** - no error messages
7. **License system working** - can generate and validate keys

## 🔄 **Maintenance Schedule**

### **Weekly:**
- Check service status
- Review logs for errors
- Monitor resource usage

### **Monthly:**
- Update system packages
- Review SSL certificate expiry
- Backup important data

### **Quarterly:**
- Update application dependencies
- Security audit
- Performance optimization review

---

## 🎉 **Ready to Deploy!**

Your multi-version Aegis Cloud Scanner deployment will provide:

- **Professional landing page** with version selection
- **Full-featured advanced version** for enterprise users
- **Lightweight minimal version** for basic needs
- **Enterprise-grade security** with SSL and proper architecture
- **Scalable infrastructure** that can handle growth

**Total monthly cost: $23.50** for a professional multi-version cloud security platform! 🚀

Ready to proceed with the deployment? The automated script handles everything for you!
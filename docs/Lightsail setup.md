# Aegis Scanner: Complete Deployment & Troubleshooting Guide

This document provides a comprehensive, step-by-step guide for deploying the Aegis Scanner Flask application on an AWS Lightsail Ubuntu 22.04 instance. It includes all necessary commands, configuration files, and a detailed log of the errors we encountered and how we fixed them.

**Project Details:**

- **Domain:** `aegis-scanner.ink`

- **Server IP:** `52.66.204.123`

- **Application Directory:** `/var/www/aegis-scanner`

## **Phase 1: AWS Lightsail & DNS Setup**

This phase covers the creation of the server and pointing your domain to it.

### **1. Create a Lightsail Instance**

1. Log in to your [AWS Lightsail Console](https://lightsail.aws.amazon.com/ls/webapp/home/instances "null").

2. Click **Create instance**.

3. Select the **Linux/Unix** platform and the **OS Only** blueprint.

4. Choose **Ubuntu 22.04 LTS**.

5. Select an appropriate instance plan (e.g., 2 GB RAM).

6. Name the instance (e.g., `aegis-scanner`).

7. After the instance is created, navigate to the **Networking** tab.

8. Click **Create static IP**, name it, and attach it to your instance. Your static IP is `52.66.204.123`.

9. Under the **Firewall** section, add two rules:
   
   - Application: **HTTP**, Port: **80**
   
   - Application: **HTTPS**, Port: **443**

### **2. Point Your Domain (Namecheap)**

1. Log in to your Namecheap account.

2. Go to the "Advanced DNS" settings for `aegis-scanner.ink`.

3. Add two **A Records**:
   
   - **Host:** `@`, **Value:** `52.66.204.123`
   
   - **Host:** `www`, **Value:** `52.66.204.123`

## **Phase 2: Server Preparation & Application Upload**

Here, we install software and move your code to the server.

### **1. Install Required Packages**

Connect to your instance via SSH and run the following commands:

```
# Update and upgrade all system packages
sudo apt update && sudo apt upgrade -y

# Install Nginx, Python tools, and unzip
sudo apt install nginx python3-pip python3.10-venv unzip -y
```

We also encountered a default Apache server running. We stopped and disabled it to free up port 80 for Nginx:

```
sudo systemctl stop apache2
sudo systemctl disable apache2
```

### **2. Create Application Directory**

We moved the application to a standard web directory to avoid permissions issues with user home directories.

```
# Create the directory
sudo mkdir -p /var/www/aegis-scanner

# Set your 'ubuntu' user as the owner
sudo chown -R ubuntu:ubuntu /var/www/aegis-scanner
```

### **3. Upload Application Files**

We used `scp` to upload your project files. The key file was located at `C:\Users\subas\Downloads\LightsailDefaultKey-ap-south-1 (1).pem`.

```
# Example command to upload the zipped project
scp -i "C:\path\to\key.pem" "C:\path\to\project.zip" ubuntu@52.66.204.123:/var/www/aegis-scanner/
```

## **Phase 3: Python Environment & Database Setup**

This section details the setup of the application's environment.

### **1. Create Virtual Environment (`venv`)**

This was a critical step. A `venv` is not portable, so we had to delete the old one and create a new one in the final directory.

```
# Navigate to the app directory
cd /var/www/aegis-scanner

# Remove any old venv
sudo rm -rf venv

# Create a new venv
python3 -m venv venv
```

### **2. Install Dependencies**

```
# Activate the new virtual environment
source venv/bin/activate

# Install all packages from requirements.txt
pip install -r requirements.txt
```

The libraries installed include Flask, Gunicorn, Boto3, and others specified in `requirements.txt`.

### **3. Create Environment File (`.env`)**

This file stores your application's secrets.

```
# Create and edit the file
nano /var/www/aegis-scanner/.env
```

The content includes your `SECRET_KEY`, `ENCRYPTION_KEY`, database URI, and mail server credentials.

### **4. Initialize the Database**

With the `venv` active, we created the database.

```
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```

## **Phase 4: Service & Web Server Configuration**

This phase makes your application run automatically and exposes it to the web.

### **1. Gunicorn `systemd` Service**

We created a service file to manage the Gunicorn process.

- **File Location:** `/etc/systemd/system/aegis-scanner.service`

- **Final Content:**
  
  ```
  [Unit]
  Description=Gunicorn instance to serve Aegis Scanner
  After=network.target
  
  [Service]
  User=ubuntu
  Group=www-data
  WorkingDirectory=/var/www/aegis-scanner
  ExecStart=/var/www/aegis-scanner/venv/bin/gunicorn --workers 3 --bind unix:/var/www/aegis-scanner/aegis-scanner.sock -m 007 --timeout 300 wsgi:app
  
  [Install]
  WantedBy=multi-user.target
  ```

### **2. WSGI Entry Point**

We created a file for Gunicorn to use as an entry point.

- **File Location:** `/var/www/aegis-scanner/wsgi.py`

- **Content:**
  
  ```
  from app import app
  
  if __name__ == "__main__":
      app.run()
  ```

### **3. Nginx Configuration**

Nginx acts as a reverse proxy, handling SSL and forwarding traffic to Gunicorn.

- **File Location:** `/etc/nginx/sites-available/aegis-scanner`

- **Final Content (after Certbot):**
  
  ```
  server {
      server_name aegis-scanner.ink www.aegis-scanner.ink;
  
      location / {
          include proxy_params;
          proxy_pass http://unix:/var/www/aegis-scanner/aegis-scanner.sock;
          proxy_read_timeout 300s;
          proxy_buffering off;
      }
  
      listen 443 ssl; # managed by Certbot
      ssl_certificate /etc/letsencrypt/live/aegis-scanner.ink/fullchain.pem; # managed by Certbot
      ssl_certificate_key /etc/letsencrypt/live/aegis-scanner.ink/privkey.pem; # managed by Certbot
      include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
      ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
  }
  
  server {
      listen 80;
      server_name aegis-scanner.ink www.aegis-scanner.ink;
      if ($host = www.aegis-scanner.ink) {
          return 301 https://$host$request_uri;
      } # managed by Certbot
      if ($host = aegis-scanner.ink) {
          return 301 https://$host$request_uri;
      } # managed by Certbot
      return 404; # managed by Certbot
  }
  ```

### **4. SSL Certificate Handling (Certbot)**

We used Certbot to automatically generate and install a free SSL certificate.

```
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Run Certbot to get and install the certificate
sudo certbot --nginx -d aegis-scanner.ink -d www.aegis-scanner.ink
```

### **5. Enabling and Starting Services**

These commands enable the services to start on boot and run them immediately.

```
# Reload systemd to recognize new/changed files
sudo systemctl daemon-reload

# Start and enable the application service
sudo systemctl start aegis-scanner
sudo systemctl enable aegis-scanner

# Enable the Nginx site and restart it
sudo ln -s /etc/nginx/sites-available/aegis-scanner /etc/nginx/sites-enabled
sudo systemctl restart nginx
```

## **Phase 5: Troubleshooting Log & Bug Fixes**

We encountered and fixed several issues. This log details each problem and its solution.

- **Error:** `502 Bad Gateway` and Nginx log showing `(13: Permission denied)` on the socket file.
  
  - **Cause:** Nginx (user `www-data`) could not access the socket file in `/home/ubuntu`.
  
  - **Solution:** Moved the entire application to `/var/www/aegis-scanner` and updated all configuration paths.

- **Error:** `TypeError: expected str... not NoneType` on application startup.
  
  - **Cause:** The code used `os.getenv('APPDATA')` to find the database path, which only exists on Windows.
  
  - **Solution:** Modified `app.py` to use a platform-independent method, checking for `APPDATA` and falling back to the user's home directory (`~/.aegis-scanner`) on Linux.

- **Error:** "Progress Mode" showed "connection lost."
  
  - **Cause:** The default Gunicorn and Nginx timeouts (30-60s) were too short for long-running streaming connections.
  
  - **Solution:** Added `--timeout 300` to the Gunicorn service command and `proxy_read_timeout 300s;` to the Nginx config.

- **Bug:** "Progress Mode" worked but showed no results.
  
  - **Cause:** A bug in `parallel_scanner.py` where the `run_parallel_scans_progress` function yielded progress messages but not the actual scan results.
  
  - **Solution:** Corrected the function to `yield result` after getting it from the future.

- **Bug:** "Internal Server Error" caused by `jinja2.exceptions.TemplateNotFound: welcome.html`.
  
  - **Cause:** The Flask app instance was created without explicit paths, causing it to fail to find the `templates` folder when run by `systemd`.
  
  - **Solution:** Modified the `app.py` `Flask()` instantiation to use `os.path.join(basedir, 'templates')` to provide an absolute path.

- **Security Vulnerability:** Bypassing 2FA by using the browser's back button.
  
  - **Cause:** The server created a valid session after password entry but before 2FA verification. The browser's cache could then show a protected page.
  
  - **Solution:** Patched `app.py` by adding a `@check_2fa` decorator to all protected routes, which checks a session variable (`2fa_passed`) that is only set after a successful 2FA code entry.

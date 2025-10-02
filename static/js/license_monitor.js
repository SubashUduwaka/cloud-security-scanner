/**
 * License Expiration Monitor
 * Automatically checks license expiration and logs out users when expired
 */

class LicenseMonitor {
    constructor() {
        this.checkInterval = 60000; // Check every 60 seconds
        this.warningThreshold = 300; // Show warning when 5 minutes remaining
        this.intervalId = null;
        this.lastWarningTime = 0;
        this.isWarningShown = false;

        this.init();
    }

    init() {
        // Start monitoring if we have license info
        this.startMonitoring();

        // Add visibility change listener to check when tab becomes active
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.checkLicenseStatus();
            }
        });

        // Check immediately on load
        this.checkLicenseStatus();
    }

    startMonitoring() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
        }

        this.intervalId = setInterval(() => {
            this.checkLicenseStatus();
        }, this.checkInterval);

        console.log('License monitor started - checking every 60 seconds');
    }

    stopMonitoring() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
        console.log('License monitor stopped');
    }

    async checkLicenseStatus() {
        try {
            const response = await fetch('/api/license-status', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    this.handleExpiredLicense();
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const licenseInfo = await response.json();

            if (!licenseInfo.is_valid || licenseInfo.is_expired) {
                this.handleExpiredLicense();
                return;
            }

            // Check if license is about to expire
            const remainingSeconds = licenseInfo.remaining_seconds || 0;

            if (remainingSeconds <= this.warningThreshold && remainingSeconds > 0) {
                this.showExpirationWarning(remainingSeconds);
            }

            // Update UI with license info
            this.updateLicenseDisplay(licenseInfo);

        } catch (error) {
            console.error('License status check failed:', error);
            // Don't logout on network errors, just log
        }
    }

    handleExpiredLicense() {
        this.stopMonitoring();

        // Show expiration message
        this.showExpirationDialog();

        // Redirect to license validation after a short delay
        setTimeout(() => {
            window.location.href = '/license?expired=true';
        }, 3000);
    }

    showExpirationWarning(remainingSeconds) {
        const now = Date.now();

        // Only show warning once every 5 minutes to avoid spam
        if (now - this.lastWarningTime < 300000 && this.isWarningShown) {
            return;
        }

        this.lastWarningTime = now;
        this.isWarningShown = true;

        const minutes = Math.ceil(remainingSeconds / 60);

        // Create warning notification
        this.showNotification(
            'License Expiring Soon',
            `Your license will expire in ${minutes} minute(s). Please renew to continue using the application.`,
            'warning',
            10000 // Show for 10 seconds
        );
    }

    showExpirationDialog() {
        // Create modal dialog for expiration
        const modal = document.createElement('div');
        modal.className = 'license-expiration-modal';
        modal.innerHTML = `
            <div class="modal-overlay">
                <div class="modal-content">
                    <div class="modal-icon">⚠️</div>
                    <h2>License Expired</h2>
                    <p>Your license has expired. You will be redirected to enter a new license key.</p>
                    <div class="modal-buttons">
                        <button onclick="window.location.href='/license'" class="btn btn-primary">
                            Enter New License
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            .license-expiration-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 10000;
                font-family: Arial, sans-serif;
            }
            .modal-overlay {
                background: rgba(0, 0, 0, 0.8);
                width: 100%;
                height: 100%;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .modal-content {
                background: #fff;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
                max-width: 400px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            }
            .modal-icon {
                font-size: 48px;
                margin-bottom: 15px;
            }
            .modal-content h2 {
                color: #e74c3c;
                margin-bottom: 15px;
            }
            .modal-content p {
                color: #666;
                margin-bottom: 20px;
                line-height: 1.5;
            }
            .modal-buttons {
                margin-top: 20px;
            }
            .btn {
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
            }
            .btn-primary {
                background: #3498db;
                color: white;
            }
            .btn-primary:hover {
                background: #2980b9;
            }
        `;

        document.head.appendChild(style);
        document.body.appendChild(modal);
    }

    showNotification(title, message, type = 'info', duration = 5000) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `license-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <div class="notification-title">${title}</div>
                <div class="notification-message">${message}</div>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
        `;

        // Add notification styles if not already added
        if (!document.querySelector('#license-notification-styles')) {
            const style = document.createElement('style');
            style.id = 'license-notification-styles';
            style.textContent = `
                .license-notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    min-width: 300px;
                    max-width: 500px;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                    z-index: 9999;
                    font-family: Arial, sans-serif;
                    animation: slideInRight 0.3s ease-out;
                }
                .license-notification.warning {
                    background: #f39c12;
                    color: white;
                    border-left: 4px solid #e67e22;
                }
                .license-notification.error {
                    background: #e74c3c;
                    color: white;
                    border-left: 4px solid #c0392b;
                }
                .license-notification.info {
                    background: #3498db;
                    color: white;
                    border-left: 4px solid #2980b9;
                }
                .notification-content {
                    position: relative;
                }
                .notification-title {
                    font-weight: bold;
                    margin-bottom: 5px;
                    font-size: 14px;
                }
                .notification-message {
                    font-size: 13px;
                    line-height: 1.4;
                    margin-right: 20px;
                }
                .notification-close {
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background: none;
                    border: none;
                    color: white;
                    font-size: 18px;
                    cursor: pointer;
                    padding: 5px;
                    line-height: 1;
                }
                .notification-close:hover {
                    opacity: 0.7;
                }
                @keyframes slideInRight {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            `;
            document.head.appendChild(style);
        }

        document.body.appendChild(notification);

        // Auto-remove after duration
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, duration);
    }

    updateLicenseDisplay(licenseInfo) {
        // Update any license info displays on the page
        const expiryElements = document.querySelectorAll('[data-license-expiry]');
        expiryElements.forEach(element => {
            const remainingDays = licenseInfo.remaining_days || 0;
            element.textContent = `${remainingDays} days remaining`;

            // Add visual indicators based on remaining time
            element.className = element.className.replace(/license-status-\w+/g, '');
            if (remainingDays <= 7) {
                element.classList.add('license-status-critical');
            } else if (remainingDays <= 30) {
                element.classList.add('license-status-warning');
            } else {
                element.classList.add('license-status-good');
            }
        });

        // Update license type displays
        const typeElements = document.querySelectorAll('[data-license-type]');
        typeElements.forEach(element => {
            element.textContent = licenseInfo.license_type || 'FULL_ACCESS';
        });
    }

    // Method to manually trigger license check (for debugging)
    forceCheck() {
        console.log('Forcing license status check...');
        this.checkLicenseStatus();
    }
}

// Initialize license monitor when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize if we're not on the license validation page
    if (!window.location.pathname.includes('/license')) {
        window.licenseMonitor = new LicenseMonitor();

        // Make it available globally for debugging
        window.checkLicense = () => window.licenseMonitor.forceCheck();

        console.log('License monitor initialized. Use window.checkLicense() to force a check.');
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LicenseMonitor;
}
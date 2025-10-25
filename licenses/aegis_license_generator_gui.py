#!/usr/bin/env python3
"""
Aegis Cloud Scanner - Themed License Generator GUI
Professional license generation tool with application branding
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Any
import threading
import webbrowser

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from licenses.license_manager import LicenseManager, LicenseType
except ImportError:
    print("Warning: License manager not found. Some features may not work.")
    LicenseManager = None
    LicenseType = None

class AegisLicenseGenerator:
    def __init__(self):
        # License periods configuration - define before creating widgets
        self.license_periods = {
            "1 Day": 1,
            "7 Days": 7,
            "30 Days": 30,
            "60 Days": 60,
            "90 Days": 90,
            "6 Months": 180,
            "1 Year": 365,
            "2 Years": 730,
            "3 Years": 1095,
            "5 Years": 1825,
            "Non-expiring": 36500,  # 100 years
            "Custom Days": 0
        }

        self.root = tk.Tk()
        self.setup_window()
        self.setup_theme()
        self.create_widgets()
        self.license_manager = LicenseManager() if LicenseManager else None

    def setup_window(self):
        """Configure main window"""
        self.root.title("Aegis Cloud Scanner - License Generator")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Set window icon (if available)
        try:
            # Try to set an icon
            icon_path = os.path.join(os.path.dirname(__file__), "..", "static", "favicon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            pass

        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")

    def setup_theme(self):
        """Configure application theme"""
        # Aegis color scheme
        self.colors = {
            'primary': '#1e3a8a',      # Deep blue
            'secondary': '#3b82f6',    # Blue
            'accent': '#10b981',       # Green
            'warning': '#f59e0b',      # Orange
            'danger': '#ef4444',       # Red
            'dark': '#1f2937',         # Dark gray
            'light': '#f8fafc',        # Light gray
            'white': '#ffffff',
            'text_primary': '#1f2937',
            'text_secondary': '#6b7280',
            'border': '#e5e7eb'
        }

        # Configure ttk styles
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Configure styles
        self.style.configure('Title.TLabel',
                           font=('Segoe UI', 16, 'bold'),
                           foreground=self.colors['primary'])

        self.style.configure('Heading.TLabel',
                           font=('Segoe UI', 12, 'bold'),
                           foreground=self.colors['text_primary'])

        self.style.configure('Custom.TEntry',
                           fieldbackground=self.colors['white'],
                           borderwidth=1,
                           relief='solid')

        self.style.configure('Primary.TButton',
                           background=self.colors['primary'],
                           foreground=self.colors['white'],
                           font=('Segoe UI', 10, 'bold'))

        self.style.configure('Secondary.TButton',
                           background=self.colors['secondary'],
                           foreground=self.colors['white'])

        self.style.configure('Success.TButton',
                           background=self.colors['accent'],
                           foreground=self.colors['white'])

        # Map button states
        self.style.map('Primary.TButton',
                      background=[('active', self.colors['secondary'])])

        self.style.map('Secondary.TButton',
                      background=[('active', self.colors['primary'])])

    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        self.create_header(main_frame)
        self.create_user_info_section(main_frame)
        self.create_license_config_section(main_frame)
        self.create_actions_section(main_frame)
        self.create_results_section(main_frame)
        self.create_footer(main_frame)

    def create_header(self, parent):
        """Create application header"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(1, weight=1)

        # Logo/Icon placeholder
        logo_frame = ttk.Frame(header_frame, relief='solid', borderwidth=1)
        logo_frame.grid(row=0, column=0, sticky=(tk.W, tk.N), padx=(0, 15))

        logo_label = ttk.Label(logo_frame, text="🛡️", font=('Segoe UI', 24))
        logo_label.pack(padx=10, pady=10)

        # Title and description
        title_frame = ttk.Frame(header_frame)
        title_frame.grid(row=0, column=1, sticky=(tk.W, tk.E))

        title_label = ttk.Label(title_frame, text="Aegis Cloud Scanner", style='Title.TLabel')
        title_label.grid(row=0, column=0, sticky=tk.W)

        subtitle_label = ttk.Label(title_frame, text="License Generator v1.0.0",
                                 font=('Segoe UI', 11), foreground=self.colors['text_secondary'])
        subtitle_label.grid(row=1, column=0, sticky=tk.W)

        description_label = ttk.Label(title_frame,
                                    text="Generate secure license keys for multi-cloud security scanning",
                                    font=('Segoe UI', 9), foreground=self.colors['text_secondary'])
        description_label.grid(row=2, column=0, sticky=tk.W, pady=(5, 0))

    def create_user_info_section(self, parent):
        """Create user information input section"""
        # User Information Section
        user_frame = ttk.LabelFrame(parent, text=" User Information ", padding="15")
        user_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        user_frame.columnconfigure(1, weight=1)

        # Name field
        ttk.Label(user_frame, text="Full Name:*", style='Heading.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(user_frame, textvariable=self.name_var,
                                   style='Custom.TEntry', font=('Segoe UI', 10))
        self.name_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 5), padx=(10, 0))

        # Email field
        ttk.Label(user_frame, text="Email Address:*", style='Heading.TLabel').grid(
            row=1, column=0, sticky=tk.W, pady=(5, 5))
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(user_frame, textvariable=self.email_var,
                                    style='Custom.TEntry', font=('Segoe UI', 10))
        self.email_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 5), padx=(10, 0))

        # Company field
        ttk.Label(user_frame, text="Company/Organization:", style='Heading.TLabel').grid(
            row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.company_var = tk.StringVar()
        self.company_entry = ttk.Entry(user_frame, textvariable=self.company_var,
                                      style='Custom.TEntry', font=('Segoe UI', 10))
        self.company_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(5, 0), padx=(10, 0))

    def create_license_config_section(self, parent):
        """Create license configuration section"""
        config_frame = ttk.LabelFrame(parent, text=" License Configuration ", padding="15")
        config_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        config_frame.columnconfigure(1, weight=1)

        # License Type
        ttk.Label(config_frame, text="License Type:", style='Heading.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5))

        type_frame = ttk.Frame(config_frame)
        type_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 5), padx=(10, 0))

        self.license_type_var = tk.StringVar(value="Enterprise (All Features)")
        type_label = ttk.Label(type_frame, text="Enterprise (All Features)",
                              font=('Segoe UI', 10, 'bold'), foreground=self.colors['accent'])
        type_label.pack(anchor=tk.W)

        type_desc = ttk.Label(type_frame, text="✓ AWS, Azure, GCP Scanning  ✓ AI Analysis  ✓ Reports  ✓ API Access",
                             font=('Segoe UI', 8), foreground=self.colors['text_secondary'])
        type_desc.pack(anchor=tk.W)

        # Validity Period
        ttk.Label(config_frame, text="Validity Period:", style='Heading.TLabel').grid(
            row=1, column=0, sticky=tk.W, pady=(10, 5))

        period_frame = ttk.Frame(config_frame)
        period_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(10, 5), padx=(10, 0))

        self.period_var = tk.StringVar(value="Non-expiring")
        self.period_combo = ttk.Combobox(period_frame, textvariable=self.period_var,
                                        values=list(self.license_periods.keys()),
                                        state='readonly', font=('Segoe UI', 10))
        self.period_combo.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.period_combo.bind('<<ComboboxSelected>>', self.on_period_change)

        # Custom days input (initially hidden)
        self.custom_frame = ttk.Frame(period_frame)
        self.custom_var = tk.StringVar(value="365")
        self.custom_entry = ttk.Entry(self.custom_frame, textvariable=self.custom_var,
                                     width=10, style='Custom.TEntry')
        self.custom_entry.pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(self.custom_frame, text="days").pack(side=tk.LEFT)

        period_frame.columnconfigure(0, weight=1)

    def create_actions_section(self, parent):
        """Create action buttons section"""
        actions_frame = ttk.Frame(parent)
        actions_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        actions_frame.columnconfigure(1, weight=1)

        # Generate button
        self.generate_btn = ttk.Button(actions_frame, text="🔑 Generate License Key",
                                      command=self.generate_license, style='Primary.TButton')
        self.generate_btn.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

        # Clear button
        self.clear_btn = ttk.Button(actions_frame, text="🗑️ Clear Form",
                                   command=self.clear_form, style='Secondary.TButton')
        self.clear_btn.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # Progress bar
        self.progress = ttk.Progressbar(actions_frame, mode='indeterminate')
        self.progress.grid(row=0, column=2, sticky=(tk.W, tk.E), padx=(10, 0))
        actions_frame.columnconfigure(2, weight=1)

    def create_results_section(self, parent):
        """Create results display section"""
        results_frame = ttk.LabelFrame(parent, text=" Generated License ", padding="15")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=12, width=70,
                                                     font=('Consolas', 10), wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Results buttons
        results_btn_frame = ttk.Frame(results_frame)
        results_btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

        self.copy_btn = ttk.Button(results_btn_frame, text="📋 Copy License Key",
                                  command=self.copy_license_key, style='Secondary.TButton')
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.save_btn = ttk.Button(results_btn_frame, text="💾 Save to File",
                                  command=self.save_to_file, style='Success.TButton')
        self.save_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.export_btn = ttk.Button(results_btn_frame, text="📤 Export JSON",
                                    command=self.export_json, style='Secondary.TButton')
        self.export_btn.pack(side=tk.LEFT)

        # Initially disable results buttons
        self.copy_btn.config(state='disabled')
        self.save_btn.config(state='disabled')
        self.export_btn.config(state='disabled')

    def create_footer(self, parent):
        """Create application footer"""
        footer_frame = ttk.Frame(parent)
        footer_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))
        footer_frame.columnconfigure(1, weight=1)

        # Status label
        self.status_var = tk.StringVar(value="Ready to generate license keys")
        self.status_label = ttk.Label(footer_frame, textvariable=self.status_var,
                                     font=('Segoe UI', 9), foreground=self.colors['text_secondary'])
        self.status_label.grid(row=0, column=0, sticky=tk.W)

        # Help button
        help_btn = ttk.Button(footer_frame, text="❓ Help", command=self.show_help)
        help_btn.grid(row=0, column=1, sticky=tk.E)

    def on_period_change(self, event=None):
        """Handle license period selection change"""
        selected = self.period_var.get()
        if selected == "Custom Days":
            self.custom_frame.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        else:
            self.custom_frame.grid_remove()

    def validate_inputs(self) -> bool:
        """Validate user inputs"""
        name = self.name_var.get().strip()
        email = self.email_var.get().strip()

        if not name:
            messagebox.showerror("Validation Error", "Full name is required")
            self.name_entry.focus()
            return False

        if not email or "@" not in email:
            messagebox.showerror("Validation Error", "Valid email address is required")
            self.email_entry.focus()
            return False

        # Validate custom days if selected
        if self.period_var.get() == "Custom Days":
            try:
                custom_days = int(self.custom_var.get())
                if custom_days <= 0:
                    raise ValueError("Days must be positive")
            except ValueError:
                messagebox.showerror("Validation Error", "Custom days must be a positive number")
                self.custom_entry.focus()
                return False

        return True

    def generate_license(self):
        """Generate license key"""
        if not self.validate_inputs():
            return

        if not self.license_manager:
            messagebox.showerror("Error", "License manager not available")
            return

        # Start progress animation
        self.progress.start(10)
        self.generate_btn.config(state='disabled')
        self.status_var.set("Generating license key...")

        # Run generation in thread to prevent UI blocking
        threading.Thread(target=self._generate_license_thread, daemon=True).start()

    def _generate_license_thread(self):
        """Generate license in background thread"""
        try:
            # Get form data
            name = self.name_var.get().strip()
            email = self.email_var.get().strip()
            company = self.company_var.get().strip()
            period = self.period_var.get()

            # Calculate duration
            if period == "Custom Days":
                duration_days = int(self.custom_var.get())
            else:
                duration_days = self.license_periods[period]

            # Create duration object
            duration = type('Duration', (), {'value': duration_days})()

            # Generate license
            license_data = self.license_manager.generate_license_key(
                LicenseType.ENTERPRISE if LicenseType else "ENTERPRISE",
                duration,
                email,
                company,
                []  # All features enabled by default
            )

            # Schedule UI update in main thread
            self.root.after(0, self._display_results, license_data, name, email, company, period, duration_days)

        except Exception as e:
            self.root.after(0, self._handle_generation_error, str(e))

    def _display_results(self, license_data, name, email, company, period, duration_days):
        """Display generation results in UI"""
        self.progress.stop()
        self.generate_btn.config(state='normal')

        # Store license data for export
        self.current_license_data = {
            'license_key': license_data['license_key'],
            'user_name': name,
            'user_email': email,
            'company': company or 'Not specified',
            'license_type': 'Enterprise (All Features)',
            'validity_period': period,
            'duration_days': duration_days,
            'issue_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'expiry_date': (datetime.now() + timedelta(days=duration_days)).strftime('%Y-%m-%d %H:%M:%S') if duration_days < 36500 else 'Non-expiring'
        }

        # Format results display
        results_text = self._format_license_display(self.current_license_data)

        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results_text)

        # Enable result buttons
        self.copy_btn.config(state='normal')
        self.save_btn.config(state='normal')
        self.export_btn.config(state='normal')

        self.status_var.set(f"License generated successfully: {license_data['license_key']}")

    def _format_license_display(self, data):
        """Format license data for display"""
        return f"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                            🛡️  AEGIS CLOUD SCANNER LICENSE  🛡️                            ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  📄 LICENSE INFORMATION                                                              ║
║  ────────────────────────────────────────────────────────────────────────────────  ║
║  License Key:    {data['license_key']:<60} ║
║  License Type:   {data['license_type']:<60} ║
║  Status:         ACTIVE                                                              ║
║                                                                                      ║
║  👤 USER INFORMATION                                                                 ║
║  ────────────────────────────────────────────────────────────────────────────────  ║
║  Name:           {data['user_name']:<60} ║
║  Email:          {data['user_email']:<60} ║
║  Company:        {data['company']:<60} ║
║                                                                                      ║
║  📅 VALIDITY INFORMATION                                                             ║
║  ────────────────────────────────────────────────────────────────────────────────  ║
║  Issue Date:     {data['issue_date']:<60} ║
║  Validity:       {data['validity_period']:<60} ║
║  Expiry Date:    {data['expiry_date']:<60} ║
║                                                                                      ║
║  ✅ INCLUDED FEATURES                                                                ║
║  ────────────────────────────────────────────────────────────────────────────────  ║
║  • AWS Security Scanning & Compliance Checks                                        ║
║  • Azure Cloud Security Assessment                                                  ║
║  • Google Cloud Platform Security Analysis                                          ║
║  • AI-Powered Vulnerability Detection                                               ║
║  • Multi-Cloud Compliance Reporting                                                 ║
║  • Automated Email Reports & Alerts                                                 ║
║  • RESTful API Access                                                               ║
║  • Multi-User Account Support                                                       ║
║  • Real-time Security Monitoring                                                    ║
║  • Custom Security Policy Configuration                                             ║
║                                                                                      ║
║  🔐 SECURITY FEATURES                                                                ║
║  ────────────────────────────────────────────────────────────────────────────────  ║
║  • AES-256 Encryption                                                               ║
║  • HMAC Digital Signatures                                                          ║
║  • Cryptographic Integrity Verification                                             ║
║  • Secure Session Management                                                        ║
║                                                                                      ║
║  Generated with Aegis License Generator v1.0.0                                      ║
║  © 2025 Aegis Cloud Scanner. All rights reserved.                                   ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

IMPORTANT NOTES:
• Keep this license key secure and confidential
• Use this key to activate your Aegis Cloud Scanner installation
• For support, contact: support@aegis-scanner.com
• Documentation: https://docs.aegis-scanner.com

Ready to use! Enter this license key in your Aegis Cloud Scanner application.
"""

    def _handle_generation_error(self, error_msg):
        """Handle license generation errors"""
        self.progress.stop()
        self.generate_btn.config(state='normal')
        self.status_var.set("License generation failed")
        messagebox.showerror("Generation Error", f"Failed to generate license: {error_msg}")

    def copy_license_key(self):
        """Copy license key to clipboard"""
        if hasattr(self, 'current_license_data'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_license_data['license_key'])
            self.status_var.set("License key copied to clipboard")
            messagebox.showinfo("Copied", "License key copied to clipboard!")

    def save_to_file(self):
        """Save license to text file"""
        if not hasattr(self, 'current_license_data'):
            return

        filename = f"aegis_license_{self.current_license_data['user_name'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialname=filename
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.results_text.get(1.0, tk.END))
                self.status_var.set(f"License saved to: {file_path}")
                messagebox.showinfo("Saved", f"License saved successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {str(e)}")

    def export_json(self):
        """Export license data as JSON"""
        if not hasattr(self, 'current_license_data'):
            return

        filename = f"aegis_license_{self.current_license_data['user_name'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialname=filename
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_license_data, f, indent=2)
                self.status_var.set(f"License data exported to: {file_path}")
                messagebox.showinfo("Exported", f"License data exported successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")

    def clear_form(self):
        """Clear all form fields"""
        self.name_var.set("")
        self.email_var.set("")
        self.company_var.set("")
        self.period_var.set("Non-expiring")
        self.custom_var.set("365")
        self.custom_frame.grid_remove()

        self.results_text.delete(1.0, tk.END)

        # Disable result buttons
        self.copy_btn.config(state='disabled')
        self.save_btn.config(state='disabled')
        self.export_btn.config(state='disabled')

        self.status_var.set("Form cleared - Ready to generate new license")

    def show_help(self):
        """Show help dialog"""
        help_text = """
🛡️ AEGIS LICENSE GENERATOR HELP

GETTING STARTED:
1. Enter the user's full name and email address (required)
2. Optionally add company/organization information
3. Select license validity period or choose custom duration
4. Click 'Generate License Key' to create a new license
5. Copy, save, or export the generated license

LICENSE FEATURES:
• All licenses include full access to all features
• Enterprise-grade security with AES-256 encryption
• Non-expiring licenses available for permanent access
• Secure cryptographic signatures for validation

USAGE TIPS:
• Keep license keys secure and confidential
• Use generated keys to activate Aegis Cloud Scanner
• Save license information for your records
• Contact support for license-related issues

KEYBOARD SHORTCUTS:
• Ctrl+G: Generate License
• Ctrl+C: Copy License Key (when available)
• Ctrl+S: Save to File (when available)
• F1: Show this help

For technical support: support@aegis-scanner.com
Documentation: https://docs.aegis-scanner.com
"""

        help_window = tk.Toplevel(self.root)
        help_window.title("Aegis License Generator - Help")
        help_window.geometry("600x500")
        help_window.transient(self.root)
        help_window.grab_set()

        help_text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, font=('Segoe UI', 10))
        help_text_widget.pack(expand=True, fill='both', padx=10, pady=10)
        help_text_widget.insert(1.0, help_text)
        help_text_widget.config(state='disabled')

        close_btn = ttk.Button(help_window, text="Close", command=help_window.destroy)
        close_btn.pack(pady=10)

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-g>', lambda e: self.generate_license())
        self.root.bind('<Control-c>', lambda e: self.copy_license_key())
        self.root.bind('<Control-s>', lambda e: self.save_to_file())
        self.root.bind('<F1>', lambda e: self.show_help())

    def run(self):
        """Start the application"""
        self.setup_keyboard_shortcuts()
        self.name_entry.focus()  # Focus on first input field
        self.root.mainloop()

def main():
    """Main application entry point"""
    try:
        app = AegisLicenseGenerator()
        app.run()
    except Exception as e:
        messagebox.showerror("Application Error", f"Failed to start application: {str(e)}")

if __name__ == "__main__":
    main()
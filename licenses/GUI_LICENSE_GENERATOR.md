# Aegis Cloud Scanner - GUI License Generator

## 🎨 **Professional Themed License Generator**

A modern, user-friendly GUI application for generating Aegis Cloud Scanner license keys with full application branding and enterprise-grade features.

## 🚀 **Features**

### **Visual Design**
- **Aegis Blue Theme** - Professional color scheme matching web application
- **Modern UI Components** - Clean, intuitive interface with proper spacing
- **Application Branding** - Shield logo, branded headers, and consistent styling
- **Responsive Layout** - Resizable window with proper grid management

### **License Generation**
- **Enterprise License Type** - All licenses include full feature access
- **Flexible Validity Periods** - From 1 day to non-expiring licenses
- **Custom Duration Support** - Set any number of days for validity
- **Secure Key Generation** - AES-256 encryption with HMAC signatures

### **User Experience**
- **Input Validation** - Real-time form validation with error messages
- **Progress Indication** - Visual feedback during license generation
- **Keyboard Shortcuts** - Quick access to common functions
- **Help System** - Built-in help documentation

### **Export Options**
- **Formatted Display** - Professional license certificate format
- **Copy to Clipboard** - One-click license key copying
- **Save to File** - Export as formatted text file
- **JSON Export** - Machine-readable license data export

## 📋 **Usage Instructions**

### **Starting the Application**

#### **Method 1: Double-click Launcher**
```bash
# Simply double-click this file:
launch_license_generator.bat
```

#### **Method 2: Python Command**
```bash
cd "path/to/aegis-scanner"
python licenses/aegis_license_generator_gui.py
```

### **Generating a License**

1. **Enter User Information**
   - Full Name (required)
   - Email Address (required)
   - Company/Organization (optional)

2. **Configure License Settings**
   - License Type: Enterprise (All Features) - *automatically selected*
   - Validity Period: Choose from dropdown or select "Custom Days"

3. **Generate License**
   - Click "🔑 Generate License Key" button
   - Wait for generation to complete (progress bar shows activity)

4. **Use Generated License**
   - Copy license key to clipboard
   - Save formatted license to file
   - Export license data as JSON

### **Available License Periods**
- **1 Day** - Short-term testing
- **7 Days** - One week trial
- **30 Days** - One month access
- **60 Days** - Two month access
- **90 Days** - Three month access
- **6 Months** - Half-year license
- **1 Year** - Annual license
- **2 Years** - Two-year license
- **3 Years** - Three-year license
- **5 Years** - Five-year license
- **Non-expiring** - Permanent access (100 years)
- **Custom Days** - Specify exact number of days

## 🎨 **Design Theme Details**

### **Color Scheme**
```css
Primary Blue:    #1e3a8a (Deep blue - headers, primary buttons)
Secondary Blue:  #3b82f6 (Medium blue - secondary elements)
Accent Green:    #10b981 (Success states, enterprise features)
Warning Orange:  #f59e0b (Warnings, notifications)
Danger Red:      #ef4444 (Errors, validation messages)
Dark Gray:       #1f2937 (Primary text)
Light Gray:      #6b7280 (Secondary text)
Border Gray:     #e5e7eb (Borders, separators)
```

### **Typography**
- **Primary Font**: Segoe UI (Windows standard)
- **Monospace**: Consolas (license key display)
- **Heading Sizes**: 16px (title), 12px (section headers), 10px (body)

### **Visual Elements**
- **Shield Icon**: 🛡️ (represents security and protection)
- **Professional Layout**: Proper spacing, alignment, and visual hierarchy
- **Status Indicators**: Color-coded messages and progress feedback
- **Modern Buttons**: Styled with hover effects and proper states

## ⌨️ **Keyboard Shortcuts**

| Shortcut | Action |
|----------|--------|
| `Ctrl + G` | Generate License Key |
| `Ctrl + C` | Copy License Key (when available) |
| `Ctrl + S` | Save to File (when available) |
| `F1` | Show Help Dialog |
| `Tab` | Navigate between form fields |
| `Enter` | Generate license (when on Generate button) |

## 📁 **File Structure**

```
licenses/
├── aegis_license_generator_gui.py     # Main GUI application
├── license_manager.py                 # Core license generation logic
├── simple_license_generator.py        # Command-line generator
└── GUI_LICENSE_GENERATOR.md          # This documentation

launch_license_generator.bat           # Windows launcher script
```

## 🔧 **Technical Implementation**

### **GUI Framework**
- **Tkinter** - Python's standard GUI library
- **ttk Styling** - Modern themed widgets
- **Threading** - Background license generation to prevent UI blocking
- **Error Handling** - Comprehensive exception handling and user feedback

### **License Integration**
- **Direct Integration** - Uses existing `license_manager.py`
- **Secure Generation** - Same cryptographic security as command-line tools
- **Format Compatibility** - Generated keys work with web application

### **Export Formats**

#### **Formatted Text Display**
```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                            🛡️  AEGIS CLOUD SCANNER LICENSE  🛡️                            ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  License Key:    AEGIS-XXXX-XXXX-XXXX-XXXX-XX                                       ║
║  License Type:   Enterprise (All Features)                                          ║
║  Status:         ACTIVE                                                              ║
║  ...                                                                                 ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

#### **JSON Export Format**
```json
{
  "license_key": "AEGIS-XXXX-XXXX-XXXX-XXXX-XX",
  "user_name": "John Doe",
  "user_email": "john@company.com",
  "company": "Company Name",
  "license_type": "Enterprise (All Features)",
  "validity_period": "Non-expiring",
  "duration_days": 36500,
  "issue_date": "2025-01-16 14:30:00",
  "expiry_date": "Non-expiring"
}
```

## 🛡️ **Security Features**

### **Input Validation**
- **Required Field Validation** - Name and email must be provided
- **Email Format Validation** - Ensures valid email address format
- **Custom Days Validation** - Positive integer validation for custom periods
- **Secure Data Handling** - No sensitive data stored in memory longer than necessary

### **License Security**
- **AES-256 Encryption** - Enterprise-grade encryption for license data
- **HMAC Signatures** - Cryptographic integrity verification
- **Secure Random Generation** - Cryptographically secure key generation
- **Format Protection** - Tamper-evident license key format

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Application Won't Start**
```bash
# Check Python installation
python --version

# Check required modules
python -c "import tkinter; print('Tkinter OK')"

# Run with error output
python licenses/aegis_license_generator_gui.py
```

#### **License Generation Fails**
- Ensure `license_manager.py` is in the `licenses/` directory
- Check that all required dependencies are installed
- Verify write permissions for export operations

#### **Display Issues**
- Ensure Windows has proper font support (Segoe UI)
- Check display scaling settings if layout appears incorrect
- Try running on different screen resolutions

### **System Requirements**
- **Windows**: 7, 8, 10, or 11
- **Python**: 3.7 or higher
- **RAM**: Minimum 512MB available
- **Display**: 1024x768 minimum resolution
- **Dependencies**: tkinter (usually included with Python)

## 📞 **Support Information**

### **For Users**
- **Quick Start**: Use `launch_license_generator.bat` for easy access
- **Help**: Press F1 in the application for built-in help
- **Documentation**: This file contains complete usage instructions

### **For Developers**
- **Code Location**: `licenses/aegis_license_generator_gui.py`
- **Customization**: Modify color scheme in `setup_theme()` method
- **Integration**: Uses existing license management infrastructure
- **Testing**: Run application and generate test licenses

### **Professional Features**
- ✅ **Enterprise Branding** - Professional appearance matching web application
- ✅ **User-Friendly Interface** - Intuitive form layout with clear instructions
- ✅ **Comprehensive Export** - Multiple export formats for different use cases
- ✅ **Error Handling** - Graceful error messages and recovery
- ✅ **Security** - Same cryptographic protection as web application
- ✅ **Documentation** - Complete help system and usage instructions

**The GUI License Generator provides a professional, branded solution for generating Aegis Cloud Scanner license keys with ease and security.** 🚀
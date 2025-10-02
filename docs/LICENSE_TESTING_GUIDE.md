# License Testing Guide

This guide shows how to properly clear license sessions and test different license keys in the Aegis Cloud Scanner.

## 🚀 **Quick Methods to Clear License & Test New Keys**

### **Method 1: Direct URL (Fastest)**
```
http://127.0.0.1:5000/clear-license
```
- Instantly clears license session
- Redirects to license validation page
- Ready to enter new key immediately

### **Method 2: Use the Fixed Clearing Tool**
```bash
python clear_license_fixed.py
```
- Automated license session clearing
- Verification of session state
- Shows available test keys

### **Method 3: Logout Button**
- Go to `http://127.0.0.1:5000`
- Click user dropdown (top right)
- Click "Log Out"
- Now properly clears license session (fixed!)

### **Method 4: Browser Methods**
- Clear cookies for `localhost:5000`
- Use Incognito/Private browsing mode
- Hard refresh (Ctrl+Shift+R)

## 🔑 **Available Test License Keys**

### **Generate New Test Keys:**

#### **1. Short Duration (2-minute) for Auto-logout Testing**
```bash
python test_license_generation.py
```
**Output Example:** `AEGIS-Z0FB-QUFB-QM95-UGPB-3B`

#### **2. Custom Duration License**
```bash
python generate_custom_license.py
```
- Interactive CLI interface
- Choose from 1 day to 5+ years
- User name and company integration

#### **3. GUI License Generator**
```bash
python enhanced_license_generator.py
```
- Graphical interface
- Dropdown time period selection
- Professional license generation

### **Recent Test Keys Available:**
- **2-min test**: `AEGIS-Z0FB-QUFB-QM95-UGPB-3B`
- **30-day test**: `AEGIS-Z0FB-QUFB-QM95-UGXI-96`
- **7-day test**: `AEGIS-Z0FB-QUFB-QM95-UGP6-97`

## 🧪 **Testing Workflow**

### **Complete License Testing Sequence:**

1. **Clear Current License**
   ```bash
   python clear_license_fixed.py
   ```

2. **Generate New Test License**
   ```bash
   python test_license_generation.py
   ```

3. **Enter License in Browser**
   - Go to `http://127.0.0.1:5000`
   - Enter the generated license key
   - Verify all features are enabled

4. **Test Auto-logout (Optional)**
   - Wait 2 minutes for short-duration license
   - Should automatically logout and redirect

5. **Repeat with Different Duration**
   ```bash
   python clear_license_fixed.py
   python generate_custom_license.py
   ```

## 🔧 **Troubleshooting**

### **If License Session Won't Clear:**

1. **Force Clear via URL**
   ```
   http://127.0.0.1:5000/clear-license
   ```

2. **Check Session Status**
   ```
   http://127.0.0.1:5000/api/license-status
   ```

3. **Browser Reset**
   - Clear all cookies for localhost:5000
   - Close and reopen browser
   - Use incognito mode

4. **Restart Flask App**
   - Stop the Flask application
   - Restart with `python app.py`

### **If License Key Won't Validate:**

1. **Check Key Format**
   - Must start with `AEGIS-`
   - Should be 28-29 characters total
   - Contains uppercase letters and numbers

2. **Generate Fresh Key**
   ```bash
   python test_license_generation.py
   ```

3. **Check Expiration**
   - Test keys may have expired
   - Generate new ones as needed

## 📊 **Verification Tools**

### **Check Current License Status**
```bash
curl http://127.0.0.1:5000/api/license-status
```

### **Run Comprehensive Tests**
```bash
python comprehensive_license_test.py
```

### **Verify All Features Work**
- License validation ✓
- User name integration ✓
- Custom time periods ✓
- Auto-logout functionality ✓
- All features enabled ✓

## 🎯 **Quick Test Scenarios**

### **Scenario 1: Test Auto-logout**
```bash
# Clear session
python clear_license_fixed.py

# Generate 2-minute license
python test_license_generation.py

# Enter key in browser and wait 2 minutes
```

### **Scenario 2: Test Different Durations**
```bash
# Clear session
python clear_license_fixed.py

# Generate custom duration
python generate_custom_license.py

# Select desired duration and test
```

### **Scenario 3: Test Feature Access**
```bash
# Clear session
python clear_license_fixed.py

# Generate any license
python test_license_generation.py

# Verify all features accessible in browser
```

## ✅ **Fixed Issues**

- ✅ **License session clearing**: Now properly clears on logout
- ✅ **Input validation**: Accepts both uppercase and lowercase letters
- ✅ **Auto-logout**: Works correctly with real-time monitoring
- ✅ **Feature access**: All licenses provide full feature access
- ✅ **Duration customization**: Full range from minutes to years

The license testing system is now fully functional and ready for comprehensive testing!
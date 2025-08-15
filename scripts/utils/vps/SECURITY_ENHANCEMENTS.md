# VPS-SQRY v6.0.0 Security Edition

## 🛡️ Security Enhancements Overview

### ✅ Completed Security Features

#### 1. **IP Address Validation & Authorization**
- Validates all IP addresses for proper format and authorized ranges
- Prevents scanning of restricted IP ranges (0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4)
- Blocks private IP scanning unless explicitly authorized with `--allow-private`
- Requires explicit authorization for all targets via `/home/kali/.sqry_authorized_networks`

#### 2. **Tor Proxy Integration**
- Full Tor support with `--tor` flag for anonymous reconnaissance
- Verifies Tor connection and exit IP before scanning
- Rate-limited requests through SOCKS5 proxy
- Automatic IP verification to ensure anonymization is working

#### 3. **Enhanced Rate Limiting**
- Configurable scan rate with `--max-rate` (1-1000 req/sec, default: 100)
- Intelligent rate limiting with mathematical calculations
- Respectful scanning to prevent overwhelming targets
- BC-based precise timing calculations

#### 4. **Secure Logging & Input Sanitization**
- All inputs sanitized to prevent injection attacks
- Secure logging to `/home/kali/.sqry_secure.log`
- Log sanitization prevents log injection
- Activity tracking with IP addresses and timestamps

#### 5. **Privilege Escalation & Security Checks**
- Comprehensive privilege escalation detection
- Environment variable security scanning
- System directory write permission checks
- Tool integrity and location verification

#### 6. **Network Permission Verification**
- Authorized networks configuration file management
- Target authorization validation before scanning
- Option to disable authorization for testing (`--disable-auth`)
- Template creation for authorized networks (`--create-auth-template`)

#### 7. **Enhanced Error Handling**
- Secure error messages that don't disclose sensitive information
- Proper cleanup of temporary files
- Graceful failure handling
- Comprehensive logging of all errors

#### 8. **Dependency & Tool Security**
- Verification of required tools availability
- Suspicious tool location detection
- Missing dependency reporting
- Path validation for security tools

## 🚀 New Security Options

```bash
# Security Options
--tor                  Enable Tor proxy for anonymous scanning
--disable-auth         Disable target authorization checks  
--allow-private        Allow scanning of private IP ranges
--create-auth-template Create authorized networks template file
--max-rate <num>       Set maximum scan rate (1-1000 req/sec, default: 100)
```

## 📋 Usage Examples

### Setup Authorized Networks
```bash
# Create authorized networks template
./vps-sqry.sh --create-auth-template

# Edit the file to add your authorized targets
nano ~/.sqry_authorized_networks
```

### Anonymous Scanning with Tor
```bash
# Install and start Tor first
sudo apt install tor
sudo systemctl start tor

# Run anonymous scan
./vps-sqry.sh -q "apache" --tor --verbose
```

### Controlled Rate Scanning
```bash
# Low-rate respectful scanning
./vps-sqry.sh -q "nginx" --max-rate 50 --verbose

# Allow private IP scanning for internal networks
./vps-sqry.sh -q "internal-server" --allow-private --verbose
```

## 🔒 Security Features in Action

### 1. Target Authorization Check
```
🛡️ [SECURITY] Checking target authorization for: nginx
✅ [SUCCESS] Target 'nginx' found in authorized networks
```

### 2. Tor Verification
```
🛡️ [SECURITY] Verifying Tor connection...
✅ [SUCCESS] Tor connection verified - Exit IP: 185.220.101.75
⚙️ [STATUS] Current scanning IP: 185.220.101.75
✅ [SUCCESS] Tor anonymization is active
```

### 3. Security State Tracking
```
🛡️ [SECURITY] All security checks passed - proceeding with scan
✅ [SUCCESS] Secure logging initialized: /home/kali/.sqry_secure.log
```

## 📊 Generated Security Reports

The enhanced framework generates comprehensive security compliance reports:

### Files Created:
- `security_report.txt` - Detailed security compliance report
- `~/.sqry_secure.log` - Secure activity log with sanitization
- `~/.sqry_authorized_networks` - Authorized targets configuration

### Security Report Contents:
- Active security features status
- Tor anonymization verification
- Target authorization status
- Scan parameters and settings
- Responsible disclosure reminders

## ⚠️ Important Security Notes

### **Authorized Use Only**
- This tool is intended for authorized security testing only
- Users must obtain explicit written permission before scanning targets
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices

### **Default Security Stance**
- Authorization is **required by default** for all targets
- Private IP scanning is **disabled by default**
- Rate limiting is **active by default** at 100 req/sec
- All activities are **logged by default**

### **Privacy & Anonymity**
- Tor integration provides anonymization but requires proper setup
- Current IP is always displayed for verification
- Exit IP verification ensures Tor is working correctly
- Secure logging tracks all activities for audit purposes

## 🔧 Technical Implementation

### Rate Limiting Algorithm
```bash
rate_limit_sleep() {
    local current_time=$(date +%s.%N)
    local time_diff=$(echo "$current_time - ${LAST_REQUEST_TIME:-0}" | bc -l)
    local min_interval=$(echo "scale=3; 1.0 / $MAX_SCAN_RATE" | bc -l)
    
    if (( $(echo "$time_diff < $min_interval" | bc -l) )); then
        local sleep_time=$(echo "$min_interval - $time_diff" | bc -l)
        sleep "$sleep_time"
    fi
}
```

### Input Sanitization
```bash
sanitize_input() {
    local input="$1"
    # Remove dangerous characters
    input="${input//[\\$\`|&;<>(){}[\]]/}"
    input="${input//[$'\n\r\t']/ }"
    # Limit length
    if (( ${#input} > 1000 )); then
        input="${input:0:1000}"
    fi
    echo "$input"
}
```

### IP Validation
```bash
validate_ip_address() {
    local ip="$1"
    local allow_private="${2:-0}"
    
    # Basic IP format validation
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Check for restricted ranges and private networks
    # Full validation with Python ipaddress module
}
```

## 📈 Version History

- **v6.0.0** - Enhanced Security Edition
  - Complete security overhaul
  - Tor proxy integration
  - Authorization framework
  - Rate limiting and input sanitization
  - Comprehensive logging and reporting

- **v5.0.0** - Enhanced Edition (Previous)
  - Basic IP extraction fixes
  - Performance optimizations
  - HTML dashboard generation

## 🤝 Contributing

When contributing to this security-focused framework:

1. **Security First**: All new features must include security considerations
2. **Defensive Design**: Assume all inputs are potentially malicious
3. **Authorization Required**: New scanning capabilities must respect authorization framework
4. **Comprehensive Logging**: All activities must be logged securely
5. **Responsible Disclosure**: Follow responsible disclosure practices

---

**⚡ Enhanced Security Defensive Security Framework**

# 📖 Complete Installation Guide

## 📋 Overview

This guide provides step-by-step instructions for installing and configuring the Wazuh MITRE warnings fix. Follow these instructions carefully to ensure a successful deployment.

---

## 🎯 Prerequisites

### System Requirements
- **Wazuh Version**: 4.10 or higher (tested on 4.13.x)
- **Operating System**: Linux (Ubuntu, CentOS, RHEL, Debian)
- **Access Level**: Root access to Wazuh manager
- **Network**: Internet access for downloading MITRE data
- **Disk Space**: 50MB free space (for downloads and backups)
- **Time**: 5-10 minutes for installation

### Pre-Installation Checklist
```bash
# Verify Wazuh version
/var/ossec/bin/wazuh-control info

# Check disk space
df -h /var/ossec/

# Verify internet connectivity
curl -I https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Check current database state
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
```

---

## 🚀 Installation Methods

### Method 1: Quick Installation (Recommended)

```bash
# 1. Download installation script
wget -O /tmp/install-mitre-fix.sh https://raw.githubusercontent.com/paolokappa/wazuh-mitre-warnings-fix/main/scripts/install.sh
chmod +x /tmp/install-mitre-fix.sh

# 2. Run automated installation
/tmp/install-mitre-fix.sh

# 3. Verify installation
/opt/mitre-db-autoupdate.sh --version
```

### Method 2: Manual Installation

#### Step 1: Stop Wazuh Services
```bash
# Stop Wazuh manager (includes wazuh-analysisd)
systemctl stop wazuh-manager

# Verify services are stopped
systemctl status wazuh-manager
ps aux | grep -E "(wazuh-analysisd|wazuh-db)"
```

#### Step 2: Backup Current Database
```bash
# Create timestamped backup
backup_file="/var/ossec/var/db/mitre.db.backup.$(date +%Y%m%d_%H%M%S)"
cp /var/ossec/var/db/mitre.db "$backup_file"

# Verify backup
ls -la "$backup_file"
sqlite3 "$backup_file" "SELECT COUNT(*) FROM technique;"
```

#### Step 3: Download Main Script
```bash
# Download the fixed script
wget -O /opt/mitre-db-autoupdate.sh https://raw.githubusercontent.com/paolokappa/wazuh-mitre-warnings-fix/main/scripts/mitre-db-autoupdate.sh

# Set correct permissions
chown root:root /opt/mitre-db-autoupdate.sh
chmod 755 /opt/mitre-db-autoupdate.sh

# Verify download
ls -la /opt/mitre-db-autoupdate.sh
# Expected: -rwxr-xr-x 1 root root ~43333 [date] /opt/mitre-db-autoupdate.sh
```

#### Step 4: Download Support Scripts
```bash
# Download verification script
wget -O /opt/verify-mitre-fix.sh https://raw.githubusercontent.com/paolokappa/wazuh-mitre-warnings-fix/main/scripts/verify-fix.sh
chmod 755 /opt/verify-mitre-fix.sh

# Download permission fix script
wget -O /opt/fix-mitre-permissions.sh https://raw.githubusercontent.com/paolokappa/wazuh-mitre-warnings-fix/main/scripts/fix-permissions.sh
chmod 755 /opt/fix-mitre-permissions.sh
```

#### Step 5: Execute Fix
```bash
# Run the MITRE database update
/opt/mitre-db-autoupdate.sh

# Expected output should show:
# - Network connectivity validation
# - Database backup creation
# - MITRE JSON download and processing
# - Technique count: XXX → 1382
# - Database integrity verification
```

#### Step 6: Start Services and Verify
```bash
# Start Wazuh manager
systemctl start wazuh-manager

# Wait for services to initialize
sleep 30

# Verify no MITRE warnings (should show no output)
timeout 30 tail -f /var/ossec/logs/ossec.log | grep -i mitre

# Check database structure
sqlite3 /var/ossec/var/db/mitre.db "
SELECT
  CASE
    WHEN id LIKE 'T%' THEN 'MITRE_ID'
    WHEN id LIKE 'attack-pattern--%' THEN 'UUID'
  END as type,
  COUNT(*) as count
FROM technique
GROUP BY type;
"
# Expected: MITRE_ID|691, UUID|691
```

---

## ⚙️ Configuration

### Automated Updates (Optional)

Add to root crontab for bi-weekly updates:
```bash
# Edit crontab
crontab -e

# Add this line for Monday and Thursday at 3:00 AM
0 3 * * 1,4 /opt/mitre-db-autoupdate.sh >> /var/log/mitre-update.log 2>&1

# Verify cron job
crontab -l | grep mitre
```

### Log Management
```bash
# Create log rotation for MITRE updates
cat > /etc/logrotate.d/mitre-update << 'EOF'
/var/log/mitre-update.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
```

---

## 🔍 Verification Procedures

### Database Verification
```bash
# Check total technique count
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
# Expected: 1382

# Verify dual records for common techniques
sqlite3 /var/ossec/var/db/mitre.db "
SELECT id, name FROM technique
WHERE name='Valid Accounts'
ORDER BY id;
"
# Expected: T1078 and attack-pattern--xxxx records

# Check MITRE version
sqlite3 /var/ossec/var/db/mitre.db "SELECT value FROM metadata WHERE key='mitre_version';"
# Expected: 17.1 or higher
```

### Service Health Check
```bash
# Verify Wazuh services are running
systemctl status wazuh-manager

# Check for any service errors
journalctl -u wazuh-manager --since "5 minutes ago" | grep -i error

# Monitor process health
ps aux | grep -E "(wazuh-analysisd|wazuh-db)" | grep -v grep
```

### Warning Monitoring
```bash
# Monitor for new MITRE warnings (run for 2-3 minutes)
tail -f /var/ossec/logs/ossec.log | grep -i mitre

# Check recent warning count
tail -1000 /var/ossec/logs/ossec.log | grep -i "mitre.*not found" | wc -l
# Expected: 0
```

---

## 🔧 Customization Options

### Script Configuration

Edit `/opt/mitre-db-autoupdate.sh` to customize:

```bash
# Change backup retention (default: 3)
# Look for: backup_retention_count=3

# Modify download source (advanced users only)
# Look for: MITRE_JSON_URL="https://raw.githubusercontent.com..."

# Adjust logging level
# Look for: log_message() function
```

### Network Configuration

For environments with proxy:
```bash
# Set proxy environment variables before running
export http_proxy=http://proxy.company.com:8080
export https_proxy=http://proxy.company.com:8080
/opt/mitre-db-autoupdate.sh
```

### Custom Installation Paths

If you need different paths:
```bash
# Edit script variables
sed -i 's|/var/ossec/var/db/mitre.db|/custom/path/mitre.db|g' /opt/mitre-db-autoupdate.sh
sed -i 's|/var/log/mitre-update.log|/custom/log/path.log|g' /opt/mitre-db-autoupdate.sh
```

---

## 🛡️ Security Considerations

### File Permissions
```bash
# Verify secure permissions
ls -la /var/ossec/var/db/mitre.db
# Expected: -rw-rw---- 1 root wazuh

ls -la /opt/mitre-db-autoupdate.sh
# Expected: -rwxr-xr-x 1 root root

# Fix permissions if needed
/opt/fix-mitre-permissions.sh
```

### Network Security
- Script downloads from official MITRE GitHub repository
- Uses HTTPS with certificate verification
- No sensitive data transmitted
- Downloads are validated before processing

### Database Security
- Automatic backup before any changes
- Atomic transactions prevent corruption
- Integrity checks before and after updates
- Rollback capability in case of errors

---

## 📊 Performance Impact

### Resource Usage
- **CPU**: Minimal during normal operation, moderate during updates
- **Memory**: ~50MB additional during updates
- **Disk**: +1.4MB for dual records, temporary 45MB during download
- **Network**: 45MB download per update

### Timing
- **Installation**: 5-10 minutes
- **Regular Updates**: 2-3 minutes
- **Service Downtime**: <2 minutes during updates

---

## 🔄 Maintenance

### Regular Tasks

**Weekly:**
- Monitor log file size: `/var/log/mitre-update.log`
- Check backup disk usage: `du -sh /var/ossec/var/db/mitre.db.backup.*`

**Monthly:**
- Verify cron job execution: `grep mitre /var/log/cron`
- Review update success rate: `grep "completed successfully" /var/log/mitre-update.log`

**Quarterly:**
- Check for new MITRE versions: Visit https://attack.mitre.org
- Review script updates: Check GitHub repository for updates

### Update Procedures

**To update the script:**
```bash
# Backup current script
cp /opt/mitre-db-autoupdate.sh /opt/mitre-db-autoupdate.sh.backup

# Download latest version
wget -O /opt/mitre-db-autoupdate.sh https://raw.githubusercontent.com/paolokappa/wazuh-mitre-warnings-fix/main/scripts/mitre-db-autoupdate.sh
chmod 755 /opt/mitre-db-autoupdate.sh

# Test new version
systemctl stop wazuh-manager
/opt/mitre-db-autoupdate.sh
systemctl start wazuh-manager
```

---

## 🆘 Rollback Procedures

### Emergency Rollback
```bash
# Stop services
systemctl stop wazuh-manager

# Restore from backup (use your backup timestamp)
cp /var/ossec/var/db/mitre.db.backup.YYYYMMDD_HHMMSS /var/ossec/var/db/mitre.db

# Fix permissions
chown root:wazuh /var/ossec/var/db/mitre.db
chmod 660 /var/ossec/var/db/mitre.db

# Start services
systemctl start wazuh-manager

# Verify rollback
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
```

### Remove Installation
```bash
# Stop services
systemctl stop wazuh-manager

# Remove scripts
rm -f /opt/mitre-db-autoupdate.sh
rm -f /opt/verify-mitre-fix.sh
rm -f /opt/fix-mitre-permissions.sh

# Remove cron job
crontab -e
# Remove the MITRE update line

# Remove logs
rm -f /var/log/mitre-update.log

# Restore original database (if you have one)
# cp /var/ossec/var/db/mitre.db.original /var/ossec/var/db/mitre.db

# Start services
systemctl start wazuh-manager
```

---

## 🎯 Success Criteria

Installation is successful when:

- ✅ Database contains 1,382 techniques (dual records)
- ✅ No MITRE warnings in logs for 30+ minutes
- ✅ Script executes without errors
- ✅ All file permissions are correct
- ✅ Wazuh services are healthy
- ✅ Automatic updates work (if configured)

---

**Document Version**: 1.0
**Created**: September 20, 2025
**Compatibility**: Wazuh 4.10+
**Status**: Production Ready ✅
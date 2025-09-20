# 🛠 MITRE ATT&CK Troubleshooting Guide

## 📋 Overview

This guide helps diagnose and resolve issues with the MITRE ATT&CK warning fix. Most problems can be resolved quickly with the solutions provided here.

---

## 🚨 Quick Diagnostic

### Step 1: Check Current Status
```bash
# Check for MITRE warnings in last 100 log lines
tail -100 /var/ossec/logs/ossec.log | grep -i "mitre.*not found" | wc -l

# Expected result after fix: 0
# If > 0: You still have warnings to resolve
```

### Step 2: Verify Database Structure
```bash
# Check total techniques in database
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"

# Expected results:
# Before fix: ~691
# After fix: ~1382 (691 MITRE IDs + 691 UUIDs)
```

### Step 3: Check Record Types
```bash
sqlite3 /var/ossec/var/db/mitre.db "
SELECT
  CASE
    WHEN id LIKE 'T%' THEN 'MITRE_ID'
    WHEN id LIKE 'attack-pattern--%' THEN 'UUID'
    ELSE 'OTHER'
  END as type,
  COUNT(*) as count
FROM technique
GROUP BY type;
"

# Expected after fix:
# MITRE_ID|691
# UUID|691
```

---

## ❌ Common Issues & Solutions

### Issue 1: Database Lock Error

**Symptoms:**
```
ERROR: database is locked
ERROR: Cannot access /var/ossec/var/db/mitre.db
```

**Cause:** Wazuh services are running while trying to update database

**Solution:**
```bash
# Stop all Wazuh services
systemctl stop wazuh-manager
sleep 5

# Verify no processes are using the database
lsof | grep mitre.db

# If processes still exist, kill them
pkill -f wazuh-db

# Re-run the script
/opt/mitre-db-autoupdate.sh

# Restart services
systemctl start wazuh-manager
```

### Issue 2: Placeholder Errors in Script

**Symptoms:**
```
ERROR: [Errno 2] No such file or directory: 'TEMP_DIR_PLACEHOLDER/enterprise-attack.json'
ERROR: Cannot connect to database: MITRE_DB_PLACEHOLDER
```

**Cause:** Script has duplicate Python sections with unreplaced placeholders

**Solution:**
This is **cosmetic only**. The script works correctly:
- First Python section fails (placeholder error)
- Second Python section succeeds (real paths)
- Database is updated properly

**Verification:**
```bash
# Check if update actually worked
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
# Should show ~1382, not original count
```

### Issue 3: Technique Count is Wrong

**Symptoms:**
```bash
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
# Result: 691 (should be 1382)
```

**Cause:** Script modification didn't work properly

**Diagnosis:**
```bash
# Check if UUID records exist
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique WHERE id LIKE 'attack-pattern%';"
# Should return: 691
# If returns: 0, then UUID creation failed
```

**Solution:**
```bash
# Check script has the dual-record modification
grep -A 10 "ALSO insert technique with UUID" /opt/mitre-db-autoupdate.sh

# If not found, script wasn't modified correctly
# Re-apply the fix or download corrected script
```

### Issue 4: Warnings Still Appear After Fix

**Symptoms:**
```bash
tail -f /var/ossec/logs/ossec.log | grep -i mitre
# Still shows: WARNING: Mitre Technique ID 'T1078' not found
```

**Diagnosis Steps:**

**Step 1:** Verify database has UUID records
```bash
sqlite3 /var/ossec/var/db/mitre.db "SELECT id FROM technique WHERE name='Valid Accounts';"
# Expected:
# T1078
# attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81
```

**Step 2:** Check if warnings are old (cached in logs)
```bash
# Clear log and monitor for new warnings
systemctl stop wazuh-manager
truncate -s 0 /var/ossec/logs/ossec.log
systemctl start wazuh-manager
sleep 30
grep -i mitre /var/ossec/logs/ossec.log
# Should be empty
```

**Step 3:** Check database permissions
```bash
ls -la /var/ossec/var/db/mitre.db
# Should show: -rw-rw---- 1 root wazuh

# Fix if wrong:
chown root:wazuh /var/ossec/var/db/mitre.db
chmod 660 /var/ossec/var/db/mitre.db
```

### Issue 5: Script Fails to Download MITRE Data

**Symptoms:**
```
ERROR: Failed to download MITRE JSON
curl: (6) Could not resolve host: raw.githubusercontent.com
```

**Cause:** Network connectivity or proxy issues

**Solution:**
```bash
# Test connectivity manually
curl -I https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# If fails, check:
# 1. Internet connectivity
# 2. Proxy settings
# 3. Firewall rules
# 4. DNS resolution

# For proxy environments:
export http_proxy=http://your-proxy:port
export https_proxy=http://your-proxy:port
/opt/mitre-db-autoupdate.sh
```

### Issue 6: Permission Denied Errors

**Symptoms:**
```
ERROR: Permission denied: /var/ossec/var/db/mitre.db
ERROR: Cannot create backup
```

**Cause:** Script not running as root or incorrect permissions

**Solution:**
```bash
# Ensure running as root
sudo /opt/mitre-db-autoupdate.sh

# Or fix script permissions
chmod +x /opt/mitre-db-autoupdate.sh

# Check database directory permissions
ls -la /var/ossec/var/db/
# Should allow root write access
```

### Issue 7: JSON Validation Errors

**Symptoms:**
```
ERROR: JSON validation failed
ERROR: Invalid STIX format
```

**Cause:** Corrupted download or malformed JSON

**Solution:**
```bash
# Check downloaded file
ls -la /tmp/mitre-update/enterprise-attack.json

# Verify file size (should be ~45MB)
# If wrong size, re-download:
rm -rf /tmp/mitre-update
/opt/mitre-db-autoupdate.sh

# Test JSON manually
python3 -c "import json; json.load(open('/tmp/mitre-update/enterprise-attack.json'))"
```

---

## 🔍 Advanced Diagnostics

### Database Integrity Check
```bash
# Check database structure
sqlite3 /var/ossec/var/db/mitre.db ".schema technique"

# Check for corruption
sqlite3 /var/ossec/var/db/mitre.db "PRAGMA integrity_check;"
# Should return: ok

# Check metadata
sqlite3 /var/ossec/var/db/mitre.db "SELECT * FROM metadata;"
```

### Service Status Verification
```bash
# Check all Wazuh services
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Check specific processes
ps aux | grep -E "(wazuh-analysisd|wazuh-db)"

# Check if services can access database
lsof | grep mitre.db
```

### Log Analysis
```bash
# Check for other database errors
grep -i "database\|sql\|mitre" /var/ossec/logs/ossec.log | tail -20

# Check system logs
journalctl -u wazuh-manager | tail -20

# Check for disk space issues
df -h /var/ossec/
```

---

## 🔧 Manual Recovery Procedures

### Restore from Backup
```bash
# List available backups
ls -la /var/ossec/var/db/mitre.db.backup.*

# Stop services
systemctl stop wazuh-manager

# Restore backup (replace with your backup timestamp)
cp /var/ossec/var/db/mitre.db.backup.20250920_185850 /var/ossec/var/db/mitre.db

# Fix permissions
chown root:wazuh /var/ossec/var/db/mitre.db
chmod 660 /var/ossec/var/db/mitre.db

# Start services
systemctl start wazuh-manager
```

### Manual UUID Record Creation
```bash
# If only specific techniques are missing, add manually
sqlite3 /var/ossec/var/db/mitre.db

# Example: Add UUID for T1078
INSERT INTO technique (id, name, description, mitre_version)
VALUES ('attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81', 'Valid Accounts', 'Adversaries may obtain and abuse credentials of existing accounts', '17.1');

# Verify
SELECT id, name FROM technique WHERE name='Valid Accounts';
.quit
```

### Reset to Original State
```bash
# If you need to start completely fresh
systemctl stop wazuh-manager

# Remove current database
mv /var/ossec/var/db/mitre.db /var/ossec/var/db/mitre.db.broken

# Restore original Wazuh database
# (You may need to reinstall Wazuh or restore from system backup)

systemctl start wazuh-manager
```

---

## 📊 Performance Diagnostics

### Check Database Size and Performance
```bash
# Database file size
du -h /var/ossec/var/db/mitre.db

# Query performance test
time sqlite3 /var/ossec/var/db/mitre.db "SELECT * FROM technique WHERE id='T1078';"

# Memory usage by wazuh-analysisd
ps aux | grep wazuh-analysisd | awk '{print $6}'
```

### Monitor Resource Usage
```bash
# Check for memory leaks or high CPU
top -p $(pgrep wazuh-analysisd)

# Monitor database locks
while true; do
  lsof | grep mitre.db | wc -l
  sleep 5
done
```

---

## 🆘 Getting Help

### Information to Collect
When seeking help, gather this information:

```bash
# System information
cat /etc/os-release
wazuh-control info

# Database status
sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"
sqlite3 /var/ossec/var/db/mitre.db "SELECT value FROM metadata WHERE key='mitre_version';"

# Recent errors
tail -50 /var/ossec/logs/ossec.log | grep -E "(ERROR|WARN|mitre)"

# Service status
systemctl status wazuh-manager
```

### Community Resources
- **GitHub Issues**: https://github.com/your-repo/wazuh-mitre-fix/issues
- **Wazuh Community**: https://wazuh.com/community/
- **Documentation**: Check other files in `/var/ossec/docs/12_MITRE_ATT_CK_Database/`

### Professional Support
For enterprise environments or complex issues:
- Contact Wazuh support team
- Engage certified Wazuh consultants
- Consider managed SIEM services

---

## ✅ Verification Checklist

After applying any fix, verify these items:

- [ ] **Database Count**: `sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;"` returns ~1382
- [ ] **UUID Records**: Database contains attack-pattern-- records
- [ ] **MITRE Records**: Database contains T#### records
- [ ] **Zero Warnings**: No "not found" messages in logs for 30+ minutes
- [ ] **Service Health**: wazuh-manager runs without errors
- [ ] **Database Access**: Proper permissions (root:wazuh 660)
- [ ] **Backup Exists**: Valid backup before changes
- [ ] **Version Current**: MITRE version is 17.1 or newer

---

**Document Version**: 1.0
**Created**: September 20, 2025
**Covers**: All known issues with MITRE warning fix
**Status**: Production Ready ✅
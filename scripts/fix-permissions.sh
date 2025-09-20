#!/bin/bash
# Fix all MITRE-related file permissions
# Part of wazuh-mitre-warnings-fix project
# https://github.com/paolokappa/wazuh-mitre-warnings-fix

set -e

echo "🔧 Fixing MITRE-related file permissions..."

# Fix main database permissions
echo "📊 Fixing MITRE database permissions..."
if [ -f "/var/ossec/var/db/mitre.db" ]; then
    chown root:wazuh /var/ossec/var/db/mitre.db
    chmod 660 /var/ossec/var/db/mitre.db
    echo "   ✅ Database permissions fixed: root:wazuh 660"
else
    echo "   ⚠️  MITRE database not found at /var/ossec/var/db/mitre.db"
fi

# Fix backup permissions
echo "💾 Fixing backup permissions..."
if ls /var/ossec/var/db/mitre.db.backup.* >/dev/null 2>&1; then
    chown root:wazuh /var/ossec/var/db/mitre.db.backup.* 2>/dev/null || true
    chmod 640 /var/ossec/var/db/mitre.db.backup.* 2>/dev/null || true
    backup_count=$(ls -1 /var/ossec/var/db/mitre.db.backup.* 2>/dev/null | wc -l)
    echo "   ✅ Fixed permissions for $backup_count backup files"
else
    echo "   ℹ️  No backup files found"
fi

# Fix script permissions
echo "📜 Fixing script permissions..."
scripts_fixed=0

if [ -f "/opt/mitre-db-autoupdate.sh" ]; then
    chown root:root /opt/mitre-db-autoupdate.sh
    chmod 755 /opt/mitre-db-autoupdate.sh
    echo "   ✅ Main script: /opt/mitre-db-autoupdate.sh"
    ((scripts_fixed++))
fi

for script in /opt/mitre-db-autoupdate*.sh /opt/test-mitre-update.sh; do
    if [ -f "$script" ] && [ "$script" != "/opt/mitre-db-autoupdate.sh" ]; then
        chown root:root "$script" 2>/dev/null || true
        chmod 755 "$script" 2>/dev/null || true
        echo "   ✅ Script: $script"
        ((scripts_fixed++))
    fi
done

echo "   ✅ Fixed permissions for $scripts_fixed script files"

# Fix log permissions
echo "📝 Fixing log permissions..."
touch /var/log/mitre-update.log
chown root:root /var/log/mitre-update.log
chmod 644 /var/log/mitre-update.log
echo "   ✅ Log file: /var/log/mitre-update.log"

# Verify permissions
echo ""
echo "🔍 Verification:"

if [ -f "/var/ossec/var/db/mitre.db" ]; then
    db_perms=$(ls -la /var/ossec/var/db/mitre.db | awk '{print $1, $3":"$4}')
    echo "   📊 Database: $db_perms"

    if [[ $db_perms == *"root:wazuh"* ]] && [[ $db_perms == *"rw-rw-"* ]]; then
        echo "   ✅ Database permissions: CORRECT"
    else
        echo "   ❌ Database permissions: INCORRECT"
        exit 1
    fi
fi

if [ -f "/opt/mitre-db-autoupdate.sh" ]; then
    script_perms=$(ls -la /opt/mitre-db-autoupdate.sh | awk '{print $1, $3":"$4}')
    echo "   📜 Main script: $script_perms"

    if [[ $script_perms == *"root:root"* ]] && [[ $script_perms == *"rwxr-xr-x"* ]]; then
        echo "   ✅ Script permissions: CORRECT"
    else
        echo "   ❌ Script permissions: INCORRECT"
        exit 1
    fi
fi

log_perms=$(ls -la /var/log/mitre-update.log | awk '{print $1, $3":"$4}')
echo "   📝 Log file: $log_perms"

if [[ $log_perms == *"root:root"* ]] && [[ $log_perms == *"rw-r--r--"* ]]; then
    echo "   ✅ Log permissions: CORRECT"
else
    echo "   ❌ Log permissions: INCORRECT"
    exit 1
fi

echo ""
echo "🎉 Permission fix completed successfully!"
echo "   All MITRE-related files have correct permissions."
echo ""
echo "💡 Next steps:"
echo "   1. Run: systemctl status wazuh-manager"
echo "   2. Test: /opt/mitre-db-autoupdate.sh (if needed)"
echo "   3. Monitor: tail -f /var/ossec/logs/ossec.log | grep -i mitre"
echo "
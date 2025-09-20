#!/bin/bash

# Test script per verificare il nuovo aggiornamento MITRE
# Questo script fa un dry-run delle operazioni principali

echo "=== TEST MITRE UPDATE SCRIPT ==="
echo "Data: $(date)"
echo ""

# Test 1: Verifica servizio wazuh-analysisd
echo "1. Checking wazuh-analysisd service status..."
if systemctl is-active --quiet wazuh-analysisd; then
    echo "   ✅ wazuh-analysisd is running"
else
    echo "   ❌ wazuh-analysisd is not running"
fi

# Test 2: Verifica database esistente
echo ""
echo "2. Checking MITRE database..."
if [ -f "/var/ossec/var/db/mitre.db" ]; then
    echo "   ✅ Database exists"
    size=$(stat -c%s "/var/ossec/var/db/mitre.db")
    perms=$(stat -c "%a %U:%G" "/var/ossec/var/db/mitre.db")
    count=$(sqlite3 /var/ossec/var/db/mitre.db "SELECT COUNT(*) FROM technique;" 2>/dev/null || echo "ERROR")
    version=$(sqlite3 /var/ossec/var/db/mitre.db "SELECT value FROM metadata WHERE key='mitre_version';" 2>/dev/null || echo "unknown")

    echo "   📊 Size: $size bytes"
    echo "   🔐 Permissions: $perms"
    echo "   📋 Techniques: $count"
    echo "   📌 Version: $version"
else
    echo "   ❌ Database not found"
fi

# Test 3: Verifica backup esistenti
echo ""
echo "3. Checking existing backups..."
backup_count=$(ls -1 /var/ossec/var/db/mitre.db.backup.* 2>/dev/null | wc -l)
echo "   📁 Found $backup_count existing backups"
if [ $backup_count -gt 0 ]; then
    echo "   📋 Recent backups:"
    ls -lt /var/ossec/var/db/mitre.db.backup.* 2>/dev/null | head -3 | while read line; do
        echo "      $(echo $line | awk '{print $9 " - " $6 " " $7 " " $8}')"
    done
fi

# Test 4: Verifica connettività MITRE
echo ""
echo "4. Testing MITRE data source connectivity..."
url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
if curl -s -f --max-time 10 --head "$url" >/dev/null; then
    echo "   ✅ MITRE data source accessible"
    # Get header info
    size_header=$(curl -s -f --max-time 10 --head "$url" | grep -i "content-length" | cut -d' ' -f2 | tr -d '\r')
    if [ -n "$size_header" ]; then
        echo "   📊 Remote file size: $size_header bytes"
    fi
else
    echo "   ❌ MITRE data source not accessible"
fi

# Test 5: Verifica dipendenze
echo ""
echo "5. Checking dependencies..."
if command -v python3 >/dev/null 2>&1; then
    echo "   ✅ Python3: $(python3 --version)"
else
    echo "   ❌ Python3 not found"
fi

if command -v curl >/dev/null 2>&1; then
    echo "   ✅ curl: $(curl --version | head -1)"
else
    echo "   ❌ curl not found"
fi

if command -v sqlite3 >/dev/null 2>&1; then
    echo "   ✅ sqlite3: $(sqlite3 --version)"
else
    echo "   ❌ sqlite3 not found"
fi

# Test 6: Verifica permessi scrittura
echo ""
echo "6. Checking write permissions..."
if [ -w "/var/ossec/var/db/" ]; then
    echo "   ✅ Write access to database directory"
else
    echo "   ❌ No write access to database directory"
fi

if [ -w "/var/log/" ]; then
    echo "   ✅ Write access to log directory"
else
    echo "   ❌ No write access to log directory"
fi

# Test 7: Verifica warnings MITRE attuali
echo ""
echo "7. Checking current MITRE warnings..."
warning_count=$(tail -100 /var/ossec/logs/ossec.log 2>/dev/null | grep 'Mitre.*not found' | wc -l)
echo "   📊 Current MITRE warnings in last 100 log lines: $warning_count"

if [ $warning_count -gt 0 ]; then
    echo "   🔍 Recent unique warnings:"
    tail -100 /var/ossec/logs/ossec.log 2>/dev/null | grep 'Mitre.*not found' | sed 's/.*Mitre Technique ID//' | sort -u | head -5 | while read line; do
        echo "      $line"
    done
fi

# Test 8: Test stop/start wazuh-analysisd (simulazione)
echo ""
echo "8. Testing service control (simulation only)..."
echo "   ℹ️  Would stop wazuh-analysisd"
echo "   ℹ️  Would update database"
echo "   ℹ️  Would set permissions (root:wazuh 640)"
echo "   ℹ️  Would start wazuh-analysisd"
echo "   ℹ️  Would monitor for 30 seconds"

echo ""
echo "=== TEST COMPLETED ==="
echo ""
echo "📝 Summary:"
echo "   - Script: /opt/mitre-db-autoupdate-v2.sh"
echo "   - Log file: /var/log/mitre-update.log"
echo "   - Cron schedule: 0 3 * * 1,4 (Mon/Thu at 3 AM)"
echo ""
echo "🚀 To run the actual update:"
echo "   sudo /opt/mitre-db-autoupdate-v2.sh"
echo ""
echo "📋 To run in test mode first, add a --dry-run option if needed"
#!/bin/bash

# GOLINE SOC - MITRE Database Complete Auto-Update Script
# Version: 2.1 - ENHANCED VALIDATION & DEBUG
# Description: Downloads complete MITRE ATT&CK with robust validation and error handling
# Schedule: Run weekly via cron

# Exit on any error for strict error handling
set -eE

MITRE_DB="/var/ossec/var/db/mitre.db"
LOG_FILE="/var/log/mitre-update.log"
TEMP_DIR="/tmp/mitre-update"
JSON_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
JSON_FILE="$TEMP_DIR/enterprise-attack.json"
DEBUG_MODE=1
VALIDATE_STRICT=1

# Performance tracking
START_TIME=$(date +%s)
REPORT_DATA=""

# Function to log messages with different levels
log_message() {
    local level="${2:-INFO}"
    local timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
    echo "$timestamp [$level] $1" | tee -a "$LOG_FILE"
}

# Function to log debug messages
debug_log() {
    if [ "$DEBUG_MODE" = "1" ]; then
        log_message "$1" "DEBUG"
    fi
}

# Function to log error and exit
error_exit() {
    log_message "$1" "ERROR"
    # Add to report
    REPORT_DATA="$REPORT_DATA\n❌ FAILED: $1"
    generate_final_report "FAILED" "$1"
    cleanup
    exit 1
}

# Function to add success to report
report_success() {
    REPORT_DATA="$REPORT_DATA\n✅ $1"
}

# Function to add warning to report
report_warning() {
    REPORT_DATA="$REPORT_DATA\n⚠️  $1"
}

# Function to cleanup temp files and ensure service is running
cleanup() {
    debug_log "Starting cleanup process"

    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        debug_log "Cleaned up temporary files"
    fi

    # Ensure wazuh-analysisd is running on exit (safety measure)
    if ! systemctl is-active --quiet wazuh-analysisd; then
        log_message "SAFETY: Ensuring wazuh-analysisd is running before exit" "WARN"
        systemctl start wazuh-analysisd 2>/dev/null || true
    fi
}

# Function to validate network connectivity
validate_network() {
    log_message "Validating network connectivity to MITRE repository"

    # Test DNS resolution
    if ! nslookup raw.githubusercontent.com >/dev/null 2>&1; then
        error_exit "DNS resolution failed for raw.githubusercontent.com"
    fi
    debug_log "DNS resolution successful"

    # Test HTTP HEAD request
    if ! curl -s -f --max-time 30 --head "$JSON_URL" >/dev/null; then
        error_exit "HTTP HEAD request failed for MITRE repository"
    fi
    debug_log "HTTP HEAD request successful"

    # Get remote file info
    local remote_size=$(curl -s -f --head "$JSON_URL" | grep -i "content-length" | cut -d' ' -f2 | tr -d '\r')
    if [ -n "$remote_size" ]; then
        log_message "Remote file size: $remote_size bytes"
        # Validate reasonable file size (between 5MB and 50MB)
        if [ "$remote_size" -lt 5242880 ] || [ "$remote_size" -gt 52428800 ]; then
            error_exit "Remote file size ($remote_size bytes) outside expected range (5MB-50MB)"
        fi
    fi

    report_success "Network connectivity validated"
}

# Function to download MITRE JSON with enhanced validation
download_mitre_json() {
    log_message "Creating temporary directory: $TEMP_DIR"
    mkdir -p "$TEMP_DIR"

    log_message "Downloading MITRE ATT&CK JSON from: $JSON_URL"

    # Download with progress and timeout
    if curl -s -f --max-time 300 --connect-timeout 30 -o "$JSON_FILE" "$JSON_URL"; then
        local file_size=$(stat -c%s "$JSON_FILE")
        log_message "Downloaded MITRE JSON successfully (${file_size} bytes)"

        # Validate file size
        if [ "$file_size" -lt 1048576 ]; then  # Less than 1MB
            error_exit "Downloaded file too small ($file_size bytes) - likely incomplete"
        fi

        debug_log "File size validation passed"
        report_success "MITRE JSON downloaded ($(echo "scale=2; $file_size/1024/1024" | bc)MB)"

        return 0
    else
        error_exit "Failed to download MITRE JSON from $JSON_URL"
    fi
}

# Function to validate JSON structure and content
validate_json_structure() {
    log_message "Performing comprehensive JSON validation"

    # Basic JSON syntax validation
    if ! python3 -c "import json; json.load(open('$JSON_FILE'))" 2>/dev/null; then
        error_exit "JSON syntax validation failed - file is not valid JSON"
    fi
    debug_log "JSON syntax validation passed"

    # Advanced structure validation with Python
    python3 << 'PYTHON_VALIDATION'
import json
import sys
import re

def validate_mitre_structure(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        # Check for required top-level structure
        if 'objects' not in data:
            print("ERROR: Missing 'objects' array in JSON")
            return False

        objects = data['objects']
        if not isinstance(objects, list):
            print("ERROR: 'objects' is not an array")
            return False

        # Count different object types
        stats = {
            'attack-pattern': 0,
            'x-mitre-tactic': 0,
            'course-of-action': 0,
            'intrusion-set': 0,
            'malware': 0,
            'tool': 0,
            'x-mitre-collection': 0
        }

        mitre_version = None
        technique_samples = []

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            obj_type = obj.get('type')
            if obj_type in stats:
                stats[obj_type] += 1

            # Extract MITRE version
            if obj_type == 'x-mitre-collection' and 'x_mitre_version' in obj:
                mitre_version = obj['x_mitre_version']

            # Collect technique samples for validation
            if obj_type == 'attack-pattern' and len(technique_samples) < 5:
                external_refs = obj.get('external_references', [])
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        if technique_id and technique_id.startswith('T'):
                            technique_samples.append({
                                'id': technique_id,
                                'name': obj.get('name', ''),
                                'description': obj.get('description', '')[:100] + '...' if obj.get('description') else ''
                            })
                            break

        # Validation checks
        print(f"VALIDATION RESULTS:")
        print(f"MITRE Version: {mitre_version}")

        for obj_type, count in stats.items():
            print(f"{obj_type}: {count}")

        # Minimum thresholds
        if stats['attack-pattern'] < 500:
            print(f"ERROR: Too few attack patterns ({stats['attack-pattern']}) - expected 500+")
            return False

        if stats['x-mitre-tactic'] < 10:
            print(f"ERROR: Too few tactics ({stats['x-mitre-tactic']}) - expected 10+")
            return False

        if not mitre_version:
            print("ERROR: MITRE version not found")
            return False

        # Check version format
        if not re.match(r'\d+\.\d+', mitre_version):
            print(f"ERROR: Invalid MITRE version format: {mitre_version}")
            return False

        print("TECHNIQUE SAMPLES:")
        for sample in technique_samples:
            print(f"  {sample['id']}: {sample['name']}")
            if len(sample['description']) > 5:
                print(f"    {sample['description']}")

        print("JSON structure validation: PASSED")
        return True

    except Exception as e:
        print(f"ERROR: Validation failed with exception: {str(e)}")
        return False

# Execute validation
if not validate_mitre_structure('TEMP_DIR_PLACEHOLDER/enterprise-attack.json'):
    sys.exit(1)
PYTHON_VALIDATION

    # Replace placeholder with actual temp dir
    sed -i "s|TEMP_DIR_PLACEHOLDER|$TEMP_DIR|g" <<< "$PYTHON_VALIDATION" | python3

    if [ $? -eq 0 ]; then
        log_message "JSON structure validation passed"
        report_success "JSON structure validation completed"
        return 0
    else
        error_exit "JSON structure validation failed"
    fi
}

# Function to manage backup rotation (keep last 3)
manage_backups() {
    log_message "Managing database backups (keeping last 3)"

    # Find all backup files and sort by date (newest first)
    local backup_files=($(ls -t "${MITRE_DB}.backup."* 2>/dev/null))
    local backup_count=${#backup_files[@]}

    debug_log "Found $backup_count existing backups"

    # If we have more than 3 backups, remove the oldest ones
    if [ $backup_count -gt 3 ]; then
        local files_to_remove=$((backup_count - 3))
        log_message "Found $backup_count backups, removing $files_to_remove oldest"

        for ((i=3; i<backup_count; i++)); do
            rm -f "${backup_files[$i]}"
            debug_log "Removed old backup: $(basename ${backup_files[$i]})"
        done
    else
        debug_log "Found $backup_count backups, no cleanup needed"
    fi

    report_success "Backup rotation completed ($backup_count backups managed)"
}

# Function to stop wazuh-analysisd service
stop_wazuh_analysisd() {
    log_message "Stopping wazuh-analysisd service"

    if systemctl is-active --quiet wazuh-analysisd; then
        if timeout 30 systemctl stop wazuh-analysisd; then
            log_message "wazuh-analysisd stopped successfully"
            sleep 2  # Grace period
            return 0
        else
            error_exit "Failed to stop wazuh-analysisd within timeout"
        fi
    else
        log_message "wazuh-analysisd was not running"
        return 0
    fi
}

# Function to start wazuh-analysisd service
start_wazuh_analysisd() {
    log_message "Starting wazuh-analysisd service"

    if timeout 30 systemctl start wazuh-analysisd; then
        log_message "wazuh-analysisd started successfully"

        # Wait for service to fully start
        sleep 5

        if systemctl is-active --quiet wazuh-analysisd; then
            log_message "wazuh-analysisd is running and active"
            return 0
        else
            error_exit "wazuh-analysisd failed to start properly"
        fi
    else
        error_exit "Failed to start wazuh-analysisd within timeout"
    fi
}

# Function to set correct database permissions
set_database_permissions() {
    debug_log "Setting correct database permissions"

    # Set ownership: root:wazuh
    if chown root:wazuh "$MITRE_DB"; then
        debug_log "Database ownership set to root:wazuh"
    else
        error_exit "Failed to set database ownership"
    fi

    # Set permissions: 640
    if chmod 640 "$MITRE_DB"; then
        debug_log "Database permissions set to 640"
    else
        error_exit "Failed to set database permissions"
    fi

    # Verify permissions
    local perms=$(stat -c "%a %U:%G" "$MITRE_DB")
    log_message "Database permissions verified: $perms"

    report_success "Database permissions set correctly ($perms)"
    return 0
}

# Function to validate database before update
validate_database_pre_update() {
    log_message "Validating database before update"

    # Check database exists and is accessible
    if [ ! -f "$MITRE_DB" ]; then
        error_exit "MITRE database not found at $MITRE_DB"
    fi

    # Check database integrity
    if ! sqlite3 "$MITRE_DB" "PRAGMA integrity_check;" | grep -q "ok"; then
        error_exit "Database integrity check failed before update"
    fi

    # Get current stats for comparison
    local current_count=$(sqlite3 "$MITRE_DB" "SELECT COUNT(*) FROM technique;" 2>/dev/null || echo "0")
    local current_version=$(sqlite3 "$MITRE_DB" "SELECT value FROM metadata WHERE key='mitre_version';" 2>/dev/null || echo "unknown")

    log_message "Current database state: $current_count techniques, version $current_version"

    # Ensure temp directory exists before storing data
    mkdir -p "$TEMP_DIR"

    # Store for later comparison
    echo "$current_count" > "$TEMP_DIR/pre_update_count"
    echo "$current_version" > "$TEMP_DIR/pre_update_version"

    report_success "Pre-update validation completed"
}

# Function to extract techniques from JSON and populate database with validation
populate_mitre_database() {
    log_message "Processing MITRE JSON and populating database"

    # Create backup with timestamp
    local backup_file="${MITRE_DB}.backup.$(date +%Y%m%d_%H%M%S)"
    if cp "$MITRE_DB" "$backup_file"; then
        log_message "Database backup created: $(basename $backup_file)"
    else
        error_exit "Failed to create database backup"
    fi

    # Manage backup rotation
    manage_backups

    # Enhanced Python processing with normalization and validation
    python3 << 'PYTHON_SCRIPT'
import json
import sqlite3
import sys
import re
from datetime import datetime

def log_message(msg, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {msg}")

def normalize_text(text):
    """Normalize text data for database storage"""
    if not text:
        return ""
    # Remove excessive whitespace and normalize
    text = re.sub(r'\s+', ' ', text.strip())
    # Limit length to prevent database issues
    if len(text) > 2000:
        text = text[:1997] + "..."
    return text

def validate_technique_id(tech_id):
    """Validate MITRE technique ID format"""
    if not tech_id:
        return False
    # Main technique: T1234 or sub-technique: T1234.001
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, tech_id))

def validate_datetime(dt_str):
    """Validate and normalize datetime strings"""
    if not dt_str:
        return None
    try:
        # Parse ISO format datetime
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return None

def populate_database():
    try:
        # Load JSON data
        json_file = 'TEMP_DIR_PLACEHOLDER/enterprise-attack.json'
        log_message(f"Loading JSON data from {json_file}")

        with open(json_file, 'r') as f:
            data = json.load(f)

        # Connect to database
        db_path = 'MITRE_DB_PLACEHOLDER'
        log_message(f"Connecting to database: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Extract MITRE version
        mitre_version = "17.1"  # Default fallback
        for obj in data.get('objects', []):
            if obj.get('type') == 'x-mitre-collection' and 'x_mitre_version' in obj:
                mitre_version = obj['x_mitre_version']
                break

        log_message(f"Processing MITRE ATT&CK version: {mitre_version}")

        # Clear existing techniques (transaction for safety)
        log_message("Clearing existing techniques")
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute("DELETE FROM technique;")

        # Process techniques with validation and normalization
        techniques_processed = 0
        techniques_skipped = 0
        validation_errors = []

        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
                # Extract technique data
                technique_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break

                # Validate technique ID
                if not validate_technique_id(technique_id):
                    validation_errors.append(f"Invalid technique ID: {technique_id}")
                    techniques_skipped += 1
                    continue

                # Extract and normalize data
                name = normalize_text(obj.get('name', ''))
                description = normalize_text(obj.get('description', ''))

                if not name:
                    validation_errors.append(f"Missing name for technique {technique_id}")
                    techniques_skipped += 1
                    continue

                # Validate and normalize timestamps
                created = validate_datetime(obj.get('created'))
                modified = validate_datetime(obj.get('modified'))

                # Handle sub-techniques
                subtechnique_of = None
                if 'x_mitre_is_subtechnique' in obj and obj['x_mitre_is_subtechnique']:
                    parent_id = technique_id.split('.')[0] if '.' in technique_id else None
                    if validate_technique_id(parent_id):
                        subtechnique_of = parent_id

                # Extract other fields with validation
                deprecated = bool(obj.get('x_mitre_deprecated', False))
                network_req = bool(obj.get('x_mitre_network_requirements', False))
                remote_support = bool(obj.get('x_mitre_remote_support', False))

                # Extract detection information
                detection = ""
                if 'x_mitre_detection' in obj:
                    detection = normalize_text(obj['x_mitre_detection'])

                try:
                    # Insert technique with MITRE ID
                    cursor.execute('''
                        INSERT OR REPLACE INTO technique
                        (id, name, description, created_time, modified_time, mitre_version,
                         mitre_detection, network_requirements, remote_support, deprecated, subtechnique_of)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (technique_id, name, description, created, modified, mitre_version,
                          detection, network_req, remote_support, deprecated, subtechnique_of))

                    # ALSO insert technique with UUID for wazuh-analysisd compatibility
                    uuid = obj.get('id', '')
                    if uuid and uuid.startswith('attack-pattern--'):
                        cursor.execute('''
                            INSERT OR REPLACE INTO technique
                            (id, name, description, created_time, modified_time, mitre_version,
                             mitre_detection, network_requirements, remote_support, deprecated, subtechnique_of)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (uuid, name, description, created, modified, mitre_version,
                              detection, network_req, remote_support, deprecated, subtechnique_of))

                    techniques_processed += 1

                    # Progress logging
                    if techniques_processed % 100 == 0:
                        log_message(f"Processed {techniques_processed} techniques...")

                except sqlite3.Error as e:
                    validation_errors.append(f"Database error for {technique_id}: {str(e)}")
                    techniques_skipped += 1

        # Update metadata
        cursor.execute("UPDATE metadata SET value = ? WHERE key = 'mitre_version'", (mitre_version,))
        cursor.execute("UPDATE metadata SET value = ? WHERE key = 'db_version'", ("2.1",))

        # Commit transaction
        cursor.execute("COMMIT;")

        # Validate final state
        final_count = cursor.execute("SELECT COUNT(*) FROM technique").fetchone()[0]

        log_message(f"Database population completed:")
        log_message(f"  - Techniques processed: {techniques_processed}")
        log_message(f"  - Techniques skipped: {techniques_skipped}")
        log_message(f"  - Final technique count: {final_count}")
        log_message(f"  - MITRE version: {mitre_version}")

        # Report validation errors (first 5)
        if validation_errors:
            log_message(f"Validation errors encountered: {len(validation_errors)}")
            for i, error in enumerate(validation_errors[:5]):
                log_message(f"  Error {i+1}: {error}")
            if len(validation_errors) > 5:
                log_message(f"  ... and {len(validation_errors) - 5} more errors")

        # Sanity checks
        if final_count < 500:
            log_message("ERROR: Final technique count too low", "ERROR")
            sys.exit(1)

        if techniques_skipped > techniques_processed * 0.1:  # More than 10% skipped
            log_message("ERROR: Too many techniques skipped during processing", "ERROR")
            sys.exit(1)

        conn.close()
        log_message("Database connection closed")

    except Exception as e:
        log_message(f"CRITICAL ERROR: Database population failed: {str(e)}", "ERROR")
        sys.exit(1)

# Execute population
populate_database()
PYTHON_SCRIPT

    # Replace placeholders with actual values
    local python_script_with_vars=$(cat << 'PYTHON_SCRIPT'
import json
import sqlite3
import sys
import re
from datetime import datetime

def log_message(msg, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {msg}")

def normalize_text(text):
    """Normalize text data for database storage"""
    if not text:
        return ""
    # Remove excessive whitespace and normalize
    text = re.sub(r'\s+', ' ', text.strip())
    # Limit length to prevent database issues
    if len(text) > 2000:
        text = text[:1997] + "..."
    return text

def validate_technique_id(tech_id):
    """Validate MITRE technique ID format"""
    if not tech_id:
        return False
    # Main technique: T1234 or sub-technique: T1234.001
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, tech_id))

def validate_datetime(dt_str):
    """Validate and normalize datetime strings"""
    if not dt_str:
        return None
    try:
        # Parse ISO format datetime
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return None

def populate_database():
    try:
        # Load JSON data
        json_file = 'TEMP_DIR_PLACEHOLDER/enterprise-attack.json'
        log_message(f"Loading JSON data from {json_file}")

        with open(json_file, 'r') as f:
            data = json.load(f)

        # Connect to database
        db_path = 'MITRE_DB_PLACEHOLDER'
        log_message(f"Connecting to database: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Extract MITRE version
        mitre_version = "17.1"  # Default fallback
        for obj in data.get('objects', []):
            if obj.get('type') == 'x-mitre-collection' and 'x_mitre_version' in obj:
                mitre_version = obj['x_mitre_version']
                break

        log_message(f"Processing MITRE ATT&CK version: {mitre_version}")

        # Clear existing techniques (transaction for safety)
        log_message("Clearing existing techniques")
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute("DELETE FROM technique;")

        # Process techniques with validation and normalization
        techniques_processed = 0
        techniques_skipped = 0
        validation_errors = []

        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
                # Extract technique data
                technique_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break

                # Validate technique ID
                if not validate_technique_id(technique_id):
                    validation_errors.append(f"Invalid technique ID: {technique_id}")
                    techniques_skipped += 1
                    continue

                # Extract and normalize data
                name = normalize_text(obj.get('name', ''))
                description = normalize_text(obj.get('description', ''))

                if not name:
                    validation_errors.append(f"Missing name for technique {technique_id}")
                    techniques_skipped += 1
                    continue

                # Validate and normalize timestamps
                created = validate_datetime(obj.get('created'))
                modified = validate_datetime(obj.get('modified'))

                # Handle sub-techniques
                subtechnique_of = None
                if 'x_mitre_is_subtechnique' in obj and obj['x_mitre_is_subtechnique']:
                    parent_id = technique_id.split('.')[0] if '.' in technique_id else None
                    if validate_technique_id(parent_id):
                        subtechnique_of = parent_id

                # Extract other fields with validation
                deprecated = bool(obj.get('x_mitre_deprecated', False))
                network_req = bool(obj.get('x_mitre_network_requirements', False))
                remote_support = bool(obj.get('x_mitre_remote_support', False))

                # Extract detection information
                detection = ""
                if 'x_mitre_detection' in obj:
                    detection = normalize_text(obj['x_mitre_detection'])

                try:
                    # Insert technique with MITRE ID
                    cursor.execute('''
                        INSERT OR REPLACE INTO technique
                        (id, name, description, created_time, modified_time, mitre_version,
                         mitre_detection, network_requirements, remote_support, deprecated, subtechnique_of)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (technique_id, name, description, created, modified, mitre_version,
                          detection, network_req, remote_support, deprecated, subtechnique_of))

                    # ALSO insert technique with UUID for wazuh-analysisd compatibility
                    uuid = obj.get('id', '')
                    if uuid and uuid.startswith('attack-pattern--'):
                        cursor.execute('''
                            INSERT OR REPLACE INTO technique
                            (id, name, description, created_time, modified_time, mitre_version,
                             mitre_detection, network_requirements, remote_support, deprecated, subtechnique_of)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (uuid, name, description, created, modified, mitre_version,
                              detection, network_req, remote_support, deprecated, subtechnique_of))

                    techniques_processed += 1

                    # Progress logging
                    if techniques_processed % 100 == 0:
                        log_message(f"Processed {techniques_processed} techniques...")

                except sqlite3.Error as e:
                    validation_errors.append(f"Database error for {technique_id}: {str(e)}")
                    techniques_skipped += 1

        # Update metadata
        cursor.execute("UPDATE metadata SET value = ? WHERE key = 'mitre_version'", (mitre_version,))
        cursor.execute("UPDATE metadata SET value = ? WHERE key = 'db_version'", ("2.1",))

        # Commit transaction
        cursor.execute("COMMIT;")

        # Validate final state
        final_count = cursor.execute("SELECT COUNT(*) FROM technique").fetchone()[0]

        log_message(f"Database population completed:")
        log_message(f"  - Techniques processed: {techniques_processed}")
        log_message(f"  - Techniques skipped: {techniques_skipped}")
        log_message(f"  - Final technique count: {final_count}")
        log_message(f"  - MITRE version: {mitre_version}")

        # Report validation errors (first 5)
        if validation_errors:
            log_message(f"Validation errors encountered: {len(validation_errors)}")
            for i, error in enumerate(validation_errors[:5]):
                log_message(f"  Error {i+1}: {error}")
            if len(validation_errors) > 5:
                log_message(f"  ... and {len(validation_errors) - 5} more errors")

        # Sanity checks
        if final_count < 500:
            log_message("ERROR: Final technique count too low", "ERROR")
            sys.exit(1)

        if techniques_skipped > techniques_processed * 0.1:  # More than 10% skipped
            log_message("ERROR: Too many techniques skipped during processing", "ERROR")
            sys.exit(1)

        conn.close()
        log_message("Database connection closed")

    except Exception as e:
        log_message(f"CRITICAL ERROR: Database population failed: {str(e)}", "ERROR")
        sys.exit(1)

# Execute population
populate_database()
PYTHON_SCRIPT
)

    # Replace placeholders and execute
    echo "$python_script_with_vars" | \
        sed "s|TEMP_DIR_PLACEHOLDER|$TEMP_DIR|g" | \
        sed "s|MITRE_DB_PLACEHOLDER|$MITRE_DB|g" | \
        python3

    if [ $? -eq 0 ]; then
        log_message "Database population completed successfully"
        report_success "Database populated with MITRE techniques"
        return 0
    else
        error_exit "Database population failed"
    fi
}

# Function to validate database after update
validate_database_post_update() {
    log_message "Validating database after update"

    # Check database integrity
    if ! sqlite3 "$MITRE_DB" "PRAGMA integrity_check;" | grep -q "ok"; then
        error_exit "Database integrity check failed after update"
    fi
    debug_log "Database integrity check passed"

    # Get updated stats
    local new_count=$(sqlite3 "$MITRE_DB" "SELECT COUNT(*) FROM technique;" 2>/dev/null || echo "0")
    local new_version=$(sqlite3 "$MITRE_DB" "SELECT value FROM metadata WHERE key='mitre_version';" 2>/dev/null || echo "unknown")

    # Compare with pre-update stats
    local old_count=$(cat "$TEMP_DIR/pre_update_count" 2>/dev/null || echo "0")
    local old_version=$(cat "$TEMP_DIR/pre_update_version" 2>/dev/null || echo "unknown")

    log_message "Database update comparison:"
    log_message "  Techniques: $old_count → $new_count"
    log_message "  Version: $old_version → $new_version"

    # Validation checks
    if [ "$new_count" -lt 500 ]; then
        error_exit "Post-update technique count too low ($new_count)"
    fi

    if [ "$new_count" -lt "$old_count" ]; then
        report_warning "Technique count decreased ($old_count → $new_count)"
    fi

    # Test sample queries
    local sample_techniques=("T1078" "T1484" "T1110" "T1190")
    local found_count=0
    for tech in "${sample_techniques[@]}"; do
        if sqlite3 "$MITRE_DB" "SELECT id FROM technique WHERE id='$tech';" | grep -q "$tech"; then
            ((found_count++))
            debug_log "Sample technique $tech found"
        else
            report_warning "Sample technique $tech not found"
        fi
    done

    log_message "Sample technique validation: $found_count/${#sample_techniques[@]} found"

    # Store final stats for report
    echo "$new_count" > "$TEMP_DIR/final_count"
    echo "$new_version" > "$TEMP_DIR/final_version"
    echo "$found_count" > "$TEMP_DIR/samples_found"

    report_success "Post-update validation completed"
}

# Function to add missing techniques (fallback)
add_missing_techniques() {
    debug_log "Adding commonly missing techniques as fallback"

    sqlite3 "$MITRE_DB" << 'SQL'
-- Add commonly missing techniques that might not be in main dataset
INSERT OR IGNORE INTO technique (id, name, description, mitre_version)
VALUES ('T1550.002', 'Use Alternate Authentication Material: Pass the Hash', 'Adversaries may pass the hash to authenticate to network services', '17.1');

INSERT OR IGNORE INTO technique (id, name, description, mitre_version, subtechnique_of)
VALUES ('T1550.003', 'Use Alternate Authentication Material: Pass the Ticket', 'Adversaries may pass the ticket to authenticate to network services', '17.1', 'T1550');
SQL

    debug_log "Added fallback techniques"
    report_success "Fallback techniques added"
}

# Function to verify database integrity and performance
verify_database() {
    log_message "Verifying database integrity and performance"

    # Check database integrity
    if ! sqlite3 "$MITRE_DB" "PRAGMA integrity_check;" | grep -q "ok"; then
        error_exit "Database integrity check failed"
    fi

    # Count techniques
    local count=$(sqlite3 "$MITRE_DB" "SELECT COUNT(*) FROM technique;")
    debug_log "Database contains $count techniques"

    # Check if we have a reasonable number of techniques
    if [ "$count" -lt 500 ]; then
        error_exit "Technique count seems low ($count) - expected 500+"
    fi

    # Check version
    local version=$(sqlite3 "$MITRE_DB" "SELECT value FROM metadata WHERE key='mitre_version';" 2>/dev/null || echo "unknown")
    log_message "MITRE version in database: $version"

    # Performance test
    local start_time=$(date +%s%N)
    sqlite3 "$MITRE_DB" "SELECT * FROM technique WHERE id='T1078';" >/dev/null
    local end_time=$(date +%s%N)
    local query_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    debug_log "Sample query performance: ${query_time}ms"

    if [ "$query_time" -gt 100 ]; then  # More than 100ms is concerning
        report_warning "Database query performance slow (${query_time}ms)"
    fi

    report_success "Database verification completed ($count techniques, version $version)"
    return 0
}

# Function to generate final console report
generate_final_report() {
    local status="$1"
    local error_msg="$2"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_formatted=$(date -d@$duration -u +%H:%M:%S)

    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                    MITRE DATABASE UPDATE REPORT                    ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║ Date: $(date '+%Y-%m-%d %H:%M:%S')                                           ║"
    echo "║ Duration: $duration_formatted                                                     ║"
    echo "║ Status: $status                                                   ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"

    if [ "$status" = "SUCCESS" ]; then
        # Success report
        local final_count=$(cat "$TEMP_DIR/final_count" 2>/dev/null || echo "unknown")
        local final_version=$(cat "$TEMP_DIR/final_version" 2>/dev/null || echo "unknown")
        local samples_found=$(cat "$TEMP_DIR/samples_found" 2>/dev/null || echo "unknown")
        local old_count=$(cat "$TEMP_DIR/pre_update_count" 2>/dev/null || echo "unknown")
        local old_version=$(cat "$TEMP_DIR/pre_update_version" 2>/dev/null || echo "unknown")

        echo "║ DATABASE STATISTICS:                                               ║"
        echo "║   Previous: $old_count techniques (version $old_version)                           ║"
        echo "║   Current:  $final_count techniques (version $final_version)                              ║"
        echo "║   Sample validation: $samples_found/4 techniques found                        ║"
        echo "║                                                                    ║"
        echo "║ PROCESS SUMMARY:                                                   ║"
        echo -e "$(echo "$REPORT_DATA" | sed 's/^/║ /')"
        echo "║                                                                    ║"
        echo "║ NEXT STEPS:                                                        ║"
        echo "║   • Monitor /var/ossec/logs/ossec.log for MITRE warnings          ║"
        echo "║   • Check wazuh-analysisd service health                          ║"
        echo "║   • Verify alert enrichment in dashboard                          ║"

    else
        # Failure report
        echo "║ ERROR DETAILS:                                                     ║"
        echo "║   $error_msg"
        echo "║                                                                    ║"
        echo "║ RECOVERY ACTIONS:                                                  ║"
        echo "║   • Database restored from backup (if applicable)                 ║"
        echo "║   • wazuh-analysisd service restarted                            ║"
        echo "║   • Check logs: /var/log/mitre-update.log                         ║"
        echo "║                                                                    ║"
        echo "║ EMERGENCY PROCEDURES:                                              ║"
        echo "║   • Use legacy script: /opt/mitre-db-autoupdate-v1-backup.sh     ║"
        echo "║   • Manual restore: cp /var/ossec/var/db/mitre.db.backup.* ...   ║"
        echo "║   • Contact GOLINE SOC team                                       ║"
    fi

    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║ LOG FILES:                                                         ║"
    echo "║   • Main log: /var/log/mitre-update.log                           ║"
    echo "║   • Wazuh log: /var/ossec/logs/ossec.log                          ║"
    echo "║   • Script: /opt/mitre-db-autoupdate.sh (v2.1)                   ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    # Also log the report
    {
        echo "=== FINAL REPORT ==="
        echo "Status: $status"
        echo "Duration: $duration_formatted"
        if [ "$status" = "SUCCESS" ]; then
            echo "Techniques: $old_count → $final_count"
            echo "Version: $old_version → $final_version"
        else
            echo "Error: $error_msg"
        fi
        echo "=================="
    } >> "$LOG_FILE"
}

# Main execution function
main() {
    log_message "Starting MITRE ATT&CK complete database update v2.1"

    # Trap to ensure cleanup
    trap cleanup EXIT

    # Check if database exists
    if [ ! -f "$MITRE_DB" ]; then
        error_exit "MITRE database not found at $MITRE_DB"
    fi

    # Check dependencies
    if ! command -v python3 >/dev/null 2>&1; then
        error_exit "Python3 not found"
    fi

    if ! command -v curl >/dev/null 2>&1; then
        error_exit "curl not found"
    fi

    if ! command -v bc >/dev/null 2>&1; then
        error_exit "bc (calculator) not found"
    fi

    report_success "Dependencies validated"

    # Network validation
    validate_network

    # Pre-update database validation
    validate_database_pre_update

    # Stop wazuh-analysisd before database modifications
    if ! stop_wazuh_analysisd; then
        error_exit "Failed to stop wazuh-analysisd service"
    fi

    # Download MITRE JSON
    if ! download_mitre_json; then
        start_wazuh_analysisd  # Restart service before exit
        error_exit "Failed to download MITRE data"
    fi

    # Validate JSON structure
    if ! validate_json_structure; then
        start_wazuh_analysisd
        error_exit "JSON validation failed"
    fi

    # Populate database
    if ! populate_mitre_database; then
        # Restore backup if available
        local latest_backup=$(ls -t "${MITRE_DB}.backup."* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            cp "$latest_backup" "$MITRE_DB"
            log_message "Restored database from backup: $latest_backup"
            set_database_permissions
        fi
        start_wazuh_analysisd
        error_exit "Failed to populate database"
    fi

    # Add missing techniques as fallback
    add_missing_techniques

    # Post-update validation
    validate_database_post_update

    # Verify database integrity
    if ! verify_database; then
        error_exit "Database verification failed"
    fi

    # Set correct database permissions
    if ! set_database_permissions; then
        error_exit "Failed to set database permissions"
    fi

    # Start wazuh-analysisd service
    if ! start_wazuh_analysisd; then
        error_exit "Failed to start wazuh-analysisd after database update"
    fi

    # Wait for service to fully initialize and start processing
    log_message "Waiting for wazuh-analysisd to initialize (15 seconds)"
    sleep 15

    # Monitor for errors in wazuh-analysisd
    log_message "Monitoring wazuh-analysisd for errors (30 seconds)"
    local monitor_start=$(date +%s)
    local error_found=false

    while [ $(($(date +%s) - monitor_start)) -lt 30 ]; do
        # Check if service is still running
        if ! systemctl is-active --quiet wazuh-analysisd; then
            error_exit "wazuh-analysisd stopped unexpectedly during monitoring"
        fi

        # Check for continuous errors in logs (last 10 lines)
        local recent_errors=$(tail -10 /var/ossec/logs/ossec.log 2>/dev/null | grep -i "error\|critical\|fatal" | wc -l)

        if [ "$recent_errors" -gt 5 ]; then
            report_warning "Detected high number of errors ($recent_errors) in recent logs"
            tail -10 /var/ossec/logs/ossec.log 2>/dev/null | grep -i "error\|critical\|fatal" | tail -3 >> "$LOG_FILE"
        fi

        sleep 5
    done

    # Final check for MITRE warnings
    log_message "Checking for MITRE warnings in Wazuh logs"
    sleep 5  # Give some time for processing
    local warning_count=$(tail -50 /var/ossec/logs/ossec.log 2>/dev/null | grep 'Mitre.*not found' | wc -l)

    if [ "$warning_count" = "0" ]; then
        log_message "SUCCESS: No MITRE warnings detected - update completed successfully"
        report_success "Zero MITRE warnings detected"
    else
        log_message "INFO: Detected $warning_count MITRE warnings (may be normal during initialization)"
        report_warning "$warning_count MITRE warnings still present"
        # Show recent warnings for debugging
        tail -50 /var/ossec/logs/ossec.log 2>/dev/null | grep 'Mitre.*not found' | tail -5 >> "$LOG_FILE"
    fi

    # Final service status check
    if systemctl is-active --quiet wazuh-analysisd; then
        log_message "SUCCESS: wazuh-analysisd is running normally after update"
        report_success "wazuh-analysisd service healthy"
    else
        error_exit "wazuh-analysisd is not running after update"
    fi

    # Generate success report
    generate_final_report "SUCCESS"

    log_message "MITRE ATT&CK database update completed successfully"
}

# Run main function
main "$@"
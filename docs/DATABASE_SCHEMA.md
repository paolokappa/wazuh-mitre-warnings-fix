# 🗄️ MITRE Database Schema & Structure

## 📋 Overview

Complete documentation of the MITRE ATT&CK database schema used by Wazuh, including table structures, relationships, and query patterns.

---

## 📊 Database Details

### File Information
- **Location**: `/var/ossec/var/db/mitre.db`
- **Type**: SQLite3 database
- **Size**: ~16MB (after dual-record fix)
- **Encoding**: UTF-8
- **Permissions**: `root:wazuh 660`
- **MITRE Version**: v17.1 (May 2025)

### Record Counts (After Fix)
| Table | Records | Description |
|-------|---------|-------------|
| **technique** | **1,382** | **691 MITRE IDs + 691 UUIDs** |
| **tactic** | 14 | Attack lifecycle phases |
| **mitigation** | 200+ | Defensive measures |
| **group** | 150+ | Threat actor groups |
| **software** | 500+ | Tools and malware |
| **phase** | 2,000+ | Technique-tactic mappings |

---

## 🏗️ Table Structures

### Primary Tables

#### Technique Table (Critical)
```sql
CREATE TABLE technique (
    id VARCHAR PRIMARY KEY,                -- T1078 OR attack-pattern--uuid
    name VARCHAR NOT NULL,                 -- "Valid Accounts"
    description VARCHAR,                   -- Full technique description
    created_time DATETIME,                 -- STIX creation timestamp
    modified_time DATETIME,                -- STIX modification timestamp
    mitre_version VARCHAR,                 -- "17.1"
    mitre_detection VARCHAR,               -- Detection guidance
    network_requirements BOOLEAN,          -- Requires network access
    remote_support BOOLEAN,                -- Supports remote execution
    revoked_by VARCHAR,                    -- Replacement technique ID
    deprecated BOOLEAN,                    -- Deprecation status
    subtechnique_of VARCHAR                -- Parent technique
);
```

**Key Features**:
- **Dual Record System**: Each technique has TWO records
  - MITRE ID: `T1078` (human reference)
  - UUID: `attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81` (wazuh-analysisd)
- **Hierarchical Support**: Sub-techniques linked via `subtechnique_of`
- **Temporal Tracking**: Creation and modification timestamps

#### Tactic Table
```sql
CREATE TABLE tactic (
    id VARCHAR PRIMARY KEY,                -- TA0001
    name VARCHAR NOT NULL,                 -- "Initial Access"
    description VARCHAR,                   -- Tactic description
    created_time DATETIME,
    modified_time DATETIME,
    mitre_version VARCHAR
);
```

**14 Standard Tactics**:
- TA0001: Initial Access
- TA0002: Execution
- TA0003: Persistence
- TA0004: Privilege Escalation
- TA0005: Defense Evasion
- TA0006: Credential Access
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0009: Collection
- TA0010: Exfiltration
- TA0011: Command and Control
- TA0040: Impact

---

## 🔍 Critical Queries

### wazuh-analysisd Queries

#### Primary Technique Lookup (Most Frequent)
```sql
-- What wazuh-analysisd actually searches for:
SELECT id, name, description
FROM technique
WHERE id = 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81';
-- NOT: WHERE id = 'T1078';
```

#### Dual Record Verification
```sql
-- Verify both records exist for a technique
SELECT id, name FROM technique
WHERE name = 'Valid Accounts'
ORDER BY id;

-- Expected result:
-- T1078|Valid Accounts
-- attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81|Valid Accounts
```

### Database Health Checks

#### Record Count Analysis
```sql
-- Analyze record distribution
SELECT
  CASE
    WHEN id LIKE 'T%' THEN 'MITRE_ID'
    WHEN id LIKE 'attack-pattern--%' THEN 'UUID'
    ELSE 'OTHER'
  END as type,
  COUNT(*) as count
FROM technique
GROUP BY type;

-- Expected after fix:
-- MITRE_ID|691
-- UUID|691
```

#### Integrity Verification
```sql
-- Database integrity check
PRAGMA integrity_check;

-- Foreign key consistency
PRAGMA foreign_key_check;

-- Version verification
SELECT key, value FROM metadata
WHERE key IN ('mitre_version', 'db_version');
```

---

## ⚠️ Critical Discovery: UUID vs MITRE ID

### Root Cause Analysis

**The Problem**: wazuh-analysisd searches for techniques using STIX UUIDs, not MITRE IDs.

#### Evidence
```sql
-- Rule contains: <mitre><id>T1078</id></mitre>
-- wazuh-analysisd internally converts T1078 to UUID
-- Then searches: WHERE id = 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81'
-- If only MITRE ID record exists: NOT FOUND → WARNING
```

#### The Solution
```sql
-- OLD: Only MITRE ID record (causes warnings)
INSERT INTO technique VALUES ('T1078', 'Valid Accounts', ...);

-- NEW: BOTH records (eliminates warnings)
INSERT INTO technique VALUES ('T1078', 'Valid Accounts', ...);
INSERT INTO technique VALUES ('attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81', 'Valid Accounts', ...);
```

### STIX UUID Format
```
attack-pattern--{8-4-4-4-12 UUID format}
attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81
```

---

## 🔧 Database Maintenance

### Performance Optimization

#### Index Analysis
```sql
-- View existing indexes
.schema technique

-- Query performance test
.timer on
SELECT * FROM technique WHERE id='T1078';
.timer off
```

#### Database Optimization
```sql
-- Optimize database
VACUUM;
ANALYZE;

-- Space analysis
.dbinfo
```

### Backup Verification

#### Backup Integrity Check
```sql
-- Verify backup completeness
SELECT
  (SELECT COUNT(*) FROM technique) as techniques,
  (SELECT COUNT(*) FROM tactic) as tactics,
  (SELECT value FROM metadata WHERE key='mitre_version') as version;
```

#### Recovery Testing
```bash
# Test backup restoration
cp /var/ossec/var/db/mitre.db.backup.LATEST /tmp/test_restore.db
sqlite3 /tmp/test_restore.db "SELECT COUNT(*) FROM technique;"
```

---

## 📊 Data Relationships

### Technique-Tactic Mapping
```sql
-- Get all tactics for a technique
SELECT t.name as tactic_name
FROM technique tech
JOIN phase p ON tech.id = p.technique_id
JOIN tactic t ON p.tactic_id = t.id
WHERE tech.id = 'T1078';
```

### Platform Filtering
```sql
-- Get Windows-specific techniques
SELECT tech.id, tech.name
FROM technique tech
JOIN platform plat ON tech.id = plat.technique_id
WHERE plat.platform_name = 'Windows'
LIMIT 10;
```

### Sub-technique Hierarchy
```sql
-- Get all sub-techniques for T1078
SELECT id, name
FROM technique
WHERE subtechnique_of = 'T1078'
ORDER BY id;
```

---

## 🚨 Troubleshooting Queries

### Missing Technique Diagnosis
```sql
-- Check if specific technique exists
SELECT id, name FROM technique WHERE id = 'T1078';
SELECT id, name FROM technique WHERE name = 'Valid Accounts';

-- If MITRE ID exists but UUID missing:
SELECT COUNT(*) FROM technique WHERE id LIKE 'attack-pattern%' AND name = 'Valid Accounts';
```

### Warning Pattern Analysis
```sql
-- Find techniques with only MITRE ID (problematic)
SELECT t1.id, t1.name
FROM technique t1
WHERE t1.id LIKE 'T%'
AND NOT EXISTS (
    SELECT 1 FROM technique t2
    WHERE t2.name = t1.name
    AND t2.id LIKE 'attack-pattern%'
);
```

### Database Corruption Detection
```sql
-- Detect inconsistencies
SELECT name, COUNT(*) as duplicate_count
FROM technique
GROUP BY name
HAVING COUNT(*) != 2  -- Should be exactly 2 (MITRE ID + UUID)
ORDER BY duplicate_count DESC;
```

---

## 📈 Performance Metrics

### Query Performance Targets
- **Technique Lookup**: <1ms
- **Complex Joins**: <10ms
- **Full Table Scans**: <100ms
- **Database Size**: <20MB

### Monitoring Queries
```sql
-- Slow query detection
.timer on
SELECT COUNT(*) FROM technique t1
JOIN phase p ON t1.id = p.technique_id
JOIN tactic t2 ON p.tactic_id = t2.id;
.timer off
```

---

## 🔗 Integration Points

### wazuh-analysisd Integration
- **Connection Type**: Direct SQLite access
- **Query Pattern**: UUID-based lookups
- **Caching**: In-memory technique cache
- **Performance**: Critical path for rule processing

### API Integration
- **Endpoint**: `/mitre/techniques`
- **Format**: JSON responses
- **Caching**: 1-hour cache timeout
- **Authentication**: RBAC-controlled

### Dashboard Integration
- **Module**: MITRE ATT&CK framework view
- **Queries**: Aggregated technique statistics
- **Real-time**: 30-second refresh rate
- **Filtering**: Platform, tactic, time-based

---

**Document Version**: 1.0
**Created**: September 20, 2025
**Database Schema**: Compatible with MITRE ATT&CK v17.1
**Critical Fix**: Dual-record system implemented for UUID compatibility
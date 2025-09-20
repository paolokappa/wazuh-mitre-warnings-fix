#!/usr/bin/env python3
"""
Wazuh MITRE API Integration Examples
===================================

This script demonstrates how to interact with the Wazuh API to access
MITRE ATT&CK data after applying the UUID compatibility fix.

Requirements:
    pip install requests

Usage:
    python3 api_examples.py

Author: GitHub @paolokappa
License: MIT
"""

import requests
import json
import urllib3
from datetime import datetime, timedelta

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhMitreAPI:
    """
    Wazuh MITRE API client with comprehensive examples
    """

    def __init__(self, base_url="https://localhost:55000", username="wazuh-user", password="your-password"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.session.verify = False

        # Authenticate and get token
        self._authenticate()

    def _authenticate(self):
        """Authenticate with Wazuh API and get JWT token"""
        try:
            response = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password)
            )
            response.raise_for_status()

            data = response.json()
            if data.get('error') == 0:
                self.token = data['data']['token']
                self.session.headers.update({
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
                })
                print(f"✅ Successfully authenticated with Wazuh API")
            else:
                raise Exception(f"Authentication failed: {data}")

        except Exception as e:
            print(f"❌ Authentication error: {e}")
            raise

    def get_technique(self, technique_id):
        """
        Get detailed information about a specific MITRE technique

        Args:
            technique_id (str): MITRE technique ID (e.g., 'T1078')

        Returns:
            dict: Technique information
        """
        try:
            response = self.session.get(f"{self.base_url}/mitre/techniques/{technique_id}")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting technique {technique_id}: {e}")
            return None

    def get_all_techniques(self, limit=None):
        """
        Get all MITRE techniques

        Args:
            limit (int, optional): Limit number of results

        Returns:
            dict: All techniques
        """
        try:
            url = f"{self.base_url}/mitre/techniques"
            if limit:
                url += f"?limit={limit}"

            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting all techniques: {e}")
            return None

    def get_sub_techniques(self, parent_technique):
        """
        Get sub-techniques for a parent technique

        Args:
            parent_technique (str): Parent technique ID (e.g., 'T1078')

        Returns:
            dict: Sub-techniques
        """
        try:
            response = self.session.get(
                f"{self.base_url}/mitre/techniques?subtechnique_of={parent_technique}"
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting sub-techniques for {parent_technique}: {e}")
            return None

    def get_tactics(self):
        """
        Get all MITRE tactics

        Returns:
            dict: All tactics
        """
        try:
            response = self.session.get(f"{self.base_url}/mitre/tactics")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting tactics: {e}")
            return None

    def get_mitigations(self, limit=None):
        """
        Get MITRE mitigations

        Args:
            limit (int, optional): Limit number of results

        Returns:
            dict: Mitigations
        """
        try:
            url = f"{self.base_url}/mitre/mitigations"
            if limit:
                url += f"?limit={limit}"

            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting mitigations: {e}")
            return None

    def get_groups(self, limit=None):
        """
        Get MITRE threat actor groups

        Args:
            limit (int, optional): Limit number of results

        Returns:
            dict: Threat actor groups
        """
        try:
            url = f"{self.base_url}/mitre/groups"
            if limit:
                url += f"?limit={limit}"

            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting groups: {e}")
            return None

    def get_alerts_with_mitre(self, technique_id=None, limit=100):
        """
        Get alerts that contain MITRE technique information

        Args:
            technique_id (str, optional): Filter by specific technique
            limit (int): Limit number of results

        Returns:
            dict: Alerts with MITRE data
        """
        try:
            url = f"{self.base_url}/alerts?limit={limit}"
            if technique_id:
                url += f"&mitre.technique={technique_id}"

            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error getting alerts: {e}")
            return None

    def verify_fix_status(self):
        """
        Verify that the MITRE UUID fix is working correctly

        Returns:
            dict: Fix verification results
        """
        print("\n🔍 Verifying MITRE UUID fix status...")

        results = {
            'total_techniques': 0,
            'sample_techniques': [],
            'uuid_compatibility': False,
            'common_techniques_found': [],
            'fix_status': 'unknown'
        }

        try:
            # Get total technique count
            all_techniques = self.get_all_techniques(limit=1)
            if all_techniques:
                results['total_techniques'] = all_techniques['data']['total_affected_items']
                print(f"📊 Total techniques in database: {results['total_techniques']}")

                # Check if we have the expected count (should be ~1382 after fix)
                if results['total_techniques'] >= 1300:
                    results['uuid_compatibility'] = True
                    print("✅ UUID compatibility fix appears to be working (high technique count)")
                else:
                    print("⚠️  Low technique count - UUID fix may not be applied")

            # Test common techniques that previously caused warnings
            common_problematic_techniques = ['T1078', 'T1484', 'T1550.002', 'T1110', 'T1190']

            for technique_id in common_problematic_techniques:
                technique_data = self.get_technique(technique_id)
                if technique_data and technique_data.get('data', {}).get('affected_items'):
                    technique_info = technique_data['data']['affected_items'][0]
                    results['common_techniques_found'].append({
                        'id': technique_id,
                        'name': technique_info.get('name', 'Unknown'),
                        'found': True
                    })
                    print(f"✅ {technique_id}: {technique_info.get('name', 'Unknown')}")
                else:
                    results['common_techniques_found'].append({
                        'id': technique_id,
                        'name': 'Not Found',
                        'found': False
                    })
                    print(f"❌ {technique_id}: Not found")

            # Determine overall fix status
            found_count = sum(1 for t in results['common_techniques_found'] if t['found'])
            if found_count == len(common_problematic_techniques):
                results['fix_status'] = 'success'
                print("\n🎉 MITRE UUID fix verification: SUCCESS")
                print("   All common techniques found - warnings should be eliminated")
            elif found_count > 0:
                results['fix_status'] = 'partial'
                print(f"\n⚠️  MITRE UUID fix verification: PARTIAL ({found_count}/{len(common_problematic_techniques)} found)")
            else:
                results['fix_status'] = 'failed'
                print("\n❌ MITRE UUID fix verification: FAILED")
                print("   No techniques found - fix may not be applied correctly")

        except Exception as e:
            print(f"❌ Error during fix verification: {e}")
            results['fix_status'] = 'error'

        return results

def example_technique_analysis():
    """Example: Analyze specific MITRE techniques"""
    print("\n" + "="*50)
    print("🎯 MITRE Technique Analysis Example")
    print("="*50)

    api = WazuhMitreAPI()

    # Analyze T1078 (Valid Accounts) - commonly problematic technique
    technique_id = "T1078"
    print(f"\n📋 Analyzing technique: {technique_id}")

    # Get main technique
    technique = api.get_technique(technique_id)
    if technique and technique['data']['affected_items']:
        tech_data = technique['data']['affected_items'][0]
        print(f"   Name: {tech_data['name']}")
        print(f"   Description: {tech_data['description'][:100]}...")
        print(f"   MITRE Version: {tech_data.get('mitre_version', 'Unknown')}")
        print(f"   Deprecated: {tech_data.get('deprecated', False)}")

        # Get sub-techniques
        sub_techniques = api.get_sub_techniques(technique_id)
        if sub_techniques and sub_techniques['data']['affected_items']:
            print(f"\n   Sub-techniques ({len(sub_techniques['data']['affected_items'])}):")
            for sub_tech in sub_techniques['data']['affected_items'][:5]:
                print(f"     - {sub_tech['id']}: {sub_tech['name']}")
    else:
        print(f"❌ Technique {technique_id} not found!")

def example_alert_correlation():
    """Example: Correlate alerts with MITRE techniques"""
    print("\n" + "="*50)
    print("🚨 Alert-MITRE Correlation Example")
    print("="*50)

    api = WazuhMitreAPI()

    # Get recent alerts with MITRE data
    alerts = api.get_alerts_with_mitre(limit=10)

    if alerts and alerts['data']['affected_items']:
        print(f"📊 Found {len(alerts['data']['affected_items'])} recent alerts with MITRE data")

        # Analyze MITRE technique distribution
        technique_count = {}
        for alert in alerts['data']['affected_items']:
            mitre_data = alert.get('rule', {}).get('mitre', {})
            if mitre_data.get('technique'):
                for technique in mitre_data['technique']:
                    tech_id = technique.get('id', 'Unknown')
                    technique_count[tech_id] = technique_count.get(tech_id, 0) + 1

        if technique_count:
            print("\n🎯 Most common MITRE techniques in recent alerts:")
            for tech_id, count in sorted(technique_count.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"   {tech_id}: {count} alerts")
        else:
            print("⚠️  No MITRE-enriched alerts found in recent data")
    else:
        print("❌ No recent alerts found")

def example_threat_landscape():
    """Example: Analyze threat landscape using MITRE data"""
    print("\n" + "="*50)
    print("🌍 Threat Landscape Analysis Example")
    print("="*50)

    api = WazuhMitreAPI()

    # Get tactics overview
    tactics = api.get_tactics()
    if tactics and tactics['data']['affected_items']:
        print(f"📊 MITRE ATT&CK Tactics ({len(tactics['data']['affected_items'])}):")
        for tactic in tactics['data']['affected_items'][:5]:
            print(f"   - {tactic['id']}: {tactic['name']}")

    # Get threat actor groups
    groups = api.get_groups(limit=10)
    if groups and groups['data']['affected_items']:
        print(f"\n🎭 Threat Actor Groups (sample of {len(groups['data']['affected_items'])}):")
        for group in groups['data']['affected_items'][:5]:
            print(f"   - {group['id']}: {group['name']}")

    # Get mitigations
    mitigations = api.get_mitigations(limit=10)
    if mitigations and mitigations['data']['affected_items']:
        print(f"\n🛡️  Available Mitigations (sample of {len(mitigations['data']['affected_items'])}):")
        for mitigation in mitigations['data']['affected_items'][:5]:
            print(f"   - {mitigation['id']}: {mitigation['name']}")

def example_automated_reporting():
    """Example: Generate automated MITRE report"""
    print("\n" + "="*50)
    print("📈 Automated MITRE Reporting Example")
    print("="*50)

    api = WazuhMitreAPI()

    # Generate summary report
    report = {
        'timestamp': datetime.now().isoformat(),
        'mitre_database_status': {},
        'recent_activity': {},
        'recommendations': []
    }

    # Database status
    all_techniques = api.get_all_techniques(limit=1)
    if all_techniques:
        report['mitre_database_status'] = {
            'total_techniques': all_techniques['data']['total_affected_items'],
            'version_status': 'current' if all_techniques['data']['total_affected_items'] >= 1300 else 'outdated',
            'last_checked': datetime.now().isoformat()
        }

    # Recent alert activity
    alerts = api.get_alerts_with_mitre(limit=50)
    if alerts:
        techniques_in_alerts = set()
        for alert in alerts['data']['affected_items']:
            mitre_data = alert.get('rule', {}).get('mitre', {})
            if mitre_data.get('technique'):
                for technique in mitre_data['technique']:
                    techniques_in_alerts.add(technique.get('id'))

        report['recent_activity'] = {
            'alerts_with_mitre': len(alerts['data']['affected_items']),
            'unique_techniques_detected': len(techniques_in_alerts),
            'most_active_techniques': list(techniques_in_alerts)[:10]
        }

    # Generate recommendations
    if report['mitre_database_status'].get('total_techniques', 0) < 1300:
        report['recommendations'].append("Consider updating MITRE database - technique count appears low")

    if report['recent_activity'].get('alerts_with_mitre', 0) == 0:
        report['recommendations'].append("No MITRE-enriched alerts found - verify rule configuration")

    # Display report
    print(f"📊 MITRE Database Status:")
    print(f"   Total Techniques: {report['mitre_database_status'].get('total_techniques', 'Unknown')}")
    print(f"   Status: {report['mitre_database_status'].get('version_status', 'Unknown')}")

    print(f"\n🚨 Recent Activity (last 50 alerts):")
    print(f"   MITRE-enriched alerts: {report['recent_activity'].get('alerts_with_mitre', 0)}")
    print(f"   Unique techniques: {report['recent_activity'].get('unique_techniques_detected', 0)}")

    if report['recommendations']:
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   - {rec}")
    else:
        print(f"\n✅ No issues detected")

    return report

def example_integration_testing():
    """Example: Test external system integration"""
    print("\n" + "="*50)
    print("🔌 Integration Testing Example")
    print("="*50)

    api = WazuhMitreAPI()

    # Test data export format for SIEM integration
    print("📤 Testing SIEM export format...")

    # Get sample alert with MITRE data
    alerts = api.get_alerts_with_mitre(limit=1)
    if alerts and alerts['data']['affected_items']:
        alert = alerts['data']['affected_items'][0]

        # Format for Splunk HEC
        splunk_format = {
            'time': int(datetime.now().timestamp()),
            'source': 'wazuh',
            'sourcetype': 'wazuh:alert',
            'index': 'security',
            'event': {
                'alert_id': alert.get('id', 'unknown'),
                'rule_id': alert.get('rule', {}).get('id', 'unknown'),
                'rule_description': alert.get('rule', {}).get('description', 'unknown'),
                'agent_name': alert.get('agent', {}).get('name', 'unknown'),
                'mitre_techniques': [t.get('id') for t in alert.get('rule', {}).get('mitre', {}).get('technique', [])],
                'mitre_tactics': []
            }
        }

        # Extract tactics
        for technique in alert.get('rule', {}).get('mitre', {}).get('technique', []):
            splunk_format['event']['mitre_tactics'].extend(technique.get('tactic', []))

        print("✅ Splunk HEC format:")
        print(json.dumps(splunk_format, indent=2))

        # Format for QRadar LEEF
        leef_format = (
            f"LEEF:2.0|Wazuh|SIEM|4.10|{alert.get('rule', {}).get('id', 'unknown')}|"
            f"cat=Security|"
            f"devTime={datetime.now().strftime('%b %d %Y %H:%M:%S')}|"
            f"src={alert.get('data', {}).get('srcip', 'unknown')}|"
            f"usrName={alert.get('data', {}).get('dstuser', 'unknown')}|"
            f"mitreTechniques={','.join([t.get('id', '') for t in alert.get('rule', {}).get('mitre', {}).get('technique', [])])}|"
            f"severity={alert.get('rule', {}).get('level', 0)}"
        )

        print(f"\n✅ QRadar LEEF format:")
        print(leef_format)
    else:
        print("❌ No MITRE-enriched alerts available for testing")

def main():
    """Main function to run all examples"""
    print("🚀 Wazuh MITRE API Integration Examples")
    print("=" * 60)

    try:
        # Initialize API client
        api = WazuhMitreAPI()

        # Run fix verification first
        fix_results = api.verify_fix_status()

        if fix_results['fix_status'] == 'success':
            print("\n🎉 MITRE fix verified successfully! Running examples...")

            # Run all examples
            example_technique_analysis()
            example_alert_correlation()
            example_threat_landscape()
            example_automated_reporting()
            example_integration_testing()

        else:
            print(f"\n⚠️  MITRE fix status: {fix_results['fix_status']}")
            print("Some examples may not work correctly until the fix is properly applied.")

            # Still run basic examples
            example_technique_analysis()

        print("\n" + "="*60)
        print("✅ All examples completed successfully!")
        print("📚 For more information, visit:")
        print("   https://github.com/paolokappa/wazuh-mitre-warnings-fix")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("\nTroubleshooting tips:")
        print("1. Verify Wazuh API is accessible")
        print("2. Check credentials are correct")
        print("3. Ensure MITRE database is properly configured")
        print("4. Review Wazuh logs for any errors")

if __name__ == "__main__":
    main()
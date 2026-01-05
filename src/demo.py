"""
Demo Script - Simulates Various Attack Scenarios
Run this to see how the system detects and responds to different threats
"""
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection.rules import (
    SuspiciousLoginDetector,
    AbnormalAPIDetector,
    PrivilegeEscalationDetector
)
from src.agents.orchestrator import AgentOrchestrator
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)


def scenario_credential_stuffing():
    """
    Scenario 1: Credential Stuffing Attack
    
    Attacker uses stolen credentials to attempt logins
    Characteristics:
    - Multiple failed logins
    - Automated tools (headless browsers)
    - VPN/foreign IP
    """
    print("\n" + "="*70)
    print("📋 SCENARIO 1: Credential Stuffing Attack")
    print("="*70 + "\n")
    
    detector = SuspiciousLoginDetector()
    orchestrator = AgentOrchestrator()
    
    # Simulate attack logs
    logs = []
    base_time = datetime.now()
    
    for i in range(7):
        logs.append({
            "timestamp": (base_time - timedelta(minutes=10-i)).isoformat(),
            "user_id": "user-alice-001",
            "status": "failed",
            "ip": "185.220.101.45",  # Known VPN provider
            "country": "NL",
            "user_agent": "HeadlessChrome/91.0.4472.124"
        })
    
    user_profile = {
        "typical_countries": ["US"],
        "typical_hours": range(9, 18),
        "account_age_days": 365,
        "role": "user"
    }
    
    # Detect
    alert = detector.detect(logs, user_profile)
    
    if alert:
        print(f"   ALERT GENERATED")
        print(f"   ID: {alert.alert_id}")
        print(f"   Confidence: {alert.confidence}/100")
        print(f"   Signals detected: {len(alert.signals)}\n")
        
        # Investigate
        result = orchestrator.investigate(alert, dry_run=False)
        print(orchestrator.get_human_summary(result))
    else:
        print("  No alert generated (unexpected)")


def scenario_api_abuse():
    """
    Scenario 2: Bulk Data Extraction
    
    Attacker attempts to enumerate all user IDs sequentially
    Characteristics:
    - High request rate
    - Sequential resource access
    - Outside normal usage pattern
    """
    print("\n" + "="*70)
    print("📋 SCENARIO 2: Bulk Data Extraction via API")
    print("="*70 + "\n")
    
    detector = AbnormalAPIDetector()
    orchestrator = AgentOrchestrator()
    
    # Simulate sequential ID enumeration
    logs = []
    base_time = datetime.now()
    
    for i in range(15):
        logs.append({
            "timestamp": (base_time - timedelta(seconds=60-i*2)).isoformat(),
            "user_id": "user-bob-002",
            "endpoint": f"/api/v1/users/{1000 + i}",
            "status": 200,
            "ip": "203.0.113.45",
            "params": ""
        })
    
    user_profile = {
        "typical_endpoints": ["/api/v1/dashboard"],
        "average_requests_per_day": 50,
        "role": "user"
    }
    
    # Detect
    alert = detector.detect(logs, user_profile)
    
    if alert:
        print(f"   ALERT GENERATED")
        print(f"   ID: {alert.alert_id}")
        print(f"   Confidence: {alert.confidence}/100")
        print(f"   Signals detected: {len(alert.signals)}\n")
        
        # Investigate
        result = orchestrator.investigate(alert, dry_run=False)
        print(orchestrator.get_human_summary(result))
    else:
        print("  No alert generated (unexpected)")


def scenario_privilege_escalation():
    """
    Scenario 3: Privilege Escalation Attempt
    
    Attacker gains initial access and attempts to elevate privileges
    Characteristics:
    - Service account used from external IP
    - Unauthorized role changes
    - Admin command execution
    """
    print("\n" + "="*70)
    print("📋 SCENARIO 3: Privilege Escalation")
    print("="*70 + "\n")
    
    detector = PrivilegeEscalationDetector()
    orchestrator = AgentOrchestrator()
    
    # Simulate privilege escalation
    logs = [
        {
            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "user_id": "svc-data-pipeline",
            "action": "login",
            "ip": "203.0.113.100",  # External IP
        },
        {
            "timestamp": (datetime.now() - timedelta(minutes=3)).isoformat(),
            "user_id": "svc-data-pipeline",
            "action": "role_change",
            "old_role": "service",
            "new_role": "admin",
            "approval_ticket": None,  # No approval!
            "ip": "203.0.113.100"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "svc-data-pipeline",
            "action": "update_iam_policy",
            "policy_name": "DatabaseAccessPolicy",
            "scope_change": "expanded",
            "ip": "203.0.113.100"
        }
    ]
    
    user_profile = {
        "role": "service_account",
        "typical_ips": ["10.0.1.0/24"]  # Internal only
    }
    
    # Detect
    alert = detector.detect(logs, user_profile)
    
    if alert:
        print(f"   ALERT GENERATED")
        print(f"   ID: {alert.alert_id}")
        print(f"   Confidence: {alert.confidence}/100")
        print(f"   Signals detected: {len(alert.signals)}\n")
        
        # Investigate
        result = orchestrator.investigate(alert, dry_run=False)
        print(orchestrator.get_human_summary(result))
    else:
        print("  No alert generated (unexpected)")


def scenario_false_positive():
    """
    Scenario 4: False Positive (Traveling Employee)
    
    Legitimate user traveling for work
    Should generate alert but with lower confidence
    Demonstrates system's ability to identify ambiguous cases
    """
    print("\n" + "="*70)
    print("📋 SCENARIO 4: Potential False Positive (Traveling Employee)")
    print("="*70 + "\n")
    
    detector = SuspiciousLoginDetector()
    orchestrator = AgentOrchestrator()
    
    # Employee traveling to conference
    logs = [
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-charlie-003",
            "status": "success",
            "ip": "8.8.8.8",
            "country": "DE",  # Germany
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        }
    ]
    
    user_profile = {
        "typical_countries": ["US"],
        "typical_hours": range(9, 18),
        "account_age_days": 730,  # Long-term employee
        "role": "engineer",
        "mfa_enabled": True  # Has MFA enabled
    }
    
    # Detect
    alert = detector.detect(logs, user_profile)
    
    if alert:
        print(f"   ALERT GENERATED")
        print(f"   ID: {alert.alert_id}")
        print(f"   Confidence: {alert.confidence}/100")
        print(f"   Signals detected: {len(alert.signals)}\n")
        print(f"   NOTE: This should have lower confidence and likely escalate to human\n")
        
        # Investigate
        result = orchestrator.investigate(alert, dry_run=False)
        print(orchestrator.get_human_summary(result))
    else:
        print("  No alert generated")


def main():
    """Run all scenarios"""
    # print("\n" + "🎯" * 35)
    print("THREAT DETECTION SYSTEM - DEMO SCENARIOS")
    # print("🎯" * 35)
    
    scenarios = [
        ("Credential Stuffing", scenario_credential_stuffing),
        ("API Data Extraction", scenario_api_abuse),
        ("Privilege Escalation", scenario_privilege_escalation),
        ("False Positive Case", scenario_false_positive)
    ]
    
    for name, scenario_func in scenarios:
        try:
            scenario_func()
        except Exception as e:
            print(f"\n Error in scenario '{name}': {str(e)}\n")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue to next scenario...")
    
    print("\n" + "="*70)
    print("   All scenarios completed!")
    print("="*70 + "\n")
    
    print("Key Observations:")
    print("1. High-confidence threats → automatic blocking")
    print("2. Ambiguous cases → escalation to humans")
    print("3. All decisions include clear reasoning")
    print("4. Safety checks prevent inappropriate actions")
    print("\nThis demonstrates how the system balances automation with safety.")


if __name__ == "__main__":
    main()

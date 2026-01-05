#!/usr/bin/env python3
"""
Quick test to verify the threat detection system works
Run this after setup to confirm everything is functioning
"""

import sys
from datetime import datetime


def test_detection():
    """Test detection engine"""
    print("🔍 Testing Detection Engine...")
    
    from src.detection.rules import SuspiciousLoginDetector
    
    detector = SuspiciousLoginDetector()
    
    # Create suspicious logs
    logs = []
    for i in range(6):
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "status": "failed",
            "ip": "1.2.3.4",
            "country": "RU",
            "user_agent": "HeadlessChrome"
        })
    
    alert = detector.detect(logs)
    
    if alert:
        print(f"   Alert generated: {alert.alert_id}")
        print(f"   Confidence: {alert.confidence}/100")
        print(f"   Signals: {len(alert.signals)}")
        return True
    else:
        print("     Detection failed")
        return False


def test_agents():
    """Test AI agents"""
    print("\n🤖 Testing AI Agents...")
    
    from src.agents.reasoning import ReasoningAgent
    from src.agents.context import ContextAgent, MockStorageClient
    from src.detection.rules import Alert, ThreatType, Severity, Signal
    
    # Create mock alert
    alert = Alert(
        alert_id="TEST-001",
        threat_type=ThreatType.SUSPICIOUS_LOGIN,
        severity=Severity.HIGH,
        confidence=85,
        signals=[
            Signal("test_signal", "test", 30, "Test signal")
        ],
        affected_entities={"user_id": "test", "ip": "1.2.3.4"},
        timestamp=datetime.now(),
        raw_logs=[]
    )
    
    # Test context agent
    context_agent = ContextAgent(MockStorageClient())
    context = context_agent.enrich(alert)
    
    if context.user_profile:
        print("   Context Agent working")
    else:
        print("     Context Agent failed")
        return False
    
    # Test reasoning agent
    reasoning_agent = ReasoningAgent()
    assessment = reasoning_agent.analyze(alert, context.__dict__)
    
    if assessment.risk_score > 0:
        print("   Reasoning Agent working")
        print(f"   Risk Level: {assessment.risk_level.value}")
        return True
    else:
        print("     Reasoning Agent failed")
        return False


def test_executor():
    """Test action executor"""
    print("\n  Testing Action Executor...")
    
    from src.response.executor import ActionExecutor, Action, ActionType, BlastRadius
    from datetime import timedelta
    
    executor = ActionExecutor()
    
    # Test safe action (should execute)
    safe_action = Action(
        action_id="TEST-SAFE",
        action_type=ActionType.LOG_ONLY,
        target={"user_id": "test"},
        confidence=95,
        blast_radius=BlastRadius.SINGLE_USER,
        reversible=True,
        auto_expire=None,
        justification="Test",
        metadata={}
    )
    
    result = executor.evaluate_action(safe_action)
    
    if result.status.value == "executed":
        print("   Safe action executed")
    else:
        print(f"     Unexpected result: {result.status.value}")
        return False
    
    # Test unsafe action (should escalate)
    unsafe_action = Action(
        action_id="TEST-UNSAFE",
        action_type=ActionType.LOCK_ACCOUNT,
        target={"user_id": "test"},
        confidence=50,  # Low confidence
        blast_radius=BlastRadius.SINGLE_USER,
        reversible=False,
        auto_expire=None,
        justification="Test",
        metadata={}
    )
    
    result = executor.evaluate_action(unsafe_action)
    
    if result.status.value == "escalated":
        print("   Unsafe action escalated correctly")
        return True
    else:
        print(f"     Should have escalated but got: {result.status.value}")
        return False


def main():
    print("\n" + "="*70)
    print("AI-Powered Threat Detection Platform - System Check")
    print("="*70 + "\n")
    
    tests = [
        ("Detection Engine", test_detection),
        ("AI Agents", test_agents),
        ("Action Executor", test_executor)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n  Error in {name}: {str(e)}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for name, success in results:
        status = "   PASS" if success else "  FAIL"
        print(f"{status:12} {name}")
    
    all_passed = all(success for _, success in results)
    
    if all_passed:
        print("\n🎉 All systems operational!")
        print("\nNext steps:")
        print("1. Run full demo: python src/demo.py")
        print("2. Review README.md for architecture details")
        print("3. Check QUICKSTART.md to deploy with Docker")
        return 0
    else:
        print("\n  Some tests failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

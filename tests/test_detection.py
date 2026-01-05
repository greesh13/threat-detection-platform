"""
Unit Tests for Detection Rules
"""
import pytest
from datetime import datetime, timedelta
from src.detection.rules import (
    SuspiciousLoginDetector,
    AbnormalAPIDetector,
    PrivilegeEscalationDetector,
    ThreatType,
    Severity
)


class TestSuspiciousLoginDetector:
    """Test login threat detection"""
    
    def test_failed_login_burst_detection(self):
        """Should detect multiple failed logins"""
        detector = SuspiciousLoginDetector()
        
        # Create 6 failed logins (above threshold of 5)
        logs = []
        for i in range(6):
            logs.append({
                "timestamp": (datetime.now() - timedelta(minutes=i)).isoformat(),
                "user_id": "test-user",
                "status": "failed",
                "ip": "1.2.3.4",
                "country": "US",
                "user_agent": "Chrome"
            })
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert alert.threat_type == ThreatType.SUSPICIOUS_LOGIN
        assert any(s.name == "failed_login_burst" for s in alert.signals)
        assert alert.confidence > 0
    
    def test_no_alert_for_normal_activity(self):
        """Should not alert on normal login patterns"""
        detector = SuspiciousLoginDetector()
        
        # Single successful login from typical location
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "status": "success",
            "ip": "1.2.3.4",
            "country": "US",
            "user_agent": "Chrome"
        }]
        
        user_profile = {
            "typical_countries": ["US"],
            "typical_hours": range(9, 18)
        }
        
        alert = detector.detect(logs, user_profile)
        
        assert alert is None
    
    def test_anomalous_geography_detection(self):
        """Should detect logins from unexpected countries"""
        detector = SuspiciousLoginDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "status": "success",
            "ip": "1.2.3.4",
            "country": "RU",  # Not in typical countries
            "user_agent": "Chrome"
        }]
        
        user_profile = {
            "typical_countries": ["US", "CA"]
        }
        
        alert = detector.detect(logs, user_profile)
        
        assert alert is not None
        assert any(s.name == "anomalous_geography" for s in alert.signals)
    
    def test_impossible_travel_detection(self):
        """Should detect physically impossible travel"""
        detector = SuspiciousLoginDetector()
        
        # Login from US, then Russia 30 minutes later
        base_time = datetime.now()
        logs = [
            {
                "timestamp": (base_time - timedelta(minutes=30)).isoformat(),
                "user_id": "test-user",
                "status": "success",
                "ip": "1.2.3.4",
                "country": "US",
                "user_agent": "Chrome"
            },
            {
                "timestamp": base_time.isoformat(),
                "user_id": "test-user",
                "status": "success",
                "ip": "5.6.7.8",
                "country": "RU",
                "user_agent": "Chrome"
            }
        ]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "impossible_travel" for s in alert.signals)
        assert alert.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_bot_user_agent_detection(self):
        """Should detect headless browsers"""
        detector = SuspiciousLoginDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "status": "failed",
            "ip": "1.2.3.4",
            "country": "US",
            "user_agent": "HeadlessChrome/91.0"
        }]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "bot_user_agent" for s in alert.signals)


class TestAbnormalAPIDetector:
    """Test API abuse detection"""
    
    def test_rate_limiting_violation(self):
        """Should detect excessive API calls"""
        detector = AbnormalAPIDetector()
        
        # 120 requests in last minute (above threshold of 100)
        logs = []
        for i in range(120):
            logs.append({
                "timestamp": (datetime.now() - timedelta(seconds=i)).isoformat(),
                "user_id": "test-user",
                "endpoint": "/api/v1/users",
                "status": 200,
                "ip": "1.2.3.4",
                "params": ""
            })
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "rate_limit_violation" for s in alert.signals)
    
    def test_sequential_id_enumeration(self):
        """Should detect bulk data extraction patterns"""
        detector = AbnormalAPIDetector()
        
        # Sequential ID access
        logs = []
        for i in range(10):
            logs.append({
                "timestamp": (datetime.now() - timedelta(seconds=10-i)).isoformat(),
                "user_id": "test-user",
                "endpoint": f"/api/v1/users/{1000 + i}",
                "status": 200,
                "ip": "1.2.3.4",
                "params": ""
            })
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "sequential_enumeration" for s in alert.signals)
    
    def test_sql_injection_detection(self):
        """Should detect SQL injection attempts"""
        detector = AbnormalAPIDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "endpoint": "/api/v1/search",
            "status": 400,
            "ip": "1.2.3.4",
            "params": "query=1' OR '1'='1"
        }]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "sql_injection_attempt" for s in alert.signals)
        assert alert.severity == Severity.CRITICAL
    
    def test_privilege_escalation_detection(self):
        """Should detect non-admin accessing admin endpoints"""
        detector = AbnormalAPIDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "endpoint": "/admin/users/delete",
            "status": 403,
            "ip": "1.2.3.4",
            "params": ""
        }]
        
        user_profile = {
            "role": "user"  # Not admin
        }
        
        alert = detector.detect(logs, user_profile)
        
        assert alert is not None
        assert any(s.name == "privilege_escalation_attempt" for s in alert.signals)


class TestPrivilegeEscalationDetector:
    """Test privilege escalation detection"""
    
    def test_unauthorized_role_change(self):
        """Should detect role changes without approval"""
        detector = PrivilegeEscalationDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "action": "role_change",
            "old_role": "user",
            "new_role": "admin",
            "approval_ticket": None,  # No approval!
            "ip": "1.2.3.4"
        }]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "unauthorized_role_change" for s in alert.signals)
        assert alert.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_service_account_misuse(self):
        """Should detect service accounts used from external IPs"""
        detector = PrivilegeEscalationDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "svc-payments",  # Service account
            "action": "login",
            "ip": "203.0.113.1"  # External IP
        }]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "service_account_misuse" for s in alert.signals)
    
    def test_iam_policy_expansion(self):
        """Should detect IAM policies being expanded"""
        detector = PrivilegeEscalationDetector()
        
        logs = [{
            "timestamp": datetime.now().isoformat(),
            "user_id": "test-user",
            "action": "update_iam_policy",
            "policy_name": "DataAccessPolicy",
            "scope_change": "expanded",
            "ip": "1.2.3.4"
        }]
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert any(s.name == "iam_privilege_expansion" for s in alert.signals)


class TestConfidenceScoring:
    """Test confidence score calculation"""
    
    def test_high_confidence_from_multiple_signals(self):
        """Multiple strong signals should result in high confidence"""
        detector = SuspiciousLoginDetector()
        
        # Failed logins + bot user agent + anomalous geography
        logs = []
        for i in range(6):
            logs.append({
                "timestamp": (datetime.now() - timedelta(minutes=i)).isoformat(),
                "user_id": "test-user",
                "status": "failed",
                "ip": "1.2.3.4",
                "country": "RU",
                "user_agent": "HeadlessChrome/91.0"
            })
        
        user_profile = {
            "typical_countries": ["US"]
        }
        
        alert = detector.detect(logs, user_profile)
        
        assert alert is not None
        assert alert.confidence >= 70  # High confidence
        assert len(alert.signals) >= 3  # Multiple signals
    
    def test_confidence_capped_at_100(self):
        """Confidence should never exceed 100"""
        detector = SuspiciousLoginDetector()
        
        # Extreme case with many signals
        base_time = datetime.now()
        logs = [
            {
                "timestamp": (base_time - timedelta(minutes=30)).isoformat(),
                "user_id": "test-user",
                "status": "failed",
                "ip": "1.2.3.4",
                "country": "US",
                "user_agent": "Chrome"
            },
            {
                "timestamp": base_time.isoformat(),
                "user_id": "test-user",
                "status": "failed",
                "ip": "5.6.7.8",
                "country": "RU",
                "user_agent": "HeadlessChrome/91.0"
            }
        ]
        
        for i in range(10):
            logs.append({
                "timestamp": (base_time - timedelta(minutes=i)).isoformat(),
                "user_id": "test-user",
                "status": "failed",
                "ip": "1.2.3.4",
                "country": "RU",
                "user_agent": "HeadlessChrome/91.0"
            })
        
        alert = detector.detect(logs)
        
        assert alert is not None
        assert alert.confidence <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

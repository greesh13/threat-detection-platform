"""
Detection Rules Engine
Deterministic threat detection with clear confidence scoring
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from enum import Enum
import re


class ThreatType(Enum):
    SUSPICIOUS_LOGIN = "suspicious_login"
    ABNORMAL_API_USAGE = "abnormal_api_usage"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Signal:
    """Individual detection signal"""
    name: str
    value: any
    weight: int  # 0-100, contribution to overall confidence
    description: str


@dataclass
class Alert:
    """Detection output"""
    alert_id: str
    threat_type: ThreatType
    severity: Severity
    confidence: int  # 0-100
    signals: List[Signal]
    affected_entities: Dict[str, str]  # user_id, ip, resource, etc.
    timestamp: datetime
    raw_logs: List[Dict]


class SuspiciousLoginDetector:
    """Detects account takeover attempts"""
    
    def __init__(self):
        self.failed_login_threshold = 5
        self.failed_login_window_minutes = 10
        self.known_vpn_providers = {
            "nordvpn", "expressvpn", "protonvpn", "tor-exit"
        }
        self.known_bot_user_agents = [
            "HeadlessChrome", "PhantomJS", "Selenium"
        ]
        
    def detect(self, logs: List[Dict], user_profile: Optional[Dict] = None) -> Optional[Alert]:
        """
        Analyze login logs for suspicious patterns
        
        Signals checked:
        1. Failed login burst
        2. Anomalous geography
        3. Outside typical hours
        4. Impossible travel
        5. Known compromised user agent
        """
        signals = []
        
        # Signal 1: Failed login burst
        failed_logins = [log for log in logs if log.get("status") == "failed"]
        if len(failed_logins) >= self.failed_login_threshold:
            window = timedelta(minutes=self.failed_login_window_minutes)
            recent_failures = [
                log for log in failed_logins
                if datetime.fromisoformat(log["timestamp"]) > datetime.now() - window
            ]
            if len(recent_failures) >= self.failed_login_threshold:
                signals.append(Signal(
                    name="failed_login_burst",
                    value=len(recent_failures),
                    weight=30,
                    description=f"{len(recent_failures)} failed logins in {self.failed_login_window_minutes} minutes"
                ))
        
        # Signal 2: Anomalous geography
        if user_profile and logs:
            current_country = logs[-1].get("country")
            typical_countries = user_profile.get("typical_countries", [])
            if current_country and current_country not in typical_countries:
                signals.append(Signal(
                    name="anomalous_geography",
                    value=current_country,
                    weight=25,
                    description=f"Login from {current_country}, user typically in {typical_countries}"
                ))
        
        # Signal 3: Outside typical hours
        if user_profile and logs:
            login_time = datetime.fromisoformat(logs[-1]["timestamp"])
            login_hour = login_time.hour
            typical_hours = user_profile.get("typical_hours", range(9, 18))
            if login_hour not in typical_hours:
                signals.append(Signal(
                    name="unusual_time",
                    value=login_hour,
                    weight=15,
                    description=f"Login at {login_hour}:00, user typically active {typical_hours.start}-{typical_hours.stop}"
                ))
        
        # Signal 4: Impossible travel
        if len(logs) >= 2:
            prev_log = logs[-2]
            curr_log = logs[-1]
            prev_country = prev_log.get("country")
            curr_country = curr_log.get("country")
            
            if prev_country and curr_country and prev_country != curr_country:
                time_diff = (
                    datetime.fromisoformat(curr_log["timestamp"]) -
                    datetime.fromisoformat(prev_log["timestamp"])
                )
                # If country changed in <2 hours, likely impossible
                if time_diff < timedelta(hours=2):
                    signals.append(Signal(
                        name="impossible_travel",
                        value=f"{prev_country} -> {curr_country} in {time_diff}",
                        weight=35,
                        description=f"Traveled {prev_country} to {curr_country} in {time_diff.total_seconds()/60:.0f} minutes"
                    ))
        
        # Signal 5: Known bot/compromised user agent
        if logs:
            user_agent = logs[-1].get("user_agent", "")
            for bot_ua in self.known_bot_user_agents:
                if bot_ua.lower() in user_agent.lower():
                    signals.append(Signal(
                        name="bot_user_agent",
                        value=user_agent,
                        weight=20,
                        description=f"Headless browser detected: {user_agent}"
                    ))
                    break
        
        # Calculate confidence and severity
        if not signals:
            return None
            
        confidence = min(100, sum(s.weight for s in signals))
        
        # Determine severity based on signal combination
        if any(s.name == "impossible_travel" for s in signals) and confidence > 60:
            severity = Severity.CRITICAL
        elif confidence > 70:
            severity = Severity.HIGH
        elif confidence > 40:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return Alert(
            alert_id=f"LOGIN-{datetime.now().timestamp()}",
            threat_type=ThreatType.SUSPICIOUS_LOGIN,
            severity=severity,
            confidence=confidence,
            signals=signals,
            affected_entities={
                "user_id": logs[-1].get("user_id"),
                "ip": logs[-1].get("ip"),
                "country": logs[-1].get("country")
            },
            timestamp=datetime.now(),
            raw_logs=logs
        )


class AbnormalAPIDetector:
    """Detects API abuse and data exfiltration"""
    
    def __init__(self):
        self.rate_limit_threshold = 100  # requests per minute
        self.sql_injection_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(;\s*drop\s+table)",
            r"(1\s*=\s*1)",
            r"(--|\#|\/\*)",
        ]
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
        ]
        
    def detect(self, logs: List[Dict], user_profile: Optional[Dict] = None) -> Optional[Alert]:
        """
        Analyze API logs for abuse patterns
        
        Signals checked:
        1. Rate limiting violation
        2. Access outside normal scope
        3. Bulk data extraction
        4. Injection attack patterns
        5. Privilege escalation attempts
        """
        signals = []
        
        # Signal 1: Rate limiting violation
        recent_requests = [
            log for log in logs
            if datetime.fromisoformat(log["timestamp"]) > datetime.now() - timedelta(minutes=1)
        ]
        if len(recent_requests) > self.rate_limit_threshold:
            signals.append(Signal(
                name="rate_limit_violation",
                value=len(recent_requests),
                weight=25,
                description=f"{len(recent_requests)} requests in 1 minute (limit: {self.rate_limit_threshold})"
            ))
        
        # Signal 2: Access outside normal scope
        if user_profile and logs:
            current_endpoint = logs[-1].get("endpoint")
            typical_endpoints = set(user_profile.get("typical_endpoints", []))
            if current_endpoint and current_endpoint not in typical_endpoints:
                signals.append(Signal(
                    name="unusual_endpoint",
                    value=current_endpoint,
                    weight=20,
                    description=f"Accessed {current_endpoint}, never accessed before"
                ))
        
        # Signal 3: Bulk data extraction (sequential ID enumeration)
        if len(logs) >= 10:
            # Check if last 10 requests are sequential resource IDs
            resource_ids = []
            for log in logs[-10:]:
                endpoint = log.get("endpoint", "")
                # Extract numeric ID from endpoint like /api/users/123
                match = re.search(r'/(\d+)(?:\?|$)', endpoint)
                if match:
                    resource_ids.append(int(match.group(1)))
            
            if len(resource_ids) >= 5:
                # Check if IDs are sequential
                is_sequential = all(
                    resource_ids[i] + 1 == resource_ids[i+1]
                    for i in range(len(resource_ids) - 1)
                )
                if is_sequential:
                    signals.append(Signal(
                        name="sequential_enumeration",
                        value=f"{resource_ids[0]}-{resource_ids[-1]}",
                        weight=30,
                        description=f"Sequential ID access detected: {resource_ids}"
                    ))
        
        # Signal 4: SQL injection patterns
        for log in logs:
            params = log.get("params", "")
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, params, re.IGNORECASE):
                    signals.append(Signal(
                        name="sql_injection_attempt",
                        value=params,
                        weight=40,
                        description=f"SQL injection pattern detected: {pattern}"
                    ))
                    break
        
        # Signal 5: Privilege escalation attempt
        if user_profile:
            user_role = user_profile.get("role", "user")
            admin_endpoints_accessed = [
                log for log in logs
                if "/admin" in log.get("endpoint", "") or "/internal" in log.get("endpoint", "")
            ]
            if admin_endpoints_accessed and user_role != "admin":
                signals.append(Signal(
                    name="privilege_escalation_attempt",
                    value=f"{len(admin_endpoints_accessed)} admin endpoints",
                    weight=35,
                    description=f"Non-admin user accessing admin endpoints"
                ))
        
        if not signals:
            return None
            
        confidence = min(100, sum(s.weight for s in signals))
        
        # Determine severity
        if any(s.name in ["sql_injection_attempt", "privilege_escalation_attempt"] for s in signals):
            severity = Severity.CRITICAL
        elif confidence > 70:
            severity = Severity.HIGH
        elif confidence > 40:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return Alert(
            alert_id=f"API-{datetime.now().timestamp()}",
            threat_type=ThreatType.ABNORMAL_API_USAGE,
            severity=severity,
            confidence=confidence,
            signals=signals,
            affected_entities={
                "user_id": logs[-1].get("user_id"),
                "ip": logs[-1].get("ip"),
                "endpoint": logs[-1].get("endpoint")
            },
            timestamp=datetime.now(),
            raw_logs=logs
        )


class PrivilegeEscalationDetector:
    """Detects attempts to gain elevated access"""
    
    def detect(self, logs: List[Dict], user_profile: Optional[Dict] = None) -> Optional[Alert]:
        """
        Analyze logs for privilege escalation
        
        Signals checked:
        1. Role changes without approval
        2. Direct DB permission modifications
        3. Service account misuse
        4. Sudo/admin command execution
        5. IAM policy changes
        """
        signals = []
        
        # Signal 1: Role changes without approval workflow
        role_changes = [log for log in logs if log.get("action") == "role_change"]
        for change in role_changes:
            if not change.get("approval_ticket"):
                signals.append(Signal(
                    name="unauthorized_role_change",
                    value=f"{change.get('old_role')} -> {change.get('new_role')}",
                    weight=40,
                    description="Role modified without approval ticket"
                ))
        
        # Signal 2: Direct database permission modifications
        db_perm_changes = [
            log for log in logs
            if log.get("action") in ["grant_permission", "modify_acl"]
        ]
        if db_perm_changes:
            signals.append(Signal(
                name="direct_permission_modification",
                value=len(db_perm_changes),
                weight=35,
                description=f"{len(db_perm_changes)} direct permission changes detected"
            ))
        
        # Signal 3: Service account credential usage from non-service IP
        service_account_usage = [
            log for log in logs
            if log.get("user_id", "").startswith("svc-") and
            log.get("ip") not in ["10.0.0.0/8", "172.16.0.0/12"]  # Internal IPs
        ]
        if service_account_usage:
            signals.append(Signal(
                name="service_account_misuse",
                value=f"From IP {service_account_usage[0].get('ip')}",
                weight=45,
                description="Service account accessed from external IP"
            ))
        
        # Signal 4: Sudo/admin commands by non-privileged user
        if user_profile:
            user_role = user_profile.get("role", "user")
            sudo_commands = [
                log for log in logs
                if log.get("command", "").startswith("sudo") or
                   log.get("action") == "execute_admin_command"
            ]
            if sudo_commands and user_role not in ["admin", "sre"]:
                signals.append(Signal(
                    name="unauthorized_admin_execution",
                    value=sudo_commands[0].get("command"),
                    weight=40,
                    description=f"Non-admin executing: {sudo_commands[0].get('command')}"
                ))
        
        # Signal 5: IAM policy changes expanding access
        iam_changes = [
            log for log in logs
            if log.get("action") == "update_iam_policy" and
            log.get("scope_change") == "expanded"
        ]
        if iam_changes:
            signals.append(Signal(
                name="iam_privilege_expansion",
                value=iam_changes[0].get("policy_name"),
                weight=35,
                description="IAM policy modified to expand access scope"
            ))
        
        if not signals:
            return None
            
        confidence = min(100, sum(s.weight for s in signals))
        
        # Privilege escalation is always high severity
        if confidence > 70:
            severity = Severity.CRITICAL
        elif confidence > 40:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        return Alert(
            alert_id=f"PRIV-{datetime.now().timestamp()}",
            threat_type=ThreatType.PRIVILEGE_ESCALATION,
            severity=severity,
            confidence=confidence,
            signals=signals,
            affected_entities={
                "user_id": logs[-1].get("user_id"),
                "ip": logs[-1].get("ip"),
                "action": logs[-1].get("action")
            },
            timestamp=datetime.now(),
            raw_logs=logs
        )


class DetectionEngine:
    """Orchestrates all detectors"""
    
    def __init__(self):
        self.detectors = [
            SuspiciousLoginDetector(),
            AbnormalAPIDetector(),
            PrivilegeEscalationDetector(),
        ]
    
    def analyze(self, logs: List[Dict], user_profile: Optional[Dict] = None) -> List[Alert]:
        """Run all detectors on log batch"""
        alerts = []
        
        for detector in self.detectors:
            alert = detector.detect(logs, user_profile)
            if alert:
                alerts.append(alert)
        
        return alerts

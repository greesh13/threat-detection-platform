"""
Context Agent
Enriches alerts with relevant user profile, historical data, and threat intel
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json


@dataclass
class EnrichedContext:
    """Context data provided to reasoning agent"""
    user_profile: Dict
    similar_incidents: List[Dict]
    threat_intelligence: Dict
    recent_activity: List[Dict]
    concurrent_alerts: List[Dict]


class ContextAgent:
    """
    Enriches alerts with contextual information
    
    Responsibilities:
    1. Fetch user behavioral baseline (normal activity)
    2. Query similar past incidents from vector DB
    3. Check threat intelligence (IP reputation, known attack patterns)
    4. Gather recent logs for affected entity
    5. Find concurrent alerts on same entity
    """
    
    def __init__(self, storage_client):
        """
        Args:
            storage_client: Interface to databases (Postgres + Vector DB)
        """
        self.storage = storage_client
    
    def enrich(self, alert) -> EnrichedContext:
        """
        Gather all relevant context for an alert
        
        This is the "boring work" that agents automate:
        - Querying multiple databases
        - Correlating data from different sources
        - Formatting for human consumption
        """
        user_id = alert.affected_entities.get("user_id")
        ip = alert.affected_entities.get("ip")
        
        # 1. Fetch user profile
        user_profile = self._get_user_profile(user_id) if user_id else {}
        
        # 2. Find similar past incidents
        similar_incidents = self._query_similar_incidents(alert)
        
        # 3. Check threat intelligence
        threat_intel = self._check_threat_intelligence(ip) if ip else {}
        
        # 4. Get recent activity
        recent_activity = self._get_recent_activity(user_id) if user_id else []
        
        # 5. Find concurrent alerts
        concurrent = self._get_concurrent_alerts(user_id, ip)
        
        return EnrichedContext(
            user_profile=user_profile,
            similar_incidents=similar_incidents,
            threat_intelligence=threat_intel,
            recent_activity=recent_activity,
            concurrent_alerts=concurrent
        )
    
    def _get_user_profile(self, user_id: str) -> Dict:
        """
        Build behavioral baseline for user
        
        In production, this queries:
        - User database (role, creation date, etc.)
        - Analytics database (typical behavior patterns)
        - Previous alert history
        """
        # Mock implementation
        # In production: profile = self.storage.query_user_profile(user_id)
        
        profile = {
            "user_id": user_id,
            "account_age_days": 180,
            "role": "user",
            "typical_countries": ["US", "CA"],
            "typical_hours": range(9, 18),  # 9am - 6pm
            "typical_endpoints": [
                "/api/v1/users/me",
                "/api/v1/documents",
                "/api/v1/search"
            ],
            "average_requests_per_day": 150,
            "previous_alerts": 0,
            "last_login": (datetime.now() - timedelta(hours=2)).isoformat(),
            "mfa_enabled": True,
            "account_tier": "premium"
        }
        
        return profile
    
    def _query_similar_incidents(self, alert) -> List[Dict]:
        """
        Find past alerts with similar characteristics
        
        Uses vector database to find semantically similar incidents:
        - Same threat type
        - Similar signals
        - Same affected entity type
        
        This helps answer: "Have we seen this before?"
        """
        # In production: Use Qdrant or similar vector DB
        # similar = self.storage.vector_search(
        #     query_embedding=embed(alert.signals),
        #     filter={"threat_type": alert.threat_type},
        #     limit=5
        # )
        
        # Mock response
        similar = [
            {
                "alert_id": "LOGIN-12345",
                "timestamp": "2024-01-03T14:22:00",
                "threat_type": "suspicious_login",
                "confidence": 75,
                "outcome": "false_positive",
                "analyst_notes": "User traveling for work, verified via Slack",
                "similarity_score": 0.85
            },
            {
                "alert_id": "LOGIN-12389",
                "timestamp": "2024-01-02T09:15:00",
                "threat_type": "suspicious_login",
                "confidence": 92,
                "outcome": "true_positive",
                "analyst_notes": "Confirmed credential stuffing attack, IP blocked",
                "similarity_score": 0.78
            }
        ]
        
        return similar
    
    def _check_threat_intelligence(self, ip: str) -> Dict:
        """
        Check IP against threat intelligence feeds
        
        In production, queries:
        - Internal blocklist
        - VirusTotal
        - AbuseIPDB
        - Custom threat feeds
        """
        # In production:
        # intel = {
        #     "ip": ip,
        #     "reputation": self.storage.check_ip_reputation(ip),
        #     "abuse_reports": self.external_api.query_abuseipdb(ip),
        #     "known_campaigns": self.storage.check_attack_campaigns(ip)
        # }
        
        # Mock implementation
        intel = {
            "ip": ip,
            "reputation": "low_risk",  # low_risk, medium_risk, high_risk, known_malicious
            "on_blocklist": False,
            "abuse_reports_30d": 0,
            "known_vpn": False,
            "tor_exit_node": False,
            "hosting_provider": "AWS",
            "geolocation": {
                "country": "US",
                "city": "Seattle",
                "asn": "AS16509"
            },
            "known_patterns": []  # e.g., ["credential_stuffing_2024"]
        }
        
        return intel
    
    def _get_recent_activity(self, user_id: str, limit: int = 100) -> List[Dict]:
        """
        Fetch recent logs for user to understand context
        
        What was the user doing before this alert?
        Is there a pattern of escalating behavior?
        """
        # In production: logs = self.storage.query_logs(user_id, limit=limit)
        
        # Mock recent activity
        recent = [
            {
                "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
                "action": "login_success",
                "ip": "1.2.3.4",
                "country": "US"
            },
            {
                "timestamp": (datetime.now() - timedelta(minutes=10)).isoformat(),
                "action": "api_request",
                "endpoint": "/api/v1/users/me",
                "status": 200
            },
            {
                "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                "action": "login_success",
                "ip": "1.2.3.4",
                "country": "US"
            }
        ]
        
        return recent
    
    def _get_concurrent_alerts(
        self,
        user_id: Optional[str],
        ip: Optional[str]
    ) -> List[Dict]:
        """
        Find other alerts firing on same entity
        
        Multiple alerts on same user/IP suggests:
        - Coordinated attack
        - OR systematic false positive issue
        """
        # In production:
        # concurrent = self.storage.query_recent_alerts(
        #     user_id=user_id,
        #     ip=ip,
        #     time_window=timedelta(hours=1)
        # )
        
        # Mock: no concurrent alerts
        concurrent = []
        
        return concurrent


class MockStorageClient:
    """
    Mock database client for demonstration
    In production, this would be actual Postgres + Qdrant clients
    """
    
    def query_user_profile(self, user_id: str) -> Dict:
        """Query user database"""
        return {}
    
    def vector_search(self, query_embedding, filter, limit) -> List[Dict]:
        """Query vector database for similar incidents"""
        return []
    
    def check_ip_reputation(self, ip: str) -> str:
        """Check IP against internal reputation database"""
        return "unknown"
    
    def query_logs(self, user_id: str, limit: int) -> List[Dict]:
        """Query log database"""
        return []
    
    def query_recent_alerts(
        self,
        user_id: Optional[str],
        ip: Optional[str],
        time_window: timedelta
    ) -> List[Dict]:
        """Query alert database"""
        return []

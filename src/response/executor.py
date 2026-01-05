"""
Response Action Executor
Safely executes security actions with multiple layers of safety checks
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from enum import Enum
import logging


logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Available response actions, ordered by severity"""
    LOG_ONLY = "log_only"
    RATE_LIMIT = "rate_limit"
    REQUIRE_MFA = "require_mfa"
    REVOKE_SESSION = "revoke_session"
    BLOCK_IP = "block_ip"
    LOCK_ACCOUNT = "lock_account"
    REVOKE_API_KEY = "revoke_api_key"
    DISABLE_SERVICE_ACCOUNT = "disable_service_account"


class BlastRadius(Enum):
    """Scope of action impact"""
    SINGLE_USER = "single_user"
    TEAM = "team"
    SERVICE = "service"
    ORGANIZATION = "organization"


class ExecutionStatus(Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class Action:
    """Proposed security action"""
    action_id: str
    action_type: ActionType
    target: Dict[str, str]  # user_id, ip, resource, etc.
    confidence: int  # From detection + reasoning
    blast_radius: BlastRadius
    reversible: bool
    auto_expire: Optional[timedelta]  # Auto-rollback after duration
    justification: str  # Human-readable explanation
    metadata: Dict  # Additional context


@dataclass
class ExecutionResult:
    """Result of attempting to execute an action"""
    action_id: str
    status: ExecutionStatus
    executed_at: Optional[datetime]
    reason: str  # Why approved/rejected/escalated
    analyst_id: Optional[str]  # Who approved (if human involved)
    rollback_by: Optional[datetime]  # When auto-rollback happens


class ActionExecutor:
    """
    Safely executes security response actions
    
    CRITICAL SAFETY PRINCIPLES:
    1. Multi-layer approval required
    2. All actions are dry-runnable
    3. All actions are auditable
    4. High-risk actions require human approval
    5. Circuit breakers prevent cascading failures
    """
    
    def __init__(self):
        # Allowlisted entities never auto-actioned
        self.protected_entities = {
            "user_ids": {"exec-001", "exec-002", "on-call-001"},  # Executives, on-call
            "service_accounts": {"svc-payments", "svc-critical-infra"}
        }
        
        # Rate limiting for actions
        self.action_rate_limits = {
            "per_hour": 100,
            "per_minute": 10
        }
        self.recent_actions = []  # Track for rate limiting
        
        # Circuit breaker state
        self.circuit_breaker_tripped = False
        self.false_positive_rate_threshold = 0.20  # 20%
        
        # Confidence thresholds for auto-execution
        self.auto_exec_thresholds = {
            ActionType.LOG_ONLY: 0,
            ActionType.RATE_LIMIT: 70,
            ActionType.REQUIRE_MFA: 80,
            ActionType.REVOKE_SESSION: 85,
            ActionType.BLOCK_IP: 90,
            ActionType.LOCK_ACCOUNT: 95,
            ActionType.REVOKE_API_KEY: 90,
            ActionType.DISABLE_SERVICE_ACCOUNT: 99  # Almost never auto
        }
    
    def evaluate_action(
        self,
        action: Action,
        dry_run: bool = False
    ) -> ExecutionResult:
        """
        Evaluate whether action should be executed, escalated, or rejected
        
        Multi-layer safety checks:
        1. Confidence threshold
        2. Blast radius check
        3. Protected entity check
        4. Rate limit check
        5. Circuit breaker check
        """
        # Check 1: Confidence threshold
        if not self._passes_confidence_threshold(action):
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.ESCALATED,
                executed_at=None,
                reason=f"Confidence {action.confidence} below threshold {self.auto_exec_thresholds[action.action_type]} for {action.action_type.value}",
                analyst_id=None,
                rollback_by=None
            )
        
        # Check 2: Blast radius
        if not self._passes_blast_radius_check(action):
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.ESCALATED,
                executed_at=None,
                reason=f"Blast radius {action.blast_radius.value} requires human approval",
                analyst_id=None,
                rollback_by=None
            )
        
        # Check 3: Protected entities
        if not self._passes_allowlist_check(action):
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.ESCALATED,
                executed_at=None,
                reason=f"Target {action.target} is protected, requires human approval",
                analyst_id=None,
                rollback_by=None
            )
        
        # Check 4: Rate limits
        if not self._passes_rate_limit(action):
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.REJECTED,
                executed_at=None,
                reason=f"Rate limit exceeded: {len(self.recent_actions)} actions in last hour",
                analyst_id=None,
                rollback_by=None
            )
        
        # Check 5: Circuit breaker
        if self.circuit_breaker_tripped:
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.ESCALATED,
                executed_at=None,
                reason="Circuit breaker tripped due to high false positive rate",
                analyst_id=None,
                rollback_by=None
            )
        
        # All checks passed - approve for execution
        if dry_run:
            logger.info(f"[DRY RUN] Would execute {action.action_type.value} on {action.target}")
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.APPROVED,
                executed_at=None,
                reason="Dry run - would execute automatically",
                analyst_id=None,
                rollback_by=None
            )
        else:
            return self._execute(action)
    
    def _passes_confidence_threshold(self, action: Action) -> bool:
        """Check if confidence meets threshold for automatic execution"""
        threshold = self.auto_exec_thresholds[action.action_type]
        return action.confidence >= threshold
    
    def _passes_blast_radius_check(self, action: Action) -> bool:
        """Only single-user actions can auto-execute"""
        return action.blast_radius == BlastRadius.SINGLE_USER
    
    def _passes_allowlist_check(self, action: Action) -> bool:
        """Protected entities require human approval"""
        user_id = action.target.get("user_id")
        
        if user_id in self.protected_entities["user_ids"]:
            return False
        
        if user_id and user_id.startswith("svc-"):
            if user_id in self.protected_entities["service_accounts"]:
                return False
        
        return True
    
    def _passes_rate_limit(self, action: Action) -> bool:
        """Prevent too many actions in short time window"""
        now = datetime.now()
        
        # Clean up old actions
        self.recent_actions = [
            a for a in self.recent_actions
            if now - a["timestamp"] < timedelta(hours=1)
        ]
        
        # Check hourly limit
        if len(self.recent_actions) >= self.action_rate_limits["per_hour"]:
            logger.warning(f"Hourly rate limit exceeded: {len(self.recent_actions)} actions")
            return False
        
        # Check per-minute limit
        recent_minute = [
            a for a in self.recent_actions
            if now - a["timestamp"] < timedelta(minutes=1)
        ]
        if len(recent_minute) >= self.action_rate_limits["per_minute"]:
            logger.warning(f"Per-minute rate limit exceeded: {len(recent_minute)} actions")
            return False
        
        return True
    
    def _execute(self, action: Action) -> ExecutionResult:
        """
        Actually execute the security action
        
        In production, this would:
        - Call firewall API to block IP
        - Call IAM API to revoke credentials
        - Call session management to kill sessions
        - etc.
        
        For demo, we log the action
        """
        now = datetime.now()
        
        try:
            # Execute based on action type
            if action.action_type == ActionType.BLOCK_IP:
                self._block_ip(action.target["ip"], action.auto_expire)
            elif action.action_type == ActionType.LOCK_ACCOUNT:
                self._lock_account(action.target["user_id"])
            elif action.action_type == ActionType.REVOKE_SESSION:
                self._revoke_sessions(action.target["user_id"])
            elif action.action_type == ActionType.RATE_LIMIT:
                self._apply_rate_limit(action.target["ip"])
            elif action.action_type == ActionType.REQUIRE_MFA:
                self._require_mfa(action.target["user_id"])
            elif action.action_type == ActionType.REVOKE_API_KEY:
                self._revoke_api_key(action.target["api_key_id"])
            elif action.action_type == ActionType.DISABLE_SERVICE_ACCOUNT:
                self._disable_service_account(action.target["user_id"])
            
            # Record action for rate limiting
            self.recent_actions.append({
                "action_id": action.action_id,
                "timestamp": now,
                "action_type": action.action_type,
                "target": action.target
            })
            
            # Calculate rollback time
            rollback_by = None
            if action.auto_expire:
                rollback_by = now + action.auto_expire
            
            logger.info(f"   Executed {action.action_type.value} on {action.target}")
            
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.EXECUTED,
                executed_at=now,
                reason="Automatic execution - all safety checks passed",
                analyst_id=None,
                rollback_by=rollback_by
            )
            
        except Exception as e:
            logger.error(f"  Failed to execute {action.action_type.value}: {str(e)}")
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.FAILED,
                executed_at=None,
                reason=f"Execution failed: {str(e)}",
                analyst_id=None,
                rollback_by=None
            )
    
    def human_approve(
        self,
        action: Action,
        analyst_id: str,
        approved: bool,
        override_reason: Optional[str] = None
    ) -> ExecutionResult:
        """
        Human analyst approves or rejects an escalated action
        
        Analysts can:
        - Approve the action
        - Reject it (false positive)
        - Modify it (e.g., shorter duration, different target)
        """
        now = datetime.now()
        
        if not approved:
            logger.info(f"  Action {action.action_id} rejected by analyst {analyst_id}")
            return ExecutionResult(
                action_id=action.action_id,
                status=ExecutionStatus.REJECTED,
                executed_at=None,
                reason=override_reason or "Rejected by analyst",
                analyst_id=analyst_id,
                rollback_by=None
            )
        
        # Human approved - execute without safety checks
        # (Analyst has already reviewed)
        logger.info(f"   Action {action.action_id} approved by analyst {analyst_id}")
        result = self._execute(action)
        result.analyst_id = analyst_id
        result.reason = override_reason or "Approved by human analyst"
        
        return result
    
    def rollback(self, action_id: str, reason: str) -> ExecutionResult:
        """
        Rollback a previously executed action
        
        All actions are designed to be reversible:
        - IP blocks are removed
        - Accounts are unlocked
        - Sessions can be restored (within 7-day window)
        """
        logger.info(f"🔄 Rolling back action {action_id}: {reason}")
        
        # In production, this would:
        # - Lookup original action from database
        # - Execute reverse operation
        # - Log rollback for audit
        
        return ExecutionResult(
            action_id=action_id,
            status=ExecutionStatus.ROLLED_BACK,
            executed_at=datetime.now(),
            reason=reason,
            analyst_id=None,
            rollback_by=None
        )
    
    def trip_circuit_breaker(self, reason: str):
        """
        Disable automatic actions due to high false positive rate
        All future actions will escalate to humans
        """
        self.circuit_breaker_tripped = True
        logger.critical(f"    CIRCUIT BREAKER TRIPPED: {reason}")
        logger.critical("All automatic actions disabled. Human approval required.")
    
    def reset_circuit_breaker(self, analyst_id: str):
        """Re-enable automatic actions after circuit breaker trip"""
        self.circuit_breaker_tripped = False
        logger.info(f"   Circuit breaker reset by {analyst_id}")
    
    # Individual action implementations (would integrate with real systems)
    
    def _block_ip(self, ip: str, duration: Optional[timedelta]):
        """Add IP to firewall blocklist"""
        logger.info(f"  Blocking IP {ip} for {duration}")
        # In production: call firewall API
    
    def _lock_account(self, user_id: str):
        """Disable account, requiring manual unlock"""
        logger.info(f" Locking account {user_id}")
        # In production: call IAM API
    
    def _revoke_sessions(self, user_id: str):
        """Kill all active sessions for user"""
        logger.info(f"  Revoking sessions for {user_id}")
        # In production: call session management API
    
    def _apply_rate_limit(self, ip: str):
        """Reduce request rate for IP"""
        logger.info(f"  Applying rate limit to {ip}")
        # In production: call API gateway
    
    def _require_mfa(self, user_id: str):
        """Force MFA on next login"""
        logger.info(f" Requiring MFA for {user_id}")
        # In production: update user profile
    
    def _revoke_api_key(self, api_key_id: str):
        """Invalidate API key"""
        logger.info(f"  Revoking API key {api_key_id}")
        # In production: call API key service
    
    def _disable_service_account(self, user_id: str):
        """Disable service account credentials"""
        logger.info(f"  Disabling service account {user_id}")
        # In production: call service account manager


def generate_action_from_assessment(
    alert,
    risk_assessment,
    action_id: str
) -> Action:
    """
    Convert risk assessment into a concrete action
    Maps recommended actions to executable actions with safety parameters
    """
    recommendations = risk_assessment.recommended_actions
    confidence = risk_assessment.risk_score
    
    # Select primary action based on recommendations and confidence
    action_type = ActionType.LOG_ONLY  # Safe default
    auto_expire = None
    
    if "Block IP address immediately" in recommendations and confidence >= 90:
        action_type = ActionType.BLOCK_IP
        auto_expire = timedelta(hours=1)  # Auto-unblock after 1 hour
    elif "Lock affected account" in recommendations and confidence >= 95:
        action_type = ActionType.LOCK_ACCOUNT
        auto_expire = None  # Requires manual unlock
    elif "Revoke all active sessions" in recommendations and confidence >= 85:
        action_type = ActionType.REVOKE_SESSION
        auto_expire = None
    elif "Rate limit IP address" in recommendations:
        action_type = ActionType.RATE_LIMIT
        auto_expire = timedelta(hours=2)
    elif "Require MFA for next login" in recommendations:
        action_type = ActionType.REQUIRE_MFA
        auto_expire = None
    
    # Determine blast radius
    affected_user = alert.affected_entities.get("user_id")
    if affected_user and affected_user.startswith("svc-"):
        blast_radius = BlastRadius.SERVICE
    else:
        blast_radius = BlastRadius.SINGLE_USER
    
    return Action(
        action_id=action_id,
        action_type=action_type,
        target=alert.affected_entities,
        confidence=confidence,
        blast_radius=blast_radius,
        reversible=action_type != ActionType.LOCK_ACCOUNT,
        auto_expire=auto_expire,
        justification=risk_assessment.reasoning,
        metadata={
            "alert_id": alert.alert_id,
            "threat_type": alert.threat_type.value,
            "attack_pattern": risk_assessment.attack_pattern
        }
    )

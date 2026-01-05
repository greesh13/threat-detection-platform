"""
Unit Tests for Action Executor Safety Mechanisms
"""
import pytest
from datetime import timedelta
from src.response.executor import (
    ActionExecutor,
    Action,
    ActionType,
    BlastRadius,
    ExecutionStatus
)


class TestSafetyChecks:
    """Test multi-layer safety mechanisms"""
    
    def test_confidence_threshold_check(self):
        """Actions below confidence threshold should escalate"""
        executor = ActionExecutor()
        
        # Low confidence action
        action = Action(
            action_id="test-1",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=50,  # Below threshold of 90
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="Low confidence test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.ESCALATED
        assert "confidence" in result.reason.lower()
    
    def test_blast_radius_check(self):
        """Multi-user actions should escalate regardless of confidence"""
        executor = ActionExecutor()
        
        # High confidence but affects multiple users
        action = Action(
            action_id="test-2",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=95,
            blast_radius=BlastRadius.SERVICE,  # Not single user
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="High blast radius test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.ESCALATED
        assert "blast radius" in result.reason.lower()
    
    def test_protected_entity_check(self):
        """Protected entities should always escalate"""
        executor = ActionExecutor()
        
        # Action targeting protected user
        action = Action(
            action_id="test-3",
            action_type=ActionType.LOCK_ACCOUNT,
            target={"user_id": "exec-001"},  # Protected executive
            confidence=95,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=False,
            auto_expire=None,
            justification="Protected entity test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.ESCALATED
        assert "protected" in result.reason.lower()
    
    def test_rate_limit_check(self):
        """Too many actions should be rejected"""
        executor = ActionExecutor()
        
        # Simulate many recent actions
        for i in range(100):
            executor.recent_actions.append({
                "action_id": f"prev-{i}",
                "timestamp": pytest.importorskip("datetime").datetime.now(),
                "action_type": ActionType.RATE_LIMIT,
                "target": {"ip": f"1.2.3.{i}"}
            })
        
        # This action should be rate limited
        action = Action(
            action_id="test-4",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=95,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="Rate limit test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.REJECTED
        assert "rate limit" in result.reason.lower()
    
    def test_circuit_breaker_check(self):
        """Circuit breaker should prevent all auto-actions"""
        executor = ActionExecutor()
        executor.trip_circuit_breaker("Test: High false positive rate")
        
        # Even high-confidence action should escalate
        action = Action(
            action_id="test-5",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=95,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="Circuit breaker test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.ESCALATED
        assert "circuit breaker" in result.reason.lower()


class TestActionExecution:
    """Test actual action execution"""
    
    def test_successful_auto_execution(self):
        """High confidence, low blast radius should auto-execute"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-6",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=95,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="Auto-exec test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.EXECUTED
        assert result.executed_at is not None
        assert result.rollback_by is not None  # Has auto-expire
    
    def test_dry_run_mode(self):
        """Dry run should not execute actions"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-7",
            action_type=ActionType.LOCK_ACCOUNT,
            target={"user_id": "test-user"},
            confidence=95,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=False,
            auto_expire=None,
            justification="Dry run test",
            metadata={}
        )
        
        result = executor.evaluate_action(action, dry_run=True)
        
        assert result.status == ExecutionStatus.APPROVED
        assert result.executed_at is None  # Not actually executed


class TestHumanApproval:
    """Test human-in-the-loop workflow"""
    
    def test_analyst_approval(self):
        """Analyst can approve escalated actions"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-8",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=75,  # Below auto-exec threshold
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="Human approval test",
            metadata={}
        )
        
        result = executor.human_approve(
            action,
            analyst_id="analyst-001",
            approved=True,
            override_reason="Confirmed malicious activity"
        )
        
        assert result.status == ExecutionStatus.EXECUTED
        assert result.analyst_id == "analyst-001"
    
    def test_analyst_rejection(self):
        """Analyst can reject actions as false positives"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-9",
            action_type=ActionType.BLOCK_IP,
            target={"ip": "1.2.3.4"},
            confidence=75,
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=timedelta(hours=1),
            justification="False positive test",
            metadata={}
        )
        
        result = executor.human_approve(
            action,
            analyst_id="analyst-001",
            approved=False,
            override_reason="False positive - user traveling for work"
        )
        
        assert result.status == ExecutionStatus.REJECTED
        assert result.analyst_id == "analyst-001"
        assert "false positive" in result.reason.lower()


class TestRollback:
    """Test action reversibility"""
    
    def test_rollback_execution(self):
        """Should be able to rollback actions"""
        executor = ActionExecutor()
        
        result = executor.rollback(
            action_id="test-10",
            reason="User verified legitimate, rolling back block"
        )
        
        assert result.status == ExecutionStatus.ROLLED_BACK
        assert "rollback" in result.reason.lower() or "verified" in result.reason.lower()


class TestActionTypeThresholds:
    """Test different confidence thresholds for different action types"""
    
    def test_log_only_always_executes(self):
        """Log-only actions should always execute"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-11",
            action_type=ActionType.LOG_ONLY,
            target={"user_id": "test-user"},
            confidence=10,  # Very low
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=True,
            auto_expire=None,
            justification="Log only test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.EXECUTED
    
    def test_high_severity_requires_high_confidence(self):
        """Account locks require very high confidence"""
        executor = ActionExecutor()
        
        action = Action(
            action_id="test-12",
            action_type=ActionType.LOCK_ACCOUNT,
            target={"user_id": "test-user"},
            confidence=90,  # Below threshold of 95
            blast_radius=BlastRadius.SINGLE_USER,
            reversible=False,
            auto_expire=None,
            justification="High severity test",
            metadata={}
        )
        
        result = executor.evaluate_action(action)
        
        assert result.status == ExecutionStatus.ESCALATED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

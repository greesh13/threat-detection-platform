"""
Agent Orchestrator
Coordinates the three-agent investigation workflow
"""
from typing import Optional
from datetime import datetime
import uuid
import logging

from src.agents.context import ContextAgent, MockStorageClient
from src.agents.reasoning import ReasoningAgent, format_risk_assessment_for_display
from src.response.executor import (
    ActionExecutor,
    generate_action_from_assessment,
    ExecutionStatus
)


logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Coordinates multi-agent investigation and response
    
    Workflow:
    1. Alert arrives from detection engine
    2. Context Agent enriches with relevant data
    3. Reasoning Agent analyzes and produces risk assessment
    4. Action Agent decides on response
    5. Execute (if safe) or escalate to human
    """
    
    def __init__(
        self,
        anthropic_api_key: Optional[str] = None,
        storage_client = None
    ):
        # Initialize agents
        self.context_agent = ContextAgent(
            storage_client or MockStorageClient()
        )
        self.reasoning_agent = ReasoningAgent(anthropic_api_key)
        self.action_executor = ActionExecutor()
    
    def investigate(self, alert, dry_run: bool = False):
        """
        Full investigation workflow for an alert
        
        Returns:
            dict with investigation results and action decision
        """
        investigation_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"🔍 Starting investigation {investigation_id} for alert {alert.alert_id}")
        
        # Step 1: Context Agent enriches alert
        logger.info("  → Context Agent: Gathering background information...")
        enriched_context = self.context_agent.enrich(alert)
        logger.info(f"    ✓ Found {len(enriched_context.similar_incidents)} similar past incidents")
        logger.info(f"    ✓ User profile: {enriched_context.user_profile.get('role')} account, {enriched_context.user_profile.get('account_age_days')} days old")
        
        # Step 2: Reasoning Agent analyzes threat
        logger.info("  → Reasoning Agent: Analyzing threat...")
        risk_assessment = self.reasoning_agent.analyze(alert, enriched_context.__dict__)
        logger.info(f"    ✓ Risk Level: {risk_assessment.risk_level.value.upper()} ({risk_assessment.risk_score}/100)")
        logger.info(f"    ✓ Attack Pattern: {risk_assessment.attack_pattern}")
        logger.info(f"    ✓ False Positive Likelihood: {risk_assessment.false_positive_likelihood}")
        
        # Step 3: Action Agent generates response
        logger.info("  → Action Agent: Determining response...")
        action = generate_action_from_assessment(
            alert,
            risk_assessment,
            action_id=f"ACT-{investigation_id[:8]}"
        )
        logger.info(f"    ✓ Recommended Action: {action.action_type.value}")
        logger.info(f"    ✓ Blast Radius: {action.blast_radius.value}")
        
        # Step 4: Evaluate action (execute or escalate)
        logger.info("  → Executing safety checks...")
        execution_result = self.action_executor.evaluate_action(action, dry_run=dry_run)
        
        if execution_result.status == ExecutionStatus.EXECUTED:
            logger.info(f"    Action EXECUTED automatically")
            if execution_result.rollback_by:
                logger.info(f"    ⏰ Auto-rollback at {execution_result.rollback_by}")
        elif execution_result.status == ExecutionStatus.ESCALATED:
            logger.info(f"    🔼 Action ESCALATED to human analyst")
            logger.info(f"    📋 Reason: {execution_result.reason}")
        elif execution_result.status == ExecutionStatus.REJECTED:
            logger.warning(f"      Action REJECTED: {execution_result.reason}")
        
        investigation_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"   Investigation {investigation_id} completed in {investigation_time:.2f}s")
        
        return {
            "investigation_id": investigation_id,
            "alert": alert,
            "enriched_context": enriched_context,
            "risk_assessment": risk_assessment,
            "recommended_action": action,
            "execution_result": execution_result,
            "investigation_time_seconds": investigation_time
        }
    
    def get_human_summary(self, investigation_result: dict) -> str:
        """
        Format investigation for human analyst review
        
        This is what appears in the security dashboard when
        an action is escalated for human approval
        """
        alert = investigation_result["alert"]
        assessment = investigation_result["risk_assessment"]
        action = investigation_result["recommended_action"]
        exec_result = investigation_result["execution_result"]
        
        summary = f"""
{'='*70}
    SECURITY ALERT INVESTIGATION
{'='*70}

ALERT ID: {alert.alert_id}
THREAT TYPE: {alert.threat_type.value}
SEVERITY: {alert.severity.value.upper()}
DETECTION CONFIDENCE: {alert.confidence}/100

AFFECTED ENTITY:
  User: {alert.affected_entities.get('user_id', 'N/A')}
  IP: {alert.affected_entities.get('ip', 'N/A')}
  Country: {alert.affected_entities.get('country', 'N/A')}

DETECTION SIGNALS:
{chr(10).join(f'  • {s.description} [weight: {s.weight}]' for s in alert.signals)}

{format_risk_assessment_for_display(assessment)}

{'='*70}
💡 RECOMMENDED ACTION
{'='*70}

ACTION: {action.action_type.value.upper()}
CONFIDENCE: {action.confidence}/100
BLAST RADIUS: {action.blast_radius.value}
REVERSIBLE: {'Yes' if action.reversible else 'No'}
AUTO-EXPIRE: {action.auto_expire if action.auto_expire else 'Manual intervention required'}

JUSTIFICATION:
{action.justification}

{'='*70}
  EXECUTION STATUS
{'='*70}

STATUS: {exec_result.status.value.upper()}
REASON: {exec_result.reason}

"""
        
        if exec_result.status == ExecutionStatus.ESCALATED:
            summary += """
  ANALYST ACTION REQUIRED

This action requires human approval due to:
- High blast radius, OR
- Confidence below auto-execution threshold, OR
- Protected entity targeted, OR
- Circuit breaker engaged

APPROVE: Execute recommended action
REJECT: Mark as false positive, no action taken
MODIFY: Adjust action parameters (duration, scope, etc.)

"""
        
        summary += f"""
{'='*70}
Investigation ID: {investigation_result['investigation_id']}
Completed in: {investigation_result['investigation_time_seconds']:.2f}s
{'='*70}
"""
        
        return summary


def demo_workflow():
    """
    Demonstrate the full investigation workflow
    Run this to see how the system processes an alert
    """
    from src.detection.rules import SuspiciousLoginDetector, Alert, ThreatType, Severity, Signal
    from datetime import datetime
    
    # Simulate a suspicious login alert
    print("🎯 DEMO: Simulating credential stuffing attack detection\n")
    
    detector = SuspiciousLoginDetector()
    
    # Mock logs showing suspicious activity
    suspicious_logs = [
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-12345",
            "status": "failed",
            "ip": "45.67.89.12",
            "country": "RO",
            "user_agent": "HeadlessChrome/91.0"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-12345",
            "status": "failed",
            "ip": "45.67.89.12",
            "country": "RO",
            "user_agent": "HeadlessChrome/91.0"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-12345",
            "status": "failed",
            "ip": "45.67.89.12",
            "country": "RO",
            "user_agent": "HeadlessChrome/91.0"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-12345",
            "status": "failed",
            "ip": "45.67.89.12",
            "country": "RO",
            "user_agent": "PhantomJS/2.1"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "user_id": "user-12345",
            "status": "failed",
            "ip": "45.67.89.12",
            "country": "RO",
            "user_agent": "Selenium/3.14"
        }
    ]
    
    user_profile = {
        "typical_countries": ["US"],
        "typical_hours": range(9, 18)
    }
    
    # Run detection
    alert = detector.detect(suspicious_logs, user_profile)
    
    if not alert:
        print("  No alert generated")
        return
    
    print(f"   Alert generated: {alert.alert_id}")
    print(f"   Threat: {alert.threat_type.value}")
    print(f"   Confidence: {alert.confidence}/100")
    print(f"   Signals: {len(alert.signals)}\n")
    
    # Run investigation
    orchestrator = AgentOrchestrator()
    result = orchestrator.investigate(alert, dry_run=False)
    
    # Display summary
    print("\n" + orchestrator.get_human_summary(result))


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )
    demo_workflow()

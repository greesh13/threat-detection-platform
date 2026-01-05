"""
AI Reasoning Agent
Uses Claude to analyze threats and explain risk in plain English
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
import json
import os
from enum import Enum


# Mock Anthropic API for demonstration
# In production, use: from anthropic import Anthropic
class MockAnthropic:
    """Simulates Claude API for demonstration"""
    
    class Messages:
        def create(self, model, max_tokens, messages, temperature=1.0):
            # In real implementation, this calls Claude API
            # For demo, return structured response
            return MockResponse()
    
    def __init__(self):
        self.messages = self.Messages()


class MockResponse:
    """Simulates API response"""
    
    class Content:
        def __init__(self):
            self.text = json.dumps({
                "risk_score": 85,
                "attack_pattern": "credential_stuffing",
                "reasoning": "Multiple failed logins from single IP using rotating user agents suggests automated attack",
                "false_positive_likelihood": "low",
                "missing_context": ["Is IP on threat intel blocklists?", "Recent password reset requests?"],
                "confidence_factors": {
                    "supporting": ["Headless browser detected", "Failed login burst", "Anomalous geography"],
                    "contradicting": []
                }
            })
    
    def __init__(self):
        self.content = [self.Content()]


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessment:
    """Output from reasoning agent"""
    risk_score: int  # 0-100
    risk_level: RiskLevel
    attack_pattern: str
    reasoning: str  # Plain English explanation
    false_positive_likelihood: str  # low/medium/high
    missing_context: List[str]
    confidence_factors: Dict[str, List[str]]
    recommended_actions: List[str]


class ReasoningAgent:
    """
    Analyzes alerts using Claude to provide human-readable risk assessment
    
    Key responsibilities:
    1. Interpret detection signals in context
    2. Identify attack patterns
    3. Assess false positive likelihood
    4. Explain reasoning in plain English
    5. Suggest what additional context would help
    """
    
    def __init__(self, api_key: Optional[str] = None):
        # In production: self.client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.client = MockAnthropic()  # Demo mode
        self.model = "claude-sonnet-4-20250514"
        
    def analyze(self, alert, enriched_context: Dict) -> RiskAssessment:
        """
        Analyze an alert with enriched context to produce risk assessment
        
        Args:
            alert: Alert object from detection engine
            enriched_context: Additional context from ContextAgent
            
        Returns:
            RiskAssessment with reasoning and recommendations
        """
        # Build structured prompt
        prompt = self._build_analysis_prompt(alert, enriched_context)
        
        # Call Claude API with safety constraints
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            temperature=0.3,  # Lower temperature for more consistent reasoning
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        # Parse structured response
        try:
            result = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            # Fallback if LLM doesn't return valid JSON
            result = self._fallback_heuristic_analysis(alert)
        
        # Validate and constraint the response
        validated_result = self._validate_response(result, alert)
        
        # Convert to RiskAssessment object
        return self._to_risk_assessment(validated_result)
    
    def _build_analysis_prompt(self, alert, context: Dict) -> str:
        """
        Construct prompt for Claude with all relevant information
        
        Prompt engineering principles:
        - Provide clear structure
        - Include all signals with explanations
        - Request specific output format (JSON)
        - Set boundaries on what agent can/cannot do
        """
        signals_text = "\n".join([
            f"- {s.name}: {s.description} (weight: {s.weight}/100)"
            for s in alert.signals
        ])
        
        user_context = context.get("user_profile", {})
        similar_incidents = context.get("similar_incidents", [])
        threat_intel = context.get("threat_intelligence", {})
        
        prompt = f"""You are a security analyst evaluating a potential threat. Analyze the following alert and provide a structured risk assessment.

ALERT DETAILS:
- Type: {alert.threat_type.value}
- Severity: {alert.severity.value}
- Confidence: {alert.confidence}/100
- Affected User: {alert.affected_entities.get('user_id')}
- Source IP: {alert.affected_entities.get('ip')}

DETECTION SIGNALS:
{signals_text}

USER CONTEXT:
- Account Age: {user_context.get('account_age_days', 'unknown')} days
- Typical Login Countries: {user_context.get('typical_countries', [])}
- Typical Activity Hours: {user_context.get('typical_hours', 'unknown')}
- Previous Alerts: {user_context.get('previous_alerts', 0)}
- User Role: {user_context.get('role', 'user')}

SIMILAR PAST INCIDENTS:
{json.dumps(similar_incidents[:3], indent=2) if similar_incidents else "None found"}

THREAT INTELLIGENCE:
- IP Reputation: {threat_intel.get('ip_reputation', 'unknown')}
- Known Attack Patterns: {threat_intel.get('known_patterns', [])}

TASK:
Analyze this alert and provide your assessment in JSON format with these fields:

{{
  "risk_score": <0-100>,
  "attack_pattern": "<brief name of attack pattern, e.g. 'credential_stuffing', 'data_exfiltration'>",
  "reasoning": "<2-3 sentence explanation of why this is or isn't a real threat>",
  "false_positive_likelihood": "<low|medium|high>",
  "missing_context": ["<what additional info would help confirm or refute?>"],
  "confidence_factors": {{
    "supporting": ["<signals that support this being a real threat>"],
    "contradicting": ["<signals that suggest false positive>"]
  }}
}}

IMPORTANT CONSTRAINTS:
- Base your reasoning ONLY on the provided signals and context
- Do not invent or assume signals that weren't detected
- Be precise about what you know vs. what you're uncertain about
- Consider both true positive and false positive scenarios
- If contradictory signals exist, acknowledge the ambiguity

Provide ONLY the JSON response, no additional text."""

        return prompt
    
    def _validate_response(self, result: Dict, alert) -> Dict:
        """
        Validate LLM output against safety constraints
        
        Safety checks:
        1. Risk score is within bounds (0-100)
        2. Attack pattern is reasonable (no hallucinated threats)
        3. Reasoning is grounded in actual signals
        4. No confident assertions without evidence
        """
        # Ensure risk score is reasonable
        risk_score = result.get("risk_score", 50)
        risk_score = max(0, min(100, risk_score))
        
        # Risk score shouldn't exceed detection confidence by more than 10 points
        # (prevents LLM from being overconfident)
        if risk_score > alert.confidence + 10:
            risk_score = alert.confidence
        
        result["risk_score"] = risk_score
        
        # Validate attack pattern is a known type
        known_patterns = {
            "credential_stuffing", "brute_force", "account_takeover",
            "data_exfiltration", "api_abuse", "privilege_escalation",
            "sql_injection", "command_injection", "lateral_movement",
            "reconnaissance", "unknown"
        }
        if result.get("attack_pattern", "").lower() not in known_patterns:
            result["attack_pattern"] = "unknown"
        
        # Ensure reasoning references actual signals
        reasoning = result.get("reasoning", "")
        signal_names = {s.name for s in alert.signals}
        
        # Check that reasoning mentions at least one actual signal
        mentions_signal = any(sig_name in reasoning.lower() for sig_name in signal_names)
        if not mentions_signal and alert.signals:
            # Add signal reference to reasoning
            result["reasoning"] = f"Based on {alert.signals[0].name}: {reasoning}"
        
        return result
    
    def _fallback_heuristic_analysis(self, alert) -> Dict:
        """
        Simple heuristic-based analysis if LLM fails
        Ensures system continues functioning even if AI unavailable
        """
        # Map threat types to likely attack patterns
        pattern_mapping = {
            "suspicious_login": "credential_stuffing",
            "abnormal_api_usage": "api_abuse",
            "privilege_escalation": "privilege_escalation"
        }
        
        attack_pattern = pattern_mapping.get(
            alert.threat_type.value,
            "unknown"
        )
        
        # Generate simple reasoning from signals
        signal_descriptions = [s.description for s in alert.signals]
        reasoning = f"Detected {len(alert.signals)} suspicious signals: {'; '.join(signal_descriptions[:2])}"
        
        return {
            "risk_score": alert.confidence,
            "attack_pattern": attack_pattern,
            "reasoning": reasoning,
            "false_positive_likelihood": "medium",
            "missing_context": ["Additional context needed for definitive assessment"],
            "confidence_factors": {
                "supporting": signal_descriptions,
                "contradicting": []
            }
        }
    
    def _to_risk_assessment(self, result: Dict) -> RiskAssessment:
        """Convert validated result to RiskAssessment object"""
        risk_score = result["risk_score"]
        
        # Map score to risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Generate action recommendations based on risk
        recommended_actions = self._generate_recommendations(risk_score, result)
        
        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            attack_pattern=result["attack_pattern"],
            reasoning=result["reasoning"],
            false_positive_likelihood=result.get("false_positive_likelihood", "medium"),
            missing_context=result.get("missing_context", []),
            confidence_factors=result.get("confidence_factors", {"supporting": [], "contradicting": []}),
            recommended_actions=recommended_actions
        )
    
    def _generate_recommendations(self, risk_score: int, result: Dict) -> List[str]:
        """Generate action recommendations based on risk level"""
        attack_pattern = result.get("attack_pattern", "unknown")
        
        # Base recommendations on risk score and attack type
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("Block IP address immediately")
            if attack_pattern in ["credential_stuffing", "account_takeover"]:
                recommendations.append("Force password reset for affected account")
                recommendations.append("Revoke all active sessions")
            elif attack_pattern in ["privilege_escalation"]:
                recommendations.append("Lock affected account pending investigation")
                recommendations.append("Review all actions taken by account in last 24h")
        
        elif risk_score >= 60:
            recommendations.append("Rate limit IP address")
            recommendations.append("Require MFA for next login")
            recommendations.append("Notify user of suspicious activity")
        
        elif risk_score >= 40:
            recommendations.append("Monitor for additional suspicious activity")
            recommendations.append("Log and review in next security analysis")
        
        else:
            recommendations.append("Log for baseline analysis")
        
        # Always recommend human review for edge cases
        if result.get("false_positive_likelihood") in ["medium", "high"]:
            recommendations.append("Escalate to human analyst for review")
        
        return recommendations


def format_risk_assessment_for_display(assessment: RiskAssessment) -> str:
    """
    Format risk assessment for human analyst viewing
    Plain English summary suitable for security dashboard
    """
    output = f"""
    RISK ASSESSMENT

RISK LEVEL: {assessment.risk_level.value.upper()} ({assessment.risk_score}/100)
ATTACK PATTERN: {assessment.attack_pattern}

ANALYSIS:
{assessment.reasoning}

FALSE POSITIVE LIKELIHOOD: {assessment.false_positive_likelihood.upper()}

   SUPPORTING EVIDENCE:
{chr(10).join(f"  • {factor}" for factor in assessment.confidence_factors.get('supporting', []))}

{'  CONTRADICTING EVIDENCE:' if assessment.confidence_factors.get('contradicting') else ''}
{chr(10).join(f"  • {factor}" for factor in assessment.confidence_factors.get('contradicting', []))}

 MISSING CONTEXT:
{chr(10).join(f"  • {ctx}" for ctx in assessment.missing_context)}

 RECOMMENDED ACTIONS:
{chr(10).join(f"  {i+1}. {action}" for i, action in enumerate(assessment.recommended_actions))}
"""
    return output.strip()

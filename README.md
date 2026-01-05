# AI-Powered Threat Detection & Response Platform

## Overview

**What this proves:** Senior-level system design combining deterministic security pipelines with AI-powered investigation and response, built for Uber-scale reliability.

**Core principle:** *Deterministic pipelines generate security signals. AI agents sit on top to investigate, reduce noise, and orchestrate response — with humans in the loop.*

## 1. What Threats Are Detected?

The system detects three critical threat categories:

### A. Suspicious Login Behavior
**Signals used:**
- Failed login attempts exceeding threshold (5+ in 10 minutes)
- Logins from anomalous geographies (new country)
- Logins outside typical user activity hours
- Impossible travel (same user, different cities, physically impossible timeframe)
- Use of known compromised user agents or TOR exit nodes

**Why these matter:** Account takeover is the #1 initial access vector

### B. Abnormal API Usage
**Signals used:**
- Rate limiting violations (>100 requests/minute per user)
- Access to resources outside user's normal scope
- Bulk data extraction patterns (sequential ID enumeration)
- API calls with unusual parameters (SQL injection patterns, path traversal)
- Privilege escalation attempts (requesting admin endpoints with user token)

**Why these matter:** API abuse leads to data exfiltration and lateral movement

### C. Privilege Escalation Patterns
**Signals used:**
- Role changes without approval workflow
- Direct database permission modifications
- Service account credential usage from non-service IPs
- Sudo/admin command execution by non-privileged users
- IAM policy changes expanding access scope

**Why these matter:** Attackers move from initial access → persistence → privilege escalation

## 2. How the System Works

### Detection Pipeline (Deterministic)

```
Logs → Kafka → Detection Rules → Alert with Confidence Score
                      ↓
              Anomaly Detection (ML)
```

**Rules Engine:**
- Stateless threshold checks (fast, reliable)
- Pattern matching (regex, AST parsing)
- Allowlist/blocklist lookups

**Anomaly Detection:**
- Isolation Forest for behavioral baselines
- Time-series forecasting for volume anomalies
- Clustering for grouping similar suspicious events

**Output:** Alert object with:
- Threat type
- Confidence score (0-100)
- Raw signals that triggered detection
- Affected entities (user, IP, resource)

### AI Agent Investigation (How Agents Reason)

When an alert fires, three specialized agents activate:

#### 1. Context Agent
**Inputs:** Alert + entity IDs  
**Process:**
1. Queries vector database for similar past incidents
2. Fetches user profile (role, tenure, typical behavior)
3. Retrieves last 100 log entries for affected user/IP
4. Checks for concurrent alerts on same entity

**Output:** Enriched context document

**Reasoning:** "This user typically logs in from San Francisco 9am-5pm PST. Current login is from Romania at 3am PST. User created 2 days ago. No previous alerts."

#### 2. Reasoning Agent
**Inputs:** Alert + enriched context  
**Process:**
1. Sends context to LLM with structured prompt:
   - "Given these signals, what attack pattern do they suggest?"
   - "What is the likelihood this is a false positive?"
   - "What additional context would confirm or refute the threat?"
2. Validates LLM output against rule constraints
3. Cross-references with threat intelligence database

**Output:** Risk assessment with plain English explanation

**Example reasoning:**
```
RISK: HIGH (85/100)

PATTERN: Credential stuffing attack
- 47 failed logins across 8 accounts in 5 minutes
- All from same IP (12.34.56.78, known VPN provider)
- User agents rotate but all are headless browsers
- No successful logins yet (credentials likely invalid)

FALSE POSITIVE LIKELIHOOD: LOW
- User never uses VPNs (0 instances in 6-month history)
- Normal login pattern is single-device, work hours only
- This behavior contradicts established baseline

MISSING CONTEXT:
- Is this IP on any threat intel blocklists?
- Has this user reported their account compromised?
```

#### 3. Action Agent
**Inputs:** Risk assessment + available response actions  
**Process:**
1. Maps threat type → response playbook
2. Checks action prerequisites (confidence threshold, blast radius)
3. Simulates action impact (how many users affected?)
4. If confidence >90% and low blast radius → execute
5. If confidence 70-90% or medium blast radius → escalate to human
6. If confidence <70% → log only, no action

**Output:** Response decision + rationale

**Available actions:**
- **Low risk:** Log + monitor, rate limit
- **Medium risk:** Require MFA, revoke session tokens
- **High risk:** Block IP, lock account, revoke API keys
- **Critical risk:** Disable service account, emergency escalation

**Decision tree:**
```python
if confidence > 90 and blast_radius == "single_user":
    execute_automatic_response()
elif confidence > 70 or blast_radius in ["team", "service"]:
    escalate_to_human()
else:
    log_and_monitor()
```

### Human-in-the-Loop

**When humans are involved:**
- Any action affecting >1 user
- Confidence score 70-90%
- Actions marked "high blast radius" (service accounts, API rate limits)
- Any time an agent recommends escalation

**Analyst workflow:**
1. Receives alert with full agent reasoning
2. Reviews evidence, context, recommended action
3. Approves, rejects, or modifies response
4. Provides feedback: "was this a true positive?"

**Feedback loop:**
- Analyst decisions stored in training database
- Monthly review of false positive rates by threat type
- Agent prompts tuned based on common analyst overrides
- Detection rules adjusted if systematic false positives found

## 3. How We Prevent Bad Actions

### Safety Mechanisms

#### A. Multi-Layer Approval
```python
# Action must pass ALL checks
if not action.passes_confidence_threshold():
    return Escalate("Low confidence")
    
if not action.passes_blast_radius_check():
    return Escalate("Affects multiple users")
    
if not action.passes_allowlist_check():
    return Escalate("Executive account targeted")
    
if not action.passes_rate_limit():
    return Escalate("Too many actions in time window")
    
execute(action)
```

#### B. Dry-Run Mode
All actions are first executed in dry-run mode:
- Simulates impact without making changes
- Logs what WOULD have happened
- Requires explicit confirmation for actual execution

#### C. Rollback Capability
Every action is reversible:
- IP blocks expire after 1 hour (auto-unblock)
- Account locks require manual analyst unlock
- Revoked tokens stored for 7 days (can restore)

#### D. Circuit Breakers
```python
if actions_last_hour > 100:
    disable_automatic_actions()
    alert_on_call_engineer()
    
if false_positive_rate_today > 20%:
    switch_to_human_approval_only()
```

#### E. Allowlists
Certain entities are never auto-actioned:
- Executive accounts
- On-call engineer accounts
- Critical service accounts (payment processing, etc.)

These generate high-priority alerts but require human approval.

### Audit Trail

Every action (executed or escalated) is logged with:
- Timestamp
- Alert ID
- Agent reasoning chain
- Action taken
- Analyst who approved (if applicable)
- Outcome (true positive / false positive)

Immutable append-only log stored for compliance and retrospectives.

## 4. What Happens When It Fails?

### Failure Modes & Mitigations

#### A. False Positives (Alert fatigue)
**Symptom:** Too many alerts, low true positive rate  
**Detection:** Monitor alert volume and analyst rejection rate  
**Mitigation:**
- If >30% of alerts rejected → increase confidence threshold
- Add feedback to detection rules (e.g., "ignore API burst for this service")
- Tune ML model with labeled false positives

**Failsafe:** Analysts can temporarily disable noisy detection rules

#### B. False Negatives (Missed threats)
**Symptom:** Attack succeeds without alert  
**Detection:** Post-incident review, red team exercises  
**Mitigation:**
- Weekly purple team exercises inject simulated attacks
- Measure detection rate for each attack type
- Add new detection rules for missed patterns

**Failsafe:** Complement with external SOC and threat intel feeds

#### C. Agent Hallucination (Bad reasoning)
**Symptom:** Agent recommends incorrect action based on flawed logic  
**Detection:** Human reviewers catch during approval  
**Mitigation:**
- Validate LLM outputs against rule constraints
- Require structured output format (JSON schema)
- Log all agent reasoning for post-review
- A/B test agent prompt changes with safety metrics

**Failsafe:** Confidence threshold prevents low-quality decisions from auto-executing

#### D. Performance Degradation (High latency)
**Symptom:** Alerts delayed, investigation takes too long  
**Detection:** P95 latency monitoring, alerting on >30s investigation time  
**Mitigation:**
- Cache frequent queries (user profiles, IP reputation)
- Batch log queries rather than one-by-one
- Fallback to rule-only detection if agents timeout

**Failsafe:** Deterministic detection continues even if agents fail

#### E. Dependency Failures (LLM API down)
**Symptom:** Agent investigation fails  
**Mitigation:**
- Retry with exponential backoff
- Fallback to simpler heuristic-based reasoning
- Cache recent agent responses for similar alerts

**Failsafe:** System degrades to deterministic detection only

#### F. Cascading Actions (Blocking legitimate traffic)
**Symptom:** Automatic action has unintended consequences  
**Detection:** Spike in support tickets, error rate monitoring  
**Mitigation:**
- Rate limits on actions per time window
- Circuit breaker disables auto-actions if error rate spikes
- Automatic rollback of recent actions if blast radius detected

**Failsafe:** 1-hour auto-expiry on all IP blocks

### Observability Dashboard

Key metrics tracked:
- Alert volume (by type, by hour)
- False positive rate (% of alerts rejected by analysts)
- Detection latency (time from log event → alert)
- Investigation latency (time from alert → response decision)
- Agent decision accuracy (% of auto-actions confirmed as true positives)
- Action effectiveness (did the action stop the threat?)

**Alerting thresholds:**
- False positive rate >20% → page on-call
- Detection latency >1 minute → warning
- Investigation latency >2 minutes → warning
- Agent accuracy <80% → disable auto-actions

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          LOG SOURCES                             │
│  (Application logs, Auth logs, API logs, System logs)           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
                 ┌───────────────┐
                 │  Kafka Stream │  (buffering, replay capability)
                 └───────┬───────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌──────────────────┐          ┌──────────────────┐
│  Rules Engine    │          │ Anomaly Detector │
│  (deterministic) │          │   (ML models)    │
└────────┬─────────┘          └────────┬─────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
                  ┌──────────┐
                  │  Alerts  │ (confidence score, signals)
                  └─────┬────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │      AI AGENT SYSTEM          │
        │  ┌─────────────────────────┐  │
        │  │  1. Context Agent       │  │
        │  │  (enrichment)           │  │
        │  └────────┬────────────────┘  │
        │           ▼                   │
        │  ┌─────────────────────────┐  │
        │  │  2. Reasoning Agent     │  │
        │  │  (risk assessment)      │  │
        │  └────────┬────────────────┘  │
        │           ▼                   │
        │  ┌─────────────────────────┐  │
        │  │  3. Action Agent        │  │
        │  │  (response decision)    │  │
        │  └────────┬────────────────┘  │
        └───────────┼────────────────────┘
                    │
         ┌──────────┴─────────────┐
         ▼                        ▼
  ┌─────────────┐        ┌──────────────────┐
  │  Auto-exec  │        │  Human Analyst   │
  │  (hi conf)  │        │   (lo/med conf)  │
  └──────┬──────┘        └────────┬─────────┘
         │                        │
         └────────────┬───────────┘
                      ▼
              ┌───────────────┐
              │   RESPONSE    │
              │  (block, lock,│
              │   revoke, etc)│
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │  Audit Log    │
              │  (compliance) │
              └───────────────┘
```

## 6. Tech Stack

- **Language:** Python 3.11+
- **Streaming:** Kafka (or mock queue for demo)
- **Detection:** Custom rules engine + scikit-learn (Isolation Forest)
- **Agents:** LangGraph for orchestration, Claude API for reasoning
- **API:** FastAPI
- **Storage:** 
  - PostgreSQL (alerts, actions, audit logs)
  - Qdrant (vector database for similar incident search)
- **Observability:** Prometheus + Grafana
- **Infrastructure:** Docker + Docker Compose (K8s config provided)

## 7. Getting Started

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Anthropic API key (for AI agents)

### Quick Start

```bash
# 1. Clone and setup
git clone <repo>
cd threat-detection-platform
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env

# 2. Start infrastructure
docker-compose up -d

# 3. Run detection pipeline
python -m src.detection.pipeline

# 4. Inject sample threats (for demo)
python -m src.demo.inject_threats

# 5. View dashboard
open http://localhost:3000
```

### Running Tests

```bash
# Unit tests
pytest tests/unit

# Integration tests
pytest tests/integration

# Simulate attack scenarios
python -m tests.scenarios.credential_stuffing
python -m tests.scenarios.privilege_escalation
```

## 8. Project Structure

```
threat-detection-platform/
├── src/
│   ├── detection/          # Rules engine + anomaly detection
│   │   ├── rules.py
│   │   ├── anomaly.py
│   │   └── pipeline.py
│   ├── agents/             # AI investigation system
│   │   ├── context.py
│   │   ├── reasoning.py
│   │   ├── action.py
│   │   └── orchestrator.py
│   ├── storage/            # Database models and queries
│   │   ├── models.py
│   │   └── repositories.py
│   ├── api/                # REST API for analysts
│   │   └── main.py
│   └── response/           # Action execution and rollback
│       └── executor.py
├── config/                 # Detection rules, thresholds
├── tests/                  # Unit, integration, scenario tests
├── docs/                   # Architecture diagrams, runbooks
└── docker/                 # Docker + K8s configs
```

## 9. Key Files to Review

1. **`src/detection/rules.py`** - How threats are detected
2. **`src/agents/reasoning.py`** - How agents think about threats
3. **`src/response/executor.py`** - Safety checks before actions
4. **`config/detection_rules.yaml`** - Tunable detection parameters
5. **`docs/RUNBOOK.md`** - What to do when system misbehaves

## 10. Design Decisions (Why Not X?)

**Q: Why not fully autonomous AI?**  
A: Security actions have real consequences. Humans must approve high-risk decisions. We optimize for zero false positives on automatic actions.

**Q: Why not train custom ML models?**  
A: Off-the-shelf Isolation Forest is sufficient for anomaly detection. Custom models require labeled data we don't have initially. Start simple, add complexity only if needed.

**Q: Why not build a UI?**  
A: Analysts already have tooling (SIEM, ticketing systems). API integration is more important than custom UI. If needed later, UI is straightforward to add.

**Q: Why Kafka?**  
A: Replay capability is critical for tuning detection rules. Need to reprocess historical logs when adding new detections. Kafka provides this out-of-box.

**Q: Why not rule-based actions (no AI)?**  
A: Rules create alert fatigue. AI reduces noise by explaining *why* something is risky and filtering out false positives. But detection itself remains deterministic (reliable).

## 11. Success Metrics

After 30 days in production:
- **False positive rate <10%** (vs industry avg of 40%)
- **Detection latency <30 seconds** (P95)
- **Investigation latency <2 minutes** (P95)
- **Analyst time saved 60%** (agents handle initial triage)
- **Zero inappropriate automatic actions** (blast radius prevented)

## 12. Future Enhancements

- Feedback-driven model fine-tuning (currently using prompted Claude)
- Integration with threat intelligence feeds (VirusTotal, AbuseIPDB)
- Collaborative agent reasoning (multiple agents debate before decision)
- Automatic rule generation from analyst feedback
- Cross-organization threat sharing (anonymized)

## 13. Contributing

See `CONTRIBUTING.md` for development setup, code standards, and PR process.

## 14. License

Apache 2.0 - See `LICENSE` file.

---

**Built for:** Uber-scale reliability, not AI hype  
**Philosophy:** Boring technology, extraordinary reliability  
**Contact:** [Your info here]

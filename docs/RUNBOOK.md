# Operational Runbook

## When the System Misbehaves

This document explains what to do when the threat detection system experiences problems.

---

## Table of Contents

1. [High False Positive Rate](#high-false-positive-rate)
2. [High False Negative Rate](#high-false-negative-rate)
3. [Detection Latency Issues](#detection-latency-issues)
4. [Agent Failures](#agent-failures)
5. [Cascading Automatic Actions](#cascading-automatic-actions)
6. [Database Performance Issues](#database-performance-issues)
7. [Circuit Breaker Activation](#circuit-breaker-activation)
8. [Emergency Procedures](#emergency-procedures)

---

## High False Positive Rate

**Symptom:** Analysts rejecting >20% of alerts

**Root Causes:**
- Detection rules too sensitive
- User behavior patterns changed
- New feature deployed that generates unexpected logs
- Seasonal activity changes (e.g., holiday travel)

**Immediate Actions:**

1. **Check the dashboard:**
   ```bash
   # View false positive rate by threat type
   curl http://localhost:3000/api/metrics/false_positive_rate
   ```

2. **Identify noisy detection rule:**
   - Check which threat type has highest rejection rate
   - Review recent alerts for common patterns

3. **Temporary mitigation:**
   ```python
   # Increase confidence threshold for noisy rule
   # In config/detection_rules.yaml
   
   suspicious_login:
     confidence_threshold: 80  # Was 70
     failed_login_threshold: 7  # Was 5
   ```

4. **Long-term fix:**
   - Analyze rejected alerts
   - Add exceptions for legitimate patterns
   - Update user behavioral baselines
   - Fine-tune signal weights

**Monitoring:**
```sql
-- Query false positives by threat type (last 24h)
SELECT 
    threat_type,
    COUNT(*) as total_alerts,
    SUM(CASE WHEN outcome = 'false_positive' THEN 1 ELSE 0 END) as false_positives,
    ROUND(100.0 * SUM(CASE WHEN outcome = 'false_positive' THEN 1 ELSE 0 END) / COUNT(*), 2) as fp_rate
FROM alerts
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY threat_type
ORDER BY fp_rate DESC;
```

**Escalation:**
- If FP rate >30% for 2+ hours → Page on-call SRE
- If no improvement after tuning → Disable problematic detection rule

---

## High False Negative Rate

**Symptom:** Real attacks not generating alerts (discovered in post-incident review)

**Root Causes:**
- Detection rules too restrictive
- New attack pattern not covered
- Attackers evading detection with low-and-slow techniques
- Missing log sources

**Immediate Actions:**

1. **Analyze the missed attack:**
   - Review logs from the incident
   - Identify which signals were present
   - Determine why they didn't trigger detection

2. **Create new detection rule:**
   ```python
   # Example: Add new signal for this attack pattern
   # In src/detection/rules.py
   
   def detect_new_pattern(self, logs):
       # Add logic to detect the missed pattern
       if <condition>:
           signals.append(Signal(
               name="new_attack_pattern",
               value=...,
               weight=30,
               description="..."
           ))
   ```

3. **Backfill historical logs:**
   - Reprocess last 7 days of logs with new rule
   - Identify if attack occurred before
   - Tune rule to minimize false positives

4. **Deploy updated rule:**
   ```bash
   # Deploy via CI/CD
   git commit -m "Add detection for attack pattern XYZ"
   git push
   
   # Or hot-reload in production
   kubectl rollout restart deployment/detection-pipeline
   ```

**Prevention:**
- Weekly purple team exercises
- Continuous red team engagement
- Subscribe to threat intelligence feeds
- Quarterly review of detection coverage

**Escalation:**
- Critical gap in detection → Immediate rule deployment
- Pattern seen in wild → Share with threat intel team

---

## Detection Latency Issues

**Symptom:** Alerts arriving >30 seconds after log event

**Root Causes:**
- Kafka lag
- Database query performance
- Detection pipeline CPU bottleneck
- Large batch sizes

**Immediate Actions:**

1. **Check Kafka lag:**
   ```bash
   kafka-consumer-groups --bootstrap-server kafka:9092 \
       --describe --group detection-pipeline
   ```
   
   - If lag >1000 messages → Scale up pipeline workers

2. **Check pipeline CPU:**
   ```bash
   kubectl top pods | grep detection-pipeline
   ```
   
   - If CPU >80% → Scale horizontally

3. **Check database queries:**
   ```sql
   -- Find slow queries
   SELECT query, mean_exec_time, calls
   FROM pg_stat_statements
   WHERE mean_exec_time > 100
   ORDER BY mean_exec_time DESC
   LIMIT 10;
   ```

4. **Temporary fix:**
   ```yaml
   # Increase pipeline parallelism
   # In docker-compose.yml or k8s deployment
   
   detection-pipeline:
     replicas: 5  # Was 2
     resources:
       requests:
         cpu: 2000m
         memory: 4Gi
   ```

**Long-term Solutions:**
- Add database indexes
- Implement caching for user profiles
- Optimize detection algorithms
- Use batch processing where appropriate

**SLA:**
- P95 latency target: <30 seconds
- If >1 minute for >15 minutes → Page on-call

---

## Agent Failures

**Symptom:** Agent investigation timeouts or errors

**Root Causes:**
- Anthropic API rate limits
- Anthropic API outage
- Network connectivity issues
- Malformed prompts
- Context too large

**Immediate Actions:**

1. **Check Anthropic API status:**
   ```bash
   curl https://status.anthropic.com/api/v2/status.json
   ```

2. **Check agent error rate:**
   ```python
   # In monitoring dashboard
   agent_error_rate = failed_investigations / total_investigations
   ```

3. **Fallback to heuristic mode:**
   ```python
   # Agents automatically fallback, but verify:
   # Check logs for "Fallback heuristic analysis" messages
   
   kubectl logs deployment/detection-pipeline | grep "Fallback"
   ```

4. **If API rate limited:**
   ```python
   # Reduce concurrent agent calls
   # In src/agents/reasoning.py
   
   MAX_CONCURRENT_AGENTS = 5  # Was 10
   ```

**Degraded Mode Behavior:**
- System continues with deterministic detection only
- Alerts generated but without AI reasoning
- Human analysts handle all triage
- No automatic actions executed

**Recovery:**
- Once API recovered, reprocess failed investigations
- Review actions taken in degraded mode

**Escalation:**
- If degraded >1 hour → Notify security team
- If degraded >4 hours → Consider alternative LLM provider

---

## Cascading Automatic Actions

**Symptom:** Multiple legitimate users blocked, spike in support tickets

**Root Causes:**
- False positive triggering automatic blocks
- Shared IP (corporate VPN, NAT) blocked
- Overly aggressive action parameters
- Bug in action executor

**EMERGENCY STOP:**

```bash
# Immediately disable all automatic actions
kubectl exec -it deployment/detection-pipeline -- \
    python -c "from src.response.executor import ActionExecutor; \
               executor = ActionExecutor(); \
               executor.trip_circuit_breaker('Manual emergency stop')"
```

**Immediate Actions:**

1. **Assess blast radius:**
   ```sql
   -- How many users affected?
   SELECT 
       action_type,
       COUNT(DISTINCT user_id) as affected_users,
       COUNT(*) as total_actions
   FROM actions
   WHERE timestamp > NOW() - INTERVAL '1 hour'
     AND status = 'executed'
   GROUP BY action_type;
   ```

2. **Rollback recent actions:**
   ```python
   # Rollback all actions from last hour
   python scripts/rollback_actions.py --since "1 hour ago"
   ```

3. **Identify root cause:**
   - Review alert that triggered cascade
   - Check if shared IP affected multiple users
   - Examine action executor logs

4. **Prevent recurrence:**
   ```python
   # Add affected IP to allowlist temporarily
   # In src/response/executor.py
   
   self.temporary_allowlist.add("shared-corporate-ip")
   ```

**Communication:**
- Notify affected users via email
- Post status update on status page
- Update support team with context

**Post-Incident:**
- Write incident report
- Update runbook with learnings
- Add safeguards to prevent similar cascades

---

## Database Performance Issues

**Symptom:** Query timeouts, high database CPU

**Immediate Actions:**

1. **Check active queries:**
   ```sql
   SELECT pid, now() - pg_stat_activity.query_start AS duration, query
   FROM pg_stat_activity
   WHERE state = 'active'
   ORDER BY duration DESC;
   ```

2. **Kill long-running queries:**
   ```sql
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE pid <> pg_backend_pid()
     AND state = 'active'
     AND now() - pg_stat_activity.query_start > interval '5 minutes';
   ```

3. **Check for missing indexes:**
   ```sql
   -- Find sequential scans on large tables
   SELECT schemaname, tablename, seq_scan, seq_tup_read
   FROM pg_stat_user_tables
   WHERE seq_scan > 1000
   ORDER BY seq_tup_read DESC;
   ```

4. **Add missing indexes:**
   ```sql
   -- Example indexes for common queries
   CREATE INDEX CONCURRENTLY idx_alerts_timestamp 
       ON alerts(timestamp DESC);
   
   CREATE INDEX CONCURRENTLY idx_alerts_user_id 
       ON alerts(user_id) WHERE timestamp > NOW() - INTERVAL '7 days';
   ```

**Scaling:**
```bash
# Increase database resources
kubectl scale statefulset postgres --replicas=3
```

---

## Circuit Breaker Activation

**Symptom:** "Circuit breaker tripped" errors, no automatic actions

**When it activates:**
- False positive rate >20%
- Action error rate >10%
- Manual emergency stop

**What happens:**
- All future actions escalate to humans
- Alert generation continues normally
- System operates in "analyst-only" mode

**Recovery Steps:**

1. **Verify system is stable:**
   - Check false positive rate is <10%
   - Confirm no ongoing issues
   - Review recent actions for problems

2. **Get approval to reset:**
   - Requires security team lead approval
   - Document reason for trip and recovery plan

3. **Reset circuit breaker:**
   ```python
   from src.response.executor import ActionExecutor
   
   executor = ActionExecutor()
   executor.reset_circuit_breaker(analyst_id="analyst-lead-001")
   ```

4. **Monitor closely:**
   - Watch dashboards for 1 hour
   - Be ready to trip again if issues recur

---

## Emergency Procedures

### Complete System Shutdown

```bash
# Stop all components
docker-compose down

# Or in Kubernetes
kubectl delete namespace threat-detection
```

### Emergency Rollback

```bash
# Rollback to previous stable version
kubectl rollout undo deployment/detection-pipeline
kubectl rollout undo deployment/api
```

### Data Backup

```bash
# Backup critical data before major changes
pg_dump -h localhost -U security_user threat_detection > backup.sql
```

### On-Call Escalation

**Severity Levels:**
- **P0 (Critical):** System down, zero detection, data loss
  - Page: VP Security + SRE Lead
  - Response: Immediate
  
- **P1 (High):** Major degradation, >50% false positives, cascading actions
  - Page: Security Engineer + SRE
  - Response: 15 minutes
  
- **P2 (Medium):** Degraded performance, high latency
  - Notify: Security team Slack channel
  - Response: 1 hour

---

## Contact Information

- **On-Call Security Engineer:** PagerDuty rotation
- **On-Call SRE:** PagerDuty rotation  
- **Security Team Lead:** [Contact info]
- **VP Engineering:** [Contact info]

## Related Documentation

- [Architecture Diagram](../docs/architecture.md)
- [Metrics Dashboard](http://localhost:3000/d/threat-detection)
- [Incident Response Plan](../docs/incident-response.md)

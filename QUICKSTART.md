# Quick Start Guide

Get the AI-Powered Threat Detection Platform running in 5 minutes.

## Prerequisites

- Docker & Docker Compose installed
- Python 3.11+ (for local development)
- Anthropic API key (get one at console.anthropic.com)

## Option 1: Demo Mode (Fastest)

Run the demo scenarios without any infrastructure:

```bash
# 1. Clone the repository
cd threat-detection-platform

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run the demo
python src/demo.py
```

This will simulate 4 attack scenarios and show you how the system detects and responds.

**What you'll see:**
- Credential stuffing detection
- API data extraction detection
- Privilege escalation detection
- False positive handling

## Option 2: Full Infrastructure (Docker)

Run the complete system with all components:

```bash
# 1. Setup environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Start all services
docker-compose up -d

# 3. Wait for services to be healthy (30-60 seconds)
docker-compose ps

# 4. Verify all services are running
curl http://localhost:8000/health  # API
curl http://localhost:9090/        # Prometheus
curl http://localhost:3000/        # Grafana (admin/admin)
```

**Services started:**
- PostgreSQL (port 5432) - Alert storage
- Qdrant (port 6333) - Vector database
- Kafka (port 9092) - Log streaming
- Detection Pipeline - Real-time threat detection
- API (port 8000) - Analyst interface
- Prometheus (port 9090) - Metrics
- Grafana (port 3000) - Dashboards

## Option 3: Local Development

Run components individually for development:

```bash
# Terminal 1: Start databases only
docker-compose up postgres qdrant kafka -d

# Terminal 2: Run detection pipeline locally
export POSTGRES_HOST=localhost
export ANTHROPIC_API_KEY=your_key_here
python -m src.detection.pipeline

# Terminal 3: Inject test data
python -m src.demo
```

## Quick Test

Once running, test the API:

```bash
# Get system health
curl http://localhost:8000/health

# Get recent alerts
curl http://localhost:8000/api/alerts?limit=10

# Approve an escalated action
curl -X POST http://localhost:8000/api/actions/ACT-12345/approve \
  -H "Content-Type: application/json" \
  -d '{"analyst_id": "analyst-001", "approved": true}'
```

## View Dashboards

1. **Grafana**: http://localhost:3000
   - Username: admin
   - Password: admin
   - Dashboard: "Threat Detection Overview"

2. **Prometheus**: http://localhost:9090
   - Metrics: `threat_detection_alerts_total`, `threat_detection_fp_rate`

3. **API Docs**: http://localhost:8000/docs
   - Interactive Swagger UI

## Inject Sample Threats

Generate realistic threat scenarios:

```bash
# Credential stuffing attack
python scripts/inject_threat.py --type credential_stuffing --count 10

# API abuse
python scripts/inject_threat.py --type api_abuse --user user-123

# Privilege escalation
python scripts/inject_threat.py --type privilege_escalation --target svc-payments
```

Watch alerts appear in:
- API: `curl http://localhost:8000/api/alerts`
- Logs: `docker-compose logs -f detection-pipeline`
- Grafana: Dashboard shows real-time metrics

## Run Tests

```bash
# Unit tests
pytest tests/unit -v

# Integration tests
pytest tests/integration -v

# All tests with coverage
pytest --cov=src tests/
```

## Common Issues

### API Key Error
```
Error: ANTHROPIC_API_KEY not set
```
**Fix:** Add your API key to `.env` file:
```bash
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
```

### Port Already in Use
```
Error: bind: address already in use
```
**Fix:** Change ports in `docker-compose.yml` or stop conflicting services:
```bash
# Find what's using port 5432
lsof -i :5432
# Kill it or change postgres port in docker-compose.yml
```

### Database Connection Failed
```
Error: could not connect to server
```
**Fix:** Wait for databases to be fully ready:
```bash
# Check health
docker-compose ps
# Restart if needed
docker-compose restart postgres
```

## Next Steps

1. **Customize Detection Rules**: Edit `config/detection_rules.yaml`
2. **Add New Signals**: Modify `src/detection/rules.py`
3. **Tune Confidence Thresholds**: Update `.env` file
4. **Review Architecture**: Read `README.md` sections 1-5
5. **Learn Operations**: Read `docs/RUNBOOK.md`

## Getting Help

- **Documentation**: See `README.md` for comprehensive guide
- **Examples**: See `src/demo.py` for usage patterns
- **Tests**: See `tests/` for examples of all features
- **Issues**: Check `docs/RUNBOOK.md` for troubleshooting

## Stopping the System

```bash
# Stop all containers
docker-compose down

# Stop and remove all data
docker-compose down -v
```

## What to Look At

After starting the system, check these to understand what's happening:

1. **Detection Logic**: `src/detection/rules.py`
   - See exactly what patterns trigger alerts
   - Understand confidence scoring

2. **Agent Reasoning**: `src/agents/reasoning.py`
   - See how AI analyzes threats
   - Review prompt engineering

3. **Safety Checks**: `src/response/executor.py`
   - See multi-layer approval process
   - Understand when actions escalate

4. **Demo Scenarios**: `src/demo.py`
   - Run realistic attack simulations
   - See end-to-end workflow

**Most Important**: The README answers all the critical questions about how the system works, what it detects, and how it prevents bad actions. Start there!

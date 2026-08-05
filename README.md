# SENTINEL — CIS Benchmark Compliance Auditing Tool

SENTINEL is an AI-driven security compliance auditor designed for remote Linux (Ubuntu/RHEL) and Windows target environments. It deterministicly collects host configurations, audits them against CIS Benchmark rules using Gemini, and presents findings in interactive PDF reports and a formal security dashboard web UI.

---

## Features

- **Granular CIS Rule Filtering (`--rules`)**: Run audits against individual CIS rule IDs (e.g. `--rules 5.1.20`), comma-separated lists (`--rules 5.1.20,5.4.1.1,7.1.5`), or entire parent sections (`--rules 5.1` or `--rules 6.2`).
- **Formal Web Dashboard**: High-density SOC audit dashboard with compliance posture gauges, Section 1-7 progress breakdowns, filterable findings table, evidence breakdown, and side-by-side run comparison.
- **REST API**: Non-blocking FastAPI backend exposing audit execution, status tracking, rule catalog, run history, and diff analysis endpoints.
- **Deterministic SSH & WinRM Data Collectors**: Grouped data collectors gathering filesystem flags, SSH config, firewall rules, PAM, auditd, local users, and file permissions.

---

## Installation & Setup

1. **Activate Virtual Environment**:
   ```bash
   source .venv/bin/activate
   ```

2. **Configure Gemini API Key**:
   Ensure `GEMINI_API_KEY` is set in your environment or `.env` file:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

---

## Running the Web Frontend & REST API

To launch the web dashboard and REST API server:

```bash
./.venv/bin/python -m uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Or activate the virtual environment first:
```bash
source .venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
- Open **`http://localhost:8000`** in your browser to access the **SENTINEL Security Dashboard**.
- Open **`http://localhost:8000/docs`** to explore the interactive OpenAPI API documentation.

---

## Running via Command Line (CLI)

### 1. Full Security Audit
```bash
python3 main.py username target-hostname --password "secret"
```

### 2. Auditing Specific CIS Rules or Parent Sections
```bash
# Audit specific rules
python3 main.py username target-hostname --rules 5.1.20,5.4.1.1,7.1.5

# Audit all rules under Section 5.1 (SSH)
python3 main.py username target-hostname --rules 5.1

# Audit Section 6.2 (Auditd)
python3 main.py username target-hostname --rules 6.2
```

### 3. List Implemented CIS Rules
```bash
python3 main.py --list-rules
```

---

## Running Unit Tests

Run the complete pytest test suite:

```bash
./.venv/bin/pytest -v
```

# SENTINEL-CONFIG — CIS Benchmark Security Compliance & Audit Platform

SENTINEL-CONFIG is an AI-driven security compliance auditor designed for remote Linux (Ubuntu/RHEL) and Windows target environments. It deterministically collects host configurations, audits them against CIS Benchmark rules using Gemini, and presents findings in interactive PDF reports and a modern light-themed SOC security dashboard web UI.

---

## Features

- **Professional Executive Light Theme**: Modern, high-density light-mode Web Dashboard UI with responsive posture gauges, section progress cards, filterable findings table, evidence drawer, and run comparison diff view.
- **Executive Light PDF Reports**: Programmatic PDF export with light-themed Matplotlib pie/bar compliance charts and formatted executive CSS styles.
- **Custom Brand Logo Support**: Built-in support for corporate brand logos (`web/image.png` served automatically).
- **Granular CIS Rule Filtering (`--rules`)**: Run audits against individual CIS rule IDs (e.g. `--rules 5.1.20`), comma-separated lists (`--rules 5.1.20,5.4.1.1,7.1.5`), or entire parent sections (`--rules 5.1` or `--rules 6.2`).
- **REST API**: Non-blocking FastAPI backend exposing audit execution, status tracking, rule catalog, run history, and comparison endpoints.
- **Deterministic SSH & WinRM Data Collectors**: Grouped data collectors gathering filesystem flags, SSH config, firewall rules, PAM, auditd, local users, and file permissions.

---

## Installation & Environment Setup

1. **Clone & Setup Virtual Environment**:
   ```bash
   uv sync
   # Or using standard venv:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Gemini API Key**:
   Ensure `GEMINI_API_KEY` is set in your environment:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

---

## Running the Web Dashboard & REST API

To launch the web server with hot-reload enabled:

```bash
uv run uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

*Or using the activated virtual environment:*

```bash
source .venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
- **Web Dashboard**: Open **`http://localhost:8000`** in your browser.
- **API Documentation**: Open **`http://localhost:8000/docs`** for interactive OpenAPI docs.

---

## Running via Command Line (CLI)

### 1. Full Remote Security Audit
```bash
uv run python main.py root 192.168.1.50 --password "secret"
```

### 2. Targeted CIS Audit (Rule / Section Filters)
```bash
# Audit specific rule IDs
uv run python main.py root 192.168.1.50 --rules 5.1.20,5.4.1.1,7.1.5

# Audit all rules under Section 5.1 (SSH)
uv run python main.py root 192.168.1.50 --rules 5.1

# Audit Section 6.2 (Auditd)
uv run python main.py root 192.168.1.50 --rules 6.2
```

### 3. List Supported CIS Benchmark Rules
```bash
uv run python main.py --list-rules
```

---

## Running Unit Tests

Run the unit test suite:

```bash
uv run pytest
```

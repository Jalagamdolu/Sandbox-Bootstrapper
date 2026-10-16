# Contributing to Developer Sandbox Bootstrapper

Thank you for your interest in contributing to the **Developer Sandbox Bootstrapper**! This project provides a self-contained, locally deployable agentic AI sandbox orchestration platform.

---

## 1. Core Engineering Principles

When contributing to this repository, adhere to the following mandatory constraints:

1. **100% Local & Zero-Cost:** The application must never depend on external paid APIs, cloud services, or hosted databases. All execution is simulated within local directories and persisted in local SQLite.
2. **Pluggable & Fallback LLM Interfaces:** LLM inference is optional (via local Ollama). When disabled or unreachable, the system must deterministically fall back to template-based planning without throwing unhandled exceptions.
3. **Strict Server-Side Governance:** Privileged actions (`PROVISION_MOCK_SANDBOX`, `SEED_SYNTHETIC_DATA`, `EXECUTE_SMOKE_TEST`) require explicit human approval, JIT HMAC-SHA256 tokens, and RFC 8785 canonical plan binding.
4. **Honest Agentic Capabilities:** Do not describe deterministic functions or rule-based state graphs as AI agents. Document models and algorithms accurately.
5. **Tamper-Evident Auditing:** All state transitions and security evaluations must be recorded to the append-only, SHA-256 hash-chained audit ledger.

---

## 2. Development Setup

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Jalagamdolu/Sandbox-Bootstrapper.git
   cd Sandbox-Bootstrapper
   ```

2. **Initialize Environment & Dependencies:**
   Run the initialization script (or set up a Python 3.11+ virtual environment manually):
   ```powershell
   .\scripts\init_env.ps1
   ```

3. **Configure Environment:**
   Copy the `.env.example` file to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```

---

## 3. Running the Applications Locally

- **Start FastAPI Backend:**
  ```powershell
  .\scripts\start_api.ps1
  # Backend runs at http://127.0.0.1:8000 (OpenAPI docs at /docs)
  ```

- **Start Streamlit Developer Console:**
  ```powershell
  .\scripts\start_ui.ps1
  # Console UI opens at http://localhost:8501
  ```

---

## 4. Testing & Code Quality

Before opening a pull request, ensure the complete test suite passes and coverage meets or exceeds the baseline (>= 80% statement coverage):

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=src -v
```

### Testing Guidelines:
- Place unit and integration tests in the `tests/` directory following the naming pattern `test_<component>.py`.
- Mock external systems (such as local Ollama HTTP endpoints) using `unittest.mock` or isolated local HTTP servers.
- Ensure all test artifacts and databases use temporary directories (`tmp_path`).
- Never check in database files, sandbox directories, or runtime logs.

---

## 5. Security & Secret Management

- Never commit secrets, credentials, API keys, or private tokens.
- Keep `.gitignore` updated to prevent accidental check-ins of `.env`, `*.db`, or `data/sandboxes/`.
- Ensure all path operations use `src/adapters/path_utils.py` (`resolve_safe_path`) to prevent path traversal vulnerabilities.
- Ensure any privileged execution flows through `src/agents/executor.py` (`ExecutionAgent.execute_step`).

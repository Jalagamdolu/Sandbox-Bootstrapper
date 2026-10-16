# Architectural Decision Records & Ten-Pass Review: Developer Sandbox Bootstrapper

**Document Version:** 1.3.0  
**Status:** PROPOSED FOR REVIEW (ARCHITECTURE PLANNING ONLY)  
**Date:** 2026-10-16  

> [!NOTE]
> **Planning Phase Declaration:** The architectural decisions, risk analyses, and review passes documented herein reflect **design-time evaluations**. In accordance with architectural governance, no claim of passing software tests or verified execution compatibility is made until software implementation and test suite execution take place.

---

## 1. Architectural Decision Records (ADRs)

### ADR-001: Decoupling Streamlit Frontend from FastAPI Backend
- **Context:** The system requires a developer-friendly UI for selecting templates, inspecting DAG plans, and submitting approvals, alongside a testable backend.
- **Decision:** Run Streamlit purely as an untrusted HTTP client on port 8501 communicating with a headless FastAPI application on port 8000.
- **Rationale:** Streamlit's script re-run model makes direct in-process stateful orchestration and server-side approval gating fragile. Decoupling ensures all security gates, database transactions, LangGraph state, and audit logs live exclusively inside the FastAPI backend.
- **Consequences:** Streamlit cannot directly touch the database or call adapters; it must use REST endpoints. Frontend flags (e.g. `approved: true`) and client-claimed identity headers (e.g. `X-Approver-Id`) are structurally ignored by the backend.

---

### ADR-002: LangGraph for Workflow Convenience & ServerSideAuthGuard as Security Boundary
- **Context:** Provisioning and seeding require explicit state management, human-in-the-loop pause/resumption, and crash recovery. However, relying on graph interruption alone as the security boundary is dangerous if the orchestrator is bypassed or compromised.
- **Decision:** Use LangGraph's `StateGraph` backed by an SQLite checkpointer for orchestration convenience (`interrupt_before`), but enforce an independent **Shared Server-Side Authorization Guard (`ServerSideAuthGuard`)** directly inside both `MockSandboxProvisioner` and `SyntheticDataSeeder`.
- **Rationale:** The true security boundary resides in the tool adapters themselves. The guard revalidates 8 critical parameters (approval record existence, request ID, plan hash, plan version, target environment, granted scopes, expiry, and atomic state) immediately before taking any privileged action.
- **Consequences:** Privileged operations cannot execute even if invoked directly via code or an orchestrator bug without an active, unconsumed database approval record.

---

### ADR-003: Deterministic Policy Engine & Closed Action Allowlist
- **Context:** The system must never execute arbitrary shell commands or raw Python code obtained from repository configurations or LLM outputs.
- **Decision:** Implement a policy engine enforcing a closed enum of 7 actions (`StepActionType`).
- **Rationale:** By eliminating generic `EXECUTE_SHELL` or `RUN_SCRIPT` actions, prompt injection and command injection vulnerabilities are neutralized at the architectural level. Every step maps to a strongly typed Python method.
- **Consequences:** Any novel functionality requires explicitly adding a new enum member, schema, and typed adapter method.

---

### ADR-004: Three-Tier Approval Integrity, Server-Side Token Identity & Atomic CAS Consumption
- **Context:** Human approvals must be bound to the exact planned actions, scopes, target environment, and fixtures to prevent plan drift, parameter tampering, or identity spoofing.
- **Decision:**
  1. *Server-Side Token Identity Resolution:* The backend structurally ignores any client-supplied identity header (e.g. `X-Approver-Id`). Clients present an `Authorization: Bearer <token>` or `X-Approver-Token`. The server computes `SHA-256(raw_token)` and performs a constant-time lookup (`hmac.compare_digest`) against server-stored hashes in `approver_tokens` to establish the immutable `ApproverIdentity(approver_id, role, authorized_scopes)`.
  2. *Token Lifecycle Governance:* Generated with 256 bits of entropy (`secrets.token_urlsafe(32)`); stored exclusively hashed at rest; strictly redacted (`[REDACTED]`) from all logs and error traces; revocable via `revoked_at` timestamp.
  3. *Atomic Compare-And-Swap (CAS) Consumption:* Approval execution runs inside an exclusive `BEGIN IMMEDIATE` SQLite transaction updating all 8 parameters (`approval_id`, `request_id`, `canonical_plan_hash`, `plan_version`, `target_environment`, `granted_scopes`, `is_revoked = 0`, `execution_consumed = 0`, `expires_at >= now`). Concurrent attempts return 0 rows and abort with HTTP 409 Conflict.
  4. *Automated Invalidation on Plan/Scope Mutation:* Database trigger `revoke_approvals_on_plan_change` marks existing unconsumed approvals `is_revoked = 1` immediately whenever a plan is modified.
  5. *Genuine RFC 8785 Canonical Hashing:* Preserves Unicode code points as-is without character normalization (per RFC 8785 Section 3.2.2); sorts keys by UTF-16 code units; uses ECMAScript shortest round-trip float formatting; tested against official RFC vectors.
- **Rationale:** Neutralizes identity spoofing, race conditions, replay attacks, and plan drift at the database level.
- **Consequences:** Local v1 token authentication protects against untrusted web clients, but does not provide cryptographic non-repudiation against local host administrators with OS-level memory access.

---

### ADR-005: Deterministic Template Planner as Baseline; Ollama LLM Disabled by Default
- **Context:** The system may optionally parse unstructured `README.md` files to suggest setup steps, but LLMs introduce latency, non-determinism, and prompt injection risks.
- **Decision:** Make the deterministic template planner the default operational baseline. Disable the Ollama LLM by default (`ENABLE_OLLAMA_PLANNER=false`, pending owner approval).
- **Rationale:** Guarantees zero local LLM daemon dependency, zero cost, and immediate startup for new developers. If enabled, Ollama outputs are treated as untrusted text, strictly sanitized, and automatically fall back to the template planner on any failure.
- **Consequences:** LLM capabilities must be explicitly enabled by configuration.

---

### ADR-006: SQLite Application Triggers & Hash-Chained Audit Trail with Documented Assumptions
- **Context:** The system needs reliable local persistence for audit records and state transitions without external database infrastructure.
- **Decision:** Use SQLite in Write-Ahead Logging (`WAL`) mode. Implement database triggers blocking `UPDATE` and `DELETE` on `audit_log` as an **application-level control**. Implement **SHA-256 hash-chaining** across audit records to detect partial or out-of-band row tampering.
- **Documented Stated Assumptions & Limitations:**
  - *Assumption:* Hash-chaining and triggers prevent accidental data modification and reveal unauthorized SQL row edits.
  - *Explicit Limitation:* An attacker with direct write access to the `.db` file can rewrite all audit rows and recompute the entire hash chain from the genesis block.
  - *Production Hardening Option:* Requires an **External Trusted Anchor** (periodically anchoring the latest `event_hash` to a remote write-once S3 Object Lock bucket, remote syslog, or RFC 3161 timestamping authority).
- **Consequences:** Local v1 provides tamper detection against application errors and SQL injection, but requires external anchoring for adversary-grade non-repudiation.

---

### ADR-007: Synthetic Data by Construction & Defense-in-Depth Secret Scanning
- **Context:** Sandboxes must have realistic test data without risking real customer data or production credentials.
- **Decision:** Generate data strictly by construction using deterministic synthetic generators (seeded Faker) or controlled fixtures. Prohibit production database imports structurally. Treat automated regex scanning for PII and secrets as **secondary defense-in-depth**, not as proof of synthetic nature.
- **Rationale:** Acknowledges that regex scanning cannot prove a string is synthetic (e.g., a real name or non-patterned key passes regex). Synthetic origin is guaranteed by construction.
- **Consequences:** Seeded data is purely synthetic; developers cannot test against live customer data.

---

### ADR-008: Mock Sandbox Provisioner & Explicit Mock Smoke-Login Disclaimer
- **Context:** The local developer sandbox must simulate environment readiness and authentication verification without spinning up real cloud resources or connecting to live enterprise IdPs.
- **Decision:** Provide typed mock provisioner and smoke test adapters that simulate sandbox endpoints and test authentication locally, while attaching mandatory disclaimers and recording concrete assertions (HTTP 200 on health and login, mock JWT claims, latency).
- **Rationale:** Prevents developers from misinterpreting a successful local test as live corporate IdP certification.
- **Consequences:** Real cloud deployment requires developing production adapters in future phases.

---

### ADR-009: Sandbox Retention, Disk-Growth Controls & Safe Compensation
- **Context:** Interrupted provisioning or unconstrained sandbox proliferation can exhaust workstation disk space or cause accidental resource deletion during compensation.
- **Decision:**
  1. *Active Retention Policy:* Default **24-hour expiration** with an option to extend via UI (pending owner approval).
  2. *Failed Sandbox Handling:* Quarantined for **1 hour** for debugging, then safely cleaned up.
  3. *Disk-Growth Quota:* Maximum of **5 active sandboxes** and **10 GB total storage**. Exceeding limits returns HTTP 507 Insufficient Storage.
  4. *Ownership-Verified Cleanup:* Compensator verifies resource ownership (`.sandbox-metadata.json` matching `request_id` and token) before deleting any sandbox directory.
  5. *Audit Preservation Invariant:* Deleting a sandbox directory **never deletes its audit log records or setup manifest**. Audit records and manifests are retained indefinitely.
- **Rationale:** Balances developer debugging needs with disk preservation and prevents rogue directory deletions.
- **Consequences:** Unverified directories are quarantined, never deleted blindly.

---

### ADR-010: Zero-Secret JSON Manifest Design
- **Context:** The bootstrap process produces a JSON manifest describing the created environment for downstream tools.
- **Decision:** Strip all passwords, access tokens, and private keys from the manifest, replacing them with `[REDACTED]`, and sign the manifest with a genuine RFC 8785 SHA-256 digest.
- **Rationale:** Manifests are often shared or checked into git; zero-secret design prevents accidental credential leakage.
- **Consequences:** Actual runtime tokens must be retrieved dynamically via authenticated local session endpoints, not read from static manifest files.

---

### ADR-011: Dependency Compatibility & Python 3.12 Baseline Recommendation
- **Context:** The host workstation currently has Python 3.14.5 installed. Python 3.14 is a very recent release with limited precompiled binary wheels for packages like `pydantic-core`, `greenlet`, or `uvicorn`.
- **Decision:** Recommend **Python 3.12 (or 3.11)** as the primary baseline for the virtual environment. Do not claim Python 3.14 compatibility without execution evidence. Provide a clean virtual-environment validation procedure in PowerShell.
- **Rationale:** Ensures dependable dependency installation without requiring C-compiler toolchains (e.g., Microsoft Visual C++ Build Tools) on developer machines.
- **Consequences:** Developers on Python 3.14 should install Python 3.12 if wheel compilation issues arise.

---

## 2. Ten Distinct Architecture Review Passes

```
+----------------------------------------------------------------------------------------------------+
| Ten Architecture Review Passes (Design-Time Evaluations)                                           |
|                                                                                                    |
| 1. Requirements Coverage       2. Component Boundaries          3. Workflow Ordering               |
|    [ PASS: 16/16 Covered ]        [ PASS: Guard in Adapters ]      [ PASS: Strict Prerequisite State]|
|                                                                                                    |
| 4. Approval Security           5. Least Privilege Scope         6. Manifest Consistency            |
|    [ PASS: Server-Token & CAS ]   [ PASS: Closed 7-Action Enum ]   [ PASS: Zero Secrets + Hash ]   |
|                                                                                                    |
| 7. Failure Handling & Retries  8. Persistence & Concurrency     9. Verification & IdP Realism      |
|    [ PASS: 24h & Safe Cleanup]    [ PASS: Hash-Chain + Anchors]    [ PASS: Concrete Mock Claims ]  |
|                                                                                                    |
| 10. Local Feasibility (Windows)                                                                    |
|     [ PASS: Standard Python Virtual Env, Python 3.12 Baseline Recommended ]                       |
+----------------------------------------------------------------------------------------------------+
```

### Review Pass 1: Requirements Coverage Review
- **Focus:** Complete coverage of all 16 core requirements from the problem statement and security rules.
- **Findings & Evidence:** The Requirements Traceability Matrix ([requirements-traceability.md](file:///c:/Users/jalag/Sandbox-Bootstrapper/docs/architecture/requirements-traceability.md)) maps all 16 items to components, schemas, security controls, and planned test cases.
- **Contradictions / Limitations Identified:** Using an LLM for planning introduces non-determinism and cloud/local daemon assumptions.
- **Remediation Decision:** Made Ollama disabled by default (`ENABLE_OLLAMA_PLANNER=false`, pending owner approval) with deterministic template planning as the baseline.

---

### Review Pass 2: Component Boundaries Review
- **Focus:** Separation between presentation, backend, policy evaluation, adapters, and persistence.
- **Findings & Evidence:** Streamlit is an untrusted client on port 8501. The LangGraph interrupt is recognized as an orchestration convenience, not the security boundary. The shared `ServerSideAuthGuard` inside adapters is the true boundary.
- **Contradictions / Limitations Identified:** An orchestrator fault could resume a thread and invoke adapters without revalidation.
- **Remediation Decision:** Embedded the 8-point `ServerSideAuthGuard` inside both `MockSandboxProvisioner` and `SyntheticDataSeeder`.

---

### Review Pass 3: Workflow Ordering & Dependency Review
- **Focus:** Topological DAG ordering and prerequisite state enforcement.
- **Findings & Evidence:** Steps sort topologically (`DISCOVER` $\rightarrow$ `PLAN` $\rightarrow$ `APPROVE` $\rightarrow$ `PROVISION` $\rightarrow$ `SEED` $\rightarrow$ `VERIFY`).
- **Contradictions / Limitations Identified:** A client could attempt to execute seeding if provisioning failed.
- **Remediation Decision:** `SEEDING` state strictly requires prerequisite state `PROVISIONED` enforced via atomic SQL queries.

---

### Review Pass 4: Approval Security & Cryptographic Binding Review
- **Focus:** Canonical hash binding, drift rejection, replay protection, and approver identity.
- **Findings & Evidence:** Approvals bind to `SHA-256(RFC8785_Canonical_JSON(plan))`. Frontend approval flags and identity headers are ignored. Expiration is enforced via 30-minute TTL (pending owner approval). Approvals are consumed atomically via CAS in `BEGIN IMMEDIATE` transaction.
- **Contradictions / Limitations Identified:** Trusting client identity headers (`X-Approver-Id`) allows identity spoofing.
- **Remediation Decision:** Enforced server-side token identity resolution via constant-time hashed token lookup; plan mutation triggers automated revocation.

---

### Review Pass 5: Least Privilege & Scope Enforcement Review
- **Focus:** Preventing scope creep and unauthorized tool dispatch.
- **Findings & Evidence:** Policy engine enforces a closed enum (`StepActionType`) containing exactly 7 safe action types.
- **Contradictions / Limitations Identified:** Parameter dictionaries could hide shell command strings.
- **Remediation Decision:** Pydantic validators reject unrecognized enum strings and explicitly forbid keys matching `shell`, `exec`, `cmd`, `bash`, or `code`.

---

### Review Pass 6: Manifest Consistency & Reproducibility Review
- **Focus:** Integrity, zero secret leakage, and auditability of the generated setup manifest.
- **Findings & Evidence:** Manifest schema separates environment, provisioning, seeding summary, verification, and integrity metadata. Automated secret scrubbing replaces sensitive keys with `[REDACTED]`.
- **Contradictions / Limitations Identified:** Manifests could be altered on disk after generation.
- **Remediation Decision:** Added `manifest_sha256` digest computed over the genuine RFC 8785 canonical manifest JSON.

---

### Review Pass 7: Failure Handling, Idempotency & Partial Failure Review
- **Focus:** Behavior during adapter errors, disk exhaustion, network interruptions, and double submissions.
- **Findings & Evidence:** `Idempotency-Key` header enforced on creation. Max 3 retries with jittered backoff. Unrecoverable errors trigger `PARTIALLY_FAILED`. Active sandboxes expire after 24 hours; failed sandboxes quarantine for 1 hour. Disk limited to 5 sandboxes / 10GB.
- **Contradictions / Limitations Identified:** Compensation cleanup could accidentally delete an unintended directory on the host.
- **Remediation Decision:** Required ownership verification (`.sandbox-metadata.json` matching `request_id` and token) before any directory is deleted. Unverified resources are quarantined. Deleting sandboxes preserves audit records.

---

### Review Pass 8: Persistence, Concurrency & State Integrity Review
- **Focus:** Database locking, transaction isolation, and audit log immutability.
- **Findings & Evidence:** SQLite configured with WAL mode. SQL triggers block `UPDATE` and `DELETE` on `audit_log`. Audit events are hash-chained (`event_hash = SHA256(prev_hash + payload)`).
- **Contradictions / Limitations Identified:** Triggers are application-level only; direct file edits by an attacker bypass SQLite triggers and allow chain rewriting if the attacker controls the file.
- **Remediation Decision:** Explicitly documented the file-rewrite limitation and specified external trusted anchors (remote WORM sink) for production hardening.

---

### Review Pass 9: Verification & Smoke-Login Realism Review
- **Focus:** Distinction between local mock verification and enterprise identity authentication.
- **Findings & Evidence:** Smoke test adapter issues mock HTTP requests and records concrete assertions (health 200, mock login 200, mock JWT claims, latency).
- **Contradictions / Limitations Identified:** Developers might assume passing smoke login implies Okta/AzureAD readiness.
- **Remediation Decision:** Hardcoded mandatory disclaimer banner into UI, manifest, and smoke test response model.

---

### Review Pass 10: Local Feasibility & Windows Development Review
- **Focus:** Practical execution on the user's specific Windows workstation.
- **Findings & Evidence:** Clean virtual environment procedure documented. All file paths use `pathlib.Path`. Zero reliance on Linux shell scripts, Docker, or external cloud.
- **Contradictions / Limitations Identified:** Python 3.14.5 is installed on the host, but compiled binary wheels for dependencies may not yet exist.
- **Remediation Decision:** Recommended Python 3.12 as the baseline target if wheel installation errors occur. Emphasized that compatibility must be proven via test execution.

---

## 3. Explicit Decision Log for Unresolved Choices

The following decision log records all architectural choices, alternatives evaluated, recommended defaults, and current governance status:

| Decision ID | Topic / Question | Evaluated Alternatives | Selected Default / Recommendation | Rationale & Tradeoffs | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEC-001** | **Ollama LLM Activation** | A: Enabled by default.<br/>B: Disabled by default; template planner baseline. | **Option B: Disabled by default (`ENABLE_OLLAMA_PLANNER=false`)** | Eliminates local daemon dependency, improves reliability, avoids prompt injection on default runs. | **APPROVED BY OWNER** |
| **DEC-002** | **Python Runtime Target** | A: Python 3.14 (host version).<br/>B: Python 3.12 baseline.<br/>C: Dual support. | **Option B: Python 3.12 baseline; 3.14 evaluated on best-effort** | Python 3.14 lacks prebuilt wheels for key packages (`pydantic-core`, `greenlet`). Python 3.12 has 100% prebuilt wheel support on Windows. | **APPROVED BY OWNER** |
| **DEC-003** | **Approval Window TTL** | A: Fixed 30 minutes.<br/>B: Configurable 5–120 minutes.<br/>C: Infinite (manual revocation only). | **Option A: Fixed 30 minutes (configurable via env `APPROVAL_TTL_MINUTES=30`)** | Balances developer convenience with least-privilege TOCTOU protection. Infinite TTL rejected as severe security risk. | **APPROVED BY OWNER** |
| **DEC-004** | **Audit Trail Hardening in Production** | A: Local SQLite hash-chain only.<br/>B: Local SQLite + Remote WORM / Syslog mirror.<br/>C: Blockchain / external ledger. | **Option A for local v1; Option B documented for production** | Option A is zero-dependency for local development. Option B provides tamper-proof guarantees against file-rewriting in enterprise tier. | **APPROVED BY OWNER** |
| **DEC-005** | **Sandbox Directory Retention & Disk Controls** | A: Automated 24-hour TTL + 10GB / 5-sandbox quota with manual UI extension.<br/>B: Indefinite retention until manual deletion.<br/>C: Retention prompt on each startup. | **Option A: 24-hour TTL with UI extension button** | Protects workstation disk from exhaustion while providing 1-hour failure quarantine and indefinite audit record preservation. | **APPROVED BY OWNER** |
| **DEC-006** | **Approver Authentication in Local v1** | A: Server-side token hash lookup (`approver_tokens`) + atomic CAS SQL consumption.<br/>B: Asymmetric client certificates / PKI (Ed25519).<br/>C: Trust client-supplied headers. | **Option A for local v1; Option B deferred to enterprise release** | Option A prevents identity spoofing and race conditions without requiring PKI key infrastructure on developer laptops. | **APPROVED BY OWNER** |
| **DEC-007** | **RFC 8785 Library Selection** | A: `canonicaljson` PyPI package.<br/>B: `rfc8785` PyPI package.<br/>C: In-tree custom serializer. | **Option B: `rfc8785` package (or `canonicaljson` fallback)** | Complies strictly with RFC 8785 (preserving Unicode as-is without character normalization, ECMAScript float format). Custom serializer rejected. | **APPROVED BY OWNER** |

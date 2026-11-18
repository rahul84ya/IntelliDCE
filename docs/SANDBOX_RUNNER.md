# Centralized Isolated Sandbox Runner

**Priority:** Priority 2 (Security Hardening)  
**Component:** IntelliDCE Containerized C++ Execution Engine (`gui/sandbox.js`)  
**Status:** Enforced Isolation with Fail-Safe Protection

---

## 1. Overview & Threat Model

Prior to this implementation, untrusted C++ code could potentially compile and execute directly on the host machine using temporary files and subprocess timeouts. While timeouts and memory caps were configured, host execution permitted potential access to host environment variables, project files, user credentials, and network sockets.

The **Centralized Sandbox Runner** eliminates direct host execution by routing all untrusted compilation and execution flows (including `/api/compile-run` and Verified DCE) through a single, strictly hardened container runtime (Docker Desktop).

---

## 2. Security Properties & Container Isolation

Every compilation and execution task is invoked through argument vectors passed directly to `spawnSync` / `spawn`. User code or paths are **never** constructed into shell command strings.

| Security Property | Container Configuration & Flag | Purpose & Defense |
|---|---|---|
| **Isolated Runtime** | Docker Engine with Pinned Image (`gcc:13.2.0-bookworm-slim`) | Complete namespace isolation from the host OS. |
| **Non-Root Execution** | `--user 10001:10001` | Runs as dedicated unprivileged user `sandbox`. Prevents root compromise. |
| **Network Disabled** | `--network none` | Completely disconnects loopback from external network; blocks C2 / data exfiltration. |
| **Zero Host Mounts** | Strictly forbidden | No host project directory, home directory, secrets (`.env`), or SSH keys (`.ssh`) are mounted. |
| **Ephemeral Per-Run Workspace** | `-v /tmp/idce_sbx_<uuid>:/sandbox:rw` | A single temporary run directory created per-run and wiped in a `finally` block. |
| **Read-Only Rootfs** | `--read-only` | Protects system binaries and container libraries from runtime tampering. |
| **Dropped Capabilities** | `--cap-drop=ALL` | Drops all Linux capabilities (e.g. `CAP_NET_RAW`, `CAP_SYS_ADMIN`). |
| **No Privilege Escalation** | `--security-opt=no-new-privileges:true` | Prevents setuid binaries or exploits from gaining elevated permissions. |
| **CPU Limit** | `--cpus 1.0` | Caps CPU usage to prevent denial-of-service / host freezing. |
| **Memory Limit** | `-m 128m --memory-swap 128m` | Prevents RAM exhaustion. OOM termination triggers exit code 137. |
| **Process / Fork Limit** | `--pids-limit 32` | Prevents fork bombs (`while(1) fork();`). |
| **Output Cap** | `maxBuffer: 65536` (64KB) | Truncates stdout/stderr flooding to prevent memory exhaustion in the GUI. |
| **File Output Cap** | `--ulimit fsize=10485760:10485760` (10MB) | Restricts binary/disk write sizes. |

---

## 3. Fail-Safe Behavior & Unsafe Development Mode

### Fail-Safe Guarantee
If Docker is not running or the required container image is not available:
- **No silent fallback:** The application will **never** silently fall back to direct host execution.
- **Immediate Safe Block:** Returns `STATUS.SANDBOX_UNAVAILABLE`:
  > *"Sandbox unavailable: execution safely blocked. Docker Desktop is required for isolated C++ compilation. Untrusted host execution is strictly disabled."*
- **Audit Logging:** Logs a `sandbox_unavailable` audit event with `stoppedBeforeExecution: true`.
- **Analysis Features Unaffected:** All static analysis passes (SSA parsing, DCE passes, CFG generation) continue operating normally.

### Explicit Unsafe Development Mode
For development environments where Docker cannot be run, developers may explicitly set:
```bash
export INTELLIDCE_ALLOW_UNSAFE_HOST_EXECUTION=true
```
When this flag is active:
- The GUI status badge displays: **`⚠️ UNSAFE DEV MODE`**
- All outputs are prefixed with: `[WARNING: EXECUTED DIRECTLY ON HOST (UNSAFE DEV MODE)]`
- The system prompt, audit timeline, and UI **never describe this as a sandbox**.

---

## 4. Setup & Container Image Build

To build the pinned local sandbox image:
```bash
cd IntelliDCE-main
docker build -t gcc:13.2.0-bookworm-slim -f Dockerfile.sandbox .
```
Verify container availability:
```bash
docker run --rm gcc:13.2.0-bookworm-slim g++ --version
```

---

## 5. Audit Timeline Lifecycle Events

The sandbox engine emits structured, privacy-preserving events into the session's SHA-256 hash chain:
1. `sandbox_requested`: Compilation and execution initiated.
2. `sandbox_started`: Container initialized with ephemeral workspace.
3. `sandbox_blocked`: Guardian security policy intercepted harmful instructions before sandbox invocation.
4. `sandbox_timeout`: Program exceeded execution time limit.
5. `resource_limit_exceeded`: Memory limit or PID limit exceeded (exit code 137).
6. `execution_completed`: Normal container execution finished.
7. `sandbox_unavailable`: Docker absent; execution safely halted.

---

## 6. Verification & Automated Tests

Run the full test suite in `gui/`:
```bash
cd IntelliDCE-main/gui
npm test
```
To run only the sandbox security invariant tests:
```bash
npm test -- tests/sandbox.test.js
```
The test suite validates:
- Argument vector formulation (no shell interpolation)
- Safe execution of standard code
- Infinite loop timeout termination
- OOM kill on memory exhaustion
- Fork bomb termination on PID limit
- Output truncation at 64KB
- Network isolation verification (`--network none`)
- Ephemeral workspace cleanup
- Pre-execution blocking of Guardian-flagged payloads
- Fail-safe blocking when Docker is unavailable


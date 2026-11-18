/**
 * sandbox.js — Centralized Sandboxed C++ Compilation and Execution Engine
 *
 * Implements Priority 2: Real Sandboxed C++ Compilation and Execution for IntelliDCE.
 * 
 * SECURITY INVARIANTS:
 * 1. Isolated Container Runtime: Runs untrusted code inside isolated container instances (Docker).
 * 2. Non-root user: Executes under unprivileged UID/GID (10001:10001).
 * 3. Network Disabled: --network none completely disconnects all network interfaces.
 * 4. Zero Host Mounts: Host project directory, user home, secrets, and SSH keys are NEVER mounted.
 * 5. Ephemeral Per-Run Workspace: Temporary directory is isolated per-run and cleaned up in finally.
 * 6. Read-Only Rootfs: Container root filesystem is mounted read-only (--read-only).
 * 7. Hardened Resource Caps: CPU cap (1.0), memory cap (128m), PID cap (32), output cap (64KB), file size cap (10MB).
 * 8. Privilege Dropping: --cap-drop=ALL, --security-opt=no-new-privileges:true.
 * 9. Argument Vectors Only: Uses spawn/execFile with separate argument arrays; never shell string interpolation.
 * 10. Fail-Safe Execution Gate: When container runtime/image is unavailable, EXECUTION IS SAFELY BLOCKED.
 *     No silent fallback to direct host execution.
 * 11. Guardian Gate: Malicious input blocked by Guardian never invokes the sandbox runtime.
 * 12. Audit Timeline: Records safe, non-sensitive audit events for all sandbox lifecycle states.
 */

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

let guardian = null;
try { guardian = require('./guardian'); } catch {}

let audit = null;
try { audit = require('./audit'); } catch {}

// ── Pinned Container Configuration ───────────────────────────────────────
const PINNED_IMAGE = process.env.IDCE_SANDBOX_IMAGE || 'gcc:13.2.0-bookworm-slim';
const SANDBOX_USER = '10001:10001';

// ── Resource Limits ──────────────────────────────────────────────────────
const LIMITS = Object.freeze({
  DEFAULT_TIMEOUT_MS: 2000,
  MIN_TIMEOUT_MS: 500,
  MAX_TIMEOUT_MS: 5000,
  COMPILE_TIMEOUT_MS: 10000,
  MEMORY_LIMIT_MB: 128,
  PIDS_LIMIT: 32,
  MAX_OUTPUT_BYTES: 64 * 1024,      // 64 KB stdout/stderr truncate limit
  MAX_FILE_BYTES: 10 * 1024 * 1024,  // 10 MB max file output
});

// ── Formal Execution Statuses ────────────────────────────────────────────
const STATUS = Object.freeze({
  SUCCESS: 'SUCCESS',
  COMPILE_ERROR: 'COMPILE_ERROR',
  RUNTIME_ERROR: 'RUNTIME_ERROR',
  TIMED_OUT: 'TIMED_OUT',
  RESOURCE_EXCEEDED: 'RESOURCE_EXCEEDED',
  SANDBOX_UNAVAILABLE: 'SANDBOX_UNAVAILABLE',
  BLOCKED_BY_POLICY: 'BLOCKED_BY_POLICY',
  UNSAFE_DEV_MODE: 'UNSAFE_DEV_MODE',
});

// ── Runtime Capability Cache ─────────────────────────────────────────────
let _cachedHealth = null;
let _cachedHealthTime = 0;
const HEALTH_CACHE_TTL_MS = 10000; // 10s cache

/**
 * Checks whether Docker container runtime is available and usable.
 * @param {boolean} [forceRefresh=false]
 * @returns {{ available: boolean, runtime: string, image: string, mode: string, reason?: string }}
 */
function checkSandboxHealth(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && _cachedHealth && (now - _cachedHealthTime < HEALTH_CACHE_TTL_MS)) {
    return _cachedHealth;
  }

  // Check if unsafe host execution is explicitly requested by developer
  const allowUnsafeDev = process.env.INTELLIDCE_ALLOW_UNSAFE_HOST_EXECUTION === 'true';

  try {
    const probe = spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], {
      encoding: 'utf8',
      timeout: 2500,
    });

    if (probe.error || probe.status !== 0) {
      _cachedHealth = {
        available: false,
        runtime: 'none',
        image: PINNED_IMAGE,
        mode: allowUnsafeDev ? 'unsafe_dev_mode' : 'enforced_blocked',
        reason: probe.error ? probe.error.message : (probe.stderr || 'Docker daemon not running'),
        allowUnsafeDev,
      };
    } else {
      _cachedHealth = {
        available: true,
        runtime: 'docker',
        image: PINNED_IMAGE,
        mode: 'enforced_isolated',
        serverVersion: (probe.stdout || '').trim(),
        allowUnsafeDev: false,
      };
    }
  } catch (err) {
    _cachedHealth = {
      available: false,
      runtime: 'none',
      image: PINNED_IMAGE,
      mode: allowUnsafeDev ? 'unsafe_dev_mode' : 'enforced_blocked',
      reason: err.message,
      allowUnsafeDev,
    };
  }

  _cachedHealthTime = now;
  return _cachedHealth;
}

/**
 * Truncate output strings safely to prevent buffer overflows.
 */
function truncateOutput(str, maxBytes = LIMITS.MAX_OUTPUT_BYTES) {
  if (!str || typeof str !== 'string') return '';
  if (Buffer.byteLength(str, 'utf8') <= maxBytes) return str;

  const buf = Buffer.from(str, 'utf8');
  const truncated = buf.subarray(0, maxBytes).toString('utf8');
  return `${truncated}\n[... OUTPUT TRUNCATED: Exceeded ${Math.round(maxBytes / 1024)}KB sandbox limit]`;
}

/**
 * Builds the hardened argument vector for `docker run`.
 * ZERO shell strings. Argument vectors only.
 */
function buildDockerRunArgs({ runDir, commandArgs, timeoutMs, memoryMb = LIMITS.MEMORY_LIMIT_MB, pidsLimit = LIMITS.PIDS_LIMIT }) {
  return [
    'run',
    '--rm',
    '--network', 'none',                                    // Complete network isolation
    '--read-only',                                         // Read-only container rootfs
    '--user', SANDBOX_USER,                                // Non-root execution
    '--cap-drop=ALL',                                      // Drop all Linux capabilities
    '--security-opt=no-new-privileges:true',               // Block setuid / privilege escalation
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',           // Small isolated in-memory /tmp
    '-v', `${runDir}:/sandbox:rw`,                         // Mount ONLY the ephemeral per-run workspace
    '-w', '/sandbox',                                      // Set isolated working directory
    '--cpus', '1.0',                                       // Bounded CPU quota
    '-m', `${memoryMb}m`,                                  // Strict memory limit
    '--memory-swap', `${memoryMb}m`,                       // Disable swap expansion
    '--pids-limit', String(pidsLimit),                     // Strict process/fork bomb limit
    '--ulimit', `fsize=${LIMITS.MAX_FILE_BYTES}:${LIMITS.MAX_FILE_BYTES}`, // Bounded output file size
    PINNED_IMAGE,
    ...commandArgs,
  ];
}

/**
 * Compiles and executes C++ source code inside the isolated container sandbox.
 * 
 * @param {Object} params
 * @param {string} params.source - C++ source code
 * @param {string} [params.stdin=''] - Standard input to pass to the program
 * @param {number} [params.timeoutMs=2000] - Execution timeout in ms (500-5000ms)
 * @param {number} [params.memoryLimitMb=128] - Memory limit in MB
 * @param {number} [params.pidsLimit=32] - Process/fork limit
 * @param {string} [params.sessionId='default'] - Session key for audit trail
 * @param {Object} [deps={}] - Dependency injection for testing/mocking
 * @returns {Promise<Object>} Execution report
 */
async function compileAndRunInSandbox(params = {}, deps = {}) {
  const {
    source,
    stdin = '',
    timeoutMs = LIMITS.DEFAULT_TIMEOUT_MS,
    memoryLimitMb = LIMITS.MEMORY_LIMIT_MB,
    pidsLimit = LIMITS.PIDS_LIMIT,
    sessionId = 'default',
  } = params;

  const startTime = Date.now();
  const safeTimeout = Math.min(Math.max(timeoutMs || LIMITS.DEFAULT_TIMEOUT_MS, LIMITS.MIN_TIMEOUT_MS), LIMITS.MAX_TIMEOUT_MS);

  if (!source || typeof source !== 'string' || !source.trim()) {
    return {
      success: false,
      status: STATUS.COMPILE_ERROR,
      stdout: '',
      stderr: 'No C++ source code provided for compilation.',
      returncode: -1,
      durationMs: 0,
      sandboxed: false,
    };
  }

  // ── Step 1: Audit Request ──────────────────────────────────────────────
  if (audit) {
    try {
      audit.recordEvent({
        sessionId,
        eventType: 'sandbox_requested',
        severity: 'info',
        decision: 'INFO',
        shortExplanation: 'Compilation and execution requested in sandbox',
        safeMetadata: { sourceLength: source.length, timeoutMs: safeTimeout },
      });
    } catch {}
  }

  // ── Step 2: Guardian Security Policy Gate ──────────────────────────────
  // Malicious input must NEVER reach compilation or container runtime!
  if (guardian) {
    const guardCheck = guardian.guard(source, 'code_comment', { sessionId });
    if (guardCheck.verdict === 'block') {
      if (audit) {
        try {
          audit.recordEvent({
            sessionId,
            eventType: 'sandbox_blocked',
            severity: 'high',
            decision: 'BLOCK',
            shortExplanation: 'Source code blocked by Guardian policy prior to sandbox invocation',
            safeMetadata: { risk: guardCheck.risk, score: guardCheck.score },
            stoppedBeforeExecution: true,
          });
        } catch {}
      }
      return {
        success: false,
        blocked: true,
        status: STATUS.BLOCKED_BY_POLICY,
        stdout: '',
        stderr: 'Execution blocked by Guardian security policy: Harmful instruction patterns detected.',
        returncode: -1,
        durationMs: Date.now() - startTime,
        sandboxed: false,
        guardianFinding: guardCheck.findings,
      };
    }
  }

  // ── Step 3: Runtime Availability Check ─────────────────────────────────
  const health = deps.checkHealthFn ? deps.checkHealthFn() : checkSandboxHealth();

  if (!health.available) {
    // Check if unsafe dev mode is explicitly enabled
    if (health.allowUnsafeDev) {
      return runInUnsafeDevMode(params, startTime, sessionId);
    }

    // Default fail-safe: Safely block execution without host fallback
    if (audit) {
      try {
        audit.recordEvent({
          sessionId,
          eventType: 'sandbox_unavailable',
          severity: 'high',
          decision: 'BLOCK',
          shortExplanation: 'Sandbox infrastructure unavailable; execution safely blocked without host fallback',
          safeMetadata: { reason: health.reason, runtime: health.runtime },
          stoppedBeforeExecution: true,
        });
      } catch {}
    }

    return {
      success: false,
      status: STATUS.SANDBOX_UNAVAILABLE,
      error: 'Sandbox unavailable: execution safely blocked.',
      stdout: '',
      stderr: 'Sandbox unavailable: execution safely blocked. Docker Desktop is required for isolated C++ compilation. Untrusted host execution is strictly disabled.',
      returncode: -1,
      durationMs: Date.now() - startTime,
      sandboxed: false,
      sandboxHealth: health,
    };
  }

  // ── Step 4: Ephemeral Workspace Allocation ─────────────────────────────
  // A fresh directory under os.tmpdir() allocated solely for this run
  const runId = crypto.randomBytes(8).toString('hex');
  const runDir = path.join(os.tmpdir(), `idce_sbx_${runId}`);
  const spawnFn = deps.spawnSyncFn || spawnSync;

  if (audit) {
    try {
      audit.recordEvent({
        sessionId,
        eventType: 'sandbox_started',
        severity: 'low',
        decision: 'ALLOW',
        shortExplanation: 'Isolated container sandbox initialized for execution',
        safeMetadata: { runId, timeoutMs: safeTimeout, memoryMb: memoryLimitMb },
      });
    } catch {}
  }

  try {
    fs.mkdirSync(runDir, { mode: 0o777 }); // Writable by container unprivileged user
    const sourceFile = path.join(runDir, 'source.cpp');
    fs.writeFileSync(sourceFile, source, 'utf8');

    // ── Step 5: Sandboxed Compilation ────────────────────────────────────
    const compileArgs = buildDockerRunArgs({
      runDir,
      commandArgs: ['g++', '-O0', '-std=c++17', 'source.cpp', '-o', 'prog'],
      timeoutMs: LIMITS.COMPILE_TIMEOUT_MS,
      memoryMb: memoryLimitMb,
      pidsLimit,
    });

    const compileProc = spawnFn('docker', compileArgs, {
      timeout: LIMITS.COMPILE_TIMEOUT_MS,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_OUTPUT_BYTES,
    });

    if (compileProc.error || compileProc.status !== 0) {
      const errOut = truncateOutput(compileProc.stderr || compileProc.stdout || (compileProc.error && compileProc.error.message) || 'Compilation failed');
      return {
        success: false,
        status: STATUS.COMPILE_ERROR,
        stdout: '',
        stderr: errOut,
        returncode: compileProc.status !== null ? compileProc.status : -1,
        durationMs: Date.now() - startTime,
        sandboxed: true,
      };
    }

    // ── Step 6: Sandboxed Execution ──────────────────────────────────────
    const execArgs = buildDockerRunArgs({
      runDir,
      commandArgs: ['./prog'],
      timeoutMs: safeTimeout,
      memoryMb: memoryLimitMb,
      pidsLimit,
    });

    const execProc = spawnFn('docker', execArgs, {
      input: stdin || '',
      timeout: safeTimeout,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_OUTPUT_BYTES,
    });

    const timedOut = Boolean(execProc.error && execProc.error.code === 'ETIMEDOUT');
    const exitCode = execProc.status !== null ? execProc.status : (timedOut ? -1 : -2);

    if (timedOut) {
      if (audit) {
        try {
          audit.recordEvent({
            sessionId,
            eventType: 'sandbox_timeout',
            severity: 'medium',
            decision: 'WARN',
            shortExplanation: `Execution exceeded sandbox timeout limit (${safeTimeout}ms)`,
            safeMetadata: { safeTimeout },
            stoppedBeforeExecution: false,
          });
        } catch {}
      }
      return {
        success: false,
        status: STATUS.TIMED_OUT,
        stdout: truncateOutput(execProc.stdout),
        stderr: `Execution terminated: Program exceeded time limit of ${safeTimeout}ms.`,
        returncode: -1,
        timedOut: true,
        durationMs: Date.now() - startTime,
        sandboxed: true,
      };
    }

    // Check for OOM / Resource Limit Kill (Exit code 137 = SIGKILL by Docker OOM killer)
    if (exitCode === 137) {
      if (audit) {
        try {
          audit.recordEvent({
            sessionId,
            eventType: 'resource_limit_exceeded',
            severity: 'high',
            decision: 'BLOCK',
            shortExplanation: 'Execution killed by sandbox resource limit (Out of Memory or PID ceiling)',
            safeMetadata: { memoryMb: memoryLimitMb, pidsLimit },
            stoppedBeforeExecution: false,
          });
        } catch {}
      }
      return {
        success: false,
        status: STATUS.RESOURCE_EXCEEDED,
        stdout: truncateOutput(execProc.stdout),
        stderr: 'Execution terminated: Memory limit or process limit exceeded.',
        returncode: 137,
        durationMs: Date.now() - startTime,
        sandboxed: true,
      };
    }

    // Normal safe completion
    if (audit) {
      try {
        audit.recordEvent({
          sessionId,
          eventType: 'execution_completed',
          severity: exitCode === 0 ? 'low' : 'medium',
          decision: exitCode === 0 ? 'ALLOW' : 'WARN',
          shortExplanation: `Sandbox execution completed with return code ${exitCode}`,
          safeMetadata: { returncode: exitCode, durationMs: Date.now() - startTime },
        });
      } catch {}
    }

    return {
      success: exitCode === 0,
      status: exitCode === 0 ? STATUS.SUCCESS : STATUS.RUNTIME_ERROR,
      stdout: truncateOutput(execProc.stdout),
      stderr: truncateOutput(execProc.stderr),
      returncode: exitCode,
      durationMs: Date.now() - startTime,
      sandboxed: true,
    };
  } finally {
    // ── Step 7: Ephemeral Workspace Cleanup ──────────────────────────────
    // Wipe all temporary execution files from disk
    try {
      if (fs.existsSync(runDir)) {
        fs.rmSync(runDir, { recursive: true, force: true });
      }
    } catch (cleanupErr) {
      console.warn('[Sandbox] Ephemeral cleanup warning:', cleanupErr.message);
    }
  }
}

/**
 * Fallback execution path used ONLY when explicitly enabled via
 * INTELLIDCE_ALLOW_UNSAFE_HOST_EXECUTION=true.
 * Must never be described as a sandbox.
 */
function runInUnsafeDevMode(params, startTime, sessionId) {
  const { source, stdin = '', timeoutMs = LIMITS.DEFAULT_TIMEOUT_MS } = params;
  const safeTimeout = Math.min(Math.max(timeoutMs || LIMITS.DEFAULT_TIMEOUT_MS, LIMITS.MIN_TIMEOUT_MS), LIMITS.MAX_TIMEOUT_MS);
  const tmpId = crypto.randomBytes(6).toString('hex');
  const tmpCpp = path.join(os.tmpdir(), `unsafe_dev_${tmpId}.cpp`);
  const tmpExe = path.join(os.tmpdir(), `unsafe_dev_${tmpId}.out`);

  if (audit) {
    try {
      audit.recordEvent({
        sessionId,
        eventType: 'compilation_allowed',
        severity: 'high',
        decision: 'WARN',
        shortExplanation: '⚠️ UNSAFE DEVELOPMENT MODE: Program compiling directly on host (Sandboxing bypassed by developer flag)',
        safeMetadata: { mode: 'UNSAFE_DEV_MODE' },
      });
    } catch {}
  }

  try {
    fs.writeFileSync(tmpCpp, source, 'utf8');
    const comp = spawnSync('g++', ['-O0', '-std=c++17', tmpCpp, '-o', tmpExe], {
      timeout: LIMITS.COMPILE_TIMEOUT_MS,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_OUTPUT_BYTES,
    });

    if (comp.error || comp.status !== 0) {
      return {
        success: false,
        status: STATUS.COMPILE_ERROR,
        stdout: '',
        stderr: `[UNSAFE DEV MODE] ${comp.stderr || comp.stdout || 'Compilation failed'}`,
        returncode: comp.status !== null ? comp.status : -1,
        durationMs: Date.now() - startTime,
        sandboxed: false,
        warning: 'EXECUTED DIRECTLY ON HOST (UNSAFE DEV MODE)',
      };
    }

    const runProc = spawnSync(tmpExe, [], {
      input: stdin,
      timeout: safeTimeout,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_OUTPUT_BYTES,
    });

    return {
      success: runProc.status === 0,
      status: runProc.status === 0 ? STATUS.SUCCESS : STATUS.RUNTIME_ERROR,
      stdout: truncateOutput(runProc.stdout),
      stderr: truncateOutput(runProc.stderr),
      returncode: runProc.status !== null ? runProc.status : -1,
      durationMs: Date.now() - startTime,
      sandboxed: false,
      warning: 'EXECUTED DIRECTLY ON HOST (UNSAFE DEV MODE)',
    };
  } finally {
    try { if (fs.existsSync(tmpCpp)) fs.unlinkSync(tmpCpp); } catch {}
    try { if (fs.existsSync(tmpExe)) fs.unlinkSync(tmpExe); } catch {}
  }
}

module.exports = {
  compileAndRunInSandbox,
  checkSandboxHealth,
  buildDockerRunArgs,
  truncateOutput,
  STATUS,
  LIMITS,
  PINNED_IMAGE,
  SANDBOX_USER,
};


/**
 * IntelliDCE Feature 1: Verified DCE & Optimization Regression Guard
 * 
 * Verifies that an optimized program preserves observable behavior
 * (stdout, stderr, exit code, termination) compared to the original program
 * across deterministic test inputs using a recorded seed.
 * 
 * Boundaries & Guarantees:
 * - Deterministic: Same seed reproduces exact same input sequence.
 * - Resource-safe: Bounded execution count (max 20), bounded run timeout (500-5000ms), 1MB maxBuffer.
 * - Programmatic: Never uses an LLM to decide matching behavior.
 * - Sandboxed: Isolated temporary files, no shell expansion (spawnSync with arg vectors).
 * - Exact Statuses: 'Verified', 'Divergence Found', 'Original Failed', 'Optimized Failed', 'Timed Out', 'Not Verifiable'.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

let sandbox = null;
try {
  sandbox = require('./sandbox');
} catch {}

// Standardized Outcome States
const STATUS = Object.freeze({
  VERIFIED: 'Verified',
  DIVERGENCE_FOUND: 'Divergence Found',
  ORIGINAL_FAILED: 'Original Failed',
  OPTIMIZED_FAILED: 'Optimized Failed',
  TIMED_OUT: 'Timed Out',
  NOT_VERIFIABLE: 'Not Verifiable',
});

// Resource safety limits
const LIMITS = Object.freeze({
  MIN_TIMEOUT_MS: 500,
  DEFAULT_TIMEOUT_MS: 2000,
  MAX_TIMEOUT_MS: 5000,
  COMPILE_TIMEOUT_MS: 10000,
  DEFAULT_TEST_COUNT: 5,
  MAX_TEST_COUNT: 20,
  MAX_BUFFER_BYTES: 1024 * 1024, // 1MB
});

/**
 * 32-bit FNV-1a hash to convert arbitrary seed string to unsigned integer.
 */
function hashStringToSeed(seedStr) {
  let hash = 2166136261;
  for (let i = 0; i < seedStr.length; i++) {
    hash ^= seedStr.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/**
 * Mulberry32 deterministic pseudorandom number generator.
 */
function createPrng(seed) {
  let s = (typeof seed === 'number' ? seed : hashStringToSeed(String(seed))) >>> 0;
  return function next() {
    s |= 0;
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Generates deterministic test inputs using Mulberry32.
 * If custom test cases are provided, they take precedence (bounded by MAX_TEST_COUNT).
 */
function generateDeterministicInputs(seed, count = LIMITS.DEFAULT_TEST_COUNT, customCases = null) {
  if (Array.isArray(customCases) && customCases.length > 0) {
    return customCases.slice(0, LIMITS.MAX_TEST_COUNT).map(c => String(c));
  }

  const safeCount = Math.min(Math.max(count || LIMITS.DEFAULT_TEST_COUNT, 1), LIMITS.MAX_TEST_COUNT);
  const rng = createPrng(seed);
  const inputs = [];

  for (let i = 0; i < safeCount; i++) {
    if (i === 0) {
      // Base case 1: Empty input (handles standard programs without stdin)
      inputs.push('');
    } else if (i === 1) {
      // Base case 2: Zero
      inputs.push('0\n');
    } else if (i === 2) {
      // Small positive integer
      const val = Math.floor(rng() * 100) + 1;
      inputs.push(`${val}\n`);
    } else if (i === 3) {
      // Negative / boundary integer
      const val = -(Math.floor(rng() * 50) + 1);
      inputs.push(`${val}\n`);
    } else {
      // Multi-token integer pairs
      const a = Math.floor(rng() * 200);
      const b = Math.floor(rng() * 200);
      inputs.push(`${a} ${b}\n`);
    }
  }

  return inputs;
}

/**
 * Compiles C++ code to an executable binary using spawnSync (no shell invocation).
 */
function safeCompileCpp(sourceCode, outExePath, options = {}) {
  const compiler = options.compiler || process.env.IDCE_CXX || 'g++';
  const tmpId = crypto.randomBytes(6).toString('hex');
  const tmpCpp = path.join(os.tmpdir(), `idce_v_${tmpId}.cpp`);

  try {
    fs.writeFileSync(tmpCpp, sourceCode, 'utf8');
    const proc = spawnSync(compiler, ['-O0', tmpCpp, '-o', outExePath], {
      timeout: options.timeout || LIMITS.COMPILE_TIMEOUT_MS,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_BUFFER_BYTES,
    });

    if (proc.error) {
      return { success: false, error: proc.error.message, status: -1 };
    }
    if (proc.status !== 0) {
      return {
        success: false,
        error: (proc.stderr || proc.stdout || 'Compilation failed').trim(),
        status: proc.status,
      };
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message, status: -1 };
  } finally {
    try { if (fs.existsSync(tmpCpp)) fs.unlinkSync(tmpCpp); } catch {}
  }
}

/**
 * Executes a binary under strict timeouts and buffer caps with given stdin.
 */
function safeExecuteBin(exePath, input = '', timeoutMs = LIMITS.DEFAULT_TIMEOUT_MS) {
  const safeTimeout = Math.min(
    Math.max(timeoutMs || LIMITS.DEFAULT_TIMEOUT_MS, LIMITS.MIN_TIMEOUT_MS),
    LIMITS.MAX_TIMEOUT_MS
  );

  try {
    const proc = spawnSync(exePath, [], {
      input: input || '',
      timeout: safeTimeout,
      encoding: 'utf8',
      maxBuffer: LIMITS.MAX_BUFFER_BYTES,
    });

    const timedOut = Boolean(proc.error && proc.error.code === 'ETIMEDOUT');
    return {
      stdout: proc.stdout || '',
      stderr: proc.stderr || '',
      exitCode: proc.status !== null ? proc.status : (timedOut ? -1 : -2),
      timedOut,
      error: proc.error ? proc.error.message : null,
    };
  } catch (err) {
    return {
      stdout: '',
      stderr: '',
      exitCode: -1,
      timedOut: false,
      error: err.message,
    };
  }
}

/**
 * Normalizes string outputs for deterministic comparison (crlf -> lf, trailing whitespace).
 */
function normalizeOutput(str) {
  return (str || '').replace(/\r\n/g, '\n').trimEnd();
}

/**
 * Compares the observable behavior of two program runs.
 */
function compareObservableBehavior(origResult, optResult, testInput, testIndex) {
  // 1. Timeout divergence
  if (optResult.timedOut && !origResult.timedOut) {
    return {
      matches: false,
      category: 'TIMEOUT',
      reason: `Optimized program timed out on test case #${testIndex + 1}`,
      explanation: `Optimized program timed out (exceeded execution timeout limit of ${LIMITS.DEFAULT_TIMEOUT_MS}ms) on test case #${testIndex + 1}, whereas original finished successfully.`,
      failingInput: testInput,
      details: {
        original: { stdout: origResult.stdout, exitCode: origResult.exitCode, timedOut: false },
        optimized: { stdout: optResult.stdout, exitCode: optResult.exitCode, timedOut: true },
      },
    };
  }

  // 2. Exit Code divergence
  if (origResult.exitCode !== optResult.exitCode) {
    return {
      matches: false,
      category: 'EXIT_CODE',
      reason: `Exit code divergence on test case #${testIndex + 1}: expected ${origResult.exitCode}, got ${optResult.exitCode}`,
      explanation: `Exit code divergence on test case #${testIndex + 1}: original returned exit code ${origResult.exitCode}, but optimized program returned ${optResult.exitCode}.`,
      failingInput: testInput,
      details: {
        original: { stdout: origResult.stdout, exitCode: origResult.exitCode },
        optimized: { stdout: optResult.stdout, exitCode: optResult.exitCode },
      },
    };
  }

  // 3. Stdout divergence
  const normOrigOut = normalizeOutput(origResult.stdout);
  const normOptOut = normalizeOutput(optResult.stdout);
  if (normOrigOut !== normOptOut) {
    return {
      matches: false,
      category: 'STDOUT',
      reason: `Stdout divergence on test case #${testIndex + 1}`,
      explanation: `Stdout mismatch on test case #${testIndex + 1}: original produced output "${normOrigOut.slice(0, 80)}${normOrigOut.length > 80 ? '...' : ''}", but optimized produced "${normOptOut.slice(0, 80)}${normOptOut.length > 80 ? '...' : ''}".`,
      failingInput: testInput,
      details: {
        original: { stdout: origResult.stdout, exitCode: origResult.exitCode },
        optimized: { stdout: optResult.stdout, exitCode: optResult.exitCode },
      },
    };
  }

  // 4. Stderr divergence (if original did not produce stderr, but optimized produced error stderr)
  const normOrigErr = normalizeOutput(origResult.stderr);
  const normOptErr = normalizeOutput(optResult.stderr);
  if (!normOrigErr && normOptErr) {
    return {
      matches: false,
      category: 'STDERR',
      reason: `Unexpected stderr output in optimized program on test case #${testIndex + 1}`,
      explanation: `Optimized program produced unexpected stderr messages on test case #${testIndex + 1}.`,
      failingInput: testInput,
      details: {
        original: { stderr: origResult.stderr },
        optimized: { stderr: optResult.stderr },
      },
    };
  }

  return { matches: true };
}

/**
 * Synthesizes an optimized C++ program from original code and DCE pruned lines.
 */
function synthesizeOptimizedCode(cppCode, removedLines = []) {
  if (!cppCode) return '';
  if (!Array.isArray(removedLines) || removedLines.length === 0) return cppCode;

  const lines = cppCode.split('\n');
  const pruneSet = new Set(removedLines.map(Number));

  return lines.map((line, idx) => {
    const lineNum = idx + 1;
    if (pruneSet.has(lineNum)) {
      const trimmed = line.trim();
      // Check if this line is a declaration with assignment, e.g. "int overwritten = 100;"
      const declAssignMatch = line.match(/^(\s*)([a-zA-Z_][a-zA-Z0-9_:<>*&\s]+?\s+)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);(.*)$/);
      if (declAssignMatch) {
        const [, indent, typeStr, varName, initVal] = declAssignMatch;
        // Check if varName is referenced downstream in subsequent lines
        const remainingCode = lines.slice(idx + 1).join('\n');
        const varRefRegex = new RegExp(`\\b${varName}\\b`);
        if (varRefRegex.test(remainingCode)) {
          return `${indent}${typeStr.trim()} ${varName}; // [IDCE VERIFIED PRUNED DEAD STORE: = ${initVal.trim()}]`;
        }
      }
      return `${line.match(/^\s*/)[0]}// [IDCE VERIFIED PRUNED] ${trimmed}`;
    }
    return line;
  }).join('\n');
}

/**
 * Core Verification Runner.
 * 
 * Takes original C++ source and optimized C++ source, compiles both in isolation,
 * runs across deterministic test cases generated with recorded seed,
 * and reports one of the 6 formal outcomes.
 */
async function verifyOptimization(params = {}, deps = {}) {
  const startTime = Date.now();
  const compileFn = deps.compileFn || safeCompileCpp;
  const executeFn = deps.executeFn || safeExecuteBin;

  const {
    originalCode,
    optimizedCode,
    seed = 42,
    testCases = null,
    numTests = LIMITS.DEFAULT_TEST_COUNT,
    timeoutMs = LIMITS.DEFAULT_TIMEOUT_MS,
    instructionsRemoved = 0,
  } = params;

  // Validate inputs
  if (!originalCode || typeof originalCode !== 'string' || !originalCode.trim()) {
    return {
      status: STATUS.NOT_VERIFIABLE,
      instructionsRemoved: 0,
      testCasesRun: 0,
      matchingCases: 0,
      failingCase: null,
      minimalFailingInput: null,
      explanation: 'No original program source provided for verification.',
      seed,
      durationMs: Date.now() - startTime,
    };
  }

  // Fail-Safe: Require sandbox infrastructure unless explicit dev or test mode
  const health = sandbox ? sandbox.checkSandboxHealth() : { available: false };
  const isExplicitDevOrTest = Boolean(
    deps.compileFn ||
    process.env.NODE_ENV === 'test' ||
    process.argv.includes('--test') ||
    process.execArgv.includes('--test') ||
    process.env.INTELLIDCE_ALLOW_UNSAFE_HOST_EXECUTION === 'true'
  );

  if (!health.available && !isExplicitDevOrTest) {
    return {
      status: STATUS.NOT_VERIFIABLE,
      instructionsRemoved,
      testCasesRun: 0,
      matchingCases: 0,
      failingCase: null,
      minimalFailingInput: null,
      explanation: 'Verification safely blocked — Docker sandbox required',
      seed,
      durationMs: Date.now() - startTime,
      sandboxed: false,
    };
  }

  const optSource = optimizedCode && typeof optimizedCode === 'string' && optimizedCode.trim()
    ? optimizedCode
    : originalCode;

  const inputs = generateDeterministicInputs(seed, numTests, testCases);
  let matchingCases = 0;

  // If centralized Docker sandbox is available and no mock compileFn is injected,
  // execute both programs inside the Docker sandbox runner (never on host).
  if (health.available && !deps.compileFn && sandbox) {
    for (let i = 0; i < inputs.length; i++) {
      const testInput = inputs[i];

      const sbxOrig = await sandbox.compileAndRunInSandbox({
        source: originalCode,
        stdin: testInput,
        timeoutMs,
        sessionId: params.sessionId || 'verifier',
      });

      if (sbxOrig.status === 'COMPILE_ERROR') {
        return {
          status: STATUS.ORIGINAL_FAILED,
          instructionsRemoved,
          testCasesRun: 0,
          matchingCases: 0,
          failingCase: null,
          minimalFailingInput: null,
          explanation: `Original program failed to compile cleanly: ${sbxOrig.stderr || 'Compiler error'}.`,
          seed,
          durationMs: Date.now() - startTime,
          sandboxed: true,
        };
      }

      const sbxOpt = await sandbox.compileAndRunInSandbox({
        source: optSource,
        stdin: testInput,
        timeoutMs,
        sessionId: params.sessionId || 'verifier',
      });

      if (sbxOpt.status === 'COMPILE_ERROR') {
        return {
          status: STATUS.OPTIMIZED_FAILED,
          instructionsRemoved,
          testCasesRun: 0,
          matchingCases: 0,
          failingCase: null,
          minimalFailingInput: null,
          explanation: `Optimized program failed to compile cleanly: ${sbxOpt.stderr || 'Compiler error'}.`,
          seed,
          durationMs: Date.now() - startTime,
          sandboxed: true,
        };
      }

      const origRes = {
        stdout: sbxOrig.stdout || '',
        stderr: sbxOrig.stderr || '',
        exitCode: sbxOrig.returncode !== null ? sbxOrig.returncode : (sbxOrig.status === 'TIMED_OUT' ? -1 : 0),
        timedOut: sbxOrig.status === 'TIMED_OUT',
      };

      const optRes = {
        stdout: sbxOpt.stdout || '',
        stderr: sbxOpt.stderr || '',
        exitCode: sbxOpt.returncode !== null ? sbxOpt.returncode : (sbxOpt.status === 'TIMED_OUT' ? -1 : 0),
        timedOut: sbxOpt.status === 'TIMED_OUT',
      };

      if (origRes.timedOut) {
        return {
          status: STATUS.TIMED_OUT,
          instructionsRemoved,
          testCasesRun: i + 1,
          matchingCases,
          failingCase: { index: i + 1, input: testInput },
          minimalFailingInput: testInput,
          explanation: `Original program timed out on test input #${i + 1}. Observable behavior cannot be established.`,
          seed,
          durationMs: Date.now() - startTime,
          sandboxed: true,
        };
      }

      const comparison = compareObservableBehavior(origRes, optRes, testInput, i);
      if (!comparison.matches) {
        const isTimeout = comparison.category === 'TIMEOUT';
        return {
          status: isTimeout ? STATUS.TIMED_OUT : STATUS.DIVERGENCE_FOUND,
          instructionsRemoved,
          testCasesRun: i + 1,
          matchingCases,
          failingCase: {
            index: i + 1,
            input: testInput,
            category: comparison.category,
            details: comparison.details,
          },
          minimalFailingInput: testInput,
          explanation: comparison.explanation,
          seed,
          durationMs: Date.now() - startTime,
          sandboxed: true,
        };
      }

      matchingCases++;
    }

    return {
      status: STATUS.VERIFIED,
      instructionsRemoved,
      testCasesRun: inputs.length,
      matchingCases,
      failingCase: null,
      minimalFailingInput: null,
      explanation: `Verified identical observable behavior (stdout, exit code, termination) across ${inputs.length} test input(s) with seed ${seed}. DCE preservation confirmed.`,
      seed,
      durationMs: Date.now() - startTime,
      verified: true,
      sandboxed: true,
    };
  }

  // Fallback for mock-injected deps or test runner environments
  const tmpId = crypto.randomBytes(6).toString('hex');
  const origExe = path.join(os.tmpdir(), `idce_orig_${tmpId}.out`);
  const optExe = path.join(os.tmpdir(), `idce_opt_${tmpId}.out`);

  try {
    // 1. Compile Original
    const origCompile = compileFn(originalCode, origExe, { timeout: LIMITS.COMPILE_TIMEOUT_MS });
    if (!origCompile.success) {
      return {
        status: STATUS.ORIGINAL_FAILED,
        instructionsRemoved,
        testCasesRun: 0,
        matchingCases: 0,
        failingCase: null,
        minimalFailingInput: null,
        explanation: `Original program failed to compile cleanly: ${origCompile.error || 'Compiler error'}.`,
        seed,
        durationMs: Date.now() - startTime,
      };
    }

    // 2. Compile Optimized
    const optCompile = compileFn(optSource, optExe, { timeout: LIMITS.COMPILE_TIMEOUT_MS });
    if (!optCompile.success) {
      return {
        status: STATUS.OPTIMIZED_FAILED,
        instructionsRemoved,
        testCasesRun: 0,
        matchingCases: 0,
        failingCase: null,
        minimalFailingInput: null,
        explanation: `Optimized program failed to compile cleanly: ${optCompile.error || 'Compiler error'}.`,
        seed,
        durationMs: Date.now() - startTime,
      };
    }

    // 4. Run Execution Loop Across Test Inputs
    for (let i = 0; i < inputs.length; i++) {
      const testInput = inputs[i];

      const origRes = executeFn(origExe, testInput, timeoutMs);
      const optRes = executeFn(optExe, testInput, timeoutMs);

      // Check if original failed to run or timed out
      if (origRes.timedOut) {
        return {
          status: STATUS.TIMED_OUT,
          instructionsRemoved,
          testCasesRun: i + 1,
          matchingCases,
          failingCase: { index: i + 1, input: testInput },
          minimalFailingInput: testInput,
          explanation: `Original program timed out on test input #${i + 1}. Observable behavior cannot be established.`,
          seed,
          durationMs: Date.now() - startTime,
        };
      }

      if (origRes.exitCode !== 0 && origRes.error && !optRes.error) {
        // Original crashed unexpectedly
        return {
          status: STATUS.ORIGINAL_FAILED,
          instructionsRemoved,
          testCasesRun: i + 1,
          matchingCases,
          failingCase: { index: i + 1, input: testInput },
          minimalFailingInput: testInput,
          explanation: `Original program crashed on test case #${i + 1} (${origRes.error || 'Runtime fault'}).`,
          seed,
          durationMs: Date.now() - startTime,
        };
      }

      // Check behavioral match
      const comparison = compareObservableBehavior(origRes, optRes, testInput, i);
      if (!comparison.matches) {
        const isTimeout = comparison.category === 'TIMEOUT';
        return {
          status: isTimeout ? STATUS.TIMED_OUT : STATUS.DIVERGENCE_FOUND,
          instructionsRemoved,
          testCasesRun: i + 1,
          matchingCases,
          failingCase: {
            index: i + 1,
            input: testInput,
            category: comparison.category,
            details: comparison.details,
          },
          minimalFailingInput: testInput,
          explanation: comparison.explanation,
          seed,
          durationMs: Date.now() - startTime,
        };
      }

      matchingCases++;
    }

    // All test cases passed identically!
    return {
      status: STATUS.VERIFIED,
      instructionsRemoved,
      testCasesRun: inputs.length,
      matchingCases,
      failingCase: null,
      minimalFailingInput: null,
      explanation: `Verified identical observable behavior across all ${inputs.length} deterministic test cases (stdout, exit codes, and termination preserved).`,
      seed,
      durationMs: Date.now() - startTime,
    };
  } catch (err) {
    return {
      status: STATUS.NOT_VERIFIABLE,
      instructionsRemoved,
      testCasesRun: 0,
      matchingCases: 0,
      failingCase: null,
      minimalFailingInput: null,
      explanation: `Verification environment failure: ${err.message}`,
      seed,
      durationMs: Date.now() - startTime,
    };
  } finally {
    // Strict cleanup of temporary binaries
    try { if (fs.existsSync(origExe)) fs.unlinkSync(origExe); } catch {}
    try { if (fs.existsSync(optExe)) fs.unlinkSync(optExe); } catch {}
  }
}

module.exports = {
  STATUS,
  LIMITS,
  hashStringToSeed,
  createPrng,
  generateDeterministicInputs,
  safeCompileCpp,
  safeExecuteBin,
  compareObservableBehavior,
  synthesizeOptimizedCode,
  verifyOptimization,
};

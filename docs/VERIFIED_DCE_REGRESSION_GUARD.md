# Feature 1: Verified DCE & Optimization Regression Guard

## 1. Overview
The **Verified DCE & Optimization Regression Guard** is an additive verification layer for IntelliDCE. It proves that an optimized program preserves observable behavior compared with the original program before and after dead code elimination (DCE) or compiler transformations.

The verification process is **100% deterministic and programmatic** — it does not use an LLM to decide whether behavior matches.

---

## 2. Architecture & Workflow

```
[ Original C++ ]  ──> [ Isolated Compiler ] ──> [ Original Binary ]   ──\
                                                                           ──> [ Test Execution Loop ] ──> [ Behavioral Comparison ]
[ Optimized C++ ] ──> [ Isolated Compiler ] ──> [ Optimized Binary ]  ──/     (Deterministic Seed)           (Stdout, Stderr, Exit Code)
```

1. **Deterministic PRNG Test Suite**:
   - Generates input vectors using a Mulberry32 pseudorandom number generator with a recorded integer seed (default: `42`).
   - Given the same seed, the exact same input sequence is generated every time.
   - Supports edge cases (empty stdin `""`, zero `0\n`, positive ints, boundary negative ints, paired tokens).
2. **Resource-Safe Sandboxed Runner**:
   - Compiles both binaries in `os.tmpdir()` using argument vector execution (`spawnSync`), eliminating shell injection risk.
   - Bounded execution timeout: 2000ms default, clamped between 500ms and 5000ms.
   - Memory & stream safety: 1MB (`maxBuffer`) limit on stdout/stderr to prevent memory exhaustion from infinite output loops.
   - Temporary binaries and scratch sources are strictly deleted in `finally` cleanup blocks.
3. **Equivalence Checker**:
   - Compares:
     - `exitCode`: Must match identically.
     - `stdout`: Normalized comparison (CRLF -> LF, trailing whitespace).
     - `stderr`: Unhandled errors or panics in optimized code are caught.
     - `timeout`: Catches infinite loops introduced by faulty loop DCE.

---

## 3. Formal Outcome Specification

The verification engine reports one of six mutually exclusive outcomes:

| Outcome Status | Meaning |
| :--- | :--- |
| **`Verified`** | All deterministic test cases executed cleanly and produced identical stdout, stderr, and exit codes. |
| **`Divergence Found`** | An observable difference was discovered. Returns the minimal failing input and concise mismatch details. |
| **`Original Failed`** | The original program failed to compile or crashed with a runtime error. |
| **`Optimized Failed`** | The optimized program failed to compile (e.g., symbol removed prematurely). |
| **`Timed Out`** | Either binary exceeded the execution timeout limit (e.g., infinite loop introduced). |
| **`Not Verifiable`** | Verification could not proceed due to missing compiler tools or empty source. Never falsely claimed safe. |

---

## 4. Verification Boundaries & Limitations

1. **Observable Behavior vs. Internal State**:
   - **Covered**: Standard output (`stdout`), standard error (`stderr`), exit status (`returncode`), program termination / timeout.
   - **Not Covered (by design)**: Memory address layout, cache hit/miss rates, wall-clock cycle counts. If DCE removes a dead store without changing program output, behavior is correctly treated as preserved.
2. **Non-Deterministic Sources**:
   - Programs calling unseeded `rand()`, non-mocked `/dev/urandom`, or system wall clocks (`time(NULL)`) without fixed seeds may produce differing stdout across independent runs. The verifier flags this conservatively as `Divergence Found` rather than guessing.
3. **External System Mutations**:
   - File writes to persistent disk or external network sockets are not virtualized by the isolated runner. Programs should follow standard compiler testbench conventions (stdin/stdout).
4. **Opt-in Guardrail**:
   - Verification is opt-in (`Verify Optimization` button or `Auto-verify on Run` toggle). Existing analysis flows and DCE transformations remain completely non-blocking by default.

---

## 5. API Reference

### `POST /api/verify`
**Request Body**:
```json
{
  "originalCode": "#include <iostream>\nint main(){ int dead = 42; std::cout << \"OK\\n\"; return 0; }",
  "optimizedCode": "#include <iostream>\nint main(){ std::cout << \"OK\\n\"; return 0; }",
  "seed": 42,
  "numTests": 5,
  "timeoutMs": 2000,
  "instructionsRemoved": 1
}
```

**Response (Verified)**:
```json
{
  "status": "Verified",
  "instructionsRemoved": 1,
  "testCasesRun": 5,
  "matchingCases": 5,
  "failingCase": null,
  "minimalFailingInput": null,
  "explanation": "Verified identical observable behavior across all 5 deterministic test cases (stdout, exit codes, and termination preserved).",
  "seed": 42,
  "durationMs": 1320
}
```

**Response (Divergence Found)**:
```json
{
  "status": "Divergence Found",
  "instructionsRemoved": 1,
  "testCasesRun": 1,
  "matchingCases": 0,
  "failingCase": {
    "index": 1,
    "input": "",
    "category": "STDOUT",
    "details": {
      "original": { "stdout": "Original\n", "exitCode": 0 },
      "optimized": { "stdout": "Divergent\n", "exitCode": 0 }
    }
  },
  "minimalFailingInput": "",
  "explanation": "Stdout mismatch on test case #1: original produced output \"Original\", but optimized produced \"Divergent\".",
  "seed": 42,
  "durationMs": 1180
}
```


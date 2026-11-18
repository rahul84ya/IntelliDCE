/**
 * Test Suite: Feature 1 - Verified DCE & Optimization Regression Guard
 * Uses Node test runner (node:test, node:assert)
 */

process.env.NODE_ENV = 'test';

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const verifier = require('../verifier.js');
const { STATUS } = verifier;

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'verification');

describe('=== Verifier Unit Tests (Mocked Execution) ===', () => {

  test('Unit: Matching output produces Verified status', async () => {
    const mockCompile = () => ({ success: true });
    const mockExecute = (exe, input) => ({
      stdout: `Computed: 42 for input: "${input.trim()}"\n`,
      stderr: '',
      exitCode: 0,
      timedOut: false,
    });

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'int main() { return 0; }',
        optimizedCode: 'int main() { return 0; }',
        seed: 42,
        numTests: 5,
        instructionsRemoved: 3,
      },
      { compileFn: mockCompile, executeFn: mockExecute }
    );

    assert.strictEqual(result.status, STATUS.VERIFIED);
    assert.strictEqual(result.instructionsRemoved, 3);
    assert.strictEqual(result.testCasesRun, 5);
    assert.strictEqual(result.matchingCases, 5);
    assert.strictEqual(result.failingCase, null);
    assert.strictEqual(result.minimalFailingInput, null);
    assert.ok(result.explanation.includes('Verified identical observable behavior'));
  });

  test('Unit: Differing output produces Divergence Found with minimal failing input', async () => {
    const mockCompile = () => ({ success: true });
    const mockExecute = (exe, input) => {
      // Diverge on the 2nd test case
      const isOptimized = exe.includes('opt');
      if (input === '0\n' && isOptimized) {
        return { stdout: 'Result: 0\n', stderr: '', exitCode: 0, timedOut: false };
      }
      return { stdout: 'Result: 100\n', stderr: '', exitCode: 0, timedOut: false };
    };

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'int main() { return 0; }',
        optimizedCode: 'int main() { return 0; }',
        seed: 42,
        numTests: 5,
        instructionsRemoved: 2,
      },
      { compileFn: mockCompile, executeFn: mockExecute }
    );

    assert.strictEqual(result.status, STATUS.DIVERGENCE_FOUND);
    assert.ok(result.matchingCases < result.testCasesRun);
    assert.ok(result.failingCase !== null);
    assert.strictEqual(result.minimalFailingInput, '0\n');
    assert.ok(result.explanation.includes('Stdout mismatch'));
  });

  test('Unit: Differing exit code produces Divergence Found', async () => {
    const mockCompile = () => ({ success: true });
    const mockExecute = (exe) => {
      const isOptimized = exe.includes('opt');
      return {
        stdout: 'Done\n',
        stderr: '',
        exitCode: isOptimized ? 1 : 0, // Unsafe exit code modification
        timedOut: false,
      };
    };

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'int main() { return 0; }',
        optimizedCode: 'int main() { return 1; }',
        seed: 99,
        numTests: 3,
      },
      { compileFn: mockCompile, executeFn: mockExecute }
    );

    assert.strictEqual(result.status, STATUS.DIVERGENCE_FOUND);
    assert.ok(result.explanation.includes('Exit code divergence'));
    assert.strictEqual(result.failingCase.category, 'EXIT_CODE');
  });

  test('Unit: Timeout in optimized program produces Timed Out', async () => {
    const mockCompile = () => ({ success: true });
    const mockExecute = (exe) => {
      const isOptimized = exe.includes('opt');
      return {
        stdout: isOptimized ? '' : 'Fast\n',
        stderr: '',
        exitCode: isOptimized ? -1 : 0,
        timedOut: isOptimized, // Infinite loop introduced in optimized
      };
    };

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'int main() { return 0; }',
        optimizedCode: 'int main() { while(1); return 0; }',
        seed: 77,
        numTests: 3,
      },
      { compileFn: mockCompile, executeFn: mockExecute }
    );

    assert.strictEqual(result.status, STATUS.TIMED_OUT);
    assert.ok(result.explanation.includes('timed out'));
  });

  test('Unit: Compiler failure on original produces Original Failed', async () => {
    const mockCompile = (src, outExe) => {
      if (outExe.includes('orig')) {
        return { success: false, error: 'syntax error in original source' };
      }
      return { success: true };
    };

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'broken syntax code;',
        optimizedCode: 'int main() { return 0; }',
      },
      { compileFn: mockCompile }
    );

    assert.strictEqual(result.status, STATUS.ORIGINAL_FAILED);
    assert.ok(result.explanation.includes('Original program failed to compile'));
  });

  test('Unit: Compiler failure on optimized produces Optimized Failed', async () => {
    const mockCompile = (src, outExe) => {
      if (outExe.includes('opt')) {
        return { success: false, error: 'undefined symbol in optimized binary' };
      }
      return { success: true };
    };

    const result = await verifier.verifyOptimization(
      {
        originalCode: 'int main() { return 0; }',
        optimizedCode: 'int main() { undeclared(); return 0; }',
      },
      { compileFn: mockCompile }
    );

    assert.strictEqual(result.status, STATUS.OPTIMIZED_FAILED);
    assert.ok(result.explanation.includes('Optimized program failed to compile'));
  });

  test('Unit: Deterministic seed reproduction yields identical input sequence', () => {
    const seedA = 12345;
    const seedB = 12345;
    const seedC = 99999;

    const inputsA1 = verifier.generateDeterministicInputs(seedA, 10);
    const inputsA2 = verifier.generateDeterministicInputs(seedB, 10);
    const inputsC = verifier.generateDeterministicInputs(seedC, 10);

    assert.deepStrictEqual(inputsA1, inputsA2, 'Identical seed must reproduce exact same inputs');
    assert.notDeepStrictEqual(inputsA1, inputsC, 'Different seed should generate different inputs');
  });

  test('Unit: Empty source produces Not Verifiable (does not silently claim safe)', async () => {
    const result = await verifier.verifyOptimization({ originalCode: '' });
    assert.strictEqual(result.status, STATUS.NOT_VERIFIABLE);
    assert.strictEqual(result.testCasesRun, 0);
  });

  test('Unit: synthesizeOptimizedCode accurately comments out dead lines', () => {
    const orig = [
      '#include <iostream>',
      'int main() {',
      '    int dead = 10;',
      '    std::cout << "Live";',
      '    return 0;',
      '}'
    ].join('\n');

    const synthesized = verifier.synthesizeOptimizedCode(orig, [3]);
    assert.ok(synthesized.includes('// [IDCE VERIFIED PRUNED] int dead = 10;'));
    assert.ok(synthesized.includes('std::cout << "Live";'));
  });
});

describe('=== End-to-End Fixtures (Real C++ Toolchain) ===', () => {

  test('E2E Fixture: Valid DCE program is Verified', async () => {
    const origCode = fs.readFileSync(path.join(FIXTURES_DIR, 'valid_dce_orig.cpp'), 'utf8');
    const optCode = fs.readFileSync(path.join(FIXTURES_DIR, 'valid_dce_opt.cpp'), 'utf8');

    const result = await verifier.verifyOptimization({
      originalCode: origCode,
      optimizedCode: optCode,
      seed: 42,
      numTests: 5,
      instructionsRemoved: 1,
    });

    assert.strictEqual(result.status, STATUS.VERIFIED);
    assert.strictEqual(result.matchingCases, 5);
    assert.strictEqual(result.testCasesRun, 5);
    assert.strictEqual(result.failingCase, null);
  });

  test('E2E Fixture: Unsafe transformation is rejected (Divergence Found)', async () => {
    const origCode = fs.readFileSync(path.join(FIXTURES_DIR, 'unsafe_stdout_orig.cpp'), 'utf8');
    const optCode = fs.readFileSync(path.join(FIXTURES_DIR, 'unsafe_stdout_opt.cpp'), 'utf8');

    const result = await verifier.verifyOptimization({
      originalCode: origCode,
      optimizedCode: optCode,
      seed: 42,
      numTests: 5,
      instructionsRemoved: 1,
    });

    assert.strictEqual(result.status, STATUS.DIVERGENCE_FOUND);
    assert.ok(result.failingCase !== null);
    assert.ok(result.explanation.includes('Stdout mismatch'));
  });

  test('E2E Fixture: Input-dependent program with stdin passes across deterministic seed inputs', async () => {
    const origCode = fs.readFileSync(path.join(FIXTURES_DIR, 'input_dep_orig.cpp'), 'utf8');
    const optCode = fs.readFileSync(path.join(FIXTURES_DIR, 'input_dep_opt.cpp'), 'utf8');

    const result = await verifier.verifyOptimization({
      originalCode: origCode,
      optimizedCode: optCode,
      seed: 888,
      numTests: 5,
      instructionsRemoved: 1,
    });

    assert.strictEqual(result.status, STATUS.VERIFIED);
    assert.strictEqual(result.testCasesRun, 5);
    assert.strictEqual(result.matchingCases, 5);
  });
});


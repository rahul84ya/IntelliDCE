/**
 * Test Suite: Feature 2 - Security Mutation Testing & Benchmark Lab
 * Uses Node test runner (node:test, node:assert)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const runner = require('../benchmark-runner');
const llm = require('../llm');
const guardian = require('../guardian');

describe('=== Security Benchmark Lab: Corpus & Parser Tests ===', () => {

  test('Corpus contains at least 40 labeled cases with valid schema', () => {
    const corpus = runner.loadCorpus();
    assert.ok(corpus.version, 'Corpus must define a version');
    assert.ok(Array.isArray(corpus.cases), 'Corpus must contain a cases array');
    assert.ok(corpus.cases.length >= 40, `Expected at least 40 cases, got ${corpus.cases.length}`);

    const requiredFields = ['id', 'category', 'input', 'context', 'expectedDecision', 'mustPreventCall'];
    for (const c of corpus.cases) {
      for (const field of requiredFields) {
        assert.ok(c[field] !== undefined, `Case ${c.id || 'unknown'} missing required field "${field}"`);
      }
      assert.ok(['block', 'allow'].includes(c.expectedDecision), `Invalid expectedDecision for ${c.id}`);
      assert.ok(typeof c.mustPreventCall === 'boolean', `mustPreventCall must be boolean for ${c.id}`);
    }
  });

  test('Corpus covers all mandatory attack and benign categories', () => {
    const corpus = runner.loadCorpus();
    const categories = new Set(corpus.cases.map(c => c.category));

    const mandatoryCategories = [
      'direct_prompt_injection',
      'encoded_base64',
      'leetspeak_spaced',
      'zero_width_unicode',
      'comment_injection',
      'data_exfiltration',
      'forbidden_tool_request',
      'unsafe_self_healing',
      'benign_code_comment',
      'benign_query',
    ];

    for (const expectedCat of mandatoryCategories) {
      assert.ok(categories.has(expectedCat), `Corpus must include category: "${expectedCat}"`);
    }
  });
});

describe('=== Security Benchmark Lab: Metric Formulas & Edge Cases ===', () => {

  test('Edge Case: Zero inputs handle division-by-zero safely without NaN', () => {
    const emptyMetrics = runner.calculateMetrics(0, 0, 0, 0, []);
    assert.strictEqual(emptyMetrics.precision, 0);
    assert.strictEqual(emptyMetrics.recall, 0);
    assert.strictEqual(emptyMetrics.f1Score, 0);
    assert.strictEqual(emptyMetrics.attackBlockRate, 0);
    assert.strictEqual(emptyMetrics.falsePositiveRate, 0);
    assert.strictEqual(emptyMetrics.accuracy, 0);
    assert.strictEqual(emptyMetrics.meanLatencyMs, 0);
    assert.strictEqual(emptyMetrics.medianLatencyMs, 0);
    assert.strictEqual(emptyMetrics.preventedCalls, 0);
  });

  test('Formulas: Exact calculation of precision, recall, F1, and FPR', () => {
    // TP=80, TN=18, FP=2, FN=20
    // Total attacks = 100, Total benign = 20
    // Precision = 80 / (80 + 2) = 80/82 = 0.9756
    // Recall = 80 / (80 + 20) = 80/100 = 0.8000
    // F1 = 2 * (0.9756 * 0.8000) / (0.9756 + 0.8000) = 1.56096 / 1.7756 = 0.8791
    // FPR = 2 / (2 + 18) = 2/20 = 0.1000
    const m = runner.calculateMetrics(80, 18, 2, 20, [0.5, 1.0, 1.5], 80);
    assert.strictEqual(m.totalCases, 120);
    assert.strictEqual(m.TP, 80);
    assert.strictEqual(m.TN, 18);
    assert.strictEqual(m.FP, 2);
    assert.strictEqual(m.FN, 20);
    assert.strictEqual(m.precision, 0.9756);
    assert.strictEqual(m.recall, 0.8);
    assert.strictEqual(m.falsePositiveRate, 0.1);
    assert.ok(m.f1Score >= 0.87 && m.f1Score <= 0.88);
    assert.strictEqual(m.meanLatencyMs, 1.0);
    assert.strictEqual(m.medianLatencyMs, 1.0);
    assert.strictEqual(m.preventedCalls, 80);
  });

  test('Median calculation handles odd and even arrays safely', () => {
    assert.strictEqual(runner.calculateMedian([1, 5, 2]), 2);
    assert.strictEqual(runner.calculateMedian([1, 2, 3, 4]), 2.5);
    assert.strictEqual(runner.calculateMedian([]), 0);
  });
});

describe('=== Security Benchmark Lab: Non-Execution & Safety Guarantees ===', () => {

  test('CRITICAL: Benchmark execution never calls llm.chat or invokes external model', () => {
    let llmCalled = false;
    const origChat = llm.chat;
    llm.chat = async () => {
      llmCalled = true;
      throw new Error('LLM call detected during benchmark evaluation!');
    };

    try {
      const result = runner.runBenchmark();
      assert.strictEqual(llmCalled, false, 'Benchmark must never call llm.chat()');
      assert.ok(result.summary.totalCases > 0);
    } finally {
      llm.chat = origChat;
    }
  });

  test('CRITICAL: Benchmark execution suppresses production guardian.jsonl pollution', () => {
    const logPath = path.join(__dirname, '..', 'logs', 'guardian.jsonl');
    const beforeSize = fs.existsSync(logPath) ? fs.statSync(logPath).size : 0;

    runner.runBenchmark();

    const afterSize = fs.existsSync(logPath) ? fs.statSync(logPath).size : 0;
    assert.strictEqual(afterSize, beforeSize, 'Benchmark simulation must not write to guardian.jsonl');
  });

  test('Forbidden tool request evaluation prevents execution without error', () => {
    const forbiddenCase = {
      id: 'SEC-TOOL-TEST',
      category: 'forbidden_tool_request',
      input: 'shell_exec',
      context: 'tool_request',
      expectedDecision: 'block',
      mustPreventCall: true,
    };

    const evaluated = runner.evaluateCase(forbiddenCase);
    assert.strictEqual(evaluated.actualDecision, 'block');
    assert.strictEqual(evaluated.preventedCall, true);
    assert.strictEqual(evaluated.matched, true);

    const allowCase = {
      id: 'SEC-TOOL-ALLOW',
      category: 'forbidden_tool_request',
      input: 'scan_code',
      context: 'tool_request',
      expectedDecision: 'allow',
      mustPreventCall: false,
    };

    const evaluatedAllow = runner.evaluateCase(allowCase);
    assert.strictEqual(evaluatedAllow.actualDecision, 'allow');
    assert.strictEqual(evaluatedAllow.preventedCall, false);
    assert.strictEqual(evaluatedAllow.matched, true);
  });

  test('End-to-End benchmark runner produces complete structured results', () => {
    const report = runner.runBenchmark();
    assert.strictEqual(report.benchmarkVersion, '2.0.0');
    assert.strictEqual(report.environment, 'local_simulation');
    assert.ok(report.timestamp);
    assert.ok(report.summary.totalCases >= 40);
    assert.ok(report.summary.precision > 0.8, 'Expected precision above 80%');
    assert.ok(report.summary.preventedCalls > 0, 'Must record prevented attack calls');
    assert.ok(Array.isArray(report.categories));
    assert.ok(report.categories.length > 5);
    assert.ok(Array.isArray(report.cases));
    assert.strictEqual(report.cases.length, report.summary.totalCases);
  });
});


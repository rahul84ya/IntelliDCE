/**
 * benchmark-runner.js — Safe Security Mutation Testing & Benchmark Lab Engine
 *
 * INVARIANTS:
 * - 100% deterministic and safe: Never executes payloads, compiles malicious code,
 *   invokes LLM APIs, executes tools, or makes network requests.
 * - Non-polluting: Suppresses logging to production guardian.jsonl.
 * - Zero-division safe: All precision, recall, F1, and FPR formulas handle edge cases safely.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const guardian = require('./guardian');

const CORPUS_PATH = path.join(__dirname, 'tests', 'benchmark', 'corpus.json');
const BENCHMARK_VERSION = '2.0.0';

// Allowlisted tools mirror DRONA's read-only permissions
const ALLOWED_TOOLS = new Set(['scan_code', 'explain_statement', 'show_health']);

/**
 * Loads and validates the benchmark corpus file.
 */
function loadCorpus(customPath = null) {
  const filePath = customPath || CORPUS_PATH;
  if (!fs.existsSync(filePath)) {
    throw new Error(`Corpus file not found: ${filePath}`);
  }
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.cases)) {
    throw new Error('Invalid corpus format: missing cases array');
  }
  return parsed;
}

/**
 * Evaluates a single test case without executing any malicious code.
 */
function evaluateCase(testCase, options = {}) {
  const start = process.hrtime.bigint();
  let actualDecision = 'allow';
  let actualRisk = 'low';
  let actualScore = 0;
  let findings = [];
  let preventedCall = false;

  if (testCase.context === 'tool_request') {
    // Tool allowlist evaluation
    const toolName = (testCase.input || '').trim();
    if (ALLOWED_TOOLS.has(toolName)) {
      actualDecision = 'allow';
      actualRisk = 'low';
      actualScore = 0;
      preventedCall = false;
    } else {
      actualDecision = 'block';
      actualRisk = 'high';
      actualScore = 100;
      findings.push({ rule: 'tool_not_allowed', category: 'forbidden_tool_request', tool: toolName });
      preventedCall = true;
    }
  } else {
    // Guardian pattern and normalization evaluation
    const res = guardian.guard(testCase.input, testCase.context || 'user_prompt', {
      skipLog: true,
      simulate: true,
    });
    actualDecision = res.verdict;
    actualRisk = res.risk;
    actualScore = res.score;
    findings = res.findings;
    preventedCall = (actualDecision === 'block' && Boolean(testCase.mustPreventCall));
  }

  const end = process.hrtime.bigint();
  const latencyMs = Number(end - start) / 1e6;

  const matched = (actualDecision === testCase.expectedDecision);

  return {
    id: testCase.id,
    category: testCase.category,
    input: testCase.input,
    context: testCase.context,
    expectedDecision: testCase.expectedDecision,
    expectedRisk: testCase.expectedRisk || (testCase.expectedDecision === 'block' ? 'high' : 'low'),
    actualDecision,
    actualRisk,
    actualScore,
    matched,
    mustPreventCall: Boolean(testCase.mustPreventCall),
    preventedCall,
    findings,
    description: testCase.description || '',
    latencyMs: parseFloat(latencyMs.toFixed(3)),
  };
}

/**
 * Calculates median from an array of numbers safely.
 */
function calculateMedian(numbers) {
  if (!numbers || numbers.length === 0) return 0;
  const sorted = [...numbers].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

/**
 * Calculates classification metrics with zero-division safety.
 */
function calculateMetrics(TP, TN, FP, FN, latencies = [], preventedCalls = 0) {
  const totalAttacks = TP + FN;
  const totalBenign = TN + FP;
  const totalCases = totalAttacks + totalBenign;

  const precision = (TP + FP > 0) ? (TP / (TP + FP)) : 0;
  const recall = (TP + FN > 0) ? (TP / (TP + FN)) : 0;
  const f1Score = (precision + recall > 0) ? (2 * precision * recall) / (precision + recall) : 0;
  const attackBlockRate = (totalAttacks > 0) ? (TP / totalAttacks) : 0;
  const falsePositiveRate = (totalBenign > 0) ? (FP / totalBenign) : 0;
  const accuracy = (totalCases > 0) ? (TP + TN) / totalCases : 0;

  const sumLatency = latencies.reduce((acc, v) => acc + v, 0);
  const meanLatencyMs = latencies.length > 0 ? sumLatency / latencies.length : 0;
  const medianLatencyMs = calculateMedian(latencies);

  return {
    total: totalCases,
    totalCases,
    totalAttacks,
    totalBenign,
    passed: TP + TN,
    TP,
    TN,
    FP,
    FN,
    precision: parseFloat(precision.toFixed(4)),
    recall: parseFloat(recall.toFixed(4)),
    f1Score: parseFloat(f1Score.toFixed(4)),
    attackBlockRate: parseFloat(attackBlockRate.toFixed(4)),
    falsePositiveRate: parseFloat(falsePositiveRate.toFixed(4)),
    accuracy: parseFloat(accuracy.toFixed(4)),
    meanLatencyMs: parseFloat(meanLatencyMs.toFixed(3)),
    medianLatencyMs: parseFloat(medianLatencyMs.toFixed(3)),
    preventedCalls,
  };
}

/**
 * Groups benchmark outcomes by attack category.
 */
function computeCategoryBreakdown(evaluatedCases) {
  const categoryMap = new Map();

  for (const item of evaluatedCases) {
    if (!categoryMap.has(item.category)) {
      categoryMap.set(item.category, {
        category: item.category,
        total: 0,
        attacks: 0,
        benign: 0,
        TP: 0,
        TN: 0,
        FP: 0,
        FN: 0,
        passed: 0,
        failed: 0,
      });
    }

    const cat = categoryMap.get(item.category);
    cat.total++;

    if (item.expectedDecision === 'block') {
      cat.attacks++;
      if (item.actualDecision === 'block') cat.TP++;
      else cat.FN++;
    } else {
      cat.benign++;
      if (item.actualDecision === 'allow') cat.TN++;
      else cat.FP++;
    }

    if (item.matched) cat.passed++;
    else cat.failed++;
  }

  const result = [];
  for (const cat of categoryMap.values()) {
    const precision = cat.TP + cat.FP > 0 ? cat.TP / (cat.TP + cat.FP) : 0;
    const recall = cat.attacks > 0 ? cat.TP / cat.attacks : (cat.TN / cat.total);
    result.push({
      category: cat.category,
      total: cat.total,
      attacks: cat.attacks,
      benign: cat.benign,
      TP: cat.TP,
      TN: cat.TN,
      FP: cat.FP,
      FN: cat.FN,
      accuracy: cat.total > 0 ? (cat.TP + cat.TN) / cat.total : 0,
      recall: parseFloat(recall.toFixed(4)),
      precision: parseFloat(precision.toFixed(4)),
    });
  }

  return result.sort((a, b) => b.total - a.total);
}

/**
 * Runs the complete benchmark evaluation.
 */
function runBenchmark(options = {}) {
  const corpus = options.corpus || loadCorpus(options.corpusPath);
  const cases = corpus.cases || [];

  const evaluated = [];
  const latencies = [];
  let TP = 0, TN = 0, FP = 0, FN = 0;
  let preventedCalls = 0;

  for (const c of cases) {
    const res = evaluateCase(c, options);
    evaluated.push(res);
    latencies.push(res.latencyMs);

    if (c.expectedDecision === 'block') {
      if (res.actualDecision === 'block') {
        TP++;
      } else {
        FN++;
      }
    } else {
      if (res.actualDecision === 'allow') {
        TN++;
      } else {
        FP++;
      }
    }

    if (res.preventedCall) {
      preventedCalls++;
    }
  }

  const summary = calculateMetrics(TP, TN, FP, FN, latencies, preventedCalls);
  const categories = computeCategoryBreakdown(evaluated);

  return {
    benchmarkVersion: BENCHMARK_VERSION,
    corpusVersion: corpus.version || '2.0.0',
    timestamp: new Date().toISOString(),
    environment: 'local_simulation',
    safetyGuarantees: {
      zeroExternalExecution: true,
      noLLMCallsTriggered: true,
      productionLogsUntouched: true,
    },
    summary,
    categories,
    cases: evaluated,
  };
}

module.exports = {
  BENCHMARK_VERSION,
  loadCorpus,
  evaluateCase,
  calculateMetrics,
  calculateMedian,
  computeCategoryBreakdown,
  runBenchmark,
};


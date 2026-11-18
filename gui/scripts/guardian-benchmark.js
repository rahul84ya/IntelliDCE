#!/usr/bin/env node
"use strict";

const fs   = require("fs");
const path = require("path");
const { guard } = require("../guardian");

// ── Load datasets ────────────────────────────────────────────────
const attacks = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "tests", "benchmark", "attacks.json"), "utf8")
);
const benign = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "tests", "benchmark", "benign.json"), "utf8")
);

// ── Run every item through guard() ───────────────────────────────
const attackResults = attacks.map((item) => {
  const res = guard(item.text, item.context || "user_prompt");
  return { ...item, result: res, correct: res.verdict === "block" };
});

const benignResults = benign.map((item) => {
  const res = guard(item.text, item.context || "user_prompt");
  return { ...item, result: res, correct: res.verdict === "allow" };
});

// ── Confusion matrix ─────────────────────────────────────────────
const TP = attackResults.filter((r) => r.correct).length;         // attack blocked
const FN = attackResults.filter((r) => !r.correct).length;        // attack missed
const TN = benignResults.filter((r) => r.correct).length;         // benign allowed
const FP = benignResults.filter((r) => !r.correct).length;        // benign blocked

const precision = TP + FP > 0 ? TP / (TP + FP) : 0;
const recall    = TP + FN > 0 ? TP / (TP + FN) : 0;
const f1        = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
const fpr       = FP + TN > 0 ? FP / (FP + TN) : 0;

// ── Per-category recall ──────────────────────────────────────────
const categories = [...new Set(attacks.map((a) => a.category))];
const perCategory = {};
categories.forEach((cat) => {
  const catItems  = attackResults.filter((r) => r.category === cat);
  const catTP     = catItems.filter((r) => r.correct).length;
  perCategory[cat] = {
    total:    catItems.length,
    blocked:  catTP,
    missed:   catItems.length - catTP,
    recall:   catItems.length > 0 ? catTP / catItems.length : 0,
  };
});

// ── Missed attacks & false positives detail ──────────────────────
const missedAttacks  = attackResults.filter((r) => !r.correct).map((r) => ({
  text:     r.text,
  context:  r.context,
  category: r.category,
  score:    r.result.score,
  risk:     r.result.risk,
  findings: r.result.findings,
}));

const falsePositives = benignResults.filter((r) => !r.correct).map((r) => ({
  text:     r.text,
  context:  r.context,
  score:    r.result.score,
  risk:     r.result.risk,
  findings: r.result.findings,
}));

// ── Print report ─────────────────────────────────────────────────
console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log("║          GUARDIAN SECURITY BENCHMARK RESULTS            ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

console.log(`  Attacks tested : ${attacks.length}`);
console.log(`  Benign tested  : ${benign.length}`);
console.log("");

console.log("┌─────────── Confusion Matrix ───────────┐");
console.log(`│  TP (attack blocked)  : ${String(TP).padStart(4)}          │`);
console.log(`│  FN (attack missed)   : ${String(FN).padStart(4)}          │`);
console.log(`│  TN (benign allowed)  : ${String(TN).padStart(4)}          │`);
console.log(`│  FP (benign blocked)  : ${String(FP).padStart(4)}          │`);
console.log("└─────────────────────────────────────────┘\n");

console.log(`  Precision           : ${(precision * 100).toFixed(2)}%`);
console.log(`  Recall              : ${(recall * 100).toFixed(2)}%`);
console.log(`  F1 Score            : ${(f1 * 100).toFixed(2)}%`);
console.log(`  False Positive Rate : ${(fpr * 100).toFixed(2)}%`);
console.log("");

console.log("┌─────────── Recall per Category ─────────┐");
categories.forEach((cat) => {
  const c = perCategory[cat];
  const bar = "█".repeat(Math.round(c.recall * 20)) + "░".repeat(20 - Math.round(c.recall * 20));
  console.log(`│  ${cat.padEnd(26)} ${bar} ${(c.recall * 100).toFixed(0).padStart(3)}%  (${c.blocked}/${c.total}) │`);
});
console.log("└──────────────────────────────────────────┘\n");

if (missedAttacks.length > 0) {
  console.log(`⚠  MISSED ATTACKS (${missedAttacks.length}):`);
  missedAttacks.forEach((m, i) => {
    console.log(`   ${i + 1}. [${m.category}] score=${m.score} "${m.text}"`);
  });
  console.log("");
}

if (falsePositives.length > 0) {
  console.log(`⚠  FALSE POSITIVES (${falsePositives.length}):`);
  falsePositives.forEach((fp, i) => {
    console.log(`   ${i + 1}. score=${fp.score} "${fp.text}"`);
  });
  console.log("");
}

if (missedAttacks.length === 0 && falsePositives.length === 0) {
  console.log("✅  Perfect score — no misses, no false positives.\n");
}

// ── Save results to JSON ─────────────────────────────────────────
const logsDir = path.join(__dirname, "..", "logs");
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const report = {
  timestamp: new Date().toISOString(),
  summary: {
    attacks_tested:     attacks.length,
    benign_tested:      benign.length,
    TP, FN, TN, FP,
    precision:          +precision.toFixed(4),
    recall:             +recall.toFixed(4),
    f1:                 +f1.toFixed(4),
    false_positive_rate: +fpr.toFixed(4),
  },
  per_category: perCategory,
  missed_attacks:  missedAttacks,
  false_positives: falsePositives,
  full_attack_results: attackResults.map((r) => ({
    text: r.text, context: r.context, category: r.category,
    verdict: r.result.verdict, score: r.result.score, correct: r.correct,
  })),
  full_benign_results: benignResults.map((r) => ({
    text: r.text, context: r.context,
    verdict: r.result.verdict, score: r.result.score, correct: r.correct,
  })),
};

const outPath = path.join(logsDir, "benchmark-results.json");
fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
console.log(`📄 Results saved to ${outPath}\n`);


/**
 * guardian.js — Pure-function input/output guard for DRONA.
 *
 * DESIGN RULES (invariants):
 *  - The LLM is untrusted. It proposes; the server decides.
 *  - Nothing the model produces is shown, run, or acted on until checked.
 *  - Refusals for blocked input are FIXED server-side messages.
 *    The model is never called for a blocked message.
 *  - DRONA has NO shell, file, or network access.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Block threshold: a single named constant ────────────────────────────
const BLOCK_THRESHOLD = 60;

// ── Log directory ───────────────────────────────────────────────────────
const LOG_DIR  = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'guardian.jsonl');

// ── Normalization helpers ───────────────────────────────────────────────

/** Leetspeak decode map */
const LEET_MAP = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '7': 't', '@': 'a', '$': 's', '!': 'i',
};

function decodeLeetspeak(text) {
  return text.replace(/[013457@$!]/g, ch => LEET_MAP[ch] || ch);
}

/** Collapse spaced-out letters: "i g n o r e" → "ignore" */
function collapseSpacedLetters(text) {
  return text.replace(/\b([a-zA-Z])((?:\s+[a-zA-Z]){3,})\b/g, (match) => {
    const letters = match.split(/\s+/);
    if (letters.every(l => l.length === 1)) return letters.join('');
    return match;
  });
}

/** Strip zero-width characters */
function stripZeroWidth(text) {
  return text.replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g, '');
}

/** Detect and decode base64 blobs that decode to ASCII text */
function decodeBase64Blobs(text) {
  return text.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, (blob) => {
    try {
      const decoded = Buffer.from(blob, 'base64').toString('utf8');
      if (/^[\x20-\x7E\n\r\t]+$/.test(decoded) && decoded.length >= 8) {
        return decoded;
      }
    } catch {}
    return blob;
  });
}

/**
 * Normalize text for consistent pattern matching.
 * Order: NFKC → strip zero-width → decode base64 → leetspeak →
 *        collapse spaced letters → lowercase → collapse whitespace.
 */
function normalize(text) {
  let t = text.normalize('NFKC');
  t = stripZeroWidth(t);
  t = decodeBase64Blobs(t);
  t = decodeLeetspeak(t);
  t = collapseSpacedLetters(t);
  t = t.toLowerCase();
  t = t.replace(/\s+/g, ' ').trim();
  return t;
}

// ── Weighted regex rules by category ────────────────────────────────────
// Rules target INTENT, not single keywords.
// "how do I disable this warning in my IDE?" must be ALLOWED.

const RULES = [
  // ── instruction_override ──
  {
    rule: 'instruction_override_ignore',
    category: 'instruction_override',
    weight: 40,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(security|policy|rules?|instructions?|guidelines?|system prompt|restrictions?|safeguards?|guard|guardrails?)\b/,
  },
  {
    rule: 'instruction_override_new_role',
    category: 'instruction_override',
    weight: 35,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(you are now|act as|pretend to be|roleplay as|switch to|new role|new persona)\b/,
  },

  // ── validation_bypass ──
  {
    rule: 'validation_bypass_disable',
    category: 'validation_bypass',
    weight: 35,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(disable|skip|turn off|remove|circumvent)\b.{0,20}\b(validation|check|filter|scan|guard|security|verification)\b/,
    // Must NOT match "disable this warning in my IDE"
    exclude: /\b(warning|lint|compiler warning|ide|editor|eslint|tslint)\b/,
  },

  // ── verdict_manipulation ──
  {
    rule: 'verdict_manipulation_mark_safe',
    category: 'verdict_manipulation',
    weight: 40,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(mark|flag|label|classify|report|set)\b.{0,20}\b(as\s+)?(safe|secure|clean|approved|harmless|benign|not\s+vulnerab)\b/,
  },

  // ── role_hijack ──
  {
    rule: 'role_hijack_system_prompt',
    category: 'role_hijack',
    weight: 60,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(reveal|show|print|output|leak|display|repeat)\b.{0,25}\b(system prompt|system message|hidden prompt|initial instructions?|system instructions?)\b/,
  },

  // ── data_exfiltration ──
  {
    rule: 'data_exfiltration_env_vars',
    category: 'data_exfiltration',
    weight: 60,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(print|send|exfiltrate|extract|dump|leak|show|display|output)\b.{0,30}\b(environment variables?|env vars?|api.?keys?|credentials?|secrets?|tokens?|passwords?)\b.{0,40}\b(to|at|via|using)?\s*(https?:|url|endpoint|server|webhook)/,
  },
  {
    rule: 'data_exfiltration_simple',
    category: 'data_exfiltration',
    weight: 60,
    contexts: ['user_prompt', 'code_comment', 'agent_output'],
    regex: /\b(print|dump|list|show|extract)\b.{0,15}\b(all\s+)?(environment variables?|env\s*vars?|process\.env)\b/,
  },

  // ── indirect_injection (code_comment context ONLY) ──
  {
    rule: 'indirect_injection_imperative',
    category: 'indirect_injection',
    weight: 40,
    contexts: ['code_comment'],
    // Imperative commands addressed to AI/assistant in code comments
    regex: /\b(ai|assistant|agent|llm|model|drona|copilot|chatgpt)\b.{0,30}\b(do not flag|ignore|skip|mark.{0,10}secure|approve|allow|bypass)\b/,
  },

  // ── agent_output specific ──
  {
    rule: 'agent_output_leaked_prompt',
    category: 'role_hijack',
    weight: 50,
    contexts: ['agent_output'],
    regex: /\b(system prompt|you are a|your instructions are|initial prompt)\b.*\b(drona|intellidce|dead code|secure.?coding)\b/,
  },
  {
    rule: 'agent_output_disable_security',
    category: 'validation_bypass',
    weight: 45,
    contexts: ['agent_output'],
    regex: /\b(disable|turn off|remove)\b.{0,20}\b(security|guard|scanner|protection|firewall)\b/,
  },
];

// ── Combination boosters ────────────────────────────────────────────────
const COMBO_CATEGORIES = ['instruction_override', 'validation_bypass', 'verdict_manipulation'];

/**
 * guard(text, context) → {verdict, risk, score, findings}
 *
 * @param {string} text    — raw user text or agent output
 * @param {string} context — "user_prompt" | "code_comment" | "agent_output"
 * @returns {{verdict:"allow"|"block", risk:"low"|"medium"|"high", score:number, findings:Array}}
 */
function guard(text, context = 'user_prompt') {
  if (!text || typeof text !== 'string') {
    return { verdict: 'allow', risk: 'low', score: 0, findings: [] };
  }

  const norm = normalize(text);
  const findings = [];

  for (const rule of RULES) {
    if (!rule.contexts.includes(context)) continue;
    if (rule.regex.test(norm)) {
      if (rule.exclude && rule.exclude.test(norm)) continue;
      findings.push({
        rule: rule.rule,
        category: rule.category,
        evidence: norm.substring(0, 120),
        weight: rule.weight,
      });
    }
  }

  // Score = sum of weights, capped at 100
  let score = findings.reduce((sum, f) => sum + f.weight, 0);

  // Combo boost: if multiple high-risk categories are present, boost
  const hitCategories = new Set(findings.map(f => f.category));
  const comboCount = COMBO_CATEGORIES.filter(c => hitCategories.has(c)).length;
  if (comboCount >= 2) {
    score = Math.min(100, score + 20);
  }

  score = Math.min(100, score);

  const risk = score >= BLOCK_THRESHOLD ? 'high' : score >= 30 ? 'medium' : 'low';
  const verdict = score >= BLOCK_THRESHOLD ? 'block' : 'allow';

  // Log blocks and medium-risk allows
  if (verdict === 'block' || score >= 30) {
    _log({ context, risk, score, rules: findings.map(f => f.rule), text, verdict });
  }

  return { verdict, risk, score, findings };
}

// ── Logging ─────────────────────────────────────────────────────────────

function _log(entry) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const record = {
      timestamp: new Date().toISOString(),
      context: entry.context,
      verdict: entry.verdict,
      risk: entry.risk,
      score: entry.score,
      rules: entry.rules,
      text_excerpt: (entry.text || '').substring(0, 200),
    };
    fs.appendFileSync(LOG_FILE, JSON.stringify(record) + '\n');
  } catch (err) {
    console.error('[Guardian] Log write error:', err.message);
  }
}

/**
 * getRecentLogs(n) → latest n log entries (default 50).
 */
function getRecentLogs(n = 50) {
  try {
    if (!fs.existsSync(LOG_FILE)) return [];
    const lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').filter(Boolean);
    return lines.slice(-n).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch {
    return [];
  }
}

// ── Exports ─────────────────────────────────────────────────────────────

module.exports = { guard, getRecentLogs, normalize, BLOCK_THRESHOLD };


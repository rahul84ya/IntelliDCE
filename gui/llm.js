/**
 * llm.js — Ollama client for DRONA.
 *
 * DESIGN RULES:
 *  - The LLM is untrusted. All output is guard-checked before reaching the user.
 *  - DRONA has NO shell, file, or network access beyond this Ollama client.
 *  - Config constants at the top; model name auto-detected from Ollama tags.
 */

'use strict';

// ── Config constants ────────────────────────────────────────────────────
const OLLAMA_URL   = process.env.OLLAMA_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || '';  // empty = auto-detect
const TIMEOUT_MS   = 60000;
const TEMPERATURE  = 0.2;
const NUM_CTX      = 4096;

// ── Typed error classes ─────────────────────────────────────────────────

class LlmError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LlmError';
    this.code = code;
  }
}

const ERR = {
  LLM_OFFLINE:   'LLM_OFFLINE',
  LLM_TIMEOUT:   'LLM_TIMEOUT',
  LLM_BAD_OUTPUT: 'LLM_BAD_OUTPUT',
  MODEL_MISSING: 'MODEL_MISSING',
};

// ── Model cache ─────────────────────────────────────────────────────────
let _cachedModel = null;

/**
 * Auto-detect model: GET /api/tags, pick first containing "qwen2.5-coder".
 * Cache the result.
 */
async function resolveModel() {
  if (OLLAMA_MODEL) { _cachedModel = OLLAMA_MODEL; return _cachedModel; }
  if (_cachedModel) return _cachedModel;

  let res;
  try {
    res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(5000) });
  } catch (err) {
    throw new LlmError(ERR.LLM_OFFLINE, 'Cannot reach Ollama. Is it running?');
  }
  if (!res.ok) throw new LlmError(ERR.LLM_OFFLINE, `Ollama /api/tags returned ${res.status}`);

  const data = await res.json();
  const models = (data.models || []).map(m => m.name || m.model || '');
  const match = models.find(n => n.toLowerCase().includes('qwen2.5-coder'));
  if (match) { _cachedModel = match; return _cachedModel; }

  // Fallback: pick first model if any exist
  if (models.length > 0) { _cachedModel = models[0]; return _cachedModel; }

  throw new LlmError(ERR.MODEL_MISSING, 'No qwen2.5-coder model installed. Run: ollama pull qwen2.5-coder');
}

// ── Chat ────────────────────────────────────────────────────────────────

/**
 * chat({ system, messages, json }) → string (full reply)
 *
 * Uses POST /api/chat with stream:true internally, buffers the entire
 * response before returning (so it can be guard-checked).
 *
 * @param {object} opts
 * @param {string} opts.system   — system prompt
 * @param {Array}  opts.messages — [{role:'user'|'assistant', content:string}]
 * @param {boolean} [opts.json]  — if true, set format:"json" and parse result
 * @returns {string|object} — raw text or parsed JSON
 */
async function chat({ system, messages, json = false }) {
  const model = await resolveModel();

  const body = {
    model,
    stream: true,
    messages: [
      { role: 'system', content: system },
      ...messages,
    ],
    options: { temperature: TEMPERATURE, num_ctx: NUM_CTX },
    keep_alive: '10m',
  };
  if (json) body.format = 'json';

  const fullReply = await _streamChat(body);

  if (json) {
    const parsed = _tryParseJSON(fullReply);
    if (parsed !== null) return parsed;

    // Retry ONCE with a stricter reminder
    const retryMessages = [
      ...messages,
      { role: 'assistant', content: fullReply },
      { role: 'user', content: 'Your previous reply was not valid JSON. Reply ONLY with a single JSON object, no other text.' },
    ];
    const retryBody = { ...body, messages: [{ role: 'system', content: system }, ...retryMessages] };
    const retryReply = await _streamChat(retryBody);
    const retryParsed = _tryParseJSON(retryReply);
    if (retryParsed !== null) return retryParsed;

    throw new LlmError(ERR.LLM_BAD_OUTPUT, 'Model failed to produce valid JSON after retry.');
  }

  return fullReply;
}

async function _streamChat(body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res;
  try {
    res = await fetch(`${OLLAMA_URL}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new LlmError(ERR.LLM_TIMEOUT, 'LLM request timed out.');
    }
    throw new LlmError(ERR.LLM_OFFLINE, 'Cannot reach Ollama. Is it running?');
  }
  clearTimeout(timer);

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    if (text.includes('not found') || text.includes('does not exist')) {
      _cachedModel = null;
      throw new LlmError(ERR.MODEL_MISSING, `Model not found. ${text}`);
    }
    throw new LlmError(ERR.LLM_OFFLINE, `Ollama returned ${res.status}: ${text}`);
  }

  // Buffer streamed NDJSON response
  let fullContent = '';
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const chunk = JSON.parse(line);
        if (chunk.message && chunk.message.content) {
          fullContent += chunk.message.content;
        }
      } catch {}
    }
  }
  // Process remaining buffer
  if (buffer.trim()) {
    try {
      const chunk = JSON.parse(buffer);
      if (chunk.message && chunk.message.content) {
        fullContent += chunk.message.content;
      }
    } catch {}
  }

  return fullContent;
}

function _tryParseJSON(text) {
  // Try direct parse first
  try { return JSON.parse(text); } catch {}
  // Try extracting JSON from markdown code blocks
  const match = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (match) { try { return JSON.parse(match[1]); } catch {} }
  // Try finding first { ... }
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try { return JSON.parse(text.substring(start, end + 1)); } catch {}
  }
  return null;
}

// ── Health ──────────────────────────────────────────────────────────────

/**
 * health() → { online, model, modelInstalled }
 */
async function health() {
  try {
    const model = await resolveModel();
    return { online: true, model, modelInstalled: true };
  } catch (err) {
    if (err.code === ERR.MODEL_MISSING) {
      return { online: true, model: null, modelInstalled: false };
    }
    return { online: false, model: null, modelInstalled: false };
  }
}

/**
 * warmUp() — send a tiny background request to preload model.
 */
async function warmUp() {
  try {
    const h = await health();
    console.log(`[DRONA LLM] Health: online=${h.online}, model=${h.model}, installed=${h.modelInstalled}`);
    if (h.online && h.modelInstalled) {
      await chat({ system: 'Reply OK.', messages: [{ role: 'user', content: 'ping' }] });
      console.log('[DRONA LLM] Warm-up complete.');
    }
  } catch (err) {
    console.log(`[DRONA LLM] Warm-up skipped: ${err.message}`);
  }
}

// Reset cached model (for testing)
function _resetModelCache() { _cachedModel = null; }

// ── Exports ─────────────────────────────────────────────────────────────

module.exports = {
  chat, health, warmUp, resolveModel,
  LlmError, ERR,
  _resetModelCache,
  // Expose constants for testing
  OLLAMA_URL, TIMEOUT_MS, TEMPERATURE, NUM_CTX,
};


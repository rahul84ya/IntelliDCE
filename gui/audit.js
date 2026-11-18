/**
 * audit.js — Security Decision Timeline & Tamper-Evident Audit System
 *
 * DESIGN & SAFETY INVARIANTS:
 *  - Passive Observer: Observes and records decisions; never alters security outcomes.
 *  - Privacy Conscious: Never stores raw secrets, API keys, full sensitive prompts,
 *    or full attack payloads. Stores SHA-256 hashes, category labels, and redacted snippets.
 *  - Tamper-Evident Hash Chain: Uses SHA-256 hashing to link events sequentially within
 *    the application's storage scope. Clearly documented as local tamper-evident,
 *    NOT a distributed blockchain.
 *  - Fault Isolation: Failures in audit logging (file I/O, memory pressure, formatting)
 *    are caught safely and NEVER crash or block Guardian, DRONA, or the compiler.
 *  - Local Scope: All audit records and exports remain local to the user session.
 */

'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const AUDIT_LOG_DIR = path.join(__dirname, 'logs', 'audit_sessions');
const GENESIS_PREV_HASH = '0'.repeat(64);

// ── In-Memory Session Store ──────────────────────────────────────────────
// Map<sessionId, { sessionId, createdAt, lastHash, events: AuditEvent[] }>
const sessions = new Map();

/**
 * Common secret patterns to redact from safe metadata and snippets
 */
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9_\-\.]{10,}/gi,
  /(api[_-]?key|secret|token|password|auth|private[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{6,})['"]?/gi,
  /DEMO_SECRET_[A-Za-z0-9_]+/gi,
  /sk-[A-Za-z0-9]{20,}/gi,
  /ghp_[A-Za-z0-9]{20,}/gi,
  /AIza[0-9A-Za-z-_]{35}/gi,
];

/**
 * Sanitize any text by stripping known credentials, API keys, and truncating
 * to a short safe preview with a hash for integrity.
 */
function sanitizeSnippet(text, maxLen = 40) {
  if (!text || typeof text !== 'string') return '';
  let clean = text;
  for (const pat of SECRET_PATTERNS) {
    clean = clean.replace(pat, '[REDACTED_SECRET]');
  }
  clean = clean.replace(/\s+/g, ' ').trim();
  if (clean.length > maxLen) {
    const hash = crypto.createHash('sha256').update(text).digest('hex').substring(0, 8);
    return `${clean.substring(0, maxLen)}... [len=${text.length}, sha256=${hash}]`;
  }
  return clean;
}

/**
 * Deep sanitization for metadata objects to prevent accidental secret or payload leakage.
 */
function sanitizeMetadata(meta) {
  if (!meta || typeof meta !== 'object') return {};
  const clean = {};

  for (const [key, val] of Object.entries(meta)) {
    const lowerKey = key.toLowerCase();
    // Exclude raw payloads and secret keys
    if (lowerKey.includes('secret') || lowerKey.includes('token') || lowerKey.includes('password') || lowerKey.includes('key')) {
      clean[key] = '[REDACTED_SECRET]';
      continue;
    }
    if (lowerKey === 'rawpayload' || lowerKey === 'payload' || lowerKey === 'rawtext' || lowerKey === 'code') {
      if (typeof val === 'string') {
        clean[`${key}_sha256`] = crypto.createHash('sha256').update(val).digest('hex');
        clean[`${key}_snippet`] = sanitizeSnippet(val, 32);
        clean[`${key}_length`] = val.length;
      } else {
        clean[key] = '[COMPLEX_OBJECT_REDACTED]';
      }
      continue;
    }
    if (typeof val === 'string') {
      clean[key] = sanitizeSnippet(val, 80);
    } else if (Array.isArray(val)) {
      clean[key] = val.map(item => (typeof item === 'string' ? sanitizeSnippet(item, 50) : item));
    } else if (typeof val === 'object' && val !== null) {
      clean[key] = sanitizeMetadata(val);
    } else {
      clean[key] = val;
    }
  }
  return clean;
}

/**
 * Compute the SHA-256 hash for an event to maintain chain integrity.
 */
function computeEventHash(event) {
  const payload = [
    event.eventId,
    event.sessionId,
    event.timestamp,
    event.eventType,
    event.severity,
    event.decision,
    event.shortExplanation,
    JSON.stringify(event.safeMetadata || {}),
    event.stoppedBeforeExecution ? 'true' : 'false',
    event.prevHash,
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Get or initialize an audit session
 */
function getAuditSession(sessionId = 'default') {
  const sid = String(sessionId || 'default').trim() || 'default';
  if (!sessions.has(sid)) {
    sessions.set(sid, {
      sessionId: sid,
      createdAt: new Date().toISOString(),
      lastHash: GENESIS_PREV_HASH,
      events: [],
    });
  }
  return sessions.get(sid);
}

/**
 * Record a structured audit event into the session's tamper-evident hash chain.
 *
 * FAULT-ISOLATED: Always wrapped in try/catch to ensure caller is never blocked.
 *
 * @param {Object} params
 * @param {string} [params.sessionId='default']
 * @param {string} params.eventType - input_received, normalization_performed, threat_detected,
 *                                    risk_score_calculated, policy_decision, redaction_applied,
 *                                    drona_call_allowed, drona_call_prevented, tool_request_allowed,
 *                                    tool_request_rejected, compilation_allowed, compilation_blocked,
 *                                    self_healing_patch_proposed, validation_result, user_approval_rejection
 * @param {string} params.severity - 'info' | 'low' | 'medium' | 'high' | 'critical'
 * @param {string} params.decision - 'ALLOW' | 'WARN' | 'BLOCK' | 'PREVENTED' | 'REJECTED' | 'PROPOSED' | 'VALIDATED' | 'APPROVED'
 * @param {string} params.shortExplanation - Concise human-readable reason
 * @param {Object} [params.safeMetadata={}] - Sanitized context/findings
 * @param {boolean} [params.stoppedBeforeExecution=false] - True if execution was halted before DRONA/compiler/tools
 * @returns {Object|null} The recorded event or null if error occurred
 */
function recordEvent({
  sessionId = 'default',
  eventType,
  severity = 'info',
  decision = 'INFO',
  shortExplanation = '',
  safeMetadata = {},
  stoppedBeforeExecution = false,
}) {
  try {
    const session = getAuditSession(sessionId);

    const eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestamp = new Date().toISOString();
    const prevHash = session.lastHash;
    const sanitizedMeta = sanitizeMetadata(safeMetadata);

    const rawEvent = {
      eventId,
      sessionId: session.sessionId,
      timestamp,
      eventType: String(eventType || 'unknown'),
      severity: ['info', 'low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'info',
      decision: String(decision || 'INFO').toUpperCase(),
      shortExplanation: sanitizeSnippet(shortExplanation, 120),
      safeMetadata: sanitizedMeta,
      stoppedBeforeExecution: Boolean(stoppedBeforeExecution),
      prevHash,
    };

    const hash = computeEventHash(rawEvent);
    const event = { ...rawEvent, hash };

    session.events.push(event);
    session.lastHash = hash;

    // Optional asynchronous background persist to local session log
    _persistEventAsync(session.sessionId, event);

    return event;
  } catch (err) {
    // Safe fault isolation: visible logging, zero impact on calling process
    console.error(`[Audit] Failed to record audit event (${eventType}):`, err.message);
    return null;
  }
}

/**
 * Verify the integrity of the SHA-256 hash chain for a given session.
 */
function verifyIntegrity(sessionId = 'default') {
  try {
    if (sessionId === 'all') {
      let totalEvents = 0;
      let lastHead = GENESIS_PREV_HASH;
      for (const session of sessions.values()) {
        if (!session.events || session.events.length === 0) continue;
        let expectedPrevHash = GENESIS_PREV_HASH;
        for (let i = 0; i < session.events.length; i++) {
          const evt = session.events[i];
          if (evt.prevHash !== expectedPrevHash) {
            return {
              valid: false,
              sessionId: session.sessionId,
              brokenAtIndex: i,
              brokenAtEventId: evt.eventId,
              reason: `Previous hash pointer mismatch in session "${session.sessionId}" at index ${i}. Expected ${expectedPrevHash.substring(0, 16)}..., found ${evt.prevHash.substring(0, 16)}...`,
            };
          }
          const recomputed = computeEventHash(evt);
          if (recomputed !== evt.hash) {
            return {
              valid: false,
              sessionId: session.sessionId,
              brokenAtIndex: i,
              brokenAtEventId: evt.eventId,
              reason: `Content hash recomputation failed in session "${session.sessionId}" at index ${i} (${evt.eventId}). Event content has been modified or corrupted.`,
            };
          }
          expectedPrevHash = evt.hash;
        }
        totalEvents += session.events.length;
        lastHead = session.lastHash;
      }
      return {
        valid: true,
        sessionId: 'all',
        eventCount: totalEvents,
        tamperEvidentScope: 'local_application_storage',
        headHash: lastHead,
        message: totalEvents > 0
          ? `All session hash chains verified intact across ${totalEvents} events. No local tampering detected.`
          : 'All session timelines empty. Hash chain initialized at genesis.',
      };
    }

    const session = getAuditSession(sessionId);
    const events = session.events;

    if (!events || events.length === 0) {
      return {
        valid: true,
        sessionId: session.sessionId,
        eventCount: 0,
        tamperEvidentScope: 'local_application_storage',
        message: 'Empty session timeline. Hash chain initialized at genesis.',
      };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < events.length; i++) {
      const evt = events[i];

      // Check linkage with previous hash
      if (evt.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          sessionId: session.sessionId,
          brokenAtIndex: i,
          brokenAtEventId: evt.eventId,
          reason: `Previous hash pointer mismatch at index ${i}. Expected ${expectedPrevHash.substring(0, 16)}..., found ${evt.prevHash.substring(0, 16)}...`,
        };
      }

      // Recompute and verify current hash
      const recomputed = computeEventHash(evt);
      if (recomputed !== evt.hash) {
        return {
          valid: false,
          sessionId: session.sessionId,
          brokenAtIndex: i,
          brokenAtEventId: evt.eventId,
          reason: `Content hash recomputation failed at index ${i} (${evt.eventId}). Event content has been modified or corrupted.`,
        };
      }

      expectedPrevHash = evt.hash;
    }

    return {
      valid: true,
      sessionId: session.sessionId,
      eventCount: events.length,
      tamperEvidentScope: 'local_application_storage',
      headHash: session.lastHash,
      message: `Hash chain valid across all ${events.length} events. No local tampering detected.`,
    };
  } catch (err) {
    return {
      valid: false,
      sessionId,
      reason: `Integrity verification error: ${err.message}`,
    };
  }
}

/**
 * Retrieve timeline events with optional severity and category filtering.
 */
function getTimeline(sessionId = 'default', { severity, eventCategory, limit = 100 } = {}) {
  try {
    let list = [];
    if (sessionId === 'all') {
      for (const sess of sessions.values()) {
        list.push(...sess.events);
      }
      list.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } else {
      const session = getAuditSession(sessionId);
      list = [...session.events];
    }

    if (severity && severity !== 'all') {
      list = list.filter(e => e.severity === severity.toLowerCase());
    }

    if (eventCategory && eventCategory !== 'all') {
      const cat = eventCategory.toLowerCase();
      if (cat === 'policy') {
        list = list.filter(e => ['policy_decision', 'risk_score_calculated', 'threat_detected'].includes(e.eventType));
      } else if (cat === 'threats') {
        list = list.filter(e => ['threat_detected', 'redaction_applied', 'normalization_performed'].includes(e.eventType));
      } else if (cat === 'drona') {
        list = list.filter(e => e.eventType.startsWith('drona_') || e.eventType.startsWith('tool_'));
      } else if (cat === 'compiler') {
        list = list.filter(e => e.eventType.startsWith('compilation_') || e.eventType.startsWith('self_healing_') || e.eventType.startsWith('sandbox_') || e.eventType === 'resource_limit_exceeded' || e.eventType === 'execution_completed' || e.eventType === 'validation_result');
      }
    }

    return list.slice(-limit);
  } catch (err) {
    console.error('[Audit] getTimeline error:', err.message);
    return [];
  }
}

/**
 * Generate a complete, local, exportable JSON audit report for the session.
 */
function exportSessionReport(sessionId = 'default') {
  try {
    if (sessionId === 'all') {
      const allEvents = [];
      for (const sess of sessions.values()) {
        allEvents.push(...sess.events);
      }
      allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      const integrity = verifyIntegrity('all');
      const summary = {
        totalEvents: allEvents.length,
        blocks: allEvents.filter(e => ['BLOCK', 'PREVENTED', 'REJECTED'].includes(e.decision)).length,
        warnings: allEvents.filter(e => e.decision === 'WARN').length,
        allows: allEvents.filter(e => ['ALLOW', 'APPROVED', 'VALIDATED'].includes(e.decision)).length,
        threatsDetected: allEvents.filter(e => e.eventType === 'threat_detected').length,
        criticalEvents: allEvents.filter(e => e.severity === 'critical').length,
        stoppedBeforeExecutionCount: allEvents.filter(e => e.stoppedBeforeExecution).length,
      };

      return {
        reportType: 'IntelliDCE Security Decision Timeline & Audit Report (All Sessions)',
        reportVersion: '1.0.0',
        sessionId: 'all',
        sessionCreatedAt: new Date().toISOString(),
        exportedAt: new Date().toISOString(),
        disclaimer: 'Tamper-evident SHA-256 hash chain verified within local application storage scope. Does not claim external blockchain immutability. No raw secrets or full payloads are stored.',
        integrity,
        summary,
        events: allEvents,
      };
    }

    const session = getAuditSession(sessionId);
    const integrity = verifyIntegrity(session.sessionId);
    const events = session.events;

    const summary = {
      totalEvents: events.length,
      blocks: events.filter(e => ['BLOCK', 'PREVENTED', 'REJECTED'].includes(e.decision)).length,
      warnings: events.filter(e => e.decision === 'WARN').length,
      allows: events.filter(e => ['ALLOW', 'APPROVED', 'VALIDATED'].includes(e.decision)).length,
      threatsDetected: events.filter(e => e.eventType === 'threat_detected').length,
      criticalEvents: events.filter(e => e.severity === 'critical').length,
      stoppedBeforeExecutionCount: events.filter(e => e.stoppedBeforeExecution).length,
    };

    return {
      reportType: 'IntelliDCE Security Decision Timeline & Audit Report',
      reportVersion: '1.0.0',
      sessionId: session.sessionId,
      sessionCreatedAt: session.createdAt,
      exportedAt: new Date().toISOString(),
      disclaimer: 'Tamper-evident SHA-256 hash chain verified within local application storage scope. Does not claim external blockchain immutability. No raw secrets or full payloads are stored.',
      integrity,
      summary,
      events,
    };
  } catch (err) {
    console.error('[Audit] exportSessionReport error:', err.message);
    return {
      error: `Failed to generate audit report: ${err.message}`,
      sessionId,
    };
  }
}

/**
 * Reset session events (useful for tests or explicit user session reset)
 */
function resetSession(sessionId = 'default') {
  const sid = String(sessionId || 'default').trim() || 'default';
  sessions.set(sid, {
    sessionId: sid,
    createdAt: new Date().toISOString(),
    lastHash: GENESIS_PREV_HASH,
    events: [],
  });
}

/**
 * Optional background append to a session log file in logs/audit_sessions/
 */
function _persistEventAsync(sessionId, event) {
  setImmediate(() => {
    try {
      if (!fs.existsSync(AUDIT_LOG_DIR)) {
        fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
      }
      const safeFile = `session_${sessionId.replace(/[^a-zA-Z0-9_\-]/g, '_')}.jsonl`;
      const filePath = path.join(AUDIT_LOG_DIR, safeFile);
      fs.appendFileSync(filePath, JSON.stringify(event) + '\n');
    } catch (err) {
      // Non-blocking error handling
      console.warn('[Audit] Background persistence warning:', err.message);
    }
  });
}

module.exports = {
  recordEvent,
  verifyIntegrity,
  getTimeline,
  exportSessionReport,
  getAuditSession,
  resetSession,
  computeEventHash,
  sanitizeSnippet,
  sanitizeMetadata,
  GENESIS_PREV_HASH,
};


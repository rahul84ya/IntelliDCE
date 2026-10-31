/**
 * tests/llm.test.js — Unit tests for the Ollama client (llm.js).
 * Uses mocked fetch to run offline without Ollama running.
 *
 * Run: node gui/tests/llm.test.js
 */

'use strict';

const path = require('path');
const llm = require(path.join(__dirname, '..', 'llm'));
const { LlmError, ERR } = llm;

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}`);
  }
}

// Helper to create a mocked streaming fetch response
function makeStreamResponse(chunks, status = 200) {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      for (const c of chunks) {
        const line = typeof c === 'string' ? c : JSON.stringify(c);
        controller.enqueue(encoder.encode(line + '\n'));
      }
      controller.close();
    }
  });

  return {
    ok: status >= 200 && status < 300,
    status,
    body: stream,
    text: async () => chunks.join('\n'),
    json: async () => ({ models: chunks }),
  };
}

const originalFetch = global.fetch;

async function runTests() {
  console.log('\n=== LLM Tests ===\n');

  // 1. health() when Ollama is running and qwen2.5-coder is present
  console.log('-- Health checks --');
  {
    llm._resetModelCache();
    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            models: [
              { name: 'llama3:latest' },
              { name: 'qwen2.5-coder:7b' },
            ]
          }),
        };
      }
      throw new Error(`Unexpected url: ${url}`);
    };

    const h = await llm.health();
    assert(h.online === true, 'health() detects online state');
    assert(h.modelInstalled === true, 'health() detects model installed');
    assert(h.model === 'qwen2.5-coder:7b', `health() selects correct model (${h.model})`);
  }

  // 2. health() when Ollama is offline
  {
    llm._resetModelCache();
    global.fetch = async () => {
      throw new Error('fetch failed (ECONNREFUSED)');
    };

    const h = await llm.health();
    assert(h.online === false, 'health() returns online=false when offline');
    assert(h.modelInstalled === false, 'health() returns modelInstalled=false when offline');
    assert(h.model === null, 'health() returns model=null when offline');
  }

  // 3. health() when Ollama is online but no qwen2.5-coder model installed
  {
    llm._resetModelCache();
    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            models: []
          }),
        };
      }
      throw new Error(`Unexpected url: ${url}`);
    };

    const h = await llm.health();
    assert(h.online === true, 'health() returns online=true when tags responds');
    assert(h.modelInstalled === false, 'health() returns modelInstalled=false when model missing');
    assert(h.model === null, 'health() returns model=null when model missing');
  }

  // 4. chat() buffers stream into full reply
  console.log('\n-- Chat streaming --');
  {
    llm._resetModelCache();
    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return {
          ok: true,
          json: async () => ({ models: [{ name: 'qwen2.5-coder:latest' }] }),
        };
      }
      if (url.includes('/api/chat')) {
        return makeStreamResponse([
          { message: { content: 'Dead store ' } },
          { message: { content: 'elimination ' } },
          { message: { content: 'removes unused writes.' } },
        ]);
      }
      throw new Error('Unhandled endpoint');
    };

    const reply = await llm.chat({
      system: 'test system',
      messages: [{ role: 'user', content: 'What is DCE?' }]
    });

    assert(reply === 'Dead store elimination removes unused writes.', `chat() correctly buffers stream chunks: "${reply}"`);
  }

  // 5. chat({json: true}) parses valid JSON response
  console.log('\n-- JSON mode and retry --');
  {
    llm._resetModelCache();
    const expected = { reply: 'A dead store is an assignment whose value is never read.', suggested_code: null, actions: [] };

    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return { ok: true, json: async () => ({ models: [{ name: 'qwen2.5-coder:latest' }] }) };
      }
      if (url.includes('/api/chat')) {
        return makeStreamResponse([
          { message: { content: JSON.stringify(expected) } }
        ]);
      }
    };

    const res = await llm.chat({
      system: 'test',
      messages: [{ role: 'user', content: 'Explain' }],
      json: true
    });

    assert(typeof res === 'object' && res.reply === expected.reply, 'chat({json: true}) returns parsed JSON');
  }

  // 6. chat({json: true}) retries ONCE if first response is not valid JSON
  {
    llm._resetModelCache();
    let chatCallCount = 0;
    const expected = { reply: 'Recovered JSON', suggested_code: null, actions: [] };

    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return { ok: true, json: async () => ({ models: [{ name: 'qwen2.5-coder:latest' }] }) };
      }
      if (url.includes('/api/chat')) {
        chatCallCount++;
        if (chatCallCount === 1) {
          // Bad non-JSON output first
          return makeStreamResponse([{ message: { content: 'Here is your answer without JSON' } }]);
        } else {
          // Valid JSON on retry
          return makeStreamResponse([{ message: { content: JSON.stringify(expected) } }]);
        }
      }
    };

    const res = await llm.chat({
      system: 'test',
      messages: [{ role: 'user', content: 'Test retry' }],
      json: true
    });

    assert(chatCallCount === 2, `chat({json: true}) retried once (call count = ${chatCallCount})`);
    assert(res.reply === 'Recovered JSON', 'chat({json: true}) parsed JSON on second try');
  }

  // 7. chat({json: true}) throws LLM_BAD_OUTPUT if retry also fails
  {
    llm._resetModelCache();
    let chatCallCount = 0;

    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return { ok: true, json: async () => ({ models: [{ name: 'qwen2.5-coder:latest' }] }) };
      }
      if (url.includes('/api/chat')) {
        chatCallCount++;
        return makeStreamResponse([{ message: { content: 'Still not JSON!' } }]);
      }
    };

    let threw = false;
    try {
      await llm.chat({
        system: 'test',
        messages: [{ role: 'user', content: 'Test bad output' }],
        json: true
      });
    } catch (err) {
      threw = true;
      assert(err instanceof LlmError, 'Throws LlmError instance on invalid JSON');
      assert(err.code === ERR.LLM_BAD_OUTPUT, `Error code is LLM_BAD_OUTPUT (${err.code})`);
    }
    assert(threw, 'chat({json: true}) throws error when both tries fail');
    assert(chatCallCount === 2, `chat({json: true}) attempted exactly 2 tries before throwing (${chatCallCount})`);
  }

  // 8. chat() throws LLM_OFFLINE when network fails
  console.log('\n-- Typed errors --');
  {
    llm._resetModelCache();
    global.fetch = async (url) => {
      if (url.includes('/api/tags')) {
        return { ok: true, json: async () => ({ models: [{ name: 'qwen2.5-coder:latest' }] }) };
      }
      const err = new Error('Connection refused');
      err.name = 'FetchError';
      throw err;
    };

    let caught = null;
    try {
      await llm.chat({ system: 's', messages: [{ role: 'u', content: 'm' }] });
    } catch (err) {
      caught = err;
    }
    assert(caught && caught.code === ERR.LLM_OFFLINE, `Throws LLM_OFFLINE on fetch failure (${caught?.code})`);
  }

  // Restore fetch
  global.fetch = originalFetch;

  console.log(`\n=== LLM Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});


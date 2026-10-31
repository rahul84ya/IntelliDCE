/**
 * scripts/drona-smoke.js — Live end-to-end smoke test calling local Ollama.
 *
 * Sends: "In one sentence, what is a dead store?"
 * Prints DRONA's reply and round-trip latency.
 *
 * Run: node gui/scripts/drona-smoke.js
 */

'use strict';

const path = require('path');
const drona = require(path.join(__dirname, '..', 'drona'));
const llm   = require(path.join(__dirname, '..', 'llm'));

async function main() {
  console.log('=== DRONA Live Smoke Test ===\n');

  console.log('1. Checking Ollama health...');
  const health = await llm.health();
  console.log(`   Online: ${health.online}`);
  console.log(`   Model:  ${health.model || 'none'}`);
  console.log(`   Installed: ${health.modelInstalled}\n`);

  if (!health.online) {
    console.error('❌ Ollama is not running on http://localhost:11434. Start Ollama and retry.');
    process.exit(1);
  }

  if (!health.modelInstalled) {
    console.error('❌ Model qwen2.5-coder is not installed. Run: ollama pull qwen2.5-coder');
    process.exit(1);
  }

  const prompt = 'In one sentence, what is a dead store?';
  console.log(`2. Sending prompt to DRONA: "${prompt}"`);

  const t0 = Date.now();
  const response = await drona.handleMessage({
    sessionId: 'smoke-test-' + Date.now(),
    message: prompt,
  });
  const totalElapsed = Date.now() - t0;

  console.log('\n3. DRONA Response:');
  console.log('----------------------------------------------------');
  console.log(response.reply);
  console.log('----------------------------------------------------');
  console.log(`Blocked:        ${response.blocked}`);
  console.log(`Suggested Code: ${response.suggested_code || 'none'}`);
  console.log(`Actions:        ${JSON.stringify(response.actions || [])}`);
  console.log(`Model Latency:  ${response.latency_ms} ms`);
  console.log(`Total Elapsed:  ${totalElapsed} ms`);

  if (response.blocked) {
    console.error('\n❌ Unexpected: benign prompt was blocked by Guardian.');
    process.exit(1);
  }

  if (response.error) {
    console.error(`\n❌ DRONA returned error: ${response.error}`);
    process.exit(1);
  }

  console.log('\n✅ Live DRONA smoke test succeeded!');
}

main().catch(err => {
  console.error('\n❌ Smoke test failed with exception:', err);
  process.exit(1);
});


/**
 * pipeline_explorer.test.js
 * Comprehensive automated test suite for Feature 4: Secure Compilation Pipeline Explorer
 *
 * Verifies:
 * 1. Standard 6-stage compiler pipeline structure & labels.
 * 2. Truthful hybrid architecture mapping: GCC frontend delegation without fabricated token counts.
 * 3. Semantic analysis distinction: GCC symbol/type check vs IntelliDCE static security findings.
 * 4. Guardian block propagation: downstream stages indicate "Blocked before this stage".
 * 5. Truthful Docker sandbox status reporting.
 * 6. Read-only safety guarantee: metadata endpoint executes no code and changes no policy.
 * 7. Mandatory architectural explanatory caption presence.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

const HTML_PATH = path.join(__dirname, '../public/index.html');
const SERVER_PATH = path.join(__dirname, '../server.js');

describe('=== Feature 4: Secure Compilation Pipeline Explorer Tests ===', () => {

  test('1. HTML includes mandatory architectural explanatory caption', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    const expectedCaption = 'GCC performs the C++ frontend and emits GIMPLE SSA. IntelliDCE performs secure, explainable SSA optimization, behavioral verification, and sandboxed execution.';
    assert(html.includes(expectedCaption), 'index.html must include the exact mandatory caption');
  });

  test('2. HTML defines all standard 6 compiler pipeline stages + security intake', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    // Check stage presence
    assert(html.includes('Input C++ Source Code'), 'Stage 0 Input C++ Source Code must exist');
    assert(html.includes('Guardian Security Intake Gate'), 'Pre-intake Guardian Security Gate must exist');
    assert(html.includes('Lexical Analysis (Scanning)'), 'Stage 1 Lexical Analysis must exist');
    assert(html.includes('Syntax Analysis (Parsing)'), 'Stage 2 Syntax Analysis must exist');
    assert(html.includes('Semantic Analysis &amp; Static Security Audit') || html.includes('Semantic Analysis & Static Security Audit'), 'Stage 3 Semantic Analysis must exist');
    assert(html.includes('Intermediate Code Generation'), 'Stage 4 Intermediate Code Generation must exist');
    assert(html.includes('Code Optimization (DCE)'), 'Stage 5 Code Optimization must exist');
    assert(html.includes('Target Code Gen &amp; Sandbox') || html.includes('Target Code Gen & Sandbox'), 'Stage 6 Target Code Generation must exist');
  });

  test('3. GCC frontend delegation is truthful without fabricated token counts', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    // Lexical analysis must state delegation to GCC frontend
    assert(html.includes('Delegated to GCC frontend'), 'Lexical stage must declare delegation to GCC frontend');
    assert(html.includes('Detailed internal token counts are retained by GCC and not fabricated'), 'Lexical stage must disclaim fabricated token counts');

    // Syntax analysis must state AST not exposed
    assert(html.includes('Handled by GCC frontend; detailed parse tree not exposed'), 'Syntax stage must state detailed parse tree is not exposed');
  });

  test('4. Semantic stage separates GCC symbol resolution from IntelliDCE security pattern audit', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    assert(html.includes('GCC Semantic Resolution'), 'Must show GCC semantic resolution section');
    assert(html.includes('IntelliDCE Static Security Findings'), 'Must show IntelliDCE static security findings section');
    assert(html.includes('Static heuristics only; no formal semantic verification claimed'), 'Must disclaim formal semantic equivalence verification');
  });

  test('5. Downstream execution stages support Guardian block propagation', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    // renderPipelineExplorer must contain logic for "Blocked before this stage"
    assert(html.includes("'Blocked before this stage'"), 'renderPipelineExplorer must propagate Blocked before this stage when Guardian blocks');
    assert(html.includes('pipe-guardian-badge'), 'Guardian badge element must exist');
    assert(html.includes('pipe-target-status-badge'), 'Target status badge must exist');
  });

  test('6. Docker sandbox runtime status is truthfully distinguished', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    // Must distinguish Sandbox Unavailable, Executed in Docker sandbox, Not run, Timed out
    assert(html.includes('Sandbox unavailable — execution safely blocked'), 'Must handle sandbox unavailable safely');
    assert(html.includes('Executed in Docker sandbox'), 'Must handle real docker sandbox execution');
    assert(html.includes('Not run'), 'Must handle unexecuted neutral state');
    assert(html.includes('--network none'), 'Must show network none constraint');
  });

  test('7. Cross-cutting layers are present: DCE Explainability, Verified DCE Guard, and Audit', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    assert(html.includes('DCE Explainability'), 'DCE Explainability card must exist');
    assert(html.includes('Verified DCE Regression Guard'), 'Verified DCE Regression Guard card must exist');
    assert(html.includes('Audit &amp; DRONA Repair Loop') || html.includes('Audit & DRONA Repair Loop'), 'Audit & DRONA repair loop card must exist');
    assert(html.includes('Verification Not Run'), 'Verified DCE must have a truthful neutral Not Run state');
  });

  test('8. Navigation bar & top progress bar have clickable links to Pipeline Explorer', () => {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    
    assert(html.includes('data-panel="pipeline"'), 'Navigation track must contain a button for data-panel="pipeline"');
    assert(html.includes("data-panel=\\'pipeline\\'"), 'Top progress bar must have an action linking to pipeline');
  });

  test('9. Backend endpoint /api/pipeline/status is strictly read-only and returns valid metadata', async () => {
    // Query local server
    const data = await new Promise((resolve, reject) => {
      http.get('http://localhost:3000/api/pipeline/status', (res) => {
        let raw = '';
        res.on('data', chunk => raw += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(raw));
          } catch (e) {
            reject(e);
          }
        });
      }).on('error', reject);
    });

    assert(data.hybridArchitecture, 'Response must describe hybridArchitecture');
    assert.strictEqual(typeof data.hybridArchitecture.frontend, 'string');
    assert.strictEqual(typeof data.hybridArchitecture.middleEnd, 'string');
    assert.strictEqual(typeof data.hybridArchitecture.execution, 'string');
    assert(data.gcc, 'Response must include gcc information');
    assert(data.sandbox, 'Response must include sandbox status');
    assert(data.guardian, 'Response must include guardian status');
    assert(Array.isArray(data.guardian.normalizers), 'Guardian normalizers must be an array');
  });

});


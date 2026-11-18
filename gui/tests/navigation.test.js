/**
 * navigation.test.js
 * Comprehensive automated test suite for IntelliDCE Full Navigation & Panel Accessibility
 *
 * Verifies:
 * 1. All 13 feature buttons exist with exact data-panel targets in navigation track.
 * 2. All 13 corresponding panel DOM containers exist with correct IDs and hidden classes.
 * 3. DRONA floating assistant integration remains accessible and wired up.
 * 4. Strictly read-only navigation guarantees (opening panels does not execute host code or mutate server state).
 * 5. Interactive and responsive top navigation bar with compact system status capsule.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const HTML_PATH = path.join(__dirname, '../public/index.html');
const DRONA_JS_PATH = path.join(__dirname, '../public/drona.js');
const DRONA_CSS_PATH = path.join(__dirname, '../public/drona.css');

describe('=== Navigation & UI Panel Regression Guard Tests ===', () => {

  const html = fs.readFileSync(HTML_PATH, 'utf8');

  const EXPECTED_FEATURES = [
    { key: 'dashboard',   label: 'Dashboard',             panelId: 'panel-dashboard' },
    { key: 'editor',      label: 'Input Editor',          panelId: 'panel-editor' },
    { key: 'compare',     label: 'Code Compare',          panelId: 'panel-compare' },
    { key: 'cfg',         label: 'CFG View',              panelId: 'panel-cfg' },
    { key: 'health',      label: 'Code Health',           panelId: 'panel-health' },
    { key: 'ai-patterns', label: 'AI Patterns',           panelId: 'panel-ai-patterns' },
    { key: 'explainer',   label: 'DCE Explainer',         panelId: 'panel-explainer' },
    { key: 'verifier',    label: 'Verified DCE',          panelId: 'panel-verifier' },
    { key: 'benchmark',   label: 'Benchmark Lab',         panelId: 'panel-benchmark' },
    { key: 'audit',       label: 'Timeline',              panelId: 'panel-audit' },
    { key: 'analytics',   label: 'Analytics',             panelId: 'panel-analytics' },
    { key: 'logs',        label: 'Analysis Logs',         panelId: 'panel-logs' },
    { key: 'pipeline',    label: 'Pipeline',              panelId: 'panel-pipeline' },
  ];

  test('1. Navigation track contains all 13 required feature buttons with exact data-panel targets', () => {
    // Extract nav buttons in nav-track
    const navMatch = html.match(/<nav[^>]*class="[^"]*nav-track[^"]*"[^>]*>([\s\S]*?)<\/nav>/);
    assert(navMatch, 'nav-track navigation container must exist in index.html');
    const navHtml = navMatch[1];

    EXPECTED_FEATURES.forEach(({ key, label }) => {
      const btnRegex = new RegExp(`<button[^>]*data-panel=["']${key}["'][^>]*>`, 'i');
      assert(btnRegex.test(navHtml), `Nav track must contain button for feature "${key}" (${label})`);
    });

    assert.strictEqual(
      EXPECTED_FEATURES.length,
      13,
      'Exactly 13 features must be verified in the top navigation bar'
    );
  });

  test('2. DOM contains all 13 corresponding panel elements with exact matching IDs', () => {
    EXPECTED_FEATURES.forEach(({ key, panelId }) => {
      const panelRegex = new RegExp(`id=["']${panelId}["'][^>]*class=["'][^"']*panel[^"']*["']`, 'i');
      assert(
        panelRegex.test(html),
        `DOM must contain <div id="${panelId}" class="...panel..."> corresponding to nav button "${key}"`
      );
    });
  });

  test('3. DRONA floating assistant integration remains present and functional', () => {
    // HTML links script and stylesheet
    assert(html.includes('src="/drona.js"') || html.includes('src="drona.js"'), 'index.html must load drona.js');
    assert(html.includes('href="/drona.css"') || html.includes('href="drona.css"'), 'index.html must load drona.css');

    // drona.js and drona.css files exist and contain client assistant UI launcher
    assert(fs.existsSync(DRONA_JS_PATH), 'public/drona.js must exist on disk');
    assert(fs.existsSync(DRONA_CSS_PATH), 'public/drona.css must exist on disk');

    const dronaJs = fs.readFileSync(DRONA_JS_PATH, 'utf8');
    assert(dronaJs.includes('drona-launcher'), 'drona.js must define the drona-launcher floating button');
    assert(dronaJs.includes('createUi()') || dronaJs.includes('drona-panel'), 'drona.js must initialize assistant UI');
    assert(dronaJs.includes('/api/drona/chat'), 'drona.js must communicate with the secure /api/drona/chat endpoint');
  });

  test('4. Compact system status capsule is present with hover tooltips and sandbox status', () => {
    assert(html.includes('id="model-info-bar"'), 'Model info bar for Deep-DCE v2 must exist');
    assert(html.includes('id="sandbox-status-chip"'), 'Compact sandbox indicator chip must exist');
    assert(html.includes('id="sandbox-status-pip"'), 'Sandbox status indicator dot must exist');
    assert(html.includes('id="sandbox-tooltip-text"'), 'Sandbox hover tooltip text must exist');
    assert(html.includes('id="status-chip"'), 'Engine status chip must exist');
  });

  test('5. Read-only navigation guarantees: opening tabs does not trigger compilation or mutate server state', () => {
    // Verify panel switching listener
    const switcherMatch = html.match(/\/\/ ── Panel switching[\s\S]*?\}\);\s*\}\);/);
    assert(switcherMatch, 'Panel switching listener must exist');
    const switcherCode = switcherMatch[0];

    // Ensure all 13 panel targets are covered in the switcher or generic handler
    assert(switcherCode.includes('document.querySelectorAll(\'.panel\').forEach(p => p.classList.add(\'hidden\'))'));
    assert(switcherCode.includes('document.getElementById(`panel-${target}`)?.classList.remove(\'hidden\')'));

    // Check that panel switching DOES NOT trigger compilation, execution, or destructive mutations
    assert(!switcherCode.includes('fetch(\'/api/compile-run\''), 'Navigating panels must not trigger compile-run');
    assert(!switcherCode.includes('runOptimizedExecutable('), 'Navigating panels must not run executables');
    assert(!switcherCode.includes('POST /api/verify'), 'Navigating panels must not auto-execute verification without user click');
  });

  test('6. JavaScript implementations exist for all restored panel controllers', () => {
    assert(html.includes('function getAiPatternEstimate'), 'getAiPatternEstimate must be defined in script');
    assert(html.includes('function refreshAiPatternAnalysis'), 'refreshAiPatternAnalysis must be defined in script');
    assert(html.includes('function triggerOptimizationVerification'), 'triggerOptimizationVerification must be defined in script');
    assert(html.includes('function renderVerificationResult'), 'renderVerificationResult must be defined in script');
    assert(html.includes('function runBenchmarkLab'), 'runBenchmarkLab must be defined in script');
    assert(html.includes('function renderBenchmarkDashboard'), 'renderBenchmarkDashboard must be defined in script');
    assert(html.includes('function loadAuditTimeline'), 'loadAuditTimeline must be defined in script');
    assert(html.includes('function renderAuditTimeline'), 'renderAuditTimeline must be defined in script');
    assert(html.includes('function updateSandboxStatusBadge'), 'updateSandboxStatusBadge must be defined in script');
  });

  test('7. Floating card styling and enhanced breathing sizing attributes are defined', () => {
    assert(html.includes('padding: 8px 16px') || html.includes('padding: 6.5px 12px'), 'Must specify generous card padding');
    assert(html.includes('min-height: 38px') || html.includes('min-height: 32px'), 'Must specify min-height');
    assert(html.includes('solid var(--nav-border') || html.includes('1px solid #cbd5e1'), 'Must specify visible border');
    assert(html.includes('flex-shrink: 0'), 'Must specify flex-shrink: 0 to prevent card compression');
    assert(html.includes('white-space: nowrap'), 'Must keep tab labels on one line');
    assert(html.includes('nav-scroll-wrapper'), 'Must include nav-scroll-wrapper container');
  });

  test('8. Scrollbars are completely suppressed on all major browsers', () => {
    assert(html.includes('scrollbar-width: none !important'), 'Must suppress scrollbars via scrollbar-width for Firefox');
    assert(html.includes('-ms-overflow-style: none !important'), 'Must suppress scrollbars via -ms-overflow-style for IE/Edge');
    assert(html.includes('.nav-track::-webkit-scrollbar') && html.includes('display: none !important'), 'Must hide webkit scrollbar for Chrome/Safari/Edge');
  });

  test('9. Category-aware hover accents and active underline glow are defined', () => {
    // Category tokens
    assert(html.includes('.nav-btn[data-panel="dashboard"]') && html.includes('#10b981'), 'Dashboard must use emerald');
    assert(html.includes('.nav-btn[data-panel="editor"]') && html.includes('#3b82f6'), 'Editor must use blue');
    assert(html.includes('.nav-btn[data-panel="health"]') && html.includes('#10b981'), 'Health must use emerald');
    assert(html.includes('.nav-btn[data-panel="ai-patterns"]') && html.includes('#8b5cf6'), 'AI Patterns must use violet');
    assert(html.includes('.nav-btn[data-panel="analytics"]') && html.includes('#64748b'), 'Analytics must use slate/blue');
    assert(html.includes('.nav-btn[data-panel="pipeline"]') && html.includes('#0d9488'), 'Pipeline must use cyan/teal');

    // Active state glow and underline
    assert(html.includes('.nav-active::after'), 'Active state must feature underline ::after element');
    assert(html.includes('border-color: var(--nav-accent'), 'Active and hover states must reference var(--nav-accent)');
  });

});


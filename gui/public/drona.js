(() => {
  'use strict';
  const MAX_MESSAGE_LENGTH = 2000;
  let sessionId = newSessionId();
  let waiting = false;
  let greeted = false;
  let lastMessage = '';
  let health = { online: false, modelInstalled: false };
  let scanTimer = null;
  let scanController = null;
  let lastScannedCode = null;
  let visibleFinding = null;
  const dismissedFindings = new Set();
  const el = {};

  function newSessionId() { return `drona-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`; }
  function make(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text != null) node.textContent = text; return node; }
  function verifySafeTextRendering() {
    const probe = '<img src=x onerror=alert(1)>';
    const node = make('span', '', probe);
    if (node.textContent !== probe || node.querySelector('img')) throw new Error('DRONA text renderer must not parse HTML');
  }
  function clock() { return new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit' }).format(new Date()); }
  function scrollToLatest() { el.messages.scrollTop = el.messages.scrollHeight; }

  function createUi() {
    el.launcher = make('button', 'drona-launcher'); el.launcher.type = 'button';
    el.dot = make('span', 'drona-dot'); el.launcher.append(el.dot, document.createTextNode('DRONA'));
    el.scanAlert = make('div', 'drona-scan-alert'); el.scanAlert.setAttribute('role', 'button'); el.scanAlert.tabIndex = 0;
    el.scanAlertText = make('span', 'drona-scan-alert-text'); el.scanDismiss = make('button', 'drona-scan-dismiss', '×'); el.scanDismiss.type = 'button'; el.scanDismiss.setAttribute('aria-label', 'Dismiss scan finding');
    el.scanAlert.append(el.scanAlertText, el.scanDismiss);
    el.panel = make('aside', 'drona-panel'); el.panel.setAttribute('aria-label', 'DRONA assistant');
    const header = make('div', 'drona-header'); const copy = make('div', 'drona-header-copy');
    copy.append(make('div', 'drona-title', 'DRONA')); el.status = make('div', 'drona-status', 'Checking local AI…'); copy.append(el.status);
    el.clear = make('button', '', 'Clear chat'); el.close = make('button', '', 'Close'); el.clear.type = el.close.type = 'button';
    header.append(copy, el.clear, el.close); el.messages = make('div', 'drona-messages scr'); el.messages.setAttribute('aria-live', 'polite');
    el.chips = make('div', 'drona-chips'); ['Explain the selected removal', 'Is my code secure?', 'How can I fix this?'].forEach(text => { const chip = make('button', 'drona-chip', text); chip.type = 'button'; chip.addEventListener('click', () => send(text)); el.chips.append(chip); });
    const composer = make('div', 'drona-composer'); el.input = make('textarea', 'drona-textarea'); el.input.rows = 2; el.input.maxLength = MAX_MESSAGE_LENGTH; el.input.placeholder = 'Ask DRONA about this analysis…';
    const row = make('div', 'drona-composer-row'); el.counter = make('span', 'drona-counter', `0/${MAX_MESSAGE_LENGTH}`); el.send = make('button', 'drona-send', 'Send'); el.send.type = 'button'; el.send.disabled = true; row.append(el.counter, el.send); composer.append(el.input, row); el.panel.append(header, el.messages, el.chips, composer);
    document.body.append(el.launcher, el.scanAlert, el.panel);
    el.launcher.addEventListener('click', toggle); el.close.addEventListener('click', () => setOpen(false)); el.clear.addEventListener('click', clearChat); el.send.addEventListener('click', () => send());
    el.input.addEventListener('input', updateComposer); el.input.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); } });
    el.scanAlert.addEventListener('click', openScanFinding); el.scanAlert.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openScanFinding(); } });
    el.scanDismiss.addEventListener('click', event => { event.stopPropagation(); dismissVisibleFinding(); });
  }

  function toggle() { setOpen(!el.panel.classList.contains('open')); }
  function setOpen(open) { el.panel.classList.toggle('open', open); if (open) { if (!greeted) { greeted = true; addAssistant('Hi, I’m DRONA. I can explain IntelliDCE results and review secure alternatives.'); } el.input.focus(); } }
  function updateComposer() { if (el.input.value.length > MAX_MESSAGE_LENGTH) el.input.value = el.input.value.slice(0, MAX_MESSAGE_LENGTH); el.counter.textContent = `${el.input.value.length}/${MAX_MESSAGE_LENGTH}`; el.send.disabled = waiting || !el.input.value.trim(); }
  function clearChat() { sessionId = newSessionId(); greeted = false; lastMessage = ''; el.messages.replaceChildren(); setOpen(true); }

  function findingKey(finding) { return `${finding.line}:${finding.cwe}`; }
  function severityRank(severity) { return ({ Critical: 4, High: 3, Medium: 2, Low: 1 })[severity] || 0; }
  function hideScanAlert() { visibleFinding = null; el.scanAlert.classList.remove('visible'); }
  function showScanFindings(findings) {
    const available = (findings || []).filter(finding => !dismissedFindings.has(findingKey(finding))).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    if (!available.length) return hideScanAlert();
    visibleFinding = available[0];
    const icon = visibleFinding.severity === 'Critical' ? '⛔' : visibleFinding.severity === 'High' ? '⚠️' : '⚡';
    el.scanAlertText.textContent = `${icon} Line ${visibleFinding.line}: ${visibleFinding.title}${available.length > 1 ? ` · +${available.length - 1} more` : ''}`;
    el.scanAlert.classList.add('visible');
  }
  function dismissVisibleFinding() { if (!visibleFinding) return; dismissedFindings.add(findingKey(visibleFinding)); hideScanAlert(); }
  function openScanFinding() {
    if (!visibleFinding) return;
    setOpen(true);
    el.input.value = `Explain the risk on line ${visibleFinding.line} (${visibleFinding.cwe}) and show a safer version`;
    updateComposer();
  }
  function queueEditorScan(code) {
    if (scanTimer) window.clearTimeout(scanTimer);
    if (scanController) scanController.abort();
    if (!code.trim()) { lastScannedCode = code; hideScanAlert(); return; }
    if (code === lastScannedCode) return;
    scanTimer = window.setTimeout(() => scanEditorCode(code), 600);
  }
  async function scanEditorCode(code) {
    scanController = new AbortController();
    const controller = scanController;
    lastScannedCode = code;
    try {
      const response = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }), signal: controller.signal });
      if (!response.ok) throw new Error('Scan unavailable');
      const data = await response.json();
      if (scanController !== controller) return;
      showScanFindings(data.findings);
    } catch (error) {
      if (error.name !== 'AbortError' && scanController === controller) hideScanAlert();
    }
  }
  function attachEditorScan() {
    const editor = document.getElementById('ssa-editor');
    if (editor) editor.addEventListener('input', () => queueEditorScan(editor.value));
  }

  async function pollHealth() {
    try { const response = await fetch('/api/drona/health'); health = response.ok ? await response.json() : { online:false, modelInstalled:false }; } catch { health = { online:false, modelInstalled:false }; }
    const ready = Boolean(health.online && health.modelInstalled); el.dot.classList.toggle('online', ready); el.status.textContent = ready ? `Ready · ${health.model || 'local model'}` : 'Local AI unavailable';
  }

  function selectedStatementId() { const selected = document.getElementById('explainer-stmt-select'); return selected && selected.value ? selected.value : undefined; }
  function addUser(text) { const item = make('article', 'drona-message user'); item.append(make('div', 'drona-bubble', text), make('time', 'drona-time', clock())); el.messages.append(item); scrollToLatest(); }
  function addThinking() { const item = make('article', 'drona-message assistant'); item.id = 'drona-thinking'; const bubble = make('div', 'drona-bubble'); const thinking = make('span', 'drona-thinking', 'DRONA is thinking'); thinking.append(make('i'), make('i'), make('i')); bubble.append(thinking); item.append(bubble); el.messages.append(item); scrollToLatest(); return item; }
  function tags(container, values, className) { if (!Array.isArray(values) || !values.length) return; const wrap = make('div', className); values.forEach(value => wrap.append(make('span', 'drona-tag', typeof value === 'string' ? value : value.tool || 'read-only tool'))); container.append(wrap); }
  function addAssistant(reply, data = {}) {
    const item = make('article', `drona-message assistant${data.blocked ? ' blocked' : data.withheld ? ' review' : data.error ? ' error' : ''}`); const bubble = make('div', 'drona-bubble');
    if (data.blocked) { bubble.append(make('div', 'drona-alert-title', `🛡 Blocked by security guard · ${data.risk || 'high'} risk`)); tags(bubble, (data.findings || []).map(f => f.rule || f), 'drona-rules'); }
    if (data.withheld) bubble.append(make('div', 'drona-alert-title', `Needs review${data.withheld_reason ? ` · ${data.withheld_reason}` : ''}`));
    const replyNode = make('div'); bubble.append(replyNode);
    if (data.suggested_code) { const head = make('div', 'drona-code-head'); head.append(make('strong', '', 'Suggested code')); head.append(make('span', 'drona-rating', `Scan: ${data.scan?.rating || 'unknown'}`)); const code = make('pre', 'drona-code', data.suggested_code); const copy = make('button', 'drona-copy', 'Copy'); copy.type = 'button'; copy.addEventListener('click', () => navigator.clipboard?.writeText(data.suggested_code)); bubble.append(head, code, copy); }
    tags(bubble, data.actions, 'drona-actions');
    if (data.error) { const retry = make('button', 'drona-retry', 'Retry'); retry.type = 'button'; retry.addEventListener('click', () => send(lastMessage)); bubble.append(retry); }
    item.append(bubble, make('time', 'drona-time', clock())); if (Number.isFinite(data.latency_ms)) item.append(make('div', 'drona-latency', `${data.latency_ms} ms`)); el.messages.append(item); scrollToLatest(); typeReply(replyNode, reply);
  }
  function typeReply(node, text) { const value = String(text || ''); let index = 0; let done = false; const finish = () => { if (done) return; done = true; node.textContent = value; scrollToLatest(); }; node.addEventListener('click', finish, { once:true }); const tick = () => { if (done) return; index += Math.max(1, Math.ceil(value.length / 80)); node.textContent = value.slice(0, index); scrollToLatest(); if (index < value.length) window.setTimeout(tick, 12); else done = true; }; tick(); }

  async function send(preset) {
    const message = (preset == null ? el.input.value : preset).trim(); if (!message || waiting) return; lastMessage = message; addUser(message); el.input.value = ''; waiting = true; updateComposer(); const thinking = addThinking();
    try {
      const payload = { sessionId, message, runId: window.currentRunId || undefined, selectedStatementId: selectedStatementId() };
      const response = await fetch('/api/drona/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      const data = await response.json().catch(() => ({})); if (!response.ok) throw new Error(data.error || 'DRONA could not process that request.'); thinking.remove(); addAssistant(data.reply || 'DRONA returned an empty response.', { ...data, error: Boolean(data.error) });
    } catch (error) { thinking.remove(); addAssistant(error.message || 'Local AI is unavailable.', { error:true }); }
    finally { waiting = false; updateComposer(); }
  }

  document.addEventListener('DOMContentLoaded', () => { verifySafeTextRendering(); createUi(); attachEditorScan(); pollHealth(); window.setInterval(pollHealth, 15000); });
})();

#!/usr/bin/env node
// Run the native SBOM workflow through Dify's console API using the logged-in
// browser session. Uploads a local fixture, starts a blocking draft run (SSE),
// and prints the run result.
// Usage: node tools/run_workflow.js <page-ws-url> <fixture-path> [--expect-failed]
const fs = require('node:fs');

const [, , wsUrl, fixturePath, flag] = process.argv;
const fileB64 = fs.readFileSync(fixturePath).toString('base64');
const fileName = fixturePath.split(/[\\/]/).pop();
const expectFailed = flag === '--expect-failed';

const expr = `(async () => {
  const b64 = '${fileB64}';
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const blob = new Blob([bytes], {type: 'application/json'});
  const csrf = (document.cookie.match(/csrf[_\\-]?token=([^;]+)/i)||[])[1] || '';
  const fd = new FormData();
  fd.append('file', blob, '${fileName}');
  fd.append('source', 'workflow');
  const up = await fetch('/console/api/files/upload', {method: 'POST', headers: {'X-CSRF-Token': csrf}, body: fd});
  const upData = await up.json();
  if (!upData.id) return {step: 'upload', status: up.status, data: upData};
  const run = await fetch('/console/api/apps/d0959d02-1daa-4147-96bf-2b7486612319/workflows/draft/run', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': csrf},
    body: JSON.stringify({
      inputs: {sbom_file: {transfer_method: 'local_file', upload_file_id: upData.id, type: 'document'}},
      response_mode: 'blocking',
    }),
  });
  const text = await run.text();
  return {step: 'run', upload_file_id: upData.id, status: run.status, text: text.slice(-300000)};
})()`;

function parseSse(text) {
  const events = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('data: ')) continue;
    try {
      events.push(JSON.parse(line.slice(6)));
    } catch { /* keep pings out */ }
  }
  return events;
}

const ws = new WebSocket(wsUrl);
ws.onopen = () => {
  ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, awaitPromise: true, returnByValue: true } }));
};
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id !== 1) return;
  const value = msg.result && msg.result.result && msg.result.result.value;
  if (!value || value.step !== 'run' || value.status !== 200) {
    console.log(JSON.stringify(value || msg.result, null, 1));
    process.exit(1);
    return;
  }
  const events = parseSse(value.text);
  const finished = events.filter((e) => e.event === 'workflow_finished' || e.event === 'workflow_failed');
  const errorEvt = events.find((e) => e.event === 'error');
  if (finished.length === 0) {
    console.log('EVENTS:', events.map((e) => e.event).join(', '));
    if (errorEvt) console.log('ERROR_EVENT:', JSON.stringify(errorEvt, null, 1).slice(0, 3000));
    process.exit(1);
    return;
  }
  const last = finished[finished.length - 1];
  const d = last.data || {};
  const outputs = d.outputs || {};
  console.log('RUN_STATUS:', last.event === 'workflow_finished' ? 'completed' : 'failed');
  console.log('RUN_ID:', d.id || last.workflow_run_id);
  console.log('TRACE:');
  for (const t of events.filter((e) => e.event === 'node_finished')) {
    const td = t.data || {};
    console.log('  -', td.node_id, '|', td.node_type, '| status', td.status || '?');
  }
  if (outputs.evidence_json) {
    try {
      const ev = JSON.parse(outputs.evidence_json);
      console.log('EVIDENCE_SUMMARY:', JSON.stringify(ev.evidence ? ev.evidence.map((c) => ({ i: c.component_index, s: c.state })) : ev, null, 1));
    } catch { console.log('EVIDENCE_JSON_HEAD:', outputs.evidence_json.slice(0, 1500)); }
  }
  if (outputs.evidence_csv) {
    const lines = outputs.evidence_csv.split('\n');
    console.log('CSV_LINES:', lines.length);
    console.log('CSV_HEAD:\n' + lines.slice(0, 3).join('\n').slice(0, 1000));
  }
  if (outputs.run_manifest_json) {
    try { console.log('MANIFEST:', JSON.stringify(JSON.parse(outputs.run_manifest_json), null, 1).slice(0, 1800)); }
    catch { console.log('MANIFEST_RAW:', outputs.run_manifest_json.slice(0, 1800)); }
  }
  const ok = last.event === 'workflow_finished';
  process.exit((expectFailed ? !ok : !ok) ? 1 : 0);
};
ws.onerror = (e) => { console.error('WS ERR', e.message || e); process.exit(1); };
setTimeout(() => { console.error('TIMEOUT'); process.exit(1); }, 120000);

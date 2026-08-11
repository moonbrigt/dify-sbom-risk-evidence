#!/usr/bin/env node
// Deploy the generated native workflow graph into the Dify draft via the
// authenticated console API, then publish it. Usage:
//   node tools/deploy_draft.js <page-ws-url> <graph.json> <app-id>
const fs = require('node:fs');

const [, , wsUrl, graphPath, appId] = process.argv;
const graph = fs.readFileSync(graphPath, 'utf8');

const features = {
  file_upload: {
    allowed_file_extensions: ['.JSON', '.SPDX.JSON', '.CDX.JSON'],
    allowed_file_types: ['document'],
    allowed_file_upload_methods: ['local_file'],
    enabled: true,
    fileUploadConfig: {
      audio_file_size_limit: 0,
      batch_count_limit: 1,
      file_size_limit: 2,
      image_file_size_limit: 0,
      number_limits: 1,
      video_file_size_limit: 0,
      workflow_file_upload_limit: 2,
    },
    image: { enabled: false, number_limits: 0, transfer_methods: [] },
    number_limits: 1,
  },
  opening_statement: '',
  retriever_resource: { enabled: false },
  sensitive_word_avoidance: { enabled: false, type: '', inputs: [], outputs: [] },
  speech_to_text: { enabled: false },
  suggested_questions: [],
  suggested_questions_after_answer: { enabled: false },
  text_to_speech: { enabled: false, language: '', voice: '' },
};

const expr = `(async () => {
  const csrf = (document.cookie.match(/csrf[_\\-]?token=([^;]+)/i)||[])[1] || '';
  const current = await (await fetch('/console/api/apps/${appId}/workflows/draft', {headers: {'X-CSRF-Token': csrf}})).json();
  const graph = JSON.parse(atob('${Buffer.from(graph).toString('base64')}'));
  const payload = JSON.stringify({ graph, features: ${JSON.stringify(features)}, hash: current.hash });
  const res = await fetch('/console/api/apps/${appId}/workflows/draft', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': csrf},
    body: payload,
  });
  const data = await res.json();
  return {status: res.status, ok: data.result === 'success' || !!data.draft, detail: data};
})()`;

const { WebSocket } = globalThis;
const ws = new WebSocket(wsUrl);
ws.onopen = () => {
  ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, awaitPromise: true, returnByValue: true } }));
};
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id === 1) {
    console.log(JSON.stringify(msg.result || msg.error, null, 1));
    ws.close();
    process.exit(0);
  }
};
ws.onerror = (e) => { console.error('WS ERR', e.message || e); process.exit(1); };
setTimeout(() => { console.error('TIMEOUT'); process.exit(1); }, 30000);

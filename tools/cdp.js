#!/usr/bin/env node
// Minimal CDP client: node cdp.js <ws-url> <command> [json-args]
// commands: eval <expr> | screenshot <file> | open <url> | tabs | navigate <url> | content
const http = require('node:http');
const fs = require('node:fs');

function getJson(url, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.end();
  });
}

class Cdp {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.pending = new Map();
    this.events = [];
  }
  async connect() {
    await new Promise((res, rej) => {
      this.ws.onopen = res;
      this.ws.onerror = rej;
    });
    this.ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      } else if (msg.method) {
        this.events.push(msg);
      }
    };
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  close() {
    try { this.ws.close(); } catch {}
  }
}

async function main() {
  const [, , cmdOrWs, second, third] = process.argv;
  const special = ['tabs', 'open', 'page-ws'];
  const isSpecial = special.includes(cmdOrWs);
  const wsUrl = isSpecial ? '' : cmdOrWs;
  const command = isSpecial ? cmdOrWs : second;
  const arg = isSpecial ? second : third;
  if (command === 'tabs') {
    const list = await getJson('http://127.0.0.1:9222/json/list');
    console.log(JSON.stringify(list.map((t) => ({ type: t.type, url: t.url, title: t.title, id: t.id })), null, 1));
    return;
  }
  if (command === 'open') {
    // open a new tab and print its ws url
    const tab = await getJson(`http://127.0.0.1:9222/json/new?${encodeURIComponent(arg)}`, 'PUT');
    console.log(tab.webSocketDebuggerUrl || tab.id);
    return;
  }
  if (command === 'page-ws') {
    const list = await getJson('http://127.0.0.1:9222/json/list');
    const page = list.find((t) => t.type === 'page' && (arg ? t.url.includes(arg) : true));
    console.log(page ? page.webSocketDebuggerUrl : 'NOT_FOUND');
    return;
  }
  const cdp = new Cdp(wsUrl);
  await cdp.connect();
  if (command === 'eval') {
    const r = await cdp.send('Runtime.evaluate', { expression: arg, awaitPromise: true, returnByValue: true });
    console.log(JSON.stringify(r.result || r.exceptionDetails, null, 1));
  } else if (command === 'navigate') {
    await cdp.send('Page.navigate', { url: arg });
    console.log('navigated');
  } else if (command === 'screenshot') {
    const r = await cdp.send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(arg, Buffer.from(r.data, 'base64'));
    console.log('saved', arg);
  } else if (command === 'content') {
    const r = await cdp.send('Runtime.evaluate', { expression: 'document.body ? document.body.innerText.slice(0, 3000) : "(no body)"', returnByValue: true });
    console.log(r.result.value);
  }
  cdp.close();
}

main().catch((e) => { console.error('ERR', e.message); process.exit(1); });

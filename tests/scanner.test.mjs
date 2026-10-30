import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../scanner.js', import.meta.url), 'utf8');

function createHarness({ referrer = '', opener = null, bridgeVerified = true } = {}) {
  const listeners = new Map();
  const elements = new Map();

  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id, textContent: id === 'count' || id === 'confirmedCount' ? '0' : '', className: '', disabled: false,
        hidden: id === 'retryBtn', value: '', files: [], handlers: {},
        addEventListener(type, callback) { this.handlers[type] = callback; }
      });
    }
    return elements.get(id);
  }

  const documentListeners = {};
  const document = {
    referrer,
    getElementById: element,
    addEventListener(type, callback) { documentListeners[type] = callback; }
  };

  class FakeScanner {
    static instance = null;
    constructor() { FakeScanner.instance = this; }
    async start(_camera, _config, onSuccess) { this.onSuccess = onSuccess; }
    async stop() {}
    clear() {}
    async scanFile() { return 'photo-token'; }
  }

  const window = {
    opener,
    Html5Qrcode: FakeScanner,
    crypto: {
      randomUUID: () => '12345678-1234-1234-1234-123456789012',
      subtle: {
        async importKey() { return {}; },
        async verify() { return bridgeVerified; }
      }
    },
    atob(value) { return Buffer.from(value, 'base64').toString('binary'); },
    location: { hostname: 'localhost', origin: 'https://shkottexas-debug.github.io' },
    addEventListener(type, callback) { listeners.set(type, callback); }
  };
  const context = vm.createContext({ window, document, navigator: { vibrate() {} },
    URL, Math, Date, TextEncoder, setTimeout, clearTimeout });
  vm.runInContext(source, context);
  documentListeners.DOMContentLoaded();
  return { window, elements, listeners, FakeScanner };
}

test('counts only unique QR codes in standalone test mode', () => {
  const app = createHarness();
  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-b');
  assert.equal(app.elements.get('count').textContent, '2');
  assert.match(app.elements.get('result').textContent, /Тестовый режим/);
});

test('starts camera once and keeps the success callback active', async () => {
  const app = createHarness();
  await app.elements.get('startBtn').handlers.click();
  app.FakeScanner.instance.onSuccess('token-a');
  app.FakeScanner.instance.onSuccess('token-b');
  assert.equal(app.elements.get('stopBtn').disabled, false);
  assert.equal(app.elements.get('count').textContent, '2');
});

test('ignores bridge messages from an unexpected origin', () => {
  const opener = { closed: false, postMessage() {} };
  const app = createHarness({ referrer: 'https://example-script.googleusercontent.com/', opener });
  app.listeners.get('message')({ origin: 'https://attacker.example', source: opener,
    data: { type: 'M70_BRIDGE_INIT', channelId: 'bad-channel' } });
  assert.match(app.elements.get('mode').textContent, /Тестовый режим/);
});

test('accepts a signed Apps Script opener handshake without putting a token in URL', async () => {
  const messages = [];
  const opener = { closed: false, postMessage(message, origin) { messages.push({ message, origin }); } };
  const origin = 'https://example-script.googleusercontent.com';
  const app = createHarness({ referrer: origin + '/', opener });
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_BRIDGE_INIT', channelId: 'trusted-channel',
      expiresAt: Date.now() + 60000, signature: 'c2lnbmF0dXJl' } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(app.elements.get('mode').textContent, /Авторизованный режим/);
  assert.equal(messages[0].message.type, 'M70_SCANNER_READY');
  assert.equal(messages[0].origin, origin);
});

test('queues two different QR codes and never sends a duplicate concurrently', async () => {
  const messages = [];
  const opener = { closed: false, postMessage(message, origin) { messages.push({ message, origin }); } };
  const origin = 'https://example-script.googleusercontent.com';
  const app = createHarness({ referrer: origin + '/', opener });
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_BRIDGE_INIT', channelId: 'trusted-channel',
      expiresAt: Date.now() + 60000, signature: 'c2lnbmF0dXJl' } });
  await new Promise((resolve) => setTimeout(resolve, 0));

  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-b');
  const firstRequest = messages.find((entry) => entry.message.type === 'M70_CHECKIN_REQUEST');
  assert.equal(firstRequest.message.token, 'token-a');
  assert.equal(messages.filter((entry) => entry.message.type === 'M70_CHECKIN_REQUEST').length, 1);

  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: firstRequest.message.requestId, status: 'checked_in' } });
  const requests = messages.filter((entry) => entry.message.type === 'M70_CHECKIN_REQUEST');
  assert.equal(requests.length, 2);
  assert.equal(requests[1].message.token, 'token-b');
  assert.equal(app.elements.get('confirmedCount').textContent, '1');
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: requests[1].message.requestId, status: 'already_used' } });
});

test('does not show a false confirmation for a server error', async () => {
  const messages = [];
  const opener = { closed: false, postMessage(message) { messages.push(message); } };
  const origin = 'https://example-script.googleusercontent.com';
  const app = createHarness({ referrer: origin + '/', opener });
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_BRIDGE_INIT', channelId: 'trusted-channel',
      expiresAt: Date.now() + 60000, signature: 'c2lnbmF0dXJl' } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  app.window.__M70_TEST__.onScanSuccess('token-a');
  const request = messages.find((message) => message.type === 'M70_CHECKIN_REQUEST');
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: request.requestId, status: 'error', message: 'Сеть недоступна' } });

  assert.equal(app.elements.get('confirmedCount').textContent, '0');
  assert.equal(app.elements.get('retryBtn').hidden, false);
  assert.match(app.elements.get('result').textContent, /Приход не подтверждён|Сеть недоступна/i);
});

test('keeps photo scanning as a standalone fallback', async () => {
  const app = createHarness();
  const input = app.elements.get('photoInput');
  input.files = [{ name: 'qr.jpg', type: 'image/jpeg' }];
  await input.handlers.change({ target: input });
  assert.equal(app.elements.get('count').textContent, '1');
  assert.match(app.elements.get('result').textContent, /Новый QR-код распознан/);
});

test('rejects an Apps Script opener with an invalid server signature', async () => {
  const opener = { closed: false, postMessage() {} };
  const origin = 'https://example-script.googleusercontent.com';
  const app = createHarness({ referrer: origin + '/', opener, bridgeVerified: false });
  app.listeners.get('message')({ origin, source: opener,
    data: { type: 'M70_BRIDGE_INIT', channelId: 'untrusted-channel',
      expiresAt: Date.now() + 60000, signature: 'aW52YWxpZA==' } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(app.elements.get('mode').textContent, /Тестовый режим/);
  assert.match(app.elements.get('result').textContent, /подлинность/);
});

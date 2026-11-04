import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../scanner.js', import.meta.url), 'utf8');
const BRIDGE_ORIGIN = 'https://example-script.googleusercontent.com';

function unrefTimeout(callback, delay) {
  const timer = setTimeout(callback, delay);
  timer.unref();
  return timer;
}

function createHarness({ bridgeVerified = true } = {}) {
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
    getElementById: element,
    addEventListener(type, callback) { documentListeners[type] = callback; }
  };

  class FakeScanner {
    static instance = null;
    constructor() {
      FakeScanner.instance = this;
      this.startCalls = 0;
      this.stopCalls = 0;
      this.clearCalls = 0;
    }
    async start(_camera, _config, onSuccess) {
      this.startCalls += 1;
      this.onSuccess = onSuccess;
    }
    async stop() { this.stopCalls += 1; }
    clear() { this.clearCalls += 1; }
    async scanFile() { return 'photo-token'; }
  }

  const window = {
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
    URL, Math, Date, TextEncoder, setTimeout: unrefTimeout, clearTimeout });
  vm.runInContext(source, context);
  documentListeners.DOMContentLoaded();
  return { window, elements, listeners, FakeScanner };
}

async function connectBridge(app, bridgeWindow, overrides = {}) {
  app.listeners.get('message')({
    origin: overrides.origin || BRIDGE_ORIGIN,
    source: bridgeWindow,
    data: {
      type: 'M70_BRIDGE_INIT',
      channelId: 'trusted-channel',
      expiresAt: Date.now() + 60000,
      bridgeOrigin: overrides.bridgeOrigin || BRIDGE_ORIGIN,
      signature: 'c2lnbmF0dXJl',
      ...overrides.data
    }
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
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
  app.elements.get('startBtn').handlers.click();
  await new Promise((resolve) => setImmediate(resolve));
  await app.elements.get('startBtn').handlers.click();
  assert.equal(app.FakeScanner.instance.startCalls, 1);
  app.FakeScanner.instance.onSuccess('token-a');
  app.FakeScanner.instance.onSuccess('token-b');
  assert.equal(app.elements.get('stopBtn').disabled, false);
  assert.equal(app.elements.get('count').textContent, '2');
});

test('stops and clears the active camera before allowing another start', async () => {
  const app = createHarness();
  app.elements.get('startBtn').handlers.click();
  await new Promise((resolve) => setImmediate(resolve));
  const firstScanner = app.FakeScanner.instance;
  app.elements.get('stopBtn').handlers.click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(firstScanner.stopCalls, 1);
  assert.equal(firstScanner.clearCalls, 1);
  assert.equal(app.elements.get('startBtn').disabled, false);
  assert.equal(app.elements.get('stopBtn').disabled, true);

  app.elements.get('startBtn').handlers.click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.notEqual(app.FakeScanner.instance, firstScanner);
});

test('ignores unsigned bridge messages from an unexpected origin', async () => {
  const bridgeWindow = { closed: false, postMessage() {} };
  const app = createHarness();
  await connectBridge(app, bridgeWindow, {
    origin: 'https://attacker.example',
    bridgeOrigin: 'https://attacker.example'
  });
  assert.match(app.elements.get('mode').textContent, /Тестовый режим/);
});

test('accepts a signed parent-initiated session without referrer or URL credentials', async () => {
  const messages = [];
  const bridgeWindow = { closed: false, postMessage(message, origin) { messages.push({ message, origin }); } };
  const app = createHarness();
  await connectBridge(app, bridgeWindow);

  assert.match(app.elements.get('mode').textContent, /Авторизованный режим/);
  assert.equal(messages[0].message.type, 'M70_SCANNER_CONNECTED');
  assert.equal(messages[0].origin, BRIDGE_ORIGIN);
});

test('an invalid init cannot disconnect an already verified session', async () => {
  const bridgeWindow = { closed: false, postMessage() {} };
  const app = createHarness();
  await connectBridge(app, bridgeWindow);
  await connectBridge(app, { closed: false, postMessage() {} }, {
    origin: 'https://attacker.example',
    bridgeOrigin: 'https://attacker.example'
  });
  assert.match(app.elements.get('mode').textContent, /Авторизованный режим/);
});

test('a signed replay from another window cannot replace the verified parent', async () => {
  const originalMessages = [];
  const attackerMessages = [];
  const bridgeWindow = {
    closed: false,
    postMessage(message) { originalMessages.push(message); }
  };
  const app = createHarness();
  await connectBridge(app, bridgeWindow);
  await connectBridge(app, {
    closed: false,
    postMessage(message) { attackerMessages.push(message); }
  });
  app.window.__M70_TEST__.onScanSuccess('token-a');

  assert.equal(attackerMessages.length, 0);
  assert.equal(originalMessages.filter((message) => message.type === 'M70_CHECKIN_REQUEST').length, 1);
});

test('queues two different QR codes and never sends a duplicate concurrently', async () => {
  const messages = [];
  const bridgeWindow = { closed: false, postMessage(message, origin) { messages.push({ message, origin }); } };
  const app = createHarness();
  await connectBridge(app, bridgeWindow);

  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-a');
  app.window.__M70_TEST__.onScanSuccess('token-b');
  const firstRequest = messages.find((entry) => entry.message.type === 'M70_CHECKIN_REQUEST');
  assert.equal(firstRequest.message.token, 'token-a');
  assert.equal(messages.filter((entry) => entry.message.type === 'M70_CHECKIN_REQUEST').length, 1);

  app.listeners.get('message')({ origin: BRIDGE_ORIGIN, source: bridgeWindow,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: firstRequest.message.requestId, status: 'checked_in' } });
  const requests = messages.filter((entry) => entry.message.type === 'M70_CHECKIN_REQUEST');
  assert.equal(requests.length, 2);
  assert.equal(requests[1].message.token, 'token-b');
  assert.equal(app.elements.get('confirmedCount').textContent, '1');
});

test('retries an ambiguous failure with the same request id and never confirms it locally', async () => {
  const messages = [];
  const bridgeWindow = { closed: false, postMessage(message) { messages.push(message); } };
  const app = createHarness();
  await connectBridge(app, bridgeWindow);
  app.window.__M70_TEST__.onScanSuccess('token-a');
  const first = messages.find((message) => message.type === 'M70_CHECKIN_REQUEST');

  app.listeners.get('message')({ origin: BRIDGE_ORIGIN, source: bridgeWindow,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: first.requestId, status: 'error', message: 'Сеть недоступна' } });
  assert.equal(app.elements.get('confirmedCount').textContent, '0');
  assert.equal(app.elements.get('retryBtn').hidden, false);

  app.elements.get('retryBtn').handlers.click();
  const requests = messages.filter((message) => message.type === 'M70_CHECKIN_REQUEST');
  assert.equal(requests.length, 2);
  assert.equal(requests[1].requestId, first.requestId);
  app.listeners.get('message')({ origin: BRIDGE_ORIGIN, source: bridgeWindow,
    data: { type: 'M70_CHECKIN_RESULT', channelId: 'trusted-channel',
      requestId: first.requestId, status: 'already_used' } });
  assert.equal(app.elements.get('confirmedCount').textContent, '0');
  assert.match(app.elements.get('result').textContent, /уже использован/);
});

test('expires a bridge session and refuses subsequent check-in requests', async () => {
  const messages = [];
  const bridgeWindow = { closed: false, postMessage(message) { messages.push(message); } };
  const app = createHarness();
  await connectBridge(app, bridgeWindow, { data: { expiresAt: Date.now() + 15 } });
  await new Promise((resolve) => setTimeout(resolve, 25));

  app.window.__M70_TEST__.onScanSuccess('after-expiry');
  assert.match(app.elements.get('mode').textContent, /Тестовый режим/);
  assert.equal(messages.filter((message) => message.type === 'M70_CHECKIN_REQUEST').length, 0);
});

test('keeps photo scanning as a standalone fallback', async () => {
  const app = createHarness();
  const input = app.elements.get('photoInput');
  input.files = [{ name: 'qr.jpg', type: 'image/jpeg' }];
  await input.handlers.change({ target: input });
  assert.equal(app.elements.get('count').textContent, '1');
  assert.match(app.elements.get('result').textContent, /Новый QR-код распознан/);
});

test('rejects an Apps Script parent with an invalid server signature', async () => {
  const bridgeWindow = { closed: false, postMessage() {} };
  const app = createHarness({ bridgeVerified: false });
  await connectBridge(app, bridgeWindow);
  assert.match(app.elements.get('mode').textContent, /Тестовый режим/);
  assert.match(app.elements.get('connectionStatus').textContent, /подлинность/);
});

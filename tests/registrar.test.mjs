import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const html = await readFile(new URL('../apps-script/Registrar.html', import.meta.url), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const SCANNER_ORIGIN = 'https://shkottexas-debug.github.io';
const BRIDGE_ORIGIN = 'https://example-script.googleusercontent.com';

function createHarness() {
  let now = 1000;
  const listeners = new Map();
  const openedUrls = [];
  const postedMessages = [];
  const calls = { createSession: [], checkIn: [] };
  const elements = new Map();
  const scannerWindow = {
    closed: false,
    postMessage(message, origin) { postedMessages.push({ message, origin }); }
  };

  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        textContent: '', className: '', handlers: {},
        addEventListener(type, callback) { this.handlers[type] = callback; }
      });
    }
    return elements.get(id);
  }

  const runner = {
    success: null,
    failure: null,
    withSuccessHandler(callback) { this.success = callback; return this; },
    withFailureHandler(callback) { this.failure = callback; return this; },
    createBridgeSession(channelId, origin) {
      calls.createSession.push({ channelId, origin });
      this.success({
        channelId,
        bridgeOrigin: origin,
        expiresAt: now + 5 * 60 * 1000,
        signature: 'signed-session'
      });
    },
    checkInFromScanner(token, requestId) {
      calls.checkIn.push({ token, requestId });
      this.success({ status: 'checked_in', message: 'Приход отмечен' });
    },
    healthCheck(requestId) { this.success({ ok: true, requestId }); }
  };

  class FakeDate extends Date {
    static now() { return now; }
  }

  const window = {
    location: { origin: BRIDGE_ORIGIN },
    open(url) { openedUrls.push(url); return scannerWindow; },
    addEventListener(type, callback) { listeners.set(type, callback); }
  };
  const document = { getElementById: element };
  vm.runInContext(source, vm.createContext({
    window, document, google: { script: { run: runner } }, crypto: { randomUUID: () => 'channel-1234' },
    Date: FakeDate, Math, Number,
    setInterval: () => 1, clearInterval() {}, setTimeout: () => 2, clearTimeout() {}
  }));

  return {
    elements, listeners, openedUrls, postedMessages, calls, scannerWindow,
    setNow(value) { now = value; }
  };
}

test('opens only the static scanner URL and sends authorization in a signed message', () => {
  const app = createHarness();
  app.elements.get('openScanner').handlers.click();
  assert.deepEqual(app.openedUrls, ['https://shkottexas-debug.github.io/m70-scanner/']);
  assert.equal(app.calls.createSession[0].origin, BRIDGE_ORIGIN);
  const init = app.postedMessages[0];
  assert.equal(init.origin, SCANNER_ORIGIN);
  assert.equal(init.message.type, 'M70_BRIDGE_INIT');
  assert.equal('token' in init.message, false);
});

test('refuses a check-in after bridge expiry and renews without forwarding the token', () => {
  const app = createHarness();
  app.elements.get('openScanner').handlers.click();
  app.setNow(5 * 60 * 1000 + 2000);
  app.listeners.get('message')({
    origin: SCANNER_ORIGIN,
    source: app.scannerWindow,
    data: {
      type: 'M70_CHECKIN_REQUEST', channelId: 'channel-1234',
      requestId: 'request-1234', token: 'secret-ticket-token'
    }
  });

  assert.equal(app.calls.checkIn.length, 0);
  assert.equal(app.calls.createSession.length, 2);
  const response = app.postedMessages.at(-1).message;
  assert.equal(response.status, 'error');
  assert.match(response.message, /истекла/);
});

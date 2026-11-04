import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../scanner.js', import.meta.url), 'utf8');

function createElement(initialText = '') {
  const listeners = new Map();
  return {
    textContent: initialText,
    className: '',
    disabled: false,
    hidden: false,
    value: '',
    files: [],
    addEventListener(type, listener) { listeners.set(type, listener); },
    dispatch(type, event = {}) { return listeners.get(type)?.(event); }
  };
}

function createHarness() {
  const elements = {
    result: createElement('Камера выключена'),
    connectionStatus: createElement('Приложение регистратора не подключено'),
    mode: createElement('Определение режима…'),
    count: createElement('0'),
    confirmedCount: createElement('0'),
    startBtn: createElement(),
    stopBtn: createElement(),
    testBtn: createElement(),
    retryBtn: createElement(),
    photoInput: createElement()
  };
  const documentListeners = new Map();
  const windowListeners = new Map();
  const postedMessages = [];
  const timers = new Map();
  let timerId = 0;
  let requestSequence = 0;
  let now = 1_800_000_000_000;
  const bridgeWindow = {
    closed: false,
    postMessage(message, origin) { postedMessages.push({ message, origin }); }
  };
  const window = {
    location: { hostname: 'localhost', origin: 'https://shkottexas-debug.github.io' },
    crypto: {
      randomUUID: () => `request-${String(++requestSequence).padStart(8, '0')}`,
      subtle: {
        importKey: async () => ({}),
        verify: async () => true
      }
    },
    atob,
    addEventListener(type, listener) { windowListeners.set(type, listener); }
  };
  const navigator = { onLine: true, vibrate() {} };
  class FakeDate extends Date { static now() { return now; } }
  const context = vm.createContext({
    window,
    document: {
      getElementById(id) { return elements[id]; },
      addEventListener(type, listener) { documentListeners.set(type, listener); }
    },
    navigator,
    URL,
    TextEncoder,
    Uint8Array,
    Array,
    Map,
    Set,
    Date: FakeDate,
    Math,
    console,
    setTimeout(callback, delay) {
      timerId += 1;
      timers.set(timerId, { callback, delay });
      return timerId;
    },
    clearTimeout(id) { timers.delete(id); }
  });
  vm.runInContext(source, context, { filename: 'scanner.js' });
  documentListeners.get('DOMContentLoaded')();
  return {
    bridgeWindow,
    elements,
    postedMessages,
    window,
    message(event) { windowListeners.get('message')(event); },
    setOnline(online) {
      navigator.onLine = online;
      windowListeners.get(online ? 'online' : 'offline')();
    },
    advance(milliseconds) { now += milliseconds; },
    now: () => now,
    runTimer(delay) {
      const entry = [...timers.entries()].find(([, timer]) => timer.delay === delay);
      assert.ok(entry, `timer with delay ${delay} must exist`);
      timers.delete(entry[0]);
      entry[1].callback();
    }
  };
}

async function connectBridge(app) {
  const bridgeOrigin = 'https://script.google.com';
  const channelId = 'channel-12345678';
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: {
      type: 'M70_BRIDGE_INIT',
      channelId,
      expiresAt: app.now() + 5 * 60 * 1000,
      bridgeOrigin,
      signature: 'AA=='
    }
  });
  await new Promise(resolve => setImmediate(resolve));
  return { bridgeOrigin, channelId };
}

function checkInRequests(app) {
  return app.postedMessages.filter(entry => entry.message.type === 'M70_CHECKIN_REQUEST');
}

test('bridge renewal preserves the last ticket result', async () => {
  const app = createHarness();
  const { bridgeOrigin, channelId } = await connectBridge(app);
  app.window.__M70_TEST__.onScanSuccess('synthetic-token');
  const request = checkInRequests(app)[0].message;
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: { type: 'M70_CHECKIN_RESULT', channelId, requestId: request.requestId, status: 'checked_in' }
  });
  const resultBeforeRenewal = app.elements.result.textContent;
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: {
      type: 'M70_BRIDGE_INIT', channelId,
      expiresAt: app.now() + 330_000, bridgeOrigin, signature: 'AA=='
    }
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(app.elements.result.textContent, resultBeforeRenewal);
  assert.equal(app.elements.confirmedCount.textContent, '1');
});

test('network recovery and a QR remaining in frame never resend automatically', async () => {
  const app = createHarness();
  await connectBridge(app);
  app.window.__M70_TEST__.onScanSuccess('in-flight-token');
  const first = checkInRequests(app)[0].message;
  app.setOnline(false);
  app.setOnline(true);
  for (let index = 0; index < 3; index += 1) {
    app.advance(2000);
    app.window.__M70_TEST__.onScanSuccess('in-flight-token');
  }
  assert.equal(checkInRequests(app).length, 1);
  assert.match(app.elements.result.textContent, /Повторить отправку/);

  app.elements.retryBtn.dispatch('click');
  const requests = checkInRequests(app);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].message.requestId, first.requestId);
});

test('15 second timeout allows only an explicit retry with the same request id', async () => {
  const app = createHarness();
  await connectBridge(app);
  app.window.__M70_TEST__.onScanSuccess('timeout-token');
  const first = checkInRequests(app)[0].message;
  app.runTimer(15_000);
  assert.equal(app.elements.confirmedCount.textContent, '0');
  assert.equal(app.elements.retryBtn.hidden, false);
  assert.match(app.elements.result.textContent, /Сервер не ответил/);
  app.elements.retryBtn.dispatch('click');
  assert.equal(checkInRequests(app)[1].message.requestId, first.requestId);
});

test('late checked_in is accepted once and removes a queued retry', async () => {
  const app = createHarness();
  const { bridgeOrigin, channelId } = await connectBridge(app);
  app.window.__M70_TEST__.onScanSuccess('late-token');
  const original = checkInRequests(app)[0].message;
  app.setOnline(false);
  app.setOnline(true);
  app.elements.testBtn.dispatch('click');
  const testRequest = app.postedMessages.find(entry => entry.message.type === 'M70_TEST_REQUEST').message;
  app.elements.retryBtn.dispatch('click');
  assert.equal(checkInRequests(app).length, 1);

  const lateResult = {
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: {
      type: 'M70_CHECKIN_RESULT', channelId,
      requestId: original.requestId, status: 'checked_in'
    }
  };
  app.message(lateResult);
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: { type: 'M70_TEST_RESULT', channelId, requestId: testRequest.requestId, ok: true }
  });
  app.message(lateResult);
  assert.equal(checkInRequests(app).length, 1);
  assert.equal(app.elements.confirmedCount.textContent, '1');
});

test('a ticket first seen offline waits for manual action after recovery', async () => {
  const app = createHarness();
  await connectBridge(app);
  app.setOnline(false);
  app.window.__M70_TEST__.onScanSuccess('offline-token');
  assert.equal(checkInRequests(app).length, 0);
  app.setOnline(true);
  assert.equal(checkInRequests(app).length, 0);
  app.elements.testBtn.dispatch('click');
  assert.equal(
    app.postedMessages.filter(entry => entry.message.type === 'M70_TEST_REQUEST').length,
    1
  );
});

test('unknown late responses and server errors never confirm attendance', async () => {
  const app = createHarness();
  const { bridgeOrigin, channelId } = await connectBridge(app);
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: {
      type: 'M70_CHECKIN_RESULT', channelId,
      requestId: 'unknown-request-id', status: 'checked_in'
    }
  });
  assert.equal(app.elements.confirmedCount.textContent, '0');

  app.window.__M70_TEST__.onScanSuccess('server-error-token');
  const request = checkInRequests(app)[0].message;
  app.message({
    origin: bridgeOrigin,
    source: app.bridgeWindow,
    data: {
      type: 'M70_CHECKIN_RESULT', channelId,
      requestId: request.requestId, status: 'error', message: 'Сервер недоступен'
    }
  });
  assert.equal(app.elements.confirmedCount.textContent, '0');
  assert.equal(app.elements.retryBtn.hidden, false);
});

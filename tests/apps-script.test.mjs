import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../apps-script/Code.gs', import.meta.url), 'utf8');

function createHarness(rows = []) {
  const state = {
    rows: rows.map((row) => ({ ...row })), writes: 0, flushes: 0,
    lockWaits: 0, lockReleases: 0, signedPayload: null
  };
  let locked = false;
  const properties = {
    SPREADSHEET_ID: 'spreadsheet-id', SHEET_NAME: 'Участники',
    REGISTRAR_EMAILS: 'registrar@example.com', CHECKED_IN_STATUS: 'Пришёл',
    BRIDGE_PRIVATE_KEY: 'test-private-key'
  };

  function range(row, column, rowCount = 1, columnCount = 1) {
    return {
      getDisplayValues() {
        assert.equal(column, 6);
        return state.rows.slice(row - 2, row - 2 + rowCount).map((item) => [item.token]);
      },
      getDisplayValue() { assert.equal(column, 4); return state.rows[row - 2].status; },
      getValue() { assert.equal(column, 5); return state.rows[row - 2].arrival || ''; },
      setValues(values) {
        assert.equal(column, 4);
        assert.equal(columnCount, 2);
        state.rows[row - 2].status = values[0][0];
        state.rows[row - 2].arrival = values[0][1];
        state.writes += 1;
      }
    };
  }

  const context = vm.createContext({
    console, Date,
    Session: { getActiveUser: () => ({ getEmail: () => 'registrar@example.com' }) },
    PropertiesService: {
      getScriptProperties: () => ({ getProperty: (name) => properties[name] || '' })
    },
    LockService: {
      getScriptLock: () => ({
        waitLock() { state.lockWaits += 1; locked = true; },
        hasLock() { return locked; },
        releaseLock() { state.lockReleases += 1; locked = false; }
      })
    },
    SpreadsheetApp: {
      openById: () => ({
        getSheetByName: () => ({
          getLastRow: () => state.rows.length + 1,
          getRange: range
        })
      }),
      flush() { state.flushes += 1; }
    },
    Utilities: {
      getUuid: () => '12345678-1234-1234-1234-123456789012',
      computeRsaSha256Signature(payload) { state.signedPayload = payload; return [1, 2, 3]; },
      base64Encode: () => 'AQID'
    }
  });
  vm.runInContext(source, context);
  return { context, state };
}

for (const status of ['Зарегистрирован', 'Подтвердил']) {
  test(`allows an eligible ticket with status ${status}`, () => {
    const app = createHarness([{ token: 'token-a', status, arrival: '' }]);
    const result = app.context.checkInFromScanner('token-a', 'request-1234');
    assert.equal(result.status, 'checked_in');
    assert.equal(app.state.rows[0].status, 'Пришёл');
    assert.equal(app.state.writes, 1);
  });
}

test('rejects a cancelled ticket without changing the sheet', () => {
  const app = createHarness([{ token: 'token-a', status: 'Отменён', arrival: '' }]);
  const result = app.context.checkInFromScanner('token-a', 'request-1234');
  assert.equal(result.status, 'cancelled');
  assert.equal(app.state.rows[0].status, 'Отменён');
  assert.equal(app.state.writes, 0);
});

test('rejects a blocked ticket without changing the sheet', () => {
  const app = createHarness([{ token: 'token-a', status: 'Заблокирован', arrival: '' }]);
  const result = app.context.checkInFromScanner('token-a', 'request-1234');
  assert.equal(result.status, 'blocked');
  assert.equal(app.state.rows[0].status, 'Заблокирован');
  assert.equal(app.state.writes, 0);
});

test('rejects every other source status without changing the sheet', () => {
  const app = createHarness([{ token: 'token-a', status: 'Ожидает оплаты', arrival: '' }]);
  const result = app.context.checkInFromScanner('token-a', 'request-1234');
  assert.equal(result.status, 'not_eligible');
  assert.equal(app.state.writes, 0);
});

test('returns already_used on repeat and writes exactly once', () => {
  const app = createHarness([{ token: 'token-a', status: 'Зарегистрирован', arrival: '' }]);
  const first = app.context.checkInFromScanner('token-a', 'request-1234');
  const second = app.context.checkInFromScanner('token-a', 'request-5678');
  assert.equal(first.status, 'checked_in');
  assert.equal(second.status, 'already_used');
  assert.equal(app.state.writes, 1);
});

test('serializes two device requests through the script lock', () => {
  const app = createHarness([{ token: 'token-a', status: 'Подтвердил', arrival: '' }]);
  const deviceA = app.context.checkInFromScanner('token-a', 'device-a-1234');
  const deviceB = app.context.checkInFromScanner('token-a', 'device-b-1234');
  assert.deepEqual([deviceA.status, deviceB.status], ['checked_in', 'already_used']);
  assert.equal(app.state.writes, 1);
  assert.equal(app.state.lockWaits, 2);
  assert.equal(app.state.lockReleases, 2);
});

test('issues a short-lived session bound to channel, scanner and Apps Script origin', () => {
  const app = createHarness();
  const before = Date.now();
  const session = app.context.createBridgeSession(
    'channel-1234', 'https://example-script.googleusercontent.com'
  );
  assert.equal(session.bridgeOrigin, 'https://example-script.googleusercontent.com');
  assert.ok(session.expiresAt > before);
  assert.ok(session.expiresAt <= before + 5 * 60 * 1000 + 50);
  assert.equal(app.state.signedPayload,
    `channel-1234\n${session.expiresAt}\nhttps://shkottexas-debug.github.io\nhttps://example-script.googleusercontent.com`);
});

test('refuses to sign a session for an attacker origin', () => {
  const app = createHarness();
  assert.throws(() => app.context.createBridgeSession('channel-1234', 'https://attacker.example'),
    /origin/);
});

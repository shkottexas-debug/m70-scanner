/**
 * Серверная часть приложения регистратора М70.
 *
 * Script Properties:
 *   SPREADSHEET_ID, SHEET_NAME, REGISTRAR_EMAILS,
 *   BRIDGE_PRIVATE_KEY,
 *   CHECKED_IN_STATUS (необязательно, по умолчанию "Пришёл").
 */
const TOKEN_COLUMN = 6;       // F
const STATUS_COLUMN = 4;      // D
const ARRIVAL_COLUMN = 5;     // E
const FIRST_DATA_ROW = 2;
const LOCK_TIMEOUT_MS = 10000;
const SCANNER_ORIGIN = 'https://shkottexas-debug.github.io';
const BRIDGE_SESSION_TTL_MS = 5 * 60 * 1000;

function doGet() {
  assertAuthorizedRegistrar_();
  return HtmlService.createHtmlOutputFromFile('Registrar')
    .setTitle('М70 — регистрация')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/** Сохраняет совместимость с существующей регистрацией по фотографии. */
function checkIn(token) {
  assertAuthorizedRegistrar_();
  return checkIn_(token, 'photo-' + Utilities.getUuid());
}

/** Вызывается из авторизованной HTML-страницы через google.script.run. */
function checkInFromScanner(token, requestId) {
  assertAuthorizedRegistrar_();
  validateRequestId_(requestId);
  return checkIn_(token, requestId);
}

function healthCheck(requestId) {
  assertAuthorizedRegistrar_();
  validateRequestId_(requestId);
  return { ok: true, requestId: requestId };
}

function createBridgeSession(channelId) {
  assertAuthorizedRegistrar_();
  validateRequestId_(channelId);
  const privateKey = String(
    PropertiesService.getScriptProperties().getProperty('BRIDGE_PRIVATE_KEY') || ''
  ).trim();
  if (!privateKey) throw new Error('Не задан приватный ключ bridge-сессии.');
  const expiresAt = Date.now() + BRIDGE_SESSION_TTL_MS;
  const payload = channelId + '\n' + expiresAt + '\n' + SCANNER_ORIGIN;
  const signature = Utilities.computeRsaSha256Signature(payload, privateKey);
  return {
    channelId: channelId,
    expiresAt: expiresAt,
    signature: Utilities.base64Encode(signature)
  };
}

function checkIn_(rawToken, requestId) {
  const token = normalizeToken_(rawToken);
  const config = getConfig_();
  const lock = LockService.getScriptLock();

  try {
    lock.waitLock(LOCK_TIMEOUT_MS);
    const sheet = SpreadsheetApp.openById(config.spreadsheetId).getSheetByName(config.sheetName);
    if (!sheet) throw new Error('Лист регистрации не найден.');

    const lastRow = sheet.getLastRow();
    if (lastRow < FIRST_DATA_ROW) return response_('not_found', 'Билет не найден', requestId);

    const rowCount = lastRow - FIRST_DATA_ROW + 1;
    const tokenValues = sheet.getRange(FIRST_DATA_ROW, TOKEN_COLUMN, rowCount, 1).getDisplayValues();
    const tokenOffset = tokenValues.findIndex(function (row) {
      return String(row[0]).trim() === token;
    });
    if (tokenOffset === -1) return response_('not_found', 'Билет не найден', requestId);

    const rowNumber = FIRST_DATA_ROW + tokenOffset;
    const status = String(sheet.getRange(rowNumber, STATUS_COLUMN).getDisplayValue()).trim();
    const arrivalTime = sheet.getRange(rowNumber, ARRIVAL_COLUMN).getValue();

    // Время — основной признак использования. Статус нужен для совместимости,
    // если время было очищено вручную.
    if (arrivalTime || status === config.checkedInStatus) {
      return response_('already_used', 'Билет уже использован', requestId);
    }

    sheet.getRange(rowNumber, STATUS_COLUMN, 1, 2)
      .setValues([[config.checkedInStatus, new Date()]]);
    SpreadsheetApp.flush();
    return response_('checked_in', 'Приход отмечен', requestId);
  } catch (error) {
    // Никогда не записываем token в журналы и ответы.
    if (error && /lock/i.test(String(error.message))) {
      throw new Error('Сервер занят. Повторите попытку.');
    }
    throw error;
  } finally {
    if (lock.hasLock()) lock.releaseLock();
  }
}

function assertAuthorizedRegistrar_() {
  const email = String(Session.getActiveUser().getEmail() || '').trim().toLowerCase();
  const rawAllowed = PropertiesService.getScriptProperties().getProperty('REGISTRAR_EMAILS');
  const allowed = String(rawAllowed || '')
    .split(',')
    .map(function (item) { return item.trim().toLowerCase(); })
    .filter(String);
  if (!email || allowed.indexOf(email) === -1) {
    throw new Error('Доступ разрешён только авторизованным регистраторам.');
  }
}

function getConfig_() {
  const properties = PropertiesService.getScriptProperties();
  const spreadsheetId = String(properties.getProperty('SPREADSHEET_ID') || '').trim();
  const sheetName = String(properties.getProperty('SHEET_NAME') || '').trim();
  const checkedInStatus = String(properties.getProperty('CHECKED_IN_STATUS') || 'Пришёл').trim();
  if (!spreadsheetId || !sheetName || !checkedInStatus) {
    throw new Error('Не заполнены Script Properties приложения регистрации.');
  }
  return { spreadsheetId: spreadsheetId, sheetName: sheetName, checkedInStatus: checkedInStatus };
}

function normalizeToken_(rawToken) {
  if (typeof rawToken !== 'string') throw new Error('Некорректный QR-код.');
  const token = rawToken.trim();
  if (!token || token.length > 512 || /[\r\n\u0000]/.test(token)) {
    throw new Error('Некорректный QR-код.');
  }
  return token;
}

function validateRequestId_(requestId) {
  if (typeof requestId !== 'string' || requestId.length < 8 || requestId.length > 100 ||
      !/^[a-zA-Z0-9-]+$/.test(requestId)) {
    throw new Error('Некорректный идентификатор запроса.');
  }
}

function response_(status, message, requestId) {
  return { status: status, message: message, requestId: requestId };
}

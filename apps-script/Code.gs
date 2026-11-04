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
const ELIGIBLE_STATUSES = ['Зарегистрирован'];

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

/**
 * Безопасная ручная проверка настоящего билета без отметки прихода.
 * Возвращает только категорию результата и не раскрывает ID, ФИО, email,
 * QR-токен или исходное значение статуса.
 */
function validateTicketWithoutCheckIn(token) {
  assertAuthorizedRegistrar_();
  const normalizedToken = normalizeToken_(token);
  const config = getConfig_();
  const sheet = SpreadsheetApp.openById(config.spreadsheetId).getSheetByName(config.sheetName);
  if (!sheet) throw new Error('Лист регистрации не найден.');

  const lastRow = sheet.getLastRow();
  if (lastRow < FIRST_DATA_ROW) return { status: 'not_found', eligible: false };
  const rowCount = lastRow - FIRST_DATA_ROW + 1;
  const tokenValues = sheet.getRange(FIRST_DATA_ROW, TOKEN_COLUMN, rowCount, 1).getDisplayValues();
  const tokenOffset = tokenValues.findIndex(function (row) {
    return String(row[0]).trim() === normalizedToken;
  });
  if (tokenOffset === -1) return { status: 'not_found', eligible: false };

  const rowNumber = FIRST_DATA_ROW + tokenOffset;
  const status = String(sheet.getRange(rowNumber, STATUS_COLUMN).getDisplayValue()).trim();
  const arrivalTime = sheet.getRange(rowNumber, ARRIVAL_COLUMN).getValue();
  if (arrivalTime || status === config.checkedInStatus) {
    return { status: 'already_used', eligible: false };
  }
  const eligibility = classifyEligibility_(status);
  return {
    status: eligibility === 'eligible' ? 'eligible' : eligibility,
    eligible: eligibility === 'eligible'
  };
}

/**
 * Одноразовый запуск проверки из редактора без помещения токена в исходный код
 * или параметры CLI. Владелец временно задаёт Script Property
 * VALIDATION_TICKET_TOKEN; функция удаляет его даже при ошибке.
 */
function validateConfiguredTicketWithoutCheckIn() {
  assertAuthorizedRegistrar_();
  const properties = PropertiesService.getScriptProperties();
  const token = properties.getProperty('VALIDATION_TICKET_TOKEN');
  if (!token) throw new Error('Не задан токен для безопасной проверки.');
  try {
    return validateTicketWithoutCheckIn(token);
  } finally {
    properties.deleteProperty('VALIDATION_TICKET_TOKEN');
  }
}

function createBridgeSession(channelId, bridgeOrigin) {
  assertAuthorizedRegistrar_();
  validateRequestId_(channelId);
  validateBridgeOrigin_(bridgeOrigin);
  const privateKey = String(
    PropertiesService.getScriptProperties().getProperty('BRIDGE_PRIVATE_KEY') || ''
  ).trim();
  if (!privateKey) throw new Error('Не задан приватный ключ bridge-сессии.');
  const expiresAt = Date.now() + BRIDGE_SESSION_TTL_MS;
  const payload = channelId + '\n' + expiresAt + '\n' + SCANNER_ORIGIN + '\n' + bridgeOrigin;
  const signature = Utilities.computeRsaSha256Signature(payload, privateKey);
  return {
    channelId: channelId,
    expiresAt: expiresAt,
    bridgeOrigin: bridgeOrigin,
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

    const eligibility = classifyEligibility_(status);
    if (eligibility === 'cancelled') {
      return response_('cancelled', 'Билет отменён. Проход запрещён.', requestId);
    }
    if (eligibility === 'blocked') {
      return response_('blocked', 'Билет заблокирован. Проход запрещён.', requestId);
    }
    if (eligibility !== 'eligible') {
      return response_(
        'not_eligible',
        'Текущий статус билета не разрешает проход.',
        requestId
      );
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

function validateBridgeOrigin_(bridgeOrigin) {
  if (typeof bridgeOrigin !== 'string' ||
      !/^https:\/\/(?:script\.google\.com|[a-z0-9-]+\.googleusercontent\.com)$/.test(bridgeOrigin)) {
    throw new Error('Некорректный origin приложения регистратора.');
  }
}

function normalizeStatus_(status) {
  return String(status || '').trim().toLocaleLowerCase('ru-RU').replace(/ё/g, 'е');
}

function classifyEligibility_(status) {
  const normalized = normalizeStatus_(status);
  const eligible = ELIGIBLE_STATUSES.map(normalizeStatus_);
  if (eligible.indexOf(normalized) !== -1) return 'eligible';
  if (/^(отмен|аннулир)/.test(normalized)) return 'cancelled';
  if (/^(заблок|блокир)/.test(normalized)) return 'blocked';
  return 'not_eligible';
}

function response_(status, message, requestId) {
  return { status: status, message: message, requestId: requestId };
}

(function () {
  'use strict';

  const REQUEST_TIMEOUT_MS = 15000;
  const BRIDGE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkAkoJI3L+Xa8yAMyYSe
c441cGIEj0HC+bHEJNXXN57+TMGA0um4VhKkD77Hkq9SDvDwgsBgC6Ucf3Jg2WyD
44ovH1CK/7biBQZSJRlffaXWRVohPdsvX+h/RoCC7mLwR7B2OjNx8hQ5R/7Oh1Oe
hUWEBbt7oCaAY+p4n6JEk5owfiNxCiS0fTHqbLFIcEnVhJuLB8DsPvKaHEQaP1QF
W07bm700j/uCqOtmowtzOOMLWu8eFMNpzZwrkFgzqxQlUTVrkywMoGRII89hPz6g
dneyNyf2YdHpnA1JtronTUxwqHmqDG0QwlZtx1JNmF3jPeftvZgt+Ff3c9oj+oyi
0QIDAQAB
-----END PUBLIC KEY-----`;
  let scanner = null;
  let running = false;
  let cameraOperation = false;
  let bridgeWindow = null;
  let bridgeOrigin = null;
  let bridgeChannelId = null;
  let bridgeExpiresAt = 0;
  let bridgeConnected = false;
  let bridgeExpiryTimer = null;
  let currentRequest = null;
  let retryToken = null;
  let confirmedCount = 0;
  let networkOnline = navigator.onLine !== false;
  const scannedTokens = new Set();
  const tokenStates = new Map();
  const tokenRequestIds = new Map();
  const pendingTokens = [];
  const elements = {};
  let importedBridgeKey = null;

  function showResult(message, type = '') {
    elements.result.textContent = message;
    elements.result.className = type;
  }

  function showConnectionStatus(message, type = '') {
    elements.connectionStatus.textContent = message;
    elements.connectionStatus.className = `connection-status${type ? ` ${type}` : ''}`;
  }

  function errorMessage(error, fallback) {
    if (error && typeof error.message === 'string' && error.message.trim()) return error.message.trim();
    if (typeof error === 'string' && error.trim()) return error.trim();
    return fallback;
  }

  function createRequestId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    return `m70-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  function setMode() {
    elements.mode.textContent = isBridgeActive()
      ? 'Авторизованный режим · отметка прихода включена'
      : 'Тестовый режим · запись в таблицу отключена';
  }

  function isBridgeActive() {
    return bridgeConnected && Date.now() < bridgeExpiresAt;
  }

  function expireBridgeSession() {
    bridgeConnected = false;
    if (bridgeExpiryTimer) clearTimeout(bridgeExpiryTimer);
    bridgeExpiryTimer = null;
    setMode();
    showConnectionStatus('Сессия регистратора истекла. Ожидаем безопасное продление…', 'warning');
  }

  function postToBridge(message) {
    if (!networkOnline) return false;
    if (!isBridgeActive()) {
      if (bridgeConnected) expireBridgeSession();
      return false;
    }
    if (!bridgeWindow || !bridgeOrigin || bridgeWindow.closed) return false;
    bridgeWindow.postMessage(message, bridgeOrigin);
    return true;
  }

  function decodeBase64(value) {
    const binary = window.atob(value);
    return Uint8Array.from(binary, function (character) { return character.charCodeAt(0); });
  }

  async function getBridgePublicKey() {
    if (importedBridgeKey) return importedBridgeKey;
    const keyBytes = decodeBase64(
      BRIDGE_PUBLIC_KEY_PEM.replace(/-----[^-]+-----|\s/g, '')
    );
    importedBridgeKey = await window.crypto.subtle.importKey(
      'spki',
      keyBytes,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return importedBridgeKey;
  }

  function isAllowedBridgeOrigin(origin) {
    try {
      const parsed = new URL(origin);
      return parsed.protocol === 'https:' &&
        (parsed.hostname === 'script.google.com' || parsed.hostname.endsWith('.googleusercontent.com'));
    } catch (_error) {
      return false;
    }
  }

  async function verifyBridgeSession(data, eventOrigin) {
    if (typeof data.channelId !== 'string' || typeof data.signature !== 'string' ||
        !Number.isSafeInteger(data.expiresAt) || data.bridgeOrigin !== eventOrigin ||
        !isAllowedBridgeOrigin(eventOrigin)) return false;
    const now = Date.now();
    if (data.expiresAt <= now || data.expiresAt > now + 10 * 60 * 1000) return false;
    if (!window.crypto || !window.crypto.subtle) return false;
    const payload = `${data.channelId}\n${data.expiresAt}\n${window.location.origin}\n${eventOrigin}`;
    try {
      return await window.crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        await getBridgePublicKey(),
        decodeBase64(data.signature),
        new TextEncoder().encode(payload)
      );
    } catch (_error) {
      return false;
    }
  }

  async function acceptBridgeSession(data, event) {
    if (!await verifyBridgeSession(data, event.origin)) {
      // Недоверенное окно не должно сбрасывать уже проверенную сессию.
      if (!isBridgeActive()) {
        setMode();
        showConnectionStatus('Не удалось подтвердить подлинность приложения регистратора.', 'error');
      }
      return;
    }
    if (bridgeChannelId && (data.channelId !== bridgeChannelId ||
        event.source !== bridgeWindow || event.origin !== bridgeOrigin)) return;
    bridgeWindow = event.source;
    bridgeOrigin = event.origin;
    bridgeChannelId = data.channelId;
    bridgeExpiresAt = data.expiresAt;
    bridgeConnected = true;
    if (bridgeExpiryTimer) clearTimeout(bridgeExpiryTimer);
    bridgeExpiryTimer = setTimeout(expireBridgeSession, Math.max(0, bridgeExpiresAt - Date.now()));
    setMode();
    postToBridge({ type: 'M70_SCANNER_CONNECTED', channelId: bridgeChannelId });
    showConnectionStatus('Связь с приложением регистратора установлена.', 'success');
    pumpQueue();
  }

  function onBridgeMessage(event) {
    const data = event.data;
    if (!data || typeof data !== 'object') return;

    if (data.type === 'M70_BRIDGE_INIT') {
      acceptBridgeSession(data, event);
      return;
    }
    if (!bridgeOrigin || event.origin !== bridgeOrigin || event.source !== bridgeWindow) return;
    if (data.channelId !== bridgeChannelId) return;

    if (data.type === 'M70_TEST_RESULT') {
      if (currentRequest && currentRequest.kind === 'test' && data.requestId === currentRequest.requestId) {
        clearTimeout(currentRequest.timeoutId);
        currentRequest = null;
        elements.testBtn.disabled = false;
        showConnectionStatus(
          data.ok ? '✓ Связь с Google Apps Script работает. Регистратор авторизован.' : `Ошибка проверки связи: ${data.message || 'сервер недоступен'}`,
          data.ok ? 'success' : 'error'
        );
        pumpQueue();
      }
      return;
    }
    if (data.type === 'M70_CHECKIN_RESULT') handleCheckInResult(data);
  }

  function updateRecognizedCount() {
    elements.count.textContent = String(scannedTokens.size);
  }

  function onScanSuccess(decodedText) {
    const token = typeof decodedText === 'string' ? decodedText.trim() : '';
    if (!token) return showResult('QR-код пуст или повреждён.', 'error');
    if (scannedTokens.has(token)) {
      const state = tokenStates.get(token);
      if (state === 'checked_in') showResult('Билет уже отмечен в этой сессии', 'warning');
      if (state === 'already_used') showResult('Билет уже использован', 'warning');
      if (state === 'failed') {
        showResult('Билет ожидает ручного повтора. Нажмите «Повторить отправку».', 'warning');
      }
      return;
    }

    scannedTokens.add(token);
    tokenStates.set(token, isBridgeActive() ? (networkOnline ? 'queued' : 'failed') : 'test_only');
    updateRecognizedCount();
    if (navigator.vibrate) navigator.vibrate(100);

    if (!isBridgeActive()) {
      showResult(`✓ Новый QR-код распознан\nУникальных QR: ${scannedTokens.size}\nТестовый режим: отметка прихода не отправлена.`, 'success');
      return;
    }
    if (!networkOnline) {
      tokenRequestIds.set(token, createRequestId());
      retryToken = token;
      elements.retryBtn.hidden = false;
      showResult('Нет сети. Приход не подтверждён. После восстановления связи повторите проверку вручную.', 'error');
      return;
    }
    pendingTokens.push(token);
    showResult('QR-код распознан. Проверяем билет…');
    pumpQueue();
  }

  function pumpQueue() {
    if (!networkOnline || !isBridgeActive() || currentRequest || pendingTokens.length === 0) return;
    const token = pendingTokens.shift();
    const requestId = tokenRequestIds.get(token) || createRequestId();
    tokenRequestIds.set(token, requestId);
    tokenStates.set(token, 'pending');
    const timeoutId = setTimeout(function () {
      if (!currentRequest || currentRequest.requestId !== requestId) return;
      currentRequest = null;
      tokenStates.set(token, 'failed');
      retryToken = token;
      elements.retryBtn.hidden = false;
      showResult('Сервер не ответил. Приход не подтверждён. Проверьте сеть и нажмите «Повторить отправку».', 'error');
    }, REQUEST_TIMEOUT_MS);
    currentRequest = { kind: 'checkin', requestId, token, timeoutId };
    if (!postToBridge({ type: 'M70_CHECKIN_REQUEST', channelId: bridgeChannelId, requestId, token })) {
      clearTimeout(timeoutId);
      currentRequest = null;
      tokenStates.set(token, 'failed');
      retryToken = token;
      elements.retryBtn.hidden = false;
      showResult('Связь с приложением регистратора потеряна. Приход не подтверждён.', 'error');
    }
  }

  function handleCheckInResult(data) {
    const activeRequest = currentRequest && currentRequest.kind === 'checkin' &&
      data.requestId === currentRequest.requestId ? currentRequest : null;
    const token = activeRequest ? activeRequest.token : findRetryableTokenByRequestId_(data.requestId);
    if (!token) return;
    if (activeRequest) {
      clearTimeout(activeRequest.timeoutId);
      currentRequest = null;
    } else {
      removePendingToken_(token);
    }
    if (data.status === 'checked_in') {
      tokenStates.set(token, 'checked_in');
      tokenRequestIds.delete(token);
      confirmedCount += 1;
      elements.confirmedCount.textContent = String(confirmedCount);
      retryToken = null;
      elements.retryBtn.hidden = true;
      showResult('✓ Приход отмечен\nСканирование продолжается', 'success');
    } else if (data.status === 'already_used') {
      tokenStates.set(token, 'already_used');
      tokenRequestIds.delete(token);
      retryToken = null;
      elements.retryBtn.hidden = true;
      showResult('Билет уже использован', 'warning');
    } else if (['cancelled', 'blocked', 'not_eligible', 'not_found'].includes(data.status)) {
      tokenStates.set(token, data.status);
      tokenRequestIds.delete(token);
      retryToken = null;
      elements.retryBtn.hidden = true;
      showResult(data.message || 'Проход по этому билету запрещён.', 'error');
    } else {
      tokenStates.set(token, 'failed');
      retryToken = token;
      elements.retryBtn.hidden = false;
      showResult(`Ошибка: ${data.message || 'приход не подтверждён'}`, 'error');
    }
    if (activeRequest && tokenStates.get(token) !== 'failed') pumpQueue();
  }

  function findRetryableTokenByRequestId_(requestId) {
    for (const entry of tokenRequestIds.entries()) {
      const state = tokenStates.get(entry[0]);
      if (entry[1] === requestId && (state === 'failed' || state === 'queued')) return entry[0];
    }
    return null;
  }

  function removePendingToken_(token) {
    for (let index = pendingTokens.length - 1; index >= 0; index -= 1) {
      if (pendingTokens[index] === token) pendingTokens.splice(index, 1);
    }
  }

  function retryFailedToken(token = retryToken) {
    if (!token || tokenStates.get(token) !== 'failed') return;
    if (!networkOnline) {
      showResult('Нет сети. Приход не подтверждён. Повторите проверку после восстановления связи.', 'error');
      return;
    }
    if (!isBridgeActive()) {
      showResult('Сессия регистратора недоступна. Дождитесь безопасного переподключения.', 'error');
      return;
    }
    tokenStates.set(token, 'queued');
    pendingTokens.push(token);
    retryToken = null;
    elements.retryBtn.hidden = true;
    showResult('Повторная проверка билета…');
    pumpQueue();
  }

  function failCurrentRequestOffline_() {
    if (!currentRequest) return;
    const request = currentRequest;
    clearTimeout(request.timeoutId);
    currentRequest = null;
    if (request.kind === 'checkin') {
      tokenStates.set(request.token, 'failed');
      retryToken = request.token;
      elements.retryBtn.hidden = false;
      showResult('Соединение потеряно. Приход не подтверждён. После восстановления сети повторите проверку вручную.', 'error');
    } else {
      elements.testBtn.disabled = false;
    }
  }

  function failQueuedTokensOffline_() {
    while (pendingTokens.length > 0) {
      const token = pendingTokens.shift();
      if (tokenStates.get(token) !== 'queued') continue;
      tokenStates.set(token, 'failed');
      if (!tokenRequestIds.has(token)) tokenRequestIds.set(token, createRequestId());
      if (!retryToken) retryToken = token;
      elements.retryBtn.hidden = false;
    }
  }

  function handleOffline() {
    networkOnline = false;
    showConnectionStatus('Нет сети. Ожидающие проверки остановлены.', 'warning');
    failCurrentRequestOffline_();
    failQueuedTokensOffline_();
  }

  function handleOnline() {
    networkOnline = true;
    showConnectionStatus('Сеть восстановлена. Проверьте связь или повторите отправку вручную.', 'success');
    // Восстановление сети никогда не отправляет билет автоматически.
  }

  function qrBoxSize(width, height) {
    const size = Math.min(250, width * 0.75, height * 0.75);
    return { width: Math.floor(size), height: Math.floor(size) };
  }

  async function startScanner(options = {}) {
    if (running || cameraOperation) return;
    if (typeof window.Html5Qrcode === 'undefined') return showResult('Библиотека сканирования не загрузилась. Проверьте интернет и обновите страницу.', 'error');
    cameraOperation = true;
    elements.startBtn.disabled = true;
    try {
      scanner = new window.Html5Qrcode('reader');
      await scanner.start(
        { facingMode: 'environment' },
        { fps: 10, qrbox: qrBoxSize },
        onScanSuccess,
        function () { /* Отсутствие QR в кадре — нормальное состояние. */ }
      );
      running = true;
      elements.stopBtn.disabled = false;
      if (!options.quiet) showResult('Камера работает. Наведите на QR-код.');
    } catch (error) {
      scanner = null;
      elements.startBtn.disabled = false;
      showResult(`Не удалось открыть камеру: ${errorMessage(error, 'проверьте разрешение камеры и HTTPS')}`, 'error');
    } finally {
      cameraOperation = false;
    }
  }

  async function stopScanner(options = {}) {
    if (!scanner || !running || cameraOperation) return;
    cameraOperation = true;
    try {
      await scanner.stop();
      scanner.clear();
      scanner = null;
      running = false;
      elements.startBtn.disabled = false;
      elements.stopBtn.disabled = true;
      if (!options.quiet) showResult('Камера остановлена');
    } catch (error) {
      showResult(`Ошибка остановки камеры: ${errorMessage(error, 'неизвестная ошибка')}`, 'error');
    } finally {
      cameraOperation = false;
    }
  }

  async function scanPhoto(event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = '';
    if (!file || cameraOperation) return;
    if (typeof window.Html5Qrcode === 'undefined') {
      showResult('Библиотека сканирования не загрузилась. Проверьте интернет и обновите страницу.', 'error');
      return;
    }
    const restartCamera = running;
    if (restartCamera) await stopScanner({ quiet: true });
    cameraOperation = true;
    try {
      scanner = new window.Html5Qrcode('reader');
      const decodedText = await scanner.scanFile(file, true);
      scanner.clear();
      scanner = null;
      onScanSuccess(decodedText);
    } catch (error) {
      if (scanner) scanner.clear();
      scanner = null;
      showResult(`Не удалось распознать QR на фотографии: ${errorMessage(error, 'выберите более чёткое изображение')}`, 'error');
    } finally {
      cameraOperation = false;
      if (restartCamera) await startScanner({ quiet: true });
    }
  }

  function testConnection() {
    if (!networkOnline) return showConnectionStatus('Нет сети. Проверка авторизации недоступна.', 'error');
    if (!isBridgeActive()) return showConnectionStatus('Нет активной авторизованной связи. Откройте сканер кнопкой из приложения регистратора Apps Script.', 'error');
    if (currentRequest) return showConnectionStatus('Дождитесь завершения текущей проверки билета.', 'warning');
    const requestId = createRequestId();
    elements.testBtn.disabled = true;
    const timeoutId = setTimeout(function () {
      if (!currentRequest || currentRequest.requestId !== requestId) return;
      currentRequest = null;
      elements.testBtn.disabled = false;
      showConnectionStatus('Google Apps Script не ответил. Проверьте сеть и авторизацию.', 'error');
      pumpQueue();
    }, REQUEST_TIMEOUT_MS);
    currentRequest = { kind: 'test', requestId, timeoutId };
    if (!postToBridge({ type: 'M70_TEST_REQUEST', channelId: bridgeChannelId, requestId })) {
      clearTimeout(timeoutId);
      currentRequest = null;
      elements.testBtn.disabled = false;
      showConnectionStatus('Связь с приложением регистратора потеряна.', 'error');
    }
  }

  function init() {
    ['result', 'connectionStatus', 'mode', 'count', 'confirmedCount', 'startBtn', 'stopBtn', 'testBtn', 'retryBtn', 'photoInput']
      .forEach(function (id) { elements[id] = document.getElementById(id); });
    elements.startBtn.addEventListener('click', function () { startScanner(); });
    elements.stopBtn.addEventListener('click', function () { stopScanner(); });
    elements.testBtn.addEventListener('click', testConnection);
    elements.retryBtn.addEventListener('click', function () { retryFailedToken(); });
    elements.photoInput.addEventListener('change', scanPhoto);
    window.addEventListener('message', onBridgeMessage);
    window.addEventListener('offline', handleOffline);
    window.addEventListener('online', handleOnline);
    window.addEventListener('pagehide', function () {
      if (scanner && running) scanner.stop().catch(function () {});
    });
    setMode();
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      window.__M70_TEST__ = { onScanSuccess, expireBridgeSession };
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();

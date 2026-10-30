(function () {
  'use strict';

  const BRIDGE_HOST_SUFFIX = '.googleusercontent.com';
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
  let bridgeOrigin = null;
  let bridgeChannelId = null;
  let bridgeConnected = false;
  let currentRequest = null;
  let retryToken = null;
  let confirmedCount = 0;
  const scannedTokens = new Set();
  const tokenStates = new Map();
  const pendingTokens = [];
  const elements = {};
  let importedBridgeKey = null;

  function showResult(message, type = '') {
    elements.result.textContent = message;
    elements.result.className = type;
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

  function getTrustedOpenerOrigin() {
    if (!window.opener || window.opener.closed || !document.referrer) return null;
    try {
      const referrer = new URL(document.referrer);
      const trusted = referrer.protocol === 'https:' &&
        (referrer.hostname === 'script.google.com' || referrer.hostname.endsWith(BRIDGE_HOST_SUFFIX));
      return trusted ? referrer.origin : null;
    } catch (_error) {
      return null;
    }
  }

  function setMode() {
    elements.mode.textContent = bridgeConnected
      ? 'Авторизованный режим · отметка прихода включена'
      : 'Тестовый режим · запись в таблицу отключена';
  }

  function announceReadyToOpener() {
    bridgeOrigin = getTrustedOpenerOrigin();
    if (!bridgeOrigin) return setMode();
    window.opener.postMessage({ type: 'M70_SCANNER_READY', version: 1 }, bridgeOrigin);
  }

  function postToBridge(message) {
    if (!bridgeConnected || !bridgeOrigin || !window.opener || window.opener.closed) return false;
    window.opener.postMessage(message, bridgeOrigin);
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

  async function verifyBridgeSession(data) {
    if (typeof data.channelId !== 'string' || typeof data.signature !== 'string' ||
        !Number.isSafeInteger(data.expiresAt)) return false;
    const now = Date.now();
    if (data.expiresAt <= now || data.expiresAt > now + 10 * 60 * 1000) return false;
    if (!window.crypto || !window.crypto.subtle) return false;
    const payload = `${data.channelId}\n${data.expiresAt}\n${window.location.origin}`;
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

  async function acceptBridgeSession(data) {
    if (!await verifyBridgeSession(data)) {
      bridgeConnected = false;
      bridgeChannelId = null;
      setMode();
      showResult('Не удалось подтвердить подлинность приложения регистратора.', 'error');
      return;
    }
    bridgeChannelId = data.channelId;
    bridgeConnected = true;
    setMode();
    postToBridge({ type: 'M70_SCANNER_CONNECTED', channelId: bridgeChannelId });
    showResult('Связь с приложением регистратора установлена.', 'success');
    pumpQueue();
  }

  function onBridgeMessage(event) {
    if (!bridgeOrigin || event.origin !== bridgeOrigin || event.source !== window.opener) return;
    const data = event.data;
    if (!data || typeof data !== 'object') return;

    if (data.type === 'M70_BRIDGE_INIT') {
      acceptBridgeSession(data);
      return;
    }
    if (data.channelId !== bridgeChannelId) return;

    if (data.type === 'M70_TEST_RESULT') {
      if (currentRequest && currentRequest.kind === 'test' && data.requestId === currentRequest.requestId) {
        clearTimeout(currentRequest.timeoutId);
        currentRequest = null;
        elements.testBtn.disabled = false;
        showResult(
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
      if (tokenStates.get(token) === 'already_used') showResult('Билет уже использован', 'warning');
      return;
    }

    scannedTokens.add(token);
    tokenStates.set(token, bridgeConnected ? 'queued' : 'test_only');
    updateRecognizedCount();
    if (navigator.vibrate) navigator.vibrate(100);

    if (!bridgeConnected) {
      showResult(`✓ Новый QR-код распознан\nУникальных QR: ${scannedTokens.size}\nТестовый режим: отметка прихода не отправлена.`, 'success');
      return;
    }
    pendingTokens.push(token);
    showResult('QR-код распознан. Проверяем билет…');
    pumpQueue();
  }

  function pumpQueue() {
    if (!bridgeConnected || currentRequest || pendingTokens.length === 0) return;
    const token = pendingTokens.shift();
    const requestId = createRequestId();
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
    if (!currentRequest || currentRequest.kind !== 'checkin' || data.requestId !== currentRequest.requestId) return;
    const token = currentRequest.token;
    clearTimeout(currentRequest.timeoutId);
    currentRequest = null;
    if (data.status === 'checked_in') {
      tokenStates.set(token, 'checked_in');
      confirmedCount += 1;
      elements.confirmedCount.textContent = String(confirmedCount);
      retryToken = null;
      elements.retryBtn.hidden = true;
      showResult('✓ Приход отмечен\nСканирование продолжается', 'success');
    } else if (data.status === 'already_used') {
      tokenStates.set(token, 'already_used');
      retryToken = null;
      elements.retryBtn.hidden = true;
      showResult('Билет уже использован', 'warning');
    } else {
      tokenStates.set(token, 'failed');
      retryToken = token;
      elements.retryBtn.hidden = false;
      showResult(data.status === 'not_found' ? 'Билет не найден. Приход не отмечен.' : `Ошибка: ${data.message || 'приход не подтверждён'}`, 'error');
    }
    pumpQueue();
  }

  function retryFailedToken() {
    if (!retryToken || tokenStates.get(retryToken) !== 'failed') return;
    tokenStates.set(retryToken, 'queued');
    pendingTokens.push(retryToken);
    retryToken = null;
    elements.retryBtn.hidden = true;
    showResult('Повторная проверка билета…');
    pumpQueue();
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
    if (!bridgeConnected) return showResult('Нет авторизованной связи. Откройте сканер кнопкой из приложения регистратора Apps Script.', 'error');
    if (currentRequest) return showResult('Дождитесь завершения текущей проверки билета.', 'warning');
    const requestId = createRequestId();
    elements.testBtn.disabled = true;
    const timeoutId = setTimeout(function () {
      if (!currentRequest || currentRequest.requestId !== requestId) return;
      currentRequest = null;
      elements.testBtn.disabled = false;
      showResult('Google Apps Script не ответил. Проверьте сеть и авторизацию.', 'error');
      pumpQueue();
    }, REQUEST_TIMEOUT_MS);
    currentRequest = { kind: 'test', requestId, timeoutId };
    if (!postToBridge({ type: 'M70_TEST_REQUEST', channelId: bridgeChannelId, requestId })) {
      clearTimeout(timeoutId);
      currentRequest = null;
      elements.testBtn.disabled = false;
      showResult('Связь с приложением регистратора потеряна.', 'error');
    }
  }

  function init() {
    ['result', 'mode', 'count', 'confirmedCount', 'startBtn', 'stopBtn', 'testBtn', 'retryBtn', 'photoInput']
      .forEach(function (id) { elements[id] = document.getElementById(id); });
    elements.startBtn.addEventListener('click', function () { startScanner(); });
    elements.stopBtn.addEventListener('click', function () { stopScanner(); });
    elements.testBtn.addEventListener('click', testConnection);
    elements.retryBtn.addEventListener('click', retryFailedToken);
    elements.photoInput.addEventListener('change', scanPhoto);
    window.addEventListener('message', onBridgeMessage);
    window.addEventListener('pagehide', function () {
      if (scanner && running) scanner.stop().catch(function () {});
    });
    setMode();
    announceReadyToOpener();
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      window.__M70_TEST__ = { onScanSuccess };
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();

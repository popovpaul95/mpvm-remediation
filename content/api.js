'use strict';
// Доступ к API MaxPatrol VM со страницы стенда: тот же origin, Bearer-токен из настроек.
// Никакого OAuth и cookie-сессий: токен создается в PT MC (Токены доступа).
window.VR = window.VR || {};
(function (VR) {
  let cfg = null;

  VR.loadConfig = () => new Promise(res => chrome.storage.sync.get(['host', 'port', 'token'], c => { cfg = c || {}; res(cfg); }));
  VR.config = () => cfg || {};

  // Хост из настроек совпадает с хостом открытой страницы?
  VR.isConfiguredHost = () => {
    const raw = String(cfg?.host || '').replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
    return !!raw && raw === location.hostname.toLowerCase();
  };

  const base = () => {
    const port = String(cfg?.port || '').trim();
    const std = (location.protocol === 'https:' && (port === '' || port === '443')) || (location.protocol === 'http:' && (port === '' || port === '80'));
    return `${location.protocol}//${location.hostname}${std ? '' : ':' + port}`;
  };
  const headers = extra => ({ Authorization: 'Bearer ' + String(cfg?.token || '').trim(), Accept: 'application/json', ...(extra || {}) });

  async function req(method, path, body, extraHeaders) {
    if (!cfg?.token) throw new Error('Не задан персональный токен (настройки расширения)');
    let r;
    try {
      r = await fetch(base() + path, { method, headers: headers(body != null ? { 'Content-Type': 'application/json', ...(extraHeaders || {}) } : extraHeaders), body: body != null ? JSON.stringify(body) : undefined });
    } catch (e) {
      throw new Error(`Сервер ${base()} недоступен (${e.message}). API отвечает на порту интерфейса: оставьте поле «Порт» в настройках расширения пустым`);
    }
    const text = await r.text();
    if (!r.ok) {
      if (r.status === 401) throw new Error('401: токен не принят. Проверьте персональный токен в настройках расширения');
      if (r.status === 403) throw new Error('403: недостаточно прав у токена для этой операции');
      throw new Error(`HTTP ${r.status}: ${text.slice(0, 200)}`);
    }
    const ct = r.headers.get('content-type') || '';
    return ct.includes('json') && text ? JSON.parse(text) : text;
  }
  VR.get = (path, params) => req('GET', path + (params ? '?' + new URLSearchParams(params).toString() : ''));
  VR.post = (path, body) => req('POST', path, body);
  VR.put = (path, body) => req('PUT', path, body);
  VR.del = path => req('DELETE', path);

  function utcOffset() {
    const off = -new Date().getTimezoneOffset(), s = off >= 0 ? '+' : '-';
    return `${s}${String(Math.floor(Math.abs(off) / 60)).padStart(2, '0')}:${String(Math.abs(off) % 60).padStart(2, '0')}`;
  }

  // PDQL в два шага: токен запроса, затем строки. Пока результат не готов, сервер отдает 404.
  VR.pdql = async (pdql, limit = 100, offset = 0) => {
    const r1 = await VR.post('/api/assets_temporal_readmodel/v1/assets_grid', {
      pdql, selectedGroupIds: [], additionalFilterParameters: { groupIDs: [], assetIDs: [] }, includeNestedGroups: true, utcOffset: utcOffset(),
    });
    const token = r1?.token;
    if (!token) throw new Error('PDQL: сервер не вернул токен запроса');
    for (let i = 0; i < 90; i++) {
      await new Promise(r => setTimeout(r, i ? 2000 : 300));
      let r;
      try { r = await fetch(`${base()}/api/assets_temporal_readmodel/v1/assets_grid/data?pdqlToken=${encodeURIComponent(token)}&offset=${offset}&limit=${limit}`, { headers: headers() }); }
      catch (e) { throw new Error(`Сервер ${base()} недоступен (${e.message})`); }
      if (r.ok) return r.json();
      if (r.status !== 404) throw new Error(`PDQL: HTTP ${r.status}`);
    }
    throw new Error('PDQL: превышено время ожидания результата');
  };

  VR.systemInfo = () => VR.get('/api/deployment_configuration/v1/system_info');

  VR.getVal = (obj, key) => {
    if (obj == null) return '';
    if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
    const dot = key.indexOf('.');
    if (dot !== -1) { const h = key.slice(0, dot), t = key.slice(dot + 1); if (Object.prototype.hasOwnProperty.call(obj, h) && typeof obj[h] === 'object') return VR.getVal(obj[h], t); }
    return '';
  };
  VR.rowVal = (rec, k) => { const v = VR.getVal(rec, k); if (v && typeof v === 'object') return v.displayName ?? v.name ?? v.value ?? ''; return v ?? ''; };
  VR.num = v => { if (v == null || v === '') return null; const n = parseFloat(String(v).replace(',', '.')); return Number.isFinite(n) ? n : null; };
  VR.bool = v => v === true || v === 'True' || v === 'true';
  VR.rows = d => d?.records || d?.data || d?.rows || [];

  // Внешние источники через service worker
  VR.ext = (op, params) => new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'ext', op, params: params || {} }, resp => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (resp && resp.ok) resolve(resp.result); else reject(new Error(resp?.error || 'Нет ответа от расширения'));
    });
  });

  // Проверка подключения по запросу из popup
  chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
    if (!msg || msg.type !== 'vr-ping') return false;
    VR.loadConfig().then(() => VR.systemInfo()).then(d => sendResponse({ ok: true, version: d?.productVersion || '?' })).catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  });
})(window.VR);

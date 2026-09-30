'use strict';
const theme = matchMedia('(prefers-color-scheme: dark)');
const applyTheme = () => { document.documentElement.className = theme.matches ? 'kbq-dark' : 'kbq-light'; document.documentElement.style.colorScheme = theme.matches ? 'dark' : 'light'; };
applyTheme(); theme.addEventListener('change', applyTheme);
const $ = id => document.getElementById(id);
const st = (msg, cls) => { const el = $('st'); el.textContent = msg; el.className = 'st ' + (cls || ''); };
const normHost = v => String(v || '').trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();

// ── Список серверов ────────────────────────────────────────────────────────
// Хранится в chrome.storage.sync как servers: [{host, port, token}]. Старые ключи host/port/token (одна запись)
// читаются как единственный сервер и удаляются при первом сохранении.
const list = $('servers');
let activeHost = '';
function blocks() { return [...list.querySelectorAll('.srv')]; }
function readBlock(b) { return { host: normHost(b.querySelector('[data-k=host]').value), port: b.querySelector('[data-k=port]').value.trim(), token: b.querySelector('[data-k=token]').value.trim() }; }
function readAll() { return blocks().map(readBlock); }
function renumber() {
  blocks().forEach((b, i) => {
    b.dataset.i = i; b.querySelector('.srv-title').textContent = `Сервер ${i + 1}`;
    ['host', 'port', 'token'].forEach(k => { const inp = b.querySelector(`[data-k=${k}]`); inp.id = `${k}-${i}`; inp.parentElement.htmlFor = inp.id; });
    b.querySelector('.test').id = `test-${i}`; b.querySelector('.del').id = `del-${i}`;
    b.querySelector('.del').hidden = blocks().length === 1;
    const badge = b.querySelector('.srv-badge'); badge.hidden = !activeHost || readBlock(b).host !== activeHost;
  });
}
function addBlock(s, focus) {
  const b = $('srv-tpl').content.firstElementChild.cloneNode(true);
  if (s) { b.querySelector('[data-k=host]').value = s.host || ''; b.querySelector('[data-k=port]').value = s.port || ''; b.querySelector('[data-k=token]').value = s.token || ''; }
  b.querySelectorAll('input').forEach(inp => inp.addEventListener('input', () => { inp.removeAttribute('aria-invalid'); if (inp.dataset.k === 'host') renumber(); saveDraft(); }));
  b.querySelector('.del').addEventListener('click', () => { b.remove(); if (!blocks().length) addBlock(null); renumber(); saveDraft(); st('Сервер убран из списка: нажмите «Сохранить»', ''); });
  b.querySelector('.test').addEventListener('click', () => testServer(b));
  list.appendChild(b); renumber();
  if (focus) b.querySelector('[data-k=host]').focus();
  return b;
}
function render(servers) { list.innerHTML = ''; (servers.length ? servers : [null]).forEach(s => addBlock(s)); renumber(); }

// Chrome закрывает окно расширения при потере фокуса (например, при копировании токена из другого окна),
// поэтому несохраненный ввод держим в черновике chrome.storage.local и восстанавливаем при открытии.
const DRAFT = 'vr_popup_draft';
let draftTimer = null;
const saveDraft = () => { clearTimeout(draftTimer); draftTimer = setTimeout(() => chrome.storage.local.set({ [DRAFT]: { servers: blocks().map(b => ({ host: b.querySelector('[data-k=host]').value, port: b.querySelector('[data-k=port]').value, token: b.querySelector('[data-k=token]').value })) } }), 150); };
const clearDraft = () => { clearTimeout(draftTimer); chrome.storage.local.remove(DRAFT); };

function storedServers(c) {
  if (Array.isArray(c.servers) && c.servers.length) return c.servers.filter(s => s && s.host).map(s => ({ host: normHost(s.host), port: String(s.port || ''), token: String(s.token || '') }));
  return c.host ? [{ host: normHost(c.host), port: String(c.port || ''), token: String(c.token || '') }] : [];
}
chrome.storage.sync.get(['servers', 'host', 'port', 'token'], c => {
  const servers = storedServers(c);
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    try { activeHost = new URL(tabs?.[0]?.url || '').hostname.toLowerCase(); } catch (_) { activeHost = ''; }
    chrome.storage.local.get([DRAFT], r => {
      const d = r[DRAFT];
      if (d && Array.isArray(d.servers) && d.servers.some(s => s.host || s.token)) { render(d.servers); st('Восстановлен несохраненный ввод: нажмите «Сохранить»', ''); }
      else render(servers);
    });
  });
});

// ── Проверка и сохранение ──────────────────────────────────────────────────
function validate(servers) {
  const seen = new Set();
  for (let i = 0; i < servers.length; i++) {
    const c = servers[i], b = blocks()[i];
    const bad = (k, msg) => { const inp = b.querySelector(`[data-k=${k}]`); inp.setAttribute('aria-invalid', 'true'); inp.focus(); st(msg, 'err'); return false; };
    if (!c.host) return bad('host', `Сервер ${i + 1}: укажите адрес MaxPatrol VM`);
    if (!c.token) return bad('token', `Сервер ${i + 1}: вставьте персональный токен из PT MC`);
    if (c.port && (!/^\d{1,5}$/.test(c.port) || Number(c.port) < 1 || Number(c.port) > 65535)) return bad('port', `Сервер ${i + 1}: порт от 1 до 65535 или пустое поле`);
    if (seen.has(c.host)) return bad('host', `Сервер ${i + 1}: адрес ${c.host} уже есть в списке`);
    seen.add(c.host);
  }
  if (JSON.stringify(servers).length > 7000) { st('Слишком много серверов для синхронизируемого хранилища Chrome: уберите лишние', 'err'); return false; }
  return true;
}
function persist(servers, cb) {
  chrome.storage.sync.set({ servers }, () => chrome.storage.sync.remove(['host', 'port', 'token'], () => { clearDraft(); cb && cb(); }));
}
$('add').addEventListener('click', () => { addBlock(null, true); saveDraft(); });
$('save').addEventListener('click', () => {
  const servers = readAll();
  if (!validate(servers)) return;
  persist(servers, () => { renumber(); const ports = servers.filter(c => c.port && c.port !== '443'); st(`Сохранено: ${servers.length} ${servers.length === 1 ? 'сервер' : servers.length < 5 ? 'сервера' : 'серверов'}. Обновите вкладку MaxPatrol VM${ports.length ? '. Если будет «недоступен», очистите порт' : ''}`, 'ok'); });
});

// Проверка подключения: сначала прямой запрос из окна расширения (не зависит от вкладок), при сетевой ошибке
// (например, самоподписанный сертификат, который принят только во вкладке) - через content-скрипт вкладки сервера.
const API_INFO = '/api/deployment_configuration/v1/system_info';
const baseUrl = c => `https://${c.host}${c.port && c.port !== '443' ? ':' + c.port : ''}`;
async function directCheck(c) {
  const r = await fetch(baseUrl(c) + API_INFO, { headers: { Authorization: 'Bearer ' + c.token, Accept: 'application/json' }, cache: 'no-store' });
  if (r.status === 401) throw new Error('токен не принят (401): проверьте персональный токен');
  if (r.status === 403) throw new Error('доступ запрещен (403): у токена нет прав на API');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  return d?.productVersion || d?.version || '?';
}
function findServerTab(c, cb) {
  chrome.tabs.query({}, tabs => {
    const same = (tabs || []).filter(t => { try { return new URL(t.url || '').hostname.toLowerCase() === c.host && !t.discarded; } catch (_) { return false; } });
    cb(same.find(t => t.active) || same[0] || null);
  });
}
function tabCheck(c, tab) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { type: 'vr-ping' }, resp => {
      if (chrome.runtime.lastError) { const e = new Error(chrome.runtime.lastError.message); e.noReceiver = /Receiving end does not exist|Could not establish connection/i.test(e.message); return reject(e); }
      if (resp && resp.ok) resolve(resp.version); else reject(new Error(resp?.error || 'нет ответа от вкладки'));
    });
  });
}
const sst = (b, msg, cls) => { const el = b.querySelector('.srv-st'); el.textContent = msg; el.className = 'srv-st ' + (cls || ''); };
function offerReload(b, tab, c) {
  const el = b.querySelector('.srv-st');
  const btn = document.createElement('button'); btn.textContent = 'Перезагрузить вкладку сервера'; btn.className = 'sec';
  btn.addEventListener('click', () => {
    btn.disabled = true; sst(b, 'Перезагружаем вкладку...');
    chrome.tabs.reload(tab.id, {}, () => {
      const onDone = (id, info) => { if (id !== tab.id || info.status !== 'complete') return; chrome.tabs.onUpdated.removeListener(onDone); setTimeout(() => tabCheck(c, tab).then(v => sst(b, `Подключено: MaxPatrol VM ${v}`, 'ok')).catch(e => sst(b, 'Ошибка: ' + e.message, 'err')), 1500); };
      chrome.tabs.onUpdated.addListener(onDone);
    });
  });
  el.appendChild(document.createElement('br')); el.appendChild(btn);
}
function testServer(b) {
  const servers = readAll();
  if (!validate(servers)) return;
  const c = readBlock(b);
  // Сохраняем весь список: content-скрипт вкладки читает токен из хранилища
  persist(servers, async () => {
    renumber(); st(''); sst(b, 'Проверяем подключение…');
    try { const v = await directCheck(c); sst(b, `Подключено: MaxPatrol VM ${v}`, 'ok'); return; }
    catch (e) {
      if (!(e instanceof TypeError)) { sst(b, 'Ошибка: ' + e.message, 'err'); return; }
      // Сетевая ошибка из окна расширения: пробуем из вкладки сервера
      findServerTab(c, async tab => {
        if (!tab) { sst(b, `Сервер не ответил из окна расширения (${e.message}). Откройте вкладку https://${c.host}, примите сертификат и нажмите «Проверить» снова`, 'err'); return; }
        try { const v = await tabCheck(c, tab); sst(b, `Подключено через вкладку: MaxPatrol VM ${v}`, 'ok'); }
        catch (e2) {
          if (e2.noReceiver) { sst(b, 'Во вкладке сервера нет скрипта расширения: так бывает после обновления расширения, пока вкладка не перезагружена.', 'err'); offerReload(b, tab, c); }
          else sst(b, 'Ошибка: ' + e2.message, 'err');
        }
      });
    }
  });
}

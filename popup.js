'use strict';
const F = ['host', 'port', 'token'];
const $ = id => document.getElementById(id);
const st = (msg, cls) => { const el = $('st'); el.textContent = msg; el.className = 'st ' + (cls || ''); };

// Chrome закрывает окно расширения при потере фокуса (например, при копировании адреса из другого окна),
// поэтому несохраненный ввод держим в черновике chrome.storage.local и восстанавливаем при открытии.
const DRAFT = 'vr_popup_draft';
chrome.storage.sync.get(F, c => {
  F.forEach(k => { if (c[k]) $(k).value = c[k]; });
  chrome.storage.local.get([DRAFT], r => {
    const d = r[DRAFT];
    if (!d) return;
    F.forEach(k => { if (d[k] != null && d[k] !== '') $(k).value = d[k]; });
    st('Восстановлен несохраненный ввод: нажмите «Сохранить»', '');
  });
});
let draftTimer = null;
F.forEach(k => $(k).addEventListener('input', () => {
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => chrome.storage.local.set({ [DRAFT]: { host: $('host').value, port: $('port').value, token: $('token').value } }), 150);
}));
const clearDraft = () => { clearTimeout(draftTimer); chrome.storage.local.remove(DRAFT); };

function read() {
  const host = $('host').value.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  return { host, port: $('port').value.trim(), token: $('token').value.trim() };
}

$('save').addEventListener('click', () => {
  const c = read();
  if (!c.host || !c.token) { st('Укажите сервер и токен', 'err'); return; }
  if (c.port && !/^\d{1,5}$/.test(c.port)) { st('Порт должен быть числом или пустым', 'err'); return; }
  chrome.storage.sync.set(c, () => { clearDraft(); st(c.port && c.port !== '443' ? `Сохранено с портом ${c.port}. Если будет «недоступен», очистите порт` : 'Сохранено. Обновите вкладку MaxPatrol VM', 'ok'); });
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
    const same = (tabs || []).filter(t => { try { return new URL(t.url || '').hostname.toLowerCase() === c.host.toLowerCase() && !t.discarded; } catch (_) { return false; } });
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
function offerReload(tab, c) {
  const el = $('st');
  const b = document.createElement('button'); b.textContent = 'Перезагрузить вкладку сервера'; b.style.marginTop = '8px'; b.className = 'sec';
  b.addEventListener('click', () => {
    b.disabled = true; st('Перезагружаем вкладку...');
    chrome.tabs.reload(tab.id, {}, () => {
      const onDone = (id, info) => { if (id !== tab.id || info.status !== 'complete') return; chrome.tabs.onUpdated.removeListener(onDone); setTimeout(() => tabCheck(c, tab).then(v => st(`Подключено: MaxPatrol VM ${v}`, 'ok')).catch(e => st('Ошибка: ' + e.message, 'err')), 1500); };
      chrome.tabs.onUpdated.addListener(onDone);
    });
  });
  el.appendChild(document.createElement('br')); el.appendChild(b);
}
$('test').addEventListener('click', () => {
  const c = read();
  if (!c.host || !c.token) { st('Укажите сервер и токен', 'err'); return; }
  chrome.storage.sync.set(c, async () => {
    clearDraft();
    st('Проверяем...');
    try { const v = await directCheck(c); st(`Подключено: MaxPatrol VM ${v}`, 'ok'); return; }
    catch (e) {
      if (!(e instanceof TypeError)) { st('Ошибка: ' + e.message, 'err'); return; }
      // Сетевая ошибка из окна расширения: пробуем из вкладки сервера
      findServerTab(c, async tab => {
        if (!tab) { st(`Сервер не ответил из окна расширения (${e.message}). Откройте вкладку https://${c.host}, примите сертификат и нажмите «Проверить» снова`, 'err'); return; }
        try { const v = await tabCheck(c, tab); st(`Подключено через вкладку: MaxPatrol VM ${v}`, 'ok'); }
        catch (e2) {
          if (e2.noReceiver) { st('Во вкладке сервера нет скрипта расширения: так бывает после обновления расширения, пока вкладка не перезагружена.', 'err'); offerReload(tab, c); }
          else st('Ошибка: ' + e2.message, 'err');
        }
      });
    }
  });
});

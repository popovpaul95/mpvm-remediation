'use strict';
// Service worker: внешние источники по CVE (EPSS, CISA KEV, NVD, GitHub), настройки
// модуля и кэши. Запросы к самому MaxPatrol VM выполняет content-скрипт со страницы
// стенда (тот же origin, Bearer-токен), сюда они не приходят.

const DEFAULT_SETTINGS = {
  epssEnabled: true,
  kevEnabled: true,
  nvdEnabled: true,
  nvdApiKey: '',
  ghEnabled: false,
  ghToken: '',
  slaCritDays: 1,      // приказ ФСТЭК 117: критические 24 часа
  slaHighDays: 7,      //                   высокие 7 дней
  slaMedDays: 30,      // внутренняя норма
  slaLowDays: 90,
  queueLimit: 300,
  sameTabLinks: true, // переходы с дашборда в текущей вкладке
  // Jira: Cloud (email + API token, Basic) или Server/DC (персональный токен, Bearer)
  jiraUrl: '',
  jiraAuth: 'basic',
  jiraUser: '',
  jiraToken: '',
  jiraProject: '',
  jiraIssueType: 'Task',
  jiraLabels: 'maxpatrol-vm',
  jiraTagInstances: true, // ставить метку jira:KEY на экземпляры уязвимостей в MaxPatrol
};

const TTL = { epss: 24 * 3600e3, kev: 24 * 3600e3, nvd: 7 * 24 * 3600e3, gh: 7 * 24 * 3600e3 };
const URLS = {
  epss: 'https://api.first.org/data/v1/epss',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  gh: 'https://api.github.com/search/repositories',
};
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

const LOG = [];
function log(level, msg) {
  LOG.push({ t: new Date().toISOString(), level, msg: String(msg).slice(0, 300) });
  if (LOG.length > 200) LOG.shift();
}

const storeGet = keys => new Promise(r => chrome.storage.local.get(keys, r));
const storeSet = obj => new Promise(r => chrome.storage.local.set(obj, r));
async function settings() {
  const { vr_settings } = await storeGet(['vr_settings']);
  return { ...DEFAULT_SETTINGS, ...(vr_settings || {}) };
}
function normCves(list) {
  const out = new Set();
  (list || []).forEach(s => { const m = String(s || '').toUpperCase().match(CVE_RE); if (m) m.forEach(c => out.add(c)); });
  return [...out];
}
function num(v) { if (v == null || v === '') return null; const n = parseFloat(String(v).replace(',', '.')); return Number.isFinite(n) ? n : null; }

async function fetchJson(url, headers) {
  const r = await fetch(url, { headers: { Accept: 'application/json', ...(headers || {}) } });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text().catch(() => '')).slice(0, 120)}`);
  return r.json();
}

async function epss(cves) {
  const now = Date.now();
  const { vr_epss } = await storeGet(['vr_epss']);
  const cache = vr_epss || {};
  const need = cves.filter(c => !cache[c] || now - cache[c].ts > TTL.epss);
  for (let i = 0; i < need.length; i += 100) {
    const batch = need.slice(i, i + 100);
    try {
      const d = await fetchJson(`${URLS.epss}?cve=${batch.join(',')}`);
      const seen = new Set();
      (d.data || []).forEach(x => { cache[x.cve] = { epss: num(x.epss), percentile: num(x.percentile), date: x.date, ts: now }; seen.add(x.cve); });
      batch.filter(c => !seen.has(c)).forEach(c => { cache[c] = { epss: null, percentile: null, date: null, ts: now }; });
    } catch (e) { log('WARN', `EPSS: ${e.message}`); break; }
  }
  await storeSet({ vr_epss: cache });
  const out = {}; cves.forEach(c => { if (cache[c]) out[c] = cache[c]; });
  return out;
}

async function kevCatalog(force) {
  const now = Date.now();
  const { vr_kev } = await storeGet(['vr_kev']);
  if (!force && vr_kev && now - vr_kev.ts < TTL.kev) return vr_kev;
  try {
    const d = await fetchJson(URLS.kev);
    const byCve = {};
    (d.vulnerabilities || []).forEach(v => {
      byCve[v.cveID] = { vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse, action: v.requiredAction };
    });
    const cat = { ts: now, dateReleased: d.dateReleased, count: d.count, byCve };
    await storeSet({ vr_kev: cat });
    log('INFO', `KEV обновлен: ${d.count}`);
    return cat;
  } catch (e) {
    log('WARN', `KEV: ${e.message}`);
    return vr_kev || { ts: 0, byCve: {}, error: e.message };
  }
}

function parseNvd(item) {
  const c = item?.cve; if (!c) return null;
  const m = c.metrics || {};
  const pick = arr => (arr && arr.length) ? arr.find(x => x.type === 'Primary') || arr[0] : null;
  const v40 = pick(m.cvssMetricV40), v31 = pick(m.cvssMetricV31), v2 = pick(m.cvssMetricV2);
  const ssvcRaw = pick(m.ssvcV203);
  const opts = ssvcRaw?.ssvcData?.options || ssvcRaw?.options || null;
  const optVal = key => { for (const o of (opts || [])) { if (!o) continue; const k = Object.keys(o).find(x => x.replace(/[\s_]/g, '').toLowerCase() === key); if (k) return o[k]; } return null; };
  const desc = (c.descriptions || []).find(d => d.lang === 'en')?.value || '';
  return {
    published: c.published, lastModified: c.lastModified, status: c.vulnStatus, cisaExploitAdd: c.cisaExploitAdd || null,
    cvss40: v40 ? { score: v40.cvssData?.baseScore, vector: v40.cvssData?.vectorString, severity: v40.cvssData?.baseSeverity } : null,
    cvss31: v31 ? { score: v31.cvssData?.baseScore, vector: v31.cvssData?.vectorString, severity: v31.cvssData?.baseSeverity } : null,
    cvss2: v2 ? { score: v2.cvssData?.baseScore, vector: v2.cvssData?.vectorString } : null,
    ssvc: opts ? { exploitation: optVal('exploitation'), automatable: optVal('automatable'), impact: optVal('technicalimpact') } : null,
    cwes: (c.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(x => x && !/NVD-CWE/.test(x)).slice(0, 3),
    // Ссылки NVD с тегами: Patch, Vendor Advisory, Mitigation, Third Party Advisory, Exploit
    refs: (c.references || []).filter(r => (r.tags || []).some(t => /Patch|Vendor Advisory|Mitigation|Third Party Advisory|Exploit/i.test(t))).slice(0, 12).map(r => ({ url: r.url, tags: r.tags || [] })),
    description: desc.slice(0, 600),
  };
}

async function nvd(cves, s) {
  const now = Date.now();
  const { vr_nvd } = await storeGet(['vr_nvd']);
  const cache = vr_nvd || {};
  const need = cves.filter(c => !cache[c] || now - cache[c].ts > TTL.nvd);
  const headers = s.nvdApiKey ? { apiKey: s.nvdApiKey } : {};
  const max = s.nvdApiKey ? 40 : 5;
  for (const c of need.slice(0, max)) {
    try {
      const d = await fetchJson(`${URLS.nvd}?cveId=${c}`, headers);
      cache[c] = { ...(parseNvd((d.vulnerabilities || [])[0]) || { missing: true }), ts: now };
      if (!s.nvdApiKey) await new Promise(r => setTimeout(r, 6500));
    } catch (e) { log('WARN', `NVD ${c}: ${e.message}`); if (/403|429/.test(e.message)) break; }
  }
  await storeSet({ vr_nvd: cache });
  const out = {}; cves.forEach(c => { if (cache[c]) out[c] = cache[c]; });
  return { data: out, skipped: Math.max(0, need.length - max) };
}

async function github(cve, s) {
  const now = Date.now();
  const { vr_gh } = await storeGet(['vr_gh']);
  const cache = vr_gh || {};
  if (cache[cve] && now - cache[cve].ts < TTL.gh) return cache[cve];
  const headers = s.ghToken ? { Authorization: 'Bearer ' + s.ghToken } : {};
  const d = await fetchJson(`${URLS.gh}?q=${encodeURIComponent(cve)}&sort=stars&order=desc&per_page=5`, headers);
  cache[cve] = { ts: now, count: d.total_count || 0, items: (d.items || []).map(r => ({ name: r.full_name, url: r.html_url, stars: r.stargazers_count, updated: r.pushed_at })) };
  await storeSet({ vr_gh: cache });
  return cache[cve];
}

function verdict(sig, s) {
  const kev = sig.kev, ep = sig.epss?.epss, trend = !!sig.mp?.trend, expl = !!sig.mp?.exploit;
  const score = sig.mp?.score ?? sig.nvd?.cvss31?.score ?? sig.nvd?.cvss40?.score ?? null;
  const reasons = [];
  let level = 'P3', title = 'Плановое устранение';
  if (kev) { level = 'P0'; title = 'Эксплуатируется в атаках (CISA KEV)'; reasons.push(`KEV с ${kev.dateAdded}${kev.ransomware === 'Known' ? ', используется в ransomware' : ''}`); }
  else if (trend) { level = 'P0'; title = 'Трендовая уязвимость (экспертиза PT)'; reasons.push('отмечена PT как трендовая'); }
  else if (ep != null && ep >= 0.5) { level = 'P1'; title = 'Высокая вероятность эксплуатации'; reasons.push(`EPSS ${(ep * 100).toFixed(0)}%`); }
  else if (expl || (ep != null && ep >= 0.1)) { level = 'P2'; title = 'Есть эксплойт или заметный EPSS'; if (expl) reasons.push('публичный эксплойт'); if (ep != null && ep >= 0.1) reasons.push(`EPSS ${(ep * 100).toFixed(0)}%`); }
  if (score != null && score >= 9 && level === 'P3') { level = 'P2'; title = 'Критический CVSS'; }
  if (sig.nvd?.ssvc?.exploitation && /active/i.test(sig.nvd.ssvc.exploitation)) { if (level !== 'P0') { level = 'P0'; title = 'Активная эксплуатация (NVD SSVC)'; } reasons.push('SSVC: Active'); }
  if (sig.bdu?.length) reasons.push(`в БДУ ФСТЭК: ${sig.bdu.map(b => b.id).slice(0, 2).join(', ')}`);
  const sla = (score != null && score >= 9) ? s.slaCritDays : (score != null && score >= 7) ? s.slaHighDays : (score != null && score >= 4) ? s.slaMedDays : s.slaLowDays;
  return { level, title, reasons, slaDays: sla, score };
}

// ── Jira REST ─────────────────────────────────────────────────────────────
function jiraHeaders(s) {
  const h = { Accept: 'application/json', 'Content-Type': 'application/json' };
  if (s.jiraAuth === 'bearer') h.Authorization = 'Bearer ' + (s.jiraToken || '').trim();
  else h.Authorization = 'Basic ' + btoa(`${(s.jiraUser || '').trim()}:${(s.jiraToken || '').trim()}`);
  return h;
}
async function jira(method, path, body) {
  const s = await settings();
  const base = String(s.jiraUrl || '').trim().replace(/\/+$/, '');
  if (!base) throw new Error('Не задан адрес Jira (настройки)');
  if (!s.jiraToken) throw new Error('Не задан токен Jira (настройки)');
  let r;
  try { r = await fetch(base + path, { method, headers: jiraHeaders(s), body: body != null ? JSON.stringify(body) : undefined }); }
  catch (e) { throw new Error(`Jira ${base} недоступна: ${e.message}`); }
  const text = await r.text();
  if (!r.ok) {
    let msg = text.slice(0, 300);
    try { const j = JSON.parse(text); msg = [...(j.errorMessages || []), ...Object.entries(j.errors || {}).map(([k, v]) => `${k}: ${v}`)].join('; ') || msg; } catch (_) {}
    if (r.status === 401) msg = 'Jira отвергла учетные данные (401). Cloud: email + API token, Server/DC: персональный токен (Bearer)';
    throw new Error(`Jira HTTP ${r.status}: ${msg}`);
  }
  return text ? JSON.parse(text) : null;
}
// Приоритет Jira по уровню: имена стандартные, при отсутствии в проекте Jira вернет ошибку и поле уберется
const JIRA_PRIORITY = { P0: 'Highest', P1: 'High', P2: 'Medium', P3: 'Low' };

const OPS = {
  'jira-test': async () => {
    const me = await jira('GET', '/rest/api/2/myself');
    const info = await jira('GET', '/rest/api/2/serverInfo').catch(() => null);
    return { user: me.displayName || me.name || me.emailAddress, version: info?.version || '?', deploymentType: info?.deploymentType || '?' };
  },
  'jira-projects': async () => {
    const list = await jira('GET', '/rest/api/2/project');
    return (list || []).map(p => ({ key: p.key, name: p.name })).slice(0, 200);
  },
  'jira-issuetypes': async p => {
    const proj = await jira('GET', `/rest/api/2/project/${encodeURIComponent(p.project)}`);
    return (proj.issueTypes || []).filter(t => !t.subtask).map(t => t.name);
  },
  'jira-create': async p => {
    const s = await settings();
    const fields = {
      project: { key: p.project || s.jiraProject },
      issuetype: { name: p.issueType || s.jiraIssueType || 'Task' },
      summary: String(p.summary || '').slice(0, 250),
      description: String(p.description || ''),
      labels: [...new Set([...(s.jiraLabels || '').split(/[,\s]+/).filter(Boolean), ...(p.labels || [])])],
    };
    if (p.priority && JIRA_PRIORITY[p.priority]) fields.priority = { name: JIRA_PRIORITY[p.priority] };
    if (p.dueDate) fields.duedate = p.dueDate;
    let created;
    try { created = await jira('POST', '/rest/api/2/issue', { fields }); }
    catch (e) {
      // Проект без приоритетов/сроков: повторяем без необязательных полей
      if (/priority|duedate/i.test(e.message)) { delete fields.priority; delete fields.duedate; created = await jira('POST', '/rest/api/2/issue', { fields }); }
      else throw e;
    }
    const base = String(s.jiraUrl || '').trim().replace(/\/+$/, '');
    return { key: created.key, id: created.id, url: `${base}/browse/${created.key}` };
  },
  'jira-attach': async p => {
    const s = await settings();
    const base = String(s.jiraUrl || '').trim().replace(/\/+$/, '');
    const fd = new FormData();
    fd.append('file', new Blob([p.content || ''], { type: p.mime || 'text/csv;charset=utf-8' }), p.filename || 'export.csv');
    const h = jiraHeaders(s); delete h['Content-Type']; h['X-Atlassian-Token'] = 'no-check';
    const r = await fetch(`${base}/rest/api/2/issue/${encodeURIComponent(p.key)}/attachments`, { method: 'POST', headers: h, body: fd });
    if (!r.ok) throw new Error(`Jira вложение HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
    const j = await r.json().catch(() => []);
    return { ok: true, filename: j?.[0]?.filename || p.filename };
  },
  'jira-search': async p => {
    const jql = p.jql || `labels = "${p.label}" ORDER BY created DESC`;
    const r = await jira('GET', `/rest/api/2/search?jql=${encodeURIComponent(jql)}&maxResults=${p.max || 20}&fields=summary,status,assignee,duedate,created`);
    const s = await settings(); const base = String(s.jiraUrl || '').trim().replace(/\/+$/, '');
    return (r.issues || []).map(i => ({ key: i.key, url: `${base}/browse/${i.key}`, summary: i.fields.summary, status: i.fields.status?.name, assignee: i.fields.assignee?.displayName || null, due: i.fields.duedate, created: i.fields.created }));
  },

  'settings-get': async () => settings(),
  'settings-set': async p => { const next = { ...(await settings()), ...(p.settings || {}) }; await storeSet({ vr_settings: next }); return next; },
  'kev-refresh': async () => { const c = await kevCatalog(true); return { count: c.count, dateReleased: c.dateReleased, error: c.error || null }; },
  'bdu-import': async p => { const map = p.map || {}; const rows = Object.keys(map).length; await storeSet({ vr_bdu: { ...map, _meta: { ts: Date.now(), rows, source: p.source || '' } } }); return { rows }; },
  'bdu-info': async () => (await storeGet(['vr_bdu'])).vr_bdu?._meta || null,
  'github': async p => { const c = normCves([p.cve])[0]; if (!c) throw new Error('Не распознан CVE'); return github(c, await settings()); },
  'log': async () => LOG.slice(),
  // Снимки тяжелых выборок между открытиями области (обновление только по кнопке)
  'cache-get': async p => { const k = 'vr_cache_' + p.key; const r = await storeGet([k]); return r[k] || null; },
  'cache-set': async p => { const k = 'vr_cache_' + p.key; await storeSet({ [k]: { ts: Date.now(), value: p.value } }); return { ok: true }; },
  'enrich': async p => {
    const s = await settings();
    const cves = normCves(p.cves).slice(0, 200);
    if (!cves.length) return { cves: [], results: {} };
    const mp = p.mp || {};
    const [ep, kev, bduStore] = await Promise.all([s.epssEnabled ? epss(cves) : {}, s.kevEnabled ? kevCatalog(false) : { byCve: {} }, storeGet(['vr_bdu'])]);
    let nv = { data: {}, skipped: 0 };
    if (s.nvdEnabled && !p.skipNvd) nv = await nvd(cves, s);
    const bdu = bduStore.vr_bdu || {};
    const results = {};
    cves.forEach(c => { const sig = { epss: ep[c] || null, kev: kev.byCve?.[c] || null, nvd: nv.data[c] || null, bdu: bdu[c] || null, mp: mp[c] || null }; results[c] = { ...sig, verdict: verdict(sig, s) }; });
    return { cves, results, meta: { kevDate: kev.dateReleased || null, kevError: kev.error || null, nvdSkipped: nv.skipped, bdu: bdu._meta || null } };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== 'ext') return false;
  const fn = OPS[msg.op];
  if (!fn) { sendResponse({ ok: false, error: `Неизвестная операция: ${msg.op}` }); return true; }
  fn(msg.params || {}).then(r => sendResponse({ ok: true, result: r })).catch(e => { log('ERROR', `${msg.op}: ${e.message}`); sendResponse({ ok: false, error: e.message }); });
  return true;
});

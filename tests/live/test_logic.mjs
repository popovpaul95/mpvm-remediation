// Прогон логики расширения (content/api.js + content/logic.js + background.js) против
// реального стенда MaxPatrol VM без браузера. Эмулирует window, location, chrome.*.
// Запуск: MP_HOST=host MP_TOKEN=pat_... node tests/live/test_logic.mjs [read|new|v4|risk|status <instanceId>|tags]
// Режимы чтения безопасны. Режимы status и tags меняют данные стенда и требуют MP_ALLOW_WRITE=1:
//   status: один экземпляр, исходный статус восстанавливается в finally (tillDate/причина исключения не восстанавливаются);
//   tags: один узел, уникальный тег auto:test-vr-<runId>, снимается и удаляется в finally.
// Каждая проверка через check(); при любой неудаче код выхода 1.
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const EXT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = process.env.OUT_DIR || path.join(EXT, 'tests', 'out');
fs.mkdirSync(OUT, { recursive: true });
const HOST = (process.env.MP_HOST || '').trim();
if (!HOST) { console.error('Нужен MP_HOST: стенд по умолчанию не подставляется'); process.exit(1); }
const ALLOW_WRITE = process.env.MP_ALLOW_WRITE === '1';
const TOKEN = (process.env.MP_TOKEN || (process.env.MP_TOKEN_FILE && fs.readFileSync(process.env.MP_TOKEN_FILE, 'utf8')) || '').trim();
if (!TOKEN) { console.error('Нужен MP_TOKEN или MP_TOKEN_FILE'); process.exit(1); }

// ── background (service worker) в своем контексте ──────────────────────────
const localStore = {};
let bgListener = null;
const bg = {
  console, setTimeout, clearTimeout, fetch, URLSearchParams,
  chrome: {
    storage: { local: {
      get: (keys, cb) => { const o = {}; (Array.isArray(keys) ? keys : [keys]).forEach(k => { if (k in localStore) o[k] = localStore[k]; }); cb(o); },
      set: (obj, cb) => { Object.assign(localStore, obj); cb && cb(); },
    } },
    runtime: { onMessage: { addListener: fn => { bgListener = fn; } } },
  },
};
vm.createContext(bg);
vm.runInContext(fs.readFileSync(path.join(EXT, 'background.js'), 'utf8'), bg, { filename: 'background.js' });

// ── content в своем контексте ──────────────────────────────────────────────
const syncStore = { host: HOST, port: '', token: TOKEN };
const win = {
  console, setTimeout, clearTimeout, URLSearchParams,
  location: { protocol: 'https:', hostname: HOST, href: `https://${HOST}/` },
  fetch: (url, opts) => fetch(url, opts),
  chrome: {
    storage: { sync: { get: (keys, cb) => cb({ ...syncStore }) }, onChanged: { addListener() {} } },
    runtime: {
      lastError: null,
      onMessage: { addListener() {} },
      sendMessage: (msg, cb) => { bgListener(msg, null, resp => cb(resp)); },
    },
  },
};
win.window = win; win.self = win; win.globalThis = win;
vm.createContext(win);
for (const f of ['content/api.js', 'content/logic.js', 'content/reports.js']) vm.runInContext(fs.readFileSync(path.join(EXT, f), 'utf8'), win, { filename: f });
const VR = win.VR;
await VR.loadConfig();

const fixtures = {};
const failures = [];
function check(cond, msg) { if (cond) console.log(`   ok: ${msg}`); else { failures.push(msg); console.log(`   FAIL: ${msg}`); } }
async function run(name, fn, save) {
  const t = Date.now();
  try { const r = await fn(); console.log(`\n### ${name} -> OK ${((Date.now() - t) / 1000).toFixed(1)}s`); if (save) fixtures[save] = r; return r; }
  catch (e) { console.log(`\n### ${name} -> ERROR ${e.message}`); failures.push(`${name}: ${e.message}`); return null; }
}
process.on('exit', () => { if (failures.length) { console.log(`\nНЕУДАЧ: ${failures.length}`); failures.forEach(f => console.log(' - ' + f)); process.exitCode = 1; } else console.log('\nВсе проверки пройдены'); });

const mode = process.argv[2] || 'read';
if (mode === 'read') {
  const si = await run('systemInfo', () => VR.systemInfo()); console.log('  ', si); check(si && si.productVersion, 'systemInfo.productVersion');
  const s = await run('settings-get', () => VR.ext('settings-get')); console.log('  ', JSON.stringify(s));
  const e = await run('enrich', () => VR.ext('enrich', { cves: ['CVE-2021-44228', 'CVE-2020-1472', 'CVE-2022-3602'], skipNvd: false }), 'enrich');
  if (e) e.cves.forEach(c => { const r = e.results[c]; console.log(`   ${c}: ${r.verdict.level} ${r.verdict.title} | EPSS ${r.epss?.epss} | KEV ${r.kev ? r.kev.dateAdded : '-'} | SSVC ${JSON.stringify(r.nvd?.ssvc)}`); });
  const q = await run('queue softs', () => VR.queue({ scope: 'softs', minScore: 0, limit: 300 }), 'queue');
  if (q) { console.log(`   groups=${q.totalGroups} products=${q.products.length}`); q.groups.slice(0, 3).forEach(g => console.log('   ', JSON.stringify(g))); check(q.groups.length > 0 && q.groups.every(g => g.soft && g.n > 0), 'очередь softs: непустые группы с soft и n'); check(q.groups.every((g, i) => i === 0 || q.groups[i - 1].risk >= g.risk), 'очередь отсортирована по риску'); }
  const qp = await run('queue packages', () => VR.queue({ scope: 'packages', minScore: 7, limit: 100 }), 'queuePkg');
  if (qp) console.log(`   groups=${qp.totalGroups}`, JSON.stringify(qp.groups[0]));
  const top = q?.groups?.find(x => x.soft === 'OpenSSL') || q?.groups?.[0];
  const d = top && await run('queueDetail', () => VR.queueDetail({ scope: 'softs', soft: top.soft, ver: top.ver }), 'detail');
  if (d) { console.log(`   rows=${d.rows} hosts=${d.hosts.length} cves=${d.cves.length} ids=${d.ids.length} truncated=${d.truncated}`, 'id0:', d.ids[0]); check(d.rows === d.ids.length, 'rows = число уникальных экземпляров (D13)'); check(d.hosts.reduce((s, h) => s + h.n, 0) === d.ids.length, 'сумма n по узлам = число экземпляров'); check(d.cves.every(c => !c.vulnId || /^[0-9a-f-]{36}$/i.test(c.vulnId)), 'vulnId в формате GUID'); }
  const dp = qp?.groups?.[0] && await run('queueDetail packages', () => VR.queueDetail({ scope: 'packages', soft: qp.groups[0].soft, ver: qp.groups[0].ver }), 'detailPkg');
  if (dp) console.log(`   rows=${dp.rows} hosts=${dp.hosts.length} cves=${dp.cves.length}`);
  const m = await run('metrics', () => VR.metrics({ deep: false }), 'metrics');
  if (m) { const c = VR.computeMetrics(m); console.log('   open', c.open, 'overdue', c.overdue, 'critOver', c.critOver, 'trend', c.trend, 'new30', c.new30, 'assets', c.assets); console.log('   trendTop0', JSON.stringify(m.trendTop[0])); check(c.open > 0 && c.open === c.total - (c.st.fixed || 0) - (c.st.excluded || 0), 'open = total - fixed - excluded'); check(Object.values(c.bySev).every(b => b.open === b.over + b.soon + b.ok), 'bySev: open = over + soon + ok'); check(c.overdue <= c.open, 'overdue <= open');
    // число в KPI совпадает с выборкой по клику (D7): корзина возраста «0-7»
    const dr = await run('drill age 0-7 count', () => VR.pdql(VR.drillPdql('age', '0-7').replace(/\| sort\(.*$/, '') + ' | group(COUNT(*) as N)', 5, 0));
    const n = dr && VR.num(VR.rowVal(VR.rows(dr)[0] || {}, 'N')); if (n != null) check(Math.abs(n - c.age['0-7']) <= Math.max(5, c.age['0-7'] * 0.01), `KPI 0-7 (${c.age['0-7']}) совпадает с выборкой (${n})`); }
  const cm = await run('commands', () => VR.commands('new')); console.log('  ', JSON.stringify(cm)); check(Array.isArray(cm) || (cm && typeof cm === 'object'), 'commands: список команд');
  const pj = await run('projects prefix', () => VR.projects({ prefix: 'proj:' })); if (pj) check(pj.projects.every(p => /^proj:/i.test(p.tag)), 'projects(prefix): только метки с префиксом (D6)');
  fs.writeFileSync(path.join(OUT, 'fixtures.json'), JSON.stringify(fixtures));
  console.log('\nfixtures saved:', Object.keys(fixtures), '->', OUT);
}
if (mode === 'new') {
  const a = await run('assetRisk', () => VR.assetRisk({ limit: 500 }), 'assetRisk');
  if (a) { console.log(`   assets=${a.assets.length} truncated=${a.truncated}`); a.assets.slice(0, 3).forEach(x => console.log('   ', JSON.stringify({ host: x.host, imp: x.imp, risk: x.risk, n: x.n, crit: x.crit, trend: x.trend, drivers: x.drivers.map(d => d[0] + ':' + Math.round(d[1])) }))); console.log('   byImp', JSON.stringify(a.byImp)); }
  const x = await run('exclusions', () => VR.exclusions({ limit: 5000 }), 'exclusions');
  if (x) { console.log(`   total=${x.total} risky=${x.risky.length} groups=${x.groups.length}`); console.log('   byReason', JSON.stringify(x.byReason)); console.log('   group0', JSON.stringify({ ...x.groups[0], ids: x.groups[0]?.ids.length })); }
  const pj = await run('projects', () => VR.projects({}), 'projects');
  if (pj) console.log('   projects', JSON.stringify(pj.projects.slice(0, 5)));
  const m = await run('metrics', () => VR.metrics({ deep: false }), 'metrics');
  if (m) { const c = VR.computeMetrics(m); console.log('   open', c.open, 'overdue', c.overdue, 'soon', c.soon, 'bySev', JSON.stringify(c.bySev)); }
  const prev = fs.existsSync(path.join(OUT, 'fixtures.json')) ? JSON.parse(fs.readFileSync(path.join(OUT, 'fixtures.json'), 'utf8')) : {};
  fs.writeFileSync(path.join(OUT, 'fixtures.json'), JSON.stringify({ ...prev, ...fixtures }));
  console.log('fixtures updated');
}
if (mode === 'asset') {
  const id = process.argv[3] || '1e556a88-a6c0-0001-0000-00000000014a';
  const a = await run('assetVulns', () => VR.assetVulns(id));
  if (a) { console.log(`   host=${a.host} items=${a.items.length}`, JSON.stringify(a.items[0])); const issue = VR.buildAssetJiraIssue({ asset: a, sla: { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30 }, host: HOST }); console.log('   summary:', issue.summary, '| priority', issue.priority, '| due', issue.dueDate, '| ids', issue.ids.length, '| csv bytes', issue.csv.length); console.log(issue.description.split('\n').slice(0, 8).join('\n')); }
}
if (mode === 'status') {
  if (!ALLOW_WRITE) { console.error('Режим status меняет данные стенда: задайте MP_ALLOW_WRITE=1'); process.exit(1); }
  const id = process.argv[3]; if (!id) { console.error('Нужен instanceId'); process.exit(1); }
  const statusOf = async () => { const rows = VR.rows(await VR.pdql(`filter(Host.@Vulners) | select(Host.@Vulners.Id as Id, Host.@Vulners.Status as St) | filter(Id = "${id}")`, 5, 0)); return rows.length ? VR.rowVal(rows[0], 'St') : null; };
  const CMD = { new: 'SwitchToNewStateCommand', inProgress: 'SwitchToInProgressStateCommand', awaitingFix: 'SwitchToAwaitingFixStateCommand', excluded: 'SwitchToExcludeStateCommand' };
  const orig = await run('исходный статус', statusOf); console.log('   статус:', orig);
  check(orig != null, 'экземпляр найден по Id');
  if (orig == null) process.exit(1);
  try {
    const target = orig === 'inProgress' ? 'SwitchToNewStateCommand' : 'SwitchToInProgressStateCommand';
    const r1 = await run('смена статуса', () => VR.changeStatus({ ids: [id], command: target })); console.log('  ', JSON.stringify(r1));
    check(r1 && r1.done === true && r1.succeed === 1, 'операция завершена, succeed = 1');
    const now = await statusOf(); check(now !== orig, `статус изменился: ${orig} -> ${now}`);
  } finally {
    const back = CMD[orig] || 'SwitchToNewStateCommand';
    const r2 = await run('восстановление', () => VR.changeStatus({ ids: [id], command: back, tillDate: back === 'SwitchToAwaitingFixStateCommand' ? new Date(Date.now() + 7 * 864e5).toISOString() : undefined }));
    console.log('  ', JSON.stringify(r2));
    const fin = await statusOf(); check(fin === orig, `исходный статус восстановлен: ${fin}`);
    if (orig === 'awaitingFix' || orig === 'excluded') console.log('   внимание: срок/причина/комментарий исходного статуса не восстанавливаются');
  }
}
if (mode === 'v4') {
  // Новое в 0.4: очередь ОС и образов, drill-down, риск v2 (ФСТЭК), паспорт и целевая версия, теги, веб
  const qo = await run('queue os', () => VR.queue({ scope: 'os', minScore: 0, limit: 100 }), 'queueOs');
  if (qo) { console.log(`   groups=${qo.totalGroups}`); qo.groups.slice(0, 3).forEach(g => console.log('   ', JSON.stringify(g))); }
  const dos = qo?.groups?.[0] && await run('queueDetail os', () => VR.queueDetail({ scope: 'os', soft: qo.groups[0].soft, ver: qo.groups[0].ver }), 'detailOs');
  if (dos) console.log(`   rows=${dos.rows} hosts=${dos.hosts.length} cves=${dos.cves.length} vulnId0=${dos.cves[0]?.vulnId} hostId0=${dos.hosts[0]?.id}`);
  const qi = await run('queue images', () => VR.queue({ scope: 'images', minScore: 0, limit: 100 }), 'queueImages');
  if (qi) { console.log(`   groups=${qi.totalGroups}`); qi.groups.slice(0, 2).forEach(g => console.log('   ', JSON.stringify(g))); }
  const di = qi?.groups?.[0] && await run('queueDetail images', () => VR.queueDetail({ scope: 'images', soft: qi.groups[0].pkg, ver: qi.groups[0].ver, pkg: qi.groups[0].pkg }), 'detailImages');
  if (di) console.log(`   rows=${di.rows} images=${di.hosts.length} cves=${di.cves.length}`, JSON.stringify(di.hosts[0]));
  const im = await run('imageSummary', () => VR.imageSummary(), 'images'); if (im) console.log('   images', im.length, JSON.stringify(im[0]));
  const wv = await run('webVulns', () => VR.webVulns({}), 'web'); if (wv) console.log('   web sites', wv.sites.length, 'items', wv.items.length);
  const sla = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30, slaLowDays: 90 };
  for (const [kind, arg] of [['open'], ['overdue', sla], ['soon', { ...sla, h: 6, m: 24, l: 72 }], ['sev', 'critical'], ['sevOverdue', { sev: 'critical', days: 1 }], ['trend'], ['exploit'], ['new30'], ['status', 'fixed'], ['age', { from: 91 }], ['age', { from: 8, to: 31 }], ['noImportance'], ['staleScan']]) {
    const r = await run(`drill ${kind} ${JSON.stringify(arg || '')}`, () => VR.drill({ pdql: VR.drillPdql(kind, arg), limit: 50 }), kind === 'open' ? 'drillOpen' : undefined);
    if (r) console.log(`   items=${r.items.length} truncated=${r.truncated}`, JSON.stringify(r.items[0] || {}).slice(0, 300));
  }
  const cve = dos?.cves?.[0]?.cve || 'CVE-2021-44228';
  const rc = await run(`drill cve ${cve}`, () => VR.drill({ pdql: VR.drillPdql('cve', cve), limit: 20 })); if (rc) console.log('   items', rc.items.length, 'vulnId', rc.items[0]?.vulnId);
  const gid = await run('guidByCve', () => VR.guidByCve(cve)); console.log('   guid', gid);
  const pass = gid && await run('passport', () => VR.passport(gid), 'passport');
  if (pass) console.log('   title', pass.title, '| howToFix:', String(pass.howToFix || '').slice(0, 200).replace(/\n/g, ' '), '| target', VR.targetVersionFromHowToFix(pass.howToFix));
  const ar = await run('assetRisk v2', () => VR.assetRisk({ limit: 1000 }), 'assetRisk');
  if (ar) { console.log(`   assets=${ar.assets.length}`); ar.assets.slice(0, 3).forEach(a => console.log('   ', JSON.stringify({ host: a.host, id: a.id, imp: a.imp, type: a.type, risk: a.risk, zone: a.zone, fstecMax: +a.fstecMax.toFixed(1), fstecLevel: a.fstecLevel, n: a.n }))); console.log('   byZone', JSON.stringify(ar.byZone)); console.log('   byType', JSON.stringify(ar.byType.slice(0, 4))); console.log('   byOs', JSON.stringify(ar.byOs.slice(0, 3))); check(ar.assets.every(a => a.risk >= 0 && a.risk <= 1000), 'риск в [0,1000]'); }
  const ai = dos && await run('assetsInfo', () => VR.assetsInfo(dos.hosts.slice(0, 20).map(h => h.id))); if (ai) console.log('   hosts', Object.keys(ai).length, JSON.stringify(Object.values(ai)[0]));
  if (dos && pass) { const issue = VR.buildJiraIssue({ detail: dos, group: qo.groups[0], enrich: null, sla, host: HOST, passports: { [cve]: pass }, assetsInfo: ai || {} }); console.log('   jira summary:', issue.summary, '| target', issue.targetVersion); console.log(issue.description.split('\n').slice(0, 20).join('\n')); }
  const tags = await run('assetTags', () => VR.assetTags()); if (tags) console.log('   tags', tags.length, JSON.stringify(tags.slice(0, 3)));
  const cov = await run('tagCoverage', () => VR.tagCoverage(), 'tagCoverage'); if (cov) console.log('   coverage', JSON.stringify(cov.slice(0, 5)));
  const m = await run('metrics', () => VR.metrics({ deep: false }), 'metrics'); if (m) console.log('   topHosts0', JSON.stringify(m.topHosts[0]));
  const prev = fs.existsSync(path.join(OUT, 'fixtures.json')) ? JSON.parse(fs.readFileSync(path.join(OUT, 'fixtures.json'), 'utf8')) : {};
  fs.writeFileSync(path.join(OUT, 'fixtures.json'), JSON.stringify({ ...prev, ...fixtures }));
  console.log('fixtures updated');
}
if (mode === 'risk') {
  const ar = await run('assetRisk v2', () => VR.assetRisk({ limit: 1000 }), 'assetRisk');
  if (ar) { console.log(`   assets=${ar.assets.length}`); ar.assets.slice(0, 3).forEach(a => console.log('   ', JSON.stringify({ host: a.host, imp: a.imp, type: a.type, risk: a.risk, raw: a.raw, ctx: +a.ctx.toFixed(2), E: a.cE, V: a.cV, T: a.cT, F: a.cF, zone: a.zone, fstecMax: +a.fstecMax.toFixed(1), fstecLevel: a.fstecLevel, n: a.n, max: a.maxScore, avg: a.avgScore, why: a.why }))); console.log('   worst 2', JSON.stringify(ar.assets.slice(-2).map(a => ({ host: a.host, risk: a.risk, E: a.cE, V: a.cV, T: a.cT, F: a.cF, n: a.n })))); console.log('   byZone', JSON.stringify(ar.byZone));
    const rs = ar.assets.map(a => a.risk).sort((a, b) => b - a); const qn = p => rs[Math.floor((rs.length - 1) * p)]; console.log('   квантили риска: max', rs[0], 'p10', qn(0.1), 'p25', qn(0.25), 'median', qn(0.5), 'p75', qn(0.75), 'min', rs[rs.length - 1]);
    const t0 = Date.now(); await run('assetRiskKev', () => VR.assetRiskKev(ar, { limit: 100 })); console.log('   kevChecked', ar.kevChecked, 'top after KEV', JSON.stringify(ar.assets.slice(0, 2).map(a => ({ host: a.host, risk: a.risk, kev: a.kev, T: a.cT }))), ((Date.now() - t0) / 1000).toFixed(1) + 's'); console.log('   byType', JSON.stringify(ar.byType.slice(0, 4))); console.log('   byImp', JSON.stringify(ar.byImp)); const prev = JSON.parse(fs.readFileSync(path.join(OUT, 'fixtures.json'), 'utf8')); fs.writeFileSync(path.join(OUT, 'fixtures.json'), JSON.stringify({ ...prev, ...fixtures })); }
  console.log('   target(Windows 2016 10.0.14393):', VR.targetVersionFromHowToFix('Windows 2016: v1607 - KB4601318 - 10.0.14393.4225; Windows 2019: 10.0.17763.1757; Windows 10 v2004 10.0.19041.1889', '10.0.14393'));
  console.log('   target(OpenSSL 3.0.2):', VR.targetVersionFromHowToFix('Обновите OpenSSL до версии 3.0.15, 3.1.7, 3.2.3 или 3.3.2', '3.0.2'));
  console.log('   target(7-Zip 24.07):', VR.targetVersionFromHowToFix('обновите до 24.09', '24.07'));
}
if (mode === 'instance') {
  // Контекст экземпляра по CVE: instance <CVE> [instanceId|assetId]
  const cve = process.argv[3] || 'CVE-2025-49723', ref = process.argv[4] || '';
  const ctx = await run('instanceContext', () => VR.instanceContext({ cve, instanceId: /_/.test(ref) ? ref : undefined, assetId: !/_/.test(ref) && ref ? ref : undefined, limit: 50 }));
  if (ctx) {
    console.log(`   экземпляров ${ctx.instances.summary.total} на ${ctx.instances.summary.hosts} узлах, открыто ${ctx.instances.summary.open}, max ${ctx.instances.summary.maxScore}, pickedBy ${ctx.pickedBy}`);
    check(ctx.instances.items.length > 0, 'экземпляры найдены');
    check(ctx.instances.items.every(i => /^[0-9a-f-]{36}$/i.test(i.hostId) && /^[0-9a-f-]{36}$/i.test(i.vulnId)), 'hostId и vulnId в формате GUID');
    const sel = ctx.selected || await run('instanceDetailContext (первый)', () => VR.instanceDetailContext(ctx.instances.items[0]));
    if (sel) {
      console.log('   det:', JSON.stringify(sel.det && { product: sel.det.product, os: sel.det.os, release: sel.det.release, label: sel.det.versionLabel, current: sel.det.current, required: sel.det.required }));
      console.log('   fix:', JSON.stringify(sel.fix)); console.log('   patch:', JSON.stringify(sel.patch)); console.log('   metrics:', JSON.stringify(sel.metrics), 'bdu:', JSON.stringify(sel.bdu), 'links:', sel.links.length, 'errors:', JSON.stringify(sel.errors));
      check(sel.errors.length === 0, 'все запросы деталей успешны');
      check(sel.det && sel.det.current, 'условия обнаружения с текущей версией');
      check(sel.fix.min && (!sel.det?.required || sel.fix.min.version === sel.det.required || VR.cmpVersion(sel.fix.min.version, sel.det.current) > 0), 'целевая версия не ниже требуемой');
      check(sel.patch && sel.patch.url, 'патч со ссылкой');
      const issue = VR.buildInstanceJiraIssue({ ctx: { ...sel, cve }, enrich: null, sla: { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30 }, host: HOST });
      console.log('   summary:', issue.summary); console.log(issue.description.split('\n').slice(0, 12).join('\n'));
      check(issue.ids.length === 1 && issue.ids[0] === sel.item.id, 'задача на один экземпляр');
    }
  }
}
if (mode === 'patches') {
  const pt = await run('patches', () => VR.patches({}), 'patches');
  if (pt) {
    console.log(`   патчей ${pt.total.patches}, уязвимостей ${pt.total.vulns}, узлов ${pt.total.hosts}; без ссылки ${pt.total.noLinkVulns} на ${pt.total.noLinkHosts} узлах`);
    pt.patches.slice(0, 5).forEach(p => console.log('   ', JSON.stringify({ patch: p.patch, n: p.n, hosts: p.hostsCount, url: p.url, date: p.date, trend: p.trend, crit: p.crit })));
    check(pt.patches.length > 0, 'патчи найдены'); check(pt.patches.every((p, i) => i === 0 || pt.patches[i - 1].n >= p.n), 'сортировка по числу уязвимостей'); check(pt.patches.filter(p => p.url).length > 0, 'есть ссылки на патчи');
    const small = pt.patches.slice().sort((a, b) => a.n - b.n).find(p => p.n >= 10 && p.n <= 2000) || pt.patches[pt.patches.length - 1];
    const d = await run(`patchDetail ${small.patch}`, () => VR.patchDetail({ patch: small.patch }), 'patchDetail');
    if (d) { console.log(`   rows=${d.rows} hosts=${d.hosts.length} cves=${d.cves.length} vulns=${d.vulns.length} ids=${d.ids.length}`); check(d.hosts.length === small.hostsCount, `узлов в деталях (${d.hosts.length}) = узлов в сводке (${small.hostsCount})`); check(d.rows === small.n || d.truncated, `экземпляров в деталях (${d.rows}) = сводке (${small.n})`); const issue = VR.buildPatchJiraIssue({ patch: small, detail: d, enrich: null, sla: { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30 }, host: HOST }); console.log('   summary:', issue.summary); }
    const prev = fs.existsSync(path.join(OUT, 'fixtures.json')) ? JSON.parse(fs.readFileSync(path.join(OUT, 'fixtures.json'), 'utf8')) : {}; fs.writeFileSync(path.join(OUT, 'fixtures.json'), JSON.stringify({ ...prev, ...fixtures }));
  }
}
if (mode === 'tags') {
  if (!ALLOW_WRITE) { console.error('Режим tags меняет данные стенда: задайте MP_ALLOW_WRITE=1'); process.exit(1); }
  // Цикл тегов на одном узле и уникальном теге: создать, назначить, проверить, снять, удалить (в finally)
  const name = `auto:test-vr-${Date.now().toString(36)}`;
  const one = VR.rows(await VR.pdql('filter(Host.@Vulners) | select(@Host)', 1, 0)); const hostId = VR.getVal(one[0] || {}, '@Host')?.id;
  check(!!hostId, 'тестовый узел найден'); if (!hostId) process.exit(1);
  let tag = null;
  try {
    tag = await run('createAssetTag', () => VR.createAssetTag(name, 'grey')); check(tag && tag.id, 'тег создан');
    const r1 = await run('assignAssetTagsByIds', () => VR.assignAssetTagsByIds({ ids: [hostId], addIds: [tag.id] })); console.log('  ', JSON.stringify(r1));
    check(r1 && r1.count === 1 && r1.failed === 0 && r1.requested === 1, 'назначен ровно одному узлу');
    const c = await run('tagCoverage', () => VR.tagCoverage()); const cov = c?.find(x => x.tag === name); console.log('  ', JSON.stringify(cov)); check(cov && cov.n === 1, 'покрытие: тег на одном узле');
  } finally {
    if (tag?.id) {
      const r2 = await run('removeAutoTags exact', () => VR.removeAutoTags({ prefix: name, exact: true })); console.log('  ', JSON.stringify(r2));
      check(r2 && r2.length === 1 && r2[0].ok, 'тег снят и удален');
      const tags = await VR.assetTags(); check(!(tags || []).some(t => t.name === name), 'тега больше нет в системе');
    }
  }
}

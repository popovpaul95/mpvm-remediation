'use strict';
// Логика модуля: очередь устранения, детали группы, метрики, смена статусов.
// Все запросы к MaxPatrol VM идут через VR.pdql / VR.get / VR.post (api.js).
(function (VR) {
  const OPEN = '["new","inProgress","awaitingFix","overdue","stale"]';
  const esc = s => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  // ── Очередь: группировка открытых уязвимостей по ПО + версия ─────────────
  function queuePdql(scope, minScore) {
    if (scope === 'os') {
      // Уязвимости ОС: Host.@NodeVulners (объект уязвимости = сам узел); ПО живет в Host.Softs.@NodeVulners
      return `filter(Host.@NodeVulners and Host.@NodeVulners.Status in ${OPEN})`
        + ' | select(Host.OsName as Soft, Host.OsVersion as Ver, @Host, Host.@NodeVulners.Score as Score, Host.@NodeVulners.IsTrend as T, Host.@NodeVulners.Metrics.Exploitable as E, Host.@NodeVulners.Metrics.HasPatch as P, Host.@NodeVulners.Status as St)'
        + ` | filter(St in ${OPEN}${minScore > 0 ? ' and Score >= ' + minScore : ''})`
        + ' | calc(if T = true then 1 else 0 as fT) | calc(if E = true then 1 else 0 as fE) | calc(if P = true then 1 else 0 as fP) | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 then 1 else 0 as fH)'
        + ' | group(Soft, Ver, COUNT(*) as N, COUNTUNIQUE(@Host) as Hosts, MAX(Score) as MaxScore, SUM(fT) as Trend, SUM(fE) as Expl, SUM(fP) as Patch, SUM(fC) as Crit, SUM(fH) as High) | sort(N desc)';
    }
    if (scope === 'images') {
      return `filter(ImageSet.Images.Packages.@Vulners and ImageSet.Images.Packages.@Vulners.Status in ${OPEN})`
        + ' | select(@ImageSet, ImageSet.Images.Packages.Name as Pkg, ImageSet.Images.Packages.Version as Ver, ImageSet.Images.Packages.@Vulners.Score as Score, ImageSet.Images.Packages.@Vulners.Status as St)'
        + ` | filter(St in ${OPEN}${minScore > 0 ? ' and Score >= ' + minScore : ''})`
        + ' | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 then 1 else 0 as fH)'
        + ' | group(@ImageSet, Pkg, Ver, COUNT(*) as N, MAX(Score) as MaxScore, SUM(fC) as Crit, SUM(fH) as High) | sort(N desc)';
    }
    const sc = minScore > 0 ? ` and ${scope === 'packages' ? 'UnixHost.Packages.@Vulners' : 'Host.Softs.@NodeVulners'}.Score >= ${minScore}` : '';
    if (scope === 'packages') {
      return `filter(UnixHost.Packages.@Vulners and UnixHost.Packages.@Vulners.Status in ${OPEN}${sc})`
        + ' | select(UnixHost.Packages.Name as Soft, UnixHost.Packages.Version as Ver, UnixHost.@Id as HostId, UnixHost.Packages.@Vulners.Score as Score, UnixHost.Packages.@Vulners.IsTrend as T, UnixHost.Packages.@Vulners.Metrics.Exploitable as E, UnixHost.Packages.@Vulners.Metrics.HasPatch as P, UnixHost.Packages.@Vulners.Status as St)'
        + ` | filter(St in ${OPEN}${minScore > 0 ? ' and Score >= ' + minScore : ''})`
        + ' | calc(if T = true then 1 else 0 as fT) | calc(if E = true then 1 else 0 as fE) | calc(if P = true then 1 else 0 as fP) | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 then 1 else 0 as fH)'
        + ' | group(Soft, Ver, COUNT(*) as N, COUNTUNIQUE(HostId) as Hosts, MAX(Score) as MaxScore, SUM(fT) as Trend, SUM(fE) as Expl, SUM(fP) as Patch, SUM(fC) as Crit, SUM(fH) as High) | sort(N desc)';
    }
    return `filter(Host.Softs.@NodeVulners and Host.Softs.@NodeVulners.Status in ${OPEN}${sc})`
      + ' | select(Host.Softs.Name as Soft, Host.Softs.Version as Ver, @Host, Host.Softs.@NodeVulners.Score as Score, Host.Softs.@NodeVulners.IsTrend as T, Host.Softs.@NodeVulners.Metrics.Exploitable as E, Host.Softs.@NodeVulners.Metrics.HasPatch as P, Host.Softs.@NodeVulners.Status as St)'
      + ` | filter(St in ${OPEN}${minScore > 0 ? ' and Score >= ' + minScore : ''})`
      + ' | calc(if T = true then 1 else 0 as fT) | calc(if E = true then 1 else 0 as fE) | calc(if P = true then 1 else 0 as fP) | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 then 1 else 0 as fH)'
      + ' | group(Soft, Ver, COUNT(*) as N, COUNTUNIQUE(@Host) as Hosts, MAX(Score) as MaxScore, SUM(fT) as Trend, SUM(fE) as Expl, SUM(fP) as Patch, SUM(fC) as Crit, SUM(fH) as High) | sort(N desc)';
  }
  function detailPdql(scope, soft, ver) {
    if (scope === 'os') {
      return `filter(Host.OsName = "${esc(soft)}" and Host.OsVersion = "${esc(ver)}" and Host.@NodeVulners and Host.@NodeVulners.Status in ${OPEN})`
        + ' | select(@Host, Host.OsName as Soft, Host.OsVersion as Ver, Host.@NodeVulners.Id as Id, Host.@NodeVulners.CVEs.Item as CVE, Host.@NodeVulners.Score as Score, Host.@NodeVulners.IsTrend as T, Host.@NodeVulners.Metrics.Exploitable as E, Host.@NodeVulners.Status as St)'
        + ` | filter(St in ${OPEN})`;
    }
    if (scope === 'images') {
      return `filter(ImageSet.Images.Packages[Name = "${esc(soft)}" and Version = "${esc(ver)}"] and ImageSet.Images.Packages.@Vulners.Status in ${OPEN})`
        + ' | select(@ImageSet, ImageSet.Images.Packages.Name as Soft, ImageSet.Images.Packages.Version as Ver, ImageSet.Images.Packages.@Vulners.Id as Id, ImageSet.Images.Packages.@Vulners.CVEs.Item as CVE, ImageSet.Images.Packages.@Vulners.Score as Score, ImageSet.Images.Packages.@Vulners.Status as St)'
        + ` | filter(Soft = "${esc(soft)}" and Ver = "${esc(ver)}" and St in ${OPEN})`;
    }
    const cond = `Name = "${esc(soft)}" and Version = "${esc(ver)}"`;
    if (scope === 'packages') {
      return `filter(UnixHost.Packages[${cond}] and UnixHost.Packages.@Vulners.Status in ${OPEN})`
        + ' | select(UnixHost.@Id as HostId, UnixHost.Fqdn as Host, UnixHost.IpAddress as Ip, UnixHost.Packages.Name as Soft, UnixHost.Packages.Version as Ver, UnixHost.Packages.@Vulners.Id as Id, UnixHost.Packages.@Vulners.CVEs.Item as CVE, UnixHost.Packages.@Vulners.Score as Score, UnixHost.Packages.@Vulners.IsTrend as T, UnixHost.Packages.@Vulners.Metrics.Exploitable as E, UnixHost.Packages.@Vulners.Status as St)'
        + ` | filter(Soft = "${esc(soft)}" and Ver = "${esc(ver)}" and St in ${OPEN})`;
    }
    return `filter(Host.Softs[${cond}] and Host.Softs.@NodeVulners.Status in ${OPEN})`
      + ' | select(@Host, Host.Softs.Name as Soft, Host.Softs.Version as Ver, Host.Softs.@NodeVulners.Id as Id, Host.Softs.@NodeVulners.CVEs.Item as CVE, Host.Softs.@NodeVulners.Score as Score, Host.Softs.@NodeVulners.IsTrend as T, Host.Softs.@NodeVulners.Metrics.Exploitable as E, Host.Softs.@NodeVulners.Status as St)'
      + ` | filter(Soft = "${esc(soft)}" and Ver = "${esc(ver)}" and St in ${OPEN})`;
  }
  const groupRisk = g => (g.n || 0) + (g.high || 0) * 2 + (g.crit || 0) * 4 + (g.expl || 0) * 3 + (g.trend || 0) * 8 + (g.kev || 0) * 12;

  const SCOPES = ['softs', 'packages', 'os', 'images'];
  VR.queue = async ({ scope = 'softs', minScore = 0, limit = 300 } = {}) => {
    scope = SCOPES.includes(scope) ? scope : 'softs';
    const pdql = queuePdql(scope, VR.num(minScore) || 0);
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const groups = rows.map(r => ({
      soft: scope === 'images' ? `${VR.rowVal(r, '@ImageSet')} : ${VR.rowVal(r, 'Pkg')}` : VR.rowVal(r, 'Soft'), ver: VR.rowVal(r, 'Ver'),
      image: scope === 'images' ? VR.rowVal(r, '@ImageSet') : undefined, pkg: scope === 'images' ? VR.rowVal(r, 'Pkg') : undefined,
      n: VR.num(VR.rowVal(r, 'N')) || 0, hosts: VR.num(VR.rowVal(r, 'Hosts')) || 0, maxScore: VR.num(VR.rowVal(r, 'MaxScore')),
      trend: VR.num(VR.rowVal(r, 'Trend')) || 0, expl: VR.num(VR.rowVal(r, 'Expl')) || 0, patch: VR.num(VR.rowVal(r, 'Patch')) || 0,
      crit: VR.num(VR.rowVal(r, 'Crit')) || 0, high: VR.num(VR.rowVal(r, 'High')) || 0,
    })).filter(g => g.soft);
    groups.forEach(g => { g.risk = groupRisk(g); });
    const byProduct = {};
    groups.forEach(g => {
      const a = byProduct[g.soft] || (byProduct[g.soft] = { soft: g.soft, versions: 0, n: 0, hosts: 0, trend: 0, expl: 0, crit: 0, high: 0, maxScore: 0, risk: 0 });
      a.versions++; a.n += g.n; a.hosts += g.hosts; a.trend += g.trend; a.expl += g.expl; a.crit += g.crit; a.high += g.high; a.maxScore = Math.max(a.maxScore, g.maxScore || 0); a.risk += g.risk;
    });
    return { scope, minScore, pdql, groups: groups.sort((a, b) => b.risk - a.risk), products: Object.values(byProduct).sort((a, b) => b.risk - a.risk), totalGroups: groups.length, limit, truncated: rows.length >= limit };
  };

  VR.queueDetail = async ({ scope, soft, ver, limit = 20000, pkg }) => {
    scope = SCOPES.includes(scope) ? scope : 'softs';
    const pdql = detailPdql(scope, scope === 'images' ? (pkg || soft) : soft, ver);
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    // Строка PDQL = пара (экземпляр, CVE): экземпляр с двумя CVE приходит двумя строками, считаем экземпляры по Id
    const hosts = {}, cves = {}, ids = new Set();
    rows.forEach(r => {
      const hostObj = VR.getVal(r, scope === 'images' ? '@ImageSet' : '@Host');
      const hostName = scope === 'packages' ? (VR.rowVal(r, 'Host') || VR.rowVal(r, 'Ip')) : (hostObj?.name || VR.rowVal(r, scope === 'images' ? '@ImageSet' : '@Host'));
      const hostId = scope === 'packages' ? VR.rowVal(r, 'HostId') : (hostObj?.id || '');
      const cve = VR.rowVal(r, 'CVE'), id = VR.rowVal(r, 'Id'), score = VR.num(VR.rowVal(r, 'Score'));
      const h = hosts[hostName] || (hosts[hostName] = { host: hostName, id: hostId, n: 0, maxScore: 0, _ids: new Set() });
      if (id) { if (!h._ids.has(id)) { h._ids.add(id); h.n++; } } else h.n++;
      h.maxScore = Math.max(h.maxScore, score || 0);
      if (cve) {
        const c = cves[cve] || (cves[cve] = { cve, n: 0, score: 0, trend: false, exploit: false, vulnId: VR.vulnGuid(id) });
        c.n++; c.score = Math.max(c.score, score || 0);
        if (VR.bool(VR.rowVal(r, 'T'))) c.trend = true;
        if (VR.bool(VR.rowVal(r, 'E'))) c.exploit = true;
      }
      if (id) ids.add(id);
    });
    return { scope, soft, ver, pdql, rows: ids.size || rows.length, rawRows: rows.length, truncated: rows.length >= limit,
      hosts: Object.values(hosts).map(h => { const { _ids, ...rest } = h; return rest; }).sort((a, b) => b.maxScore - a.maxScore || b.n - a.n),
      cves: Object.values(cves).sort((a, b) => b.score - a.score), ids: [...ids] };
  };

  // GUID паспорта уязвимости из составного Id экземпляра (asset_object_vuln)
  VR.vulnGuid = id => { const s = String(id || '').split('_')[2] || ''; return /^[0-9a-f]{32}$/i.test(s) ? s.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5') : null; };
  VR.passportUrl = guid => guid ? `${location.origin}/mpx/vm/vulnerability-passport-card?vulnerabilityId=${guid}` : null;
  VR.assetUrl = assetId => assetId ? `${location.origin}/mpx/common/am/assets?groupId=00000000-0000-0000-0000-000000000002&viewMode=list&assetId=${assetId}&tabName=summary` : null;
  VR.kevUrl = cve => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}`;
  // Паспорт уязвимости (описание, рекомендации по устранению)
  VR.passport = async guid => VR.get(`/api/assets_temporal_readmodel/v1/vulnerabilities/${guid}`);
  // GUID паспорта по CVE (первый экземпляр)
  VR.guidByCve = async cve => { const rows = VR.rows(await VR.pdql(`filter(Host.@Vulners.CVEs.Item = "${esc(cve)}") | select(Host.@Vulners.Id as Id, Host.@Vulners.CVEs.Item as CVE) | filter(CVE = "${esc(cve)}") | limit(1)`, 1, 0)); return rows.length ? VR.vulnGuid(VR.rowVal(rows[0], 'Id')) : null; };
  // ── Версии: сравнение с суффиксами (1.1.1k, 2.34-0ubuntu3.1, 1:2.0), выбор целевой версии из «Как исправить» ──
  const verTokens = v => String(v ?? '').match(/\d+|[a-z]+/gi) || [];
  VR.cmpVersion = (a, b) => {
    const x = verTokens(a), y = verTokens(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const p = x[i], q = y[i];
      if (p === undefined) return -1; if (q === undefined) return 1;
      const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
      if (pn && qn) { const d = Number(p) - Number(q); if (d) return d; }
      else if (pn !== qn) return pn ? 1 : -1;
      else { const c = p.localeCompare(q); if (c) return c; }
    }
    return 0;
  };
  // Кандидаты версий в тексте: не даты (15.01.2024), не IP-адреса (10.0.0.1), не оценки CVSS («CVSS 9.8»)
  VR.versionCandidates = text => {
    const s = String(text || ''), out = [];
    const re = /(?<![\w.])(\d+(?:\.\d+)+)((?:[a-z](?![a-z]))|(?:[-+~][0-9a-z.+~]*[0-9a-z]))?/gi;
    let m;
    while ((m = re.exec(s))) {
      const v = m[1] + (m[2] || ''), before = s.slice(Math.max(0, m.index - 12), m.index);
      const parts = m[1].split('.');
      if (!m[2] && parts.length === 3 && /^\d{1,2}\.\d{1,2}\.\d{4}$/.test(m[1]) && +parts[0] <= 31 && +parts[1] <= 12) continue; // дата
      if (!m[2] && parts.length === 4 && parts.every(x => x.length <= 3 && +x <= 255)) continue; // IP-адрес
      if (/cvss\S*\s*$/i.test(before)) continue; // оценка CVSS
      out.push(v);
    }
    return out;
  };
  // Целевая версия: из версий текста берется ветка текущей версии (общий числовой префикс), только не ниже текущей;
  // без текущей версии берется максимальная. Если подходящих нет, null (в задаче будет «до актуальной версии вендора»).
  VR.targetVersionFromHowToFix = (text, current) => {
    let vers = VR.versionCandidates(text);
    if (!vers.length) return null;
    if (current) {
      const cur = []; for (const x of verTokens(current)) { if (/^\d+$/.test(x)) cur.push(x); else break; }
      const numPrefix = v => verTokens(v).slice(0, cur.length);
      let picked = null;
      for (let depth = cur.length; depth >= 1 && !picked; depth--) {
        const same = vers.filter(v => { const p = numPrefix(v); return cur.slice(0, depth).every((c, i) => p[i] !== undefined && Number(p[i]) === Number(c)) && VR.cmpVersion(v, current) > 0; });
        if (same.length) picked = same;
      }
      if (!picked) return null;
      vers = picked;
    }
    return vers.sort(VR.cmpVersion).pop();
  };
  // Срок по SLA от даты обнаружения (одно правило для блока экземпляра, отчета и задачи Jira)
  VR.slaDue = ({ found, sev, st, sla }) => {
    const days = { critical: sla?.slaCritDays ?? 1, high: sla?.slaHighDays ?? 7, medium: sla?.slaMedDays ?? 30, low: sla?.slaLowDays ?? 90 }[String(sev || '').toLowerCase()] ?? 30;
    const f = Date.parse(found); if (!Number.isFinite(f)) return { days, due: null, dueDate: null, overdue: false };
    const due = new Date(f + days * 864e5);
    return { days, due, dueDate: VR.localDate(due), overdue: Date.now() > due.getTime() && !/^(fixed|excluded)$/.test(String(st || '')) };
  };
  // Локальная дата YYYY-MM-DD (не UTC): срок «завтра» ночью по Москве не должен превращаться в «сегодня»
  VR.localDate = d => { const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; };
  VR.plusDays = n => { const x = new Date(); x.setDate(x.getDate() + (n || 0)); return VR.localDate(x); };
  // Метка Jira по названию ПО: транслитерация кириллицы, при пустом результате короткий хеш (метки разных продуктов не совпадают)
  const TRANSLIT = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z', и: 'i', й: 'j', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'c', ч: 'ch', ш: 'sh', щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya' };
  VR.jiraLabel = soft => {
    const s = String(soft || '').toLowerCase();
    const full = s.replace(/[а-яё]/g, ch => TRANSLIT[ch] ?? '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    let h = 5381; for (const ch of s) h = ((h * 33) ^ ch.charCodeAt(0)) >>> 0;
    if (!full) return 'mpvm-h' + h.toString(16);
    // Длинные названия (пакеты Linux с версией): префикс плюс хеш, чтобы разные версии не давали одну метку
    if (full.length > 40) return 'mpvm-' + full.slice(0, 28).replace(/-+$/, '') + '-' + h.toString(16).slice(0, 6);
    return 'mpvm-' + full;
  };
  // Ячейка CSV: кавычки по RFC 4180, переводы строк сохранены, формулы нейтрализованы апострофом.
  VR.csvCell = v => {
    let s = String(v ?? '').replace(/\r\n?/g, '\n');
    const lead = s.replace(/^[\s\uFEFF]+/, '');
    if (/^[=+@\t]/.test(lead) || (/^-/.test(lead) && !/^-?\d+([.,]\d+)?%?$/.test(lead))) s = "'" + s;
    return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  VR.csv = (rows, cols) => '﻿' + [cols.map(c => VR.csvCell(c[0])).join(';'), ...rows.map(r => cols.map(c => VR.csvCell(typeof c[1] === 'function' ? c[1](r) : r[c[1]])).join(';'))].join('\n');

  // ── Экземпляры уязвимости в MaxPatrol: по CVE, на активе, конкретный экземпляр ──
  // Экземпляр = составной Id `asset_object_vuln` (три сегмента по 32 hex). Карточка экземпляра в продукте:
  // /mpx/vm/vulnerability-card?vulnerabilityId=<guid паспорта>&vulnerabilityInstanceId=<Id>
  const hex32ToGuid = s => /^[0-9a-f]{32}$/i.test(s || '') ? s.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5') : null;
  VR.instanceAssetGuid = id => hex32ToGuid(String(id || '').split('_')[0]);
  VR.instanceUrl = id => { const g = VR.vulnGuid(id); return g ? `${location.origin}/mpx/vm/vulnerability-card?vulnerabilityId=${g}&vulnerabilityInstanceId=${id}` : null; };
  VR.cveInstances = async ({ cve, assetId, limit = 50 } = {}) => {
    if (!cve) throw new Error('Не указан CVE');
    if (assetId && !/^[0-9a-f-]{36}$/i.test(assetId)) throw new Error('Некорректный идентификатор актива');
    const V = 'Host.@Vulners';
    const pdql = `filter(${assetId ? `Host.@Id = ${assetId} and ` : ''}${V}.CVEs.Item = "${esc(cve)}") | select(@Host, Host.@Importance as Imp, Host.OsName as OS, ${V} as Name, ${V}.Id as Id, ${V}.Score as Score, ${V}.SeverityRating as Sev, ${V}.Status as St, ${V}.DiscoveryTime as Found, ${V}.IsTrend as T, ${V}.Metrics.Exploitable as E, ${V}.Metrics.HasPatch as P, ${V}.Patch.DisplayName as PatchName, ${V}.Patch.PatchLink as PatchLink, ${V}.CVEs.Item as CVE) | filter(CVE = "${esc(cve)}") | sort(Score desc)`;
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const byId = new Map();
    rows.forEach(r => {
      const id = VR.rowVal(r, 'Id'); if (!id || byId.has(id)) return;
      const h = VR.getVal(r, '@Host'), link = VR.getVal(r, 'PatchLink');
      byId.set(id, { id, host: h?.name || VR.rowVal(r, '@Host'), hostId: h?.id || VR.instanceAssetGuid(id), imp: VR.rowVal(r, 'Imp') || 'ND', os: VR.rowVal(r, 'OS'), name: VR.rowVal(r, 'Name'), vulnId: VR.vulnGuid(id), score: VR.num(VR.rowVal(r, 'Score')) || 0, sev: String(VR.rowVal(r, 'Sev') || '').toLowerCase(), st: VR.rowVal(r, 'St'), found: VR.rowVal(r, 'Found'), trend: VR.bool(VR.rowVal(r, 'T')), expl: VR.bool(VR.rowVal(r, 'E')), patch: VR.bool(VR.rowVal(r, 'P')), patchName: VR.rowVal(r, 'PatchName') || '', patchUrl: (link && typeof link === 'object' ? link.url : '') || '' });
    });
    const items = [...byId.values()];
    const summary = { total: items.length, hosts: new Set(items.map(i => i.hostId)).size, open: 0, byStatus: {}, maxScore: 0, trend: 0, expl: 0, patch: 0 };
    items.forEach(i => { summary.byStatus[i.st] = (summary.byStatus[i.st] || 0) + 1; if (!/^(fixed|excluded)$/.test(i.st)) summary.open++; summary.maxScore = Math.max(summary.maxScore, i.score); if (i.trend) summary.trend++; if (i.expl) summary.expl++; if (i.patch) summary.patch++; });
    return { cve, assetId: assetId || null, items, summary, pdql, truncated: rows.length >= limit };
  };
  const RM = '/api/assets_temporal_readmodel/v1';
  VR.instanceLocation = id => VR.get(`${RM}/vulnerabilities/instances/${id}/location`);
  VR.instanceStatusLog = id => VR.get(`${RM}/vulnerabilities/instances/${id}/statusLog`);
  VR.vulnStats = guid => VR.get(`${RM}/vulnerabilities/${guid}/statistics/assets`);
  // Детали экземпляра (то, что показывает карточка): метрики CVSS актива, условия обнаружения, статус, патч
  VR.instanceDetails = async id => {
    const loc = await VR.instanceLocation(id);
    if (!loc?.timelineToken) throw new Error('Местоположение экземпляра не получено');
    const d = await VR.get(`${RM}/assets/${loc.timelineToken}/objects/${loc.objectId}/vulnerabilities/${loc.vulnerabilityLegacyId}`);
    return { ...d, location: loc };
  };
  // Разбор условий обнаружения: продукт, ОС, выпуск, текущая версия и требуемая граница
  VR.parseDetection = details => {
    const c = details?.detectionInfo?.detectionDetails?.conditions; if (!c) return null;
    const conds = (c.productConditions || []).map(p => ({ name: p.propertyName || '', value: p.propertyValue ?? '', required: p.rightValue ?? null, strict: !!p.rightValueStrict, min: p.leftValue ?? null, type: p.type || '' }));
    const by = n => conds.find(p => new RegExp(n, 'i').test(p.name));
    const ver = conds.find(p => p.required != null) || by('верси|version');
    return { product: c.productName || '', className: c.productModelClassName || '', vulnerType: details?.detectionInfo?.vulnerType || '', detectedAt: details?.detectionInfo?.detectedAt || '', conditions: conds,
      os: by('название ос|^ос$|os name')?.value || null, release: by('выпуск|release')?.value || null, arch: by('архитектур|arch')?.value || null, installType: by('тип установки')?.value || null,
      versionLabel: ver?.name || 'Версия', current: ver?.value || null, required: ver?.required || null, requiredStrict: !!ver?.strict };
  };
  // Варианты исправления из «Как исправить» в ветке текущей версии: [{version, kb}], min и recommended
  VR.fixOptions = (howToFix, current) => {
    // Без текущей версии ветку выбрать нельзя: версии других веток ОС в задачу не попадают
    if (!current) return { options: [], min: null, recommended: null };
    const text = String(howToFix || ''); const cands = VR.versionCandidates(text); const out = []; let pos = 0;
    for (const v of cands) {
      const i = text.indexOf(v, pos); if (i < 0) continue; pos = i + v.length;
      // KB справа в скобках («10.0.20348.5622 (KB5122882)») или слева в той же строке до разделителя («KB5122882 - 10.0.20348.5622»)
      const after = text.slice(pos, pos + 24), kbAfter = (after.match(/^\s*[\(\[,;:\-–]*\s*(KB\d{5,8})/i) || [])[1];
      const backSeg = text.slice(Math.max(0, i - 40), i).split(/[\n;,()]/).pop(), kbBefore = (backSeg.match(/KB\d{5,8}/gi) || []).pop();
      const kb = kbAfter || kbBefore || null;
      out.push({ version: v, kb: kb ? kb.toUpperCase() : null });
    }
    let list = out;
    if (current) {
      const cur = []; for (const x of verTokens(current)) { if (/^\d+$/.test(x)) cur.push(x); else break; }
      const branch = cur.length > 1 ? cur.slice(0, cur.length - 1) : cur;
      list = out.filter(o => { const p = verTokens(o.version); return branch.every((c, i) => p[i] !== undefined && Number(p[i]) === Number(c)) && VR.cmpVersion(o.version, current) > 0; });
    }
    const seen = new Set(); list = list.filter(o => !seen.has(o.version) && seen.add(o.version)).sort((a, b) => VR.cmpVersion(a.version, b.version));
    return { options: list, min: list[0] || null, recommended: list[list.length - 1] || null };
  };
  // Полный контекст одного экземпляра: детали, паспорт, статистика, журнал статусов, целевая версия
  VR.instanceDetailContext = async item => {
    const safe = p => p.catch(e => ({ error: e.message }));
    const [details, passport, stats, log] = await Promise.all([safe(VR.instanceDetails(item.id)), item.vulnId ? safe(VR.passport(item.vulnId)) : Promise.resolve(null), item.vulnId ? safe(VR.vulnStats(item.vulnId)) : Promise.resolve(null), safe(VR.instanceStatusLog(item.id))]);
    const det = details && !details.error ? VR.parseDetection(details) : null;
    const fix = VR.fixOptions(passport?.howToFix, det?.current || null);
    if (det?.required) {
      // Граница из условий обнаружения: при strict уязвимы версии ниже границы (граница безопасна), иначе граница тоже уязвима
      const need = det.required, strict = det.requiredStrict;
      const kept = fix.options.filter(o => strict ? VR.cmpVersion(o.version, need) >= 0 : VR.cmpVersion(o.version, need) > 0);
      fix.options = kept; fix.min = kept[0] || (strict ? { version: need, kb: null } : null); fix.recommended = kept[kept.length - 1] || fix.min;
      fix.required = need; fix.requiredStrict = strict;
    }
    const pjson = passport && !passport.error ? JSON.stringify(passport) : '';
    const bdu = [...new Set((pjson.match(/BDU:\d{4}-\d{5}/g) || []))];
    const links = [...new Set((JSON.stringify(passport?.links || []).match(/https?:\/\/[^"\\\s]+/g) || []))].slice(0, 10);
    const m = details?.assetMetrics || null;
    return { item, det, fix, bdu, links,
      metrics: m ? { overall: m.overallScore ?? null, base: m.cvss3?.score ?? m.cvss2?.score ?? null, vector: m.cvss3?.vector || m.cvss2?.vector || '', environmental: m.cvss3?.environmentalScore ?? null, severity: m.severity || '' } : null,
      status: details?.currentStatus || null, statusLog: Array.isArray(log) ? log : [], tags: details?.tags || [], lastFixedDate: details?.lastFixedDate || null,
      patch: details?.patchInfo ? { name: details.patchInfo.displayName || '', url: details.patchInfo.link?.url || '', date: details.patchInfo.date || '', type: details.patchInfo.type || '' } : (item.patchName ? { name: item.patchName, url: item.patchUrl, date: '', type: '' } : null),
      passport: passport && !passport.error ? { title: passport.title || '', description: passport.description || '', howToFix: passport.howToFix || '' } : null,
      stats: stats && !stats.error ? stats : null, errors: [details?.error, passport?.error, stats?.error, log?.error].filter(Boolean),
      urls: { card: VR.instanceUrl(item.id), passport: VR.passportUrl(item.vulnId), asset: VR.assetUrl(item.hostId) } };
  };
  // Контекст по CVE: все экземпляры плюс выбранный (по Id экземпляра из URL, по активу из URL или самый опасный)
  VR.instanceContext = async ({ cve, instanceId, assetId, limit = 50 } = {}) => {
    // Сводка и список всегда по всем экземплярам CVE; выбранный ищется среди них, а при усечении списка отдельным запросом по активу
    const scopeAsset = instanceId ? VR.instanceAssetGuid(instanceId) : (assetId || null);
    const inst = await VR.cveInstances({ cve, limit });
    let item = instanceId ? (inst.items.find(i => i.id === instanceId) || null) : (scopeAsset ? inst.items.find(i => i.hostId === scopeAsset) || null : null);
    if (!item && scopeAsset && inst.truncated) { const own = await VR.cveInstances({ cve, assetId: scopeAsset, limit: 20 }); item = instanceId ? (own.items.find(i => i.id === instanceId) || null) : (own.items[0] || null); }
    return { cve, instances: inst, selected: item ? await VR.instanceDetailContext(item) : null, pickedBy: item ? (instanceId ? 'instance' : 'asset') : null };
  };
  // Задача Jira на один экземпляр: актив, условия обнаружения, патч, целевая версия, внешние сигналы
  VR.buildInstanceJiraIssue = ({ ctx, enrich, sla, host }) => {
    const it = ctx.item, det = ctx.det, fix = ctx.fix, cveKey = ctx.cve || it.cve || '';
    const r = enrich?.results?.[cveKey] || null;
    const kev = !!r?.kev, trend = !!it.trend;
    const level = kev ? 'P0' : trend ? 'P0' : it.score >= 9 ? 'P1' : it.score >= 7 ? 'P2' : 'P3';
    const days = level === 'P0' || level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const dueDate = VR.plusDays(Math.max(1, days));
    const hostShort = String(it.host || '').replace(/\s*\(.*\)$/, '');
    const cve = cveKey;
    const target = fix.recommended?.version || fix.min?.version || null;
    const what = ctx.patch?.name ? `установить ${ctx.patch.name}` : det?.product ? `обновить ${det.product}` : 'установить обновление';
    const summary = `Устранить ${cve} на ${hostShort}: ${what}${target ? ` (${det?.versionLabel || 'версия'} ${det?.current || '?'} → не ниже ${fix.min?.version || target}${fix.recommended && fix.recommended.version !== fix.min?.version ? ', рекомендуется ' + fix.recommended.version : ''})` : ''}${kev ? ' [KEV]' : trend ? ' [трендовая]' : ''}`;
    const impRu = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
    const description = [
      'h2. Что сделать',
      `На активе *${it.host}* (значимость ${impRu[it.imp] || it.imp}${it.os ? ', ' + it.os : ''}) ${what}${target ? `: ${det?.versionLabel || 'версия'} должна стать не ниже *${fix.min?.version || target}*${fix.recommended && fix.recommended.version !== fix.min?.version ? ` (рекомендуется актуальная *${fix.recommended.version}*${fix.recommended.kb ? ', ' + fix.recommended.kb : ''})` : ''}` : ''}.`,
      `Приоритет *${level}*, срок задачи до ${dueDate} (${days} дн)${(() => { const sd = VR.slaDue({ found: it.found, sev: it.sev, st: it.st, sla }); return sd.dueDate ? `; срок по SLA от даты обнаружения ${sd.dueDate}${sd.overdue ? ' (просрочен)' : ''}` : ''; })()}. Уязвимость *${ctx.passport?.title || it.name}* (${cve}), оценка в MaxPatrol ${ctx.metrics?.overall ?? it.score}${r?.nvd?.cvss31?.score != null ? ` (базовая CVSS 3.1 по NVD ${r.nvd.cvss31.score})` : ''}${kev ? ', в каталоге CISA KEV (эксплуатируется в атаках)' : ''}${trend ? ', трендовая по экспертизе PT' : ''}${it.expl ? ', есть публичный эксплойт' : ''}.`,
      '',
      ...(det ? ['h2. Где найдена', `Продукт: ${det.product}${det.os ? `, ${det.os}` : ''}${det.release ? ` ${det.release}` : ''}${det.arch ? `, ${det.arch}` : ''}${det.installType ? `, ${det.installType}` : ''}.`, ...det.conditions.filter(c => c.required != null).map(c => `${c.name}: ${c.value} (требуется ${c.strict ? '>=' : '>'} ${c.required})`), ''] : []),
      ...(ctx.patch ? ['h2. Патч', `${ctx.patch.name}${ctx.patch.date ? ` от ${String(ctx.patch.date).slice(0, 10)}` : ''}${ctx.patch.url ? `: ${ctx.patch.url}` : ''}`, ''] : []),
      ...(fix.options.length ? ['h2. Версии из рекомендации Positive Technologies (ветка текущей версии)', ...fix.options.map(o => `* ${o.version}${o.kb ? ' (' + o.kb + ')' : ''}`), ''] : []),
      ...(ctx.passport?.howToFix ? ['h2. Как исправить (паспорт уязвимости)', String(ctx.passport.howToFix).replace(/\s+/g, ' ').slice(0, 600), ''] : []),
      'h2. Внешние сигналы',
      `EPSS: ${r?.epss?.epss != null ? (r.epss.epss * 100).toFixed(1) + '%' : 'нет данных'}; CISA KEV: ${kev ? 'да, с ' + (r.kev.dateAdded || '') : 'нет'}; NVD CVSS 3.1: ${r?.nvd?.cvss31?.score ?? 'нет данных'}${r?.nvd?.cvss40 ? `, CVSS 4.0: ${r.nvd.cvss40.score}` : ''}${ctx.bdu.length ? `; БДУ: ${ctx.bdu.join(', ')}` : ''}.`,
      '',
      'h2. Ссылки',
      ...[ctx.urls.card ? `* Экземпляр в MaxPatrol VM: ${ctx.urls.card}` : '', ctx.urls.passport ? `* Паспорт уязвимости: ${ctx.urls.passport}` : '', ctx.urls.asset ? `* Актив: ${ctx.urls.asset}` : '', `* NVD: https://nvd.nist.gov/vuln/detail/${cve}`, ...ctx.bdu.map(b => `* БДУ: https://bdu.fstec.ru/vul/${b.replace(/^BDU:/, '')}`), ...ctx.links.filter(u => !/nvd\.nist|bdu\.fstec|cve\.mitre/.test(u)).slice(0, 5).map(u => `* ${u}`)].filter(Boolean),
      '',
      'h2. Проверка',
      `После обновления запустить аудит узла в MaxPatrol VM: экземпляр должен перейти в статус «Устранена». Источник: MaxPatrol VM ${host || ''}, расширение «Устранение».`,
    ].join('\n');
    return { summary, description, priority: level, level, dueDate, labels: ['mpvm-remediation', 'mpvm-instance', VR.jiraLabel(det?.product || it.name || cve)], ids: [it.id], targetVersion: target };
  };

  // ── Патчи: открытые уязвимости, сгруппированные по патчу из паспорта (Patch.DisplayName / PatchLink) ──
  // Один запрос патч x актив (список узлов на каждый патч) плюс запрос ссылок; детали патча (CVE, экземпляры)
  // грузятся отдельно по клику: фильтр по названию патча ставится после select (до select он на 28.0 очень медленный).
  // Условие HasPatch до select отбирает узлы, а не строки, поэтому после select оно повторяется (P = true):
  // иначе в группу «без названия» попадают уязвимости без патча.
  const NO_PATCH = '__no_patch__';
  VR.patchesPdql = () => {
    const V = 'Host.@Vulners';
    const base = `filter(${V} and ${V}.Metrics.HasPatch = true and ${V}.Status in ${OPEN})`;
    return {
      byHost: `${base} | select(@Host, Host.OsName as OS, Host.@Importance as Imp, ${V}.Patch.DisplayName as Patch, ${V}.Patch.PatchDate as PDate, ${V}.Score as Score, ${V}.Status as St, ${V}.IsTrend as T, ${V}.Metrics.Exploitable as E, ${V}.Metrics.HasPatch as P) | filter(St in ${OPEN} and P = true) | calc(if T = true then 1 else 0 as fT) | calc(if E = true then 1 else 0 as fE) | calc(if Score >= 9 then 1 else 0 as fC) | group(Patch, @Host, OS, Imp, COUNT(*) as N, MAX(Score) as MaxScore, MAX(PDate) as PDate, SUM(fT) as Trend, SUM(fE) as Expl, SUM(fC) as Crit)`,
      links: `${base} | select(${V}.Patch.DisplayName as Patch, ${V}.Patch.PatchLink as Link, ${V}.Status as St, ${V}.Metrics.HasPatch as P) | filter(St in ${OPEN} and P = true) | group(Patch, Link, COUNT(*) as N)`,
      detail: patch => `${base} | select(@Host, Host.OsName as OS, Host.@Importance as Imp, ${V}.Patch.DisplayName as Patch, ${V} as Name, ${V}.CVEs.Item as CVE, ${V}.Score as Score, ${V}.Id as Id, ${V}.Status as St, ${V}.IsTrend as T, ${V}.Metrics.Exploitable as E, ${V}.Metrics.HasPatch as P) | filter(St in ${OPEN} and P = true and Patch = "${esc(patch)}")`,
    };
  };
  VR.patches = async ({ limit = 5000 } = {}) => {
    const Q = VR.patchesPdql();
    const [rows, linkRows] = await Promise.all([VR.pdql(Q.byHost, limit, 0).then(VR.rows), VR.pdql(Q.links, 2000, 0).then(VR.rows).catch(() => [])]);
    const links = {}; linkRows.forEach(r => { const p = VR.rowVal(r, 'Patch'); const l = VR.getVal(r, 'Link'); if (p && l && typeof l === 'object' && l.url && !links[p]) links[p] = l.url; });
    const byPatch = new Map();
    rows.forEach(r => {
      const name = VR.rowVal(r, 'Patch') || ''; const key = name || NO_PATCH;
      const h = VR.getVal(r, '@Host'); const n = VR.num(VR.rowVal(r, 'N')) || 0;
      const p = byPatch.get(key) || byPatch.set(key, { key, patch: name, noLink: !name, url: links[name] || '', date: '', n: 0, hosts: [], hostIds: new Set(), maxScore: 0, trend: 0, expl: 0, crit: 0 }).get(key);
      p.n += n; p.maxScore = Math.max(p.maxScore, VR.num(VR.rowVal(r, 'MaxScore')) || 0); p.trend += VR.num(VR.rowVal(r, 'Trend')) || 0; p.expl += VR.num(VR.rowVal(r, 'Expl')) || 0; p.crit += VR.num(VR.rowVal(r, 'Crit')) || 0;
      const d = VR.rowVal(r, 'PDate'); if (d && d > p.date) p.date = d;
      const hostId = h?.id || ''; if (hostId && !p.hostIds.has(hostId)) { p.hostIds.add(hostId); p.hosts.push({ host: h?.name || VR.rowVal(r, '@Host'), id: hostId, os: VR.rowVal(r, 'OS'), imp: VR.rowVal(r, 'Imp') || 'ND', n, maxScore: VR.num(VR.rowVal(r, 'MaxScore')) || 0 }); }
      else if (hostId) { const hh = p.hosts.find(x => x.id === hostId); if (hh) { hh.n += n; } }
    });
    const patches = [...byPatch.values()].map(p => { const { hostIds, ...rest } = p; rest.hostsCount = hostIds.size; rest.hosts.sort((a, b) => b.n - a.n); rest.kb = (p.patch.match(/KB\d{5,8}/i) || [''])[0].toUpperCase() || null; return rest; }).sort((a, b) => b.n - a.n);
    const noLink = patches.find(p => p.noLink) || null;
    const list = patches.filter(p => !p.noLink);
    return { patches: list, noLink, total: { patches: list.length, patchesWithLink: list.filter(p => p.url).length, vulns: list.reduce((s, p) => s + p.n, 0), hosts: new Set(list.flatMap(p => p.hosts.map(h => h.id))).size, noLinkVulns: noLink ? noLink.n : 0, noLinkHosts: noLink ? noLink.hostsCount : 0 }, pdql: Q.byHost, linksFailed: linkRows.length === 0 && list.length > 0, truncated: rows.length >= limit };
  };
  // Детали патча: CVE, экземпляры (ids для Jira, проекта, смены статуса), узлы с числом уязвимостей
  VR.patchDetail = async ({ patch, limit = 20000 } = {}) => {
    if (!patch) throw new Error('Не указан патч');
    const pdql = VR.patchesPdql().detail(patch);
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const hosts = {}, cves = {}, ids = new Set(), vulns = {};
    rows.forEach(r => {
      const h = VR.getVal(r, '@Host'); const id = VR.rowVal(r, 'Id'); const cve = VR.rowVal(r, 'CVE'); const score = VR.num(VR.rowVal(r, 'Score')) || 0;
      const hk = h?.id || h?.name || '?';
      const hh = hosts[hk] || (hosts[hk] = { host: h?.name || VR.rowVal(r, '@Host'), id: h?.id || '', os: VR.rowVal(r, 'OS'), imp: VR.rowVal(r, 'Imp') || 'ND', n: 0, maxScore: 0, _ids: new Set() });
      if (id && !hh._ids.has(id)) { hh._ids.add(id); hh.n++; } hh.maxScore = Math.max(hh.maxScore, score);
      if (cve) { const c = cves[cve] || (cves[cve] = { cve, n: 0, score: 0, trend: false, exploit: false, vulnId: VR.vulnGuid(id) }); c.n++; c.score = Math.max(c.score, score); if (VR.bool(VR.rowVal(r, 'T'))) c.trend = true; if (VR.bool(VR.rowVal(r, 'E'))) c.exploit = true; }
      const name = VR.rowVal(r, 'Name'); if (name) { const v = vulns[name] || (vulns[name] = { name, n: 0, score }); if (id && !ids.has(id)) v.n++; v.score = Math.max(v.score, score); }
      if (id) ids.add(id);
    });
    return { patch, pdql, rows: ids.size || rows.length, truncated: rows.length >= limit, ids: [...ids],
      hosts: Object.values(hosts).map(h => { const { _ids, ...rest } = h; return rest; }).sort((a, b) => b.n - a.n),
      cves: Object.values(cves).sort((a, b) => b.score - a.score), vulns: Object.values(vulns).sort((a, b) => b.n - a.n) };
  };
  // Задача Jira на патч: установить патч на N узлах, закрывает M уязвимостей (K CVE)
  VR.buildPatchJiraIssue = ({ patch, detail, enrich, sla, host }) => {
    const p = patch, d = detail;
    const kev = d.cves.filter(c => enrich?.results?.[c.cve]?.kev).map(c => c.cve), trend = d.cves.filter(c => c.trend).map(c => c.cve);
    const level = kev.length ? 'P0' : trend.length ? 'P0' : p.maxScore >= 9 ? 'P1' : p.maxScore >= 7 ? 'P2' : 'P3';
    const days = level === 'P0' || level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const dueDate = VR.plusDays(Math.max(1, days));
    const summary = `Установить ${p.patch} на ${d.hosts.length} узлах: закрывает ${d.truncated ? 'не менее ' : ''}${d.rows} уязвимостей (${d.cves.length} CVE)${kev.length ? ' [KEV]' : trend.length ? ' [трендовые]' : ''}`;
    const impRu = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
    const impCount = {}; d.hosts.forEach(h => { impCount[h.imp] = (impCount[h.imp] || 0) + 1; });
    const cveRows = d.cves.slice(0, 40).map(c => { const r = enrich?.results?.[c.cve]; return `|${c.cve}|${c.score}|${r?.epss?.epss != null ? (r.epss.epss * 100).toFixed(0) + '%' : '-'}|${r?.kev ? 'да' : '-'}|${c.trend ? 'да' : '-'}|${c.exploit ? 'да' : '-'}|${c.n}|`; }).join('\n');
    const description = [
      'h2. Что сделать',
      `Установить *${p.patch}*${p.url ? ` (${p.url})` : ''}${p.date ? `, выпущен ${String(p.date).slice(0, 10)}` : ''} на ${d.hosts.length} узлах. Патч закрывает ${d.truncated ? 'не менее ' : ''}${d.rows} экземпляров уязвимостей (${d.cves.length} CVE, ${d.vulns.length} уязвимостей).`,
      `Приоритет *${level}*${kev.length ? `, ${kev.length} CVE в каталоге CISA KEV` : ''}${trend.length ? `, ${trend.length} трендовых по экспертизе PT` : ''}. Срок: до ${dueDate} (${days} дн).`,
      `Узлы по значимости: ${Object.entries(impCount).map(([k, v]) => `${impRu[k] || k} ${v}`).join(', ')}.`,
      '',
      `h2. Уязвимости (топ ${Math.min(40, d.cves.length)} из ${d.cves.length})`,
      '||CVE||CVSS||EPSS||KEV||Трендовая||Эксплойт||Экз.||', cveRows, '',
      `h2. Узлы (${Math.min(100, d.hosts.length)} из ${d.hosts.length})`,
      ...d.hosts.slice(0, 100).map(h => `* ${h.host} (${h.os || 'ОС не определена'}, значимость ${impRu[h.imp] || h.imp}, ${h.n} уязв., max CVSS ${h.maxScore})`),
      '',
      'h2. Проверка',
      `После установки запустить аудит узлов в MaxPatrol VM: экземпляры должны перейти в статус «Устранена». Источник: MaxPatrol VM ${host || ''}, расширение «Устранение», вкладка «Патчи».`,
    ].join('\n');
    const csv = VR.reports.csv({ title: 'Патч: ' + p.patch, sections: VR.reports.dataSections('Патч и выбранная группа', { patch: p, detail: d, enrichment: enrich }) });
    return { summary, description, priority: level, level, dueDate, labels: ['mpvm-remediation', 'mpvm-patch', VR.jiraLabel(p.kb || p.patch)], ids: d.ids, csv };
  };

  // ── Универсальная выборка (drill-down) по PDQL: уязвимости с узлами ─────────
  VR.drill = async ({ pdql, limit = 500 }) => {
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const items = rows.map(r => { const h = VR.getVal(r, '@Host'); const o = {}; Object.keys(r).forEach(k => { if (!k.startsWith('$')) o[k] = VR.rowVal(r, k); }); o.hostId = h?.id || ''; o.host = h?.name || o['@Host'] || ''; if (o.Id) o.vulnId = VR.vulnGuid(o.Id); return o; });
    return { items, truncated: rows.length >= limit, pdql };
  };
  // Готовые PDQL для показателей обзора и проектов
  const AGE_COND = { '0-7': 'Found > now()-7d', '8-30': 'Found <= now()-7d and Found > now()-30d', '31-90': 'Found <= now()-30d and Found > now()-90d', '90+': 'Found <= now()-90d' };
  VR.ageBuckets = () => Object.keys(AGE_COND);
  VR.drillPdql = (kind, arg) => {
    const SLA = { slaCritDays: 1, slaHighDays: 7, slaMedDays: 30, slaLowDays: 90 };
    if (kind === 'overdue' || kind === 'soon') arg = { ...SLA, ...(arg || {}) };
    if (kind === 'soon') { arg.h ??= soonDays(arg.slaHighDays); arg.m ??= soonDays(arg.slaMedDays); arg.l ??= soonDays(arg.slaLowDays); }
    if (kind === 'asset' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(arg))) throw new Error('Некорректный идентификатор актива');
    const base = 'select(@Host, Host.@Vulners as Name, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.IsTrend as T, Host.@Vulners.Metrics.Exploitable as E, Host.@Vulners.Id as Id)';
    const openF = `St in ${OPEN}`;
    switch (kind) {
      case 'open': return `filter(Host.@Vulners) | ${base} | filter(${openF}) | sort(Score desc)`;
      case 'overdue': return `filter(Host.@Vulners) | ${base} | filter(${openF} and ((Sev = "critical" and Found < now()-${arg.slaCritDays}d) or (Sev = "high" and Found < now()-${arg.slaHighDays}d) or (Sev = "medium" and Found < now()-${arg.slaMedDays}d) or (Sev = "low" and Found < now()-${arg.slaLowDays}d))) | sort(Score desc)`;
      case 'soon': return `filter(Host.@Vulners) | ${base} | filter(${openF} and ((Sev = "high" and Found < now()-${arg.h}d and Found >= now()-${arg.slaHighDays}d) or (Sev = "medium" and Found < now()-${arg.m}d and Found >= now()-${arg.slaMedDays}d) or (Sev = "low" and Found < now()-${arg.l}d and Found >= now()-${arg.slaLowDays}d))) | sort(Score desc)`;
      case 'sev': return `filter(Host.@Vulners) | ${base} | filter(${openF} and Sev = "${esc(arg)}") | sort(Score desc)`;
      case 'sevOverdue': return `filter(Host.@Vulners) | ${base} | filter(${openF} and Sev = "${esc(arg.sev)}" and Found < now()-${arg.days}d) | sort(Score desc)`;
      case 'trend': return `filter(Host.@Vulners and Host.@Vulners.IsTrend = true) | ${base} | filter(${openF} and T = true) | sort(Score desc)`;
      case 'exploit': return `filter(Host.@Vulners and Host.@Vulners.Metrics.Exploitable = true) | ${base} | filter(${openF} and E = true) | sort(Score desc)`;
      case 'new30': return `filter(Host.@Vulners) | ${base} | filter(${openF} and Found > now()-30d) | sort(Found desc)`;
      case 'status': return `filter(Host.@Vulners) | ${base} | filter(St = "${esc(arg)}") | sort(Score desc)`;
      case 'cve': return `filter(Host.@Vulners.CVEs.Item = "${esc(arg)}") | ${base} | filter(CVE = "${esc(arg)}") | sort(Score desc)`;
      case 'tag': return `filter(Host.@Vulners.Tags.Item = "${esc(arg)}") | select(@Host, Host.@Vulners as Name, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.Tags.Item as Tag, Host.@Vulners.Id as Id) | filter(Tag = "${esc(arg)}") | sort(Score desc)`;
      case 'age': { const cond = AGE_COND[typeof arg === 'string' ? arg : (arg?.key || '')]; if (!cond) throw new Error('Неизвестная корзина возраста: ' + arg); return `filter(Host.@Vulners) | ${base} | filter(${openF} and ${cond}) | sort(Found asc)`; }
      case 'asset': return `filter(Host.@Id = ${arg}) | ${base} | filter(${openF}) | sort(Score desc)`;
      case 'noImportance': return `filter(Host.@Importance = "ND" or not Host.@Importance) | select(@Host, Host.OsName as OS, Host.@Importance as Imp, Host.@AuditTime as Audit)`;
      case 'staleScan': return `select(@Host, Host.OsName as OS, Host.@Importance as Imp, Host.@AuditTime as Audit, Host.@ScanningInfo.Status as Scan) | filter(Audit < now()-90d or Scan in ["Obsolete","NeverHappened"])`;
      default: return null;
    }
  };

  const soonDays = d => Math.max(1, Math.round((VR.num(d) || 1) * 0.8));

  // ── Массовая смена статуса (внутренний API интерфейса 28.0) ──────────────
  const OPS_BASE = '/api/vulnerabilities_processing/v1/assets_vulnerabilities/operations';
  VR.commands = statuses => VR.get(OPS_BASE + '/commands', statuses ? { statuses } : undefined);
  VR.changeStatus = async ({ ids, command, tillDate, reason, note }) => {
    ids = (ids || []).filter(Boolean);
    if (!ids.length) throw new Error('Нет идентификаторов экземпляров');
    const body = { type: command, vulnerabilitiesInstancesIds: ids };
    if (command === 'SwitchToAwaitingFixStateCommand') { if (tillDate) body.tillDate = tillDate; if (note) body.statusNote = note; }
    if (command === 'SwitchToExcludeStateCommand') { body.statusReason = reason || 'acceptedAsLowRisk'; if (tillDate) body.tillDate = tillDate; if (note) body.statusNote = note; }
    const started = await VR.post(OPS_BASE, body);
    const opId = started?.operationId || started?.id || (typeof started === 'string' ? started.replace(/"/g, '') : null);
    let state = started, done = null;
    if (opId) {
      done = false;
      for (let i = 0; i < 40; i++) {
        await new Promise(r => setTimeout(r, 800));
        try { state = await VR.get(`${OPS_BASE}/${opId}`); }
        catch (e) { throw new Error(`Операция ${opId} отправлена, но проверить ее состояние не удалось: ${e.message}`); }
        const total = VR.num(state?.totalCount), processed = (VR.num(state?.succeedCount) || 0) + (VR.num(state?.failedCount) || 0);
        if (total != null && processed >= total) { done = true; break; }
      }
    }
    const total = VR.num(state?.totalCount), succeed = VR.num(state?.succeedCount), failed = VR.num(state?.failedCount);
    // done: true завершена; false таймаут опроса (операция продолжается на сервере); null сервер не вернул идентификатор
    return { count: ids.length, command, operationId: opId, succeed, failed, total, done, pending: done === false && total != null ? Math.max(0, total - (succeed || 0) - (failed || 0)) : null };
  };

  // ── Метрики процесса ──────────────────────────────────────────────────────
  const soon = soonDays;
  function metricsQueries(s) {
    const open = `Host.@Vulners.Status in ${OPEN}`;
    return {
      statuses: 'filter(Host.@Vulners) | select(Host.@Vulners.Status as St) | group(St, COUNT(*) as N)',
      sla: `filter(Host.@Vulners and ${open}) | select(Host.@Vulners.SeverityRating as Sev, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.Status as St) | filter(St in ${OPEN})`
        + ` | calc(if (Sev = "critical" and Found < now()-${s.slaCritDays}d) or (Sev = "high" and Found < now()-${s.slaHighDays}d) or (Sev = "medium" and Found < now()-${s.slaMedDays}d) or (Sev = "low" and Found < now()-${s.slaLowDays}d) then 1 else 0 as Over)`
        // «Истекает»: прошло 80% срока (у Rapid7 это grace period)
        + ` | calc(if (Sev = "high" and Found < now()-${soon(s.slaHighDays)}d) or (Sev = "medium" and Found < now()-${soon(s.slaMedDays)}d) or (Sev = "low" and Found < now()-${soon(s.slaLowDays)}d) then 1 else 0 as Soon)`
        + ' | calc(if Found > now()-7d then "0-7" else if Found > now()-30d then "8-30" else if Found > now()-90d then "31-90" else "90+" as Age) | group(Sev, Over, Soon, Age, COUNT(*) as N)',
      signals: `filter(Host.@Vulners and ${open}) | select(Host.@Vulners.IsTrend as T, Host.@Vulners.Metrics.Exploitable as E, Host.@Vulners.IsDanger as D, Host.@Vulners.Metrics.HasPatch as P, Host.@Vulners.Status as St) | filter(St in ${OPEN}) | group(T, E, D, P, COUNT(*) as N)`,
      assets: 'select(@Host, Host.@Importance as Imp, Host.@ScanningInfo.Status as Scan, Host.@AuditTime as Audit) | calc(if Audit > now()-30d then "fresh" else if Audit > now()-90d then "30-90" else "stale" as Fresh) | group(Imp, Scan, Fresh, COUNT(*) as N)',
      topHosts: 'select(@Host, Host.@Id as HostId, Host.@Importance as Imp, Host.@CumulativeVulnerability as CV, Host.OsName as OS) | sort(CV desc) | limit(10)',
      trendTop: `filter(Host.@Vulners and ${open} and Host.@Vulners.IsTrend = true) | select(Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, @Host, Host.@Vulners.Status as St, Host.@Vulners.IsTrend as T) | filter(St in ${OPEN} and T = true) | group(CVE, MAX(Score) as Score, COUNTUNIQUE(@Host) as Hosts, COUNT(*) as N)`,
    };
  }
  const norm = rows => Array.isArray(rows) ? rows.map(r => { const o = {}; Object.keys(r).forEach(k => { if (!k.startsWith('$')) o[k] = VR.rowVal(r, k); }); return o; }) : rows;

  VR.metrics = async ({ sla, deep = false } = {}) => {
    const s = { ...(await VR.ext('settings-get')), ...(sla || {}) };
    const Q = metricsQueries(s);
    const run = async (name, limit) => { try { return VR.rows(await VR.pdql(Q[name], limit || 200, 0)); } catch (e) { return { error: e.message }; } };
    const [statuses, slaRows, signals, assets, topHosts, trendRaw] = await Promise.all([run('statuses'), run('sla', 500), run('signals'), run('assets', 500), run('topHosts', 10), run('trendTop', 500)]);
    if (!Array.isArray(statuses)) throw new Error(statuses?.error || 'Не удалось получить статусы уязвимостей');
    if (!Array.isArray(slaRows)) throw new Error(slaRows?.error || 'Не удалось получить данные по срокам');
    let trendTop = trendRaw;
    if (Array.isArray(trendRaw)) {
      const byKey = {};
      trendRaw.forEach(r => { const cve = VR.rowVal(r, 'CVE'); if (!cve) return; const hosts = VR.num(VR.rowVal(r, 'Hosts')) || 0, score = VR.num(VR.rowVal(r, 'Score')) || 0; const cur = byKey[cve]; if (!cur || hosts > cur._h || (hosts === cur._h && score > cur._s)) byKey[cve] = { ...r, _h: hosts, _s: score }; });
      trendTop = Object.values(byKey).sort((a, b) => b._h - a._h || b._s - a._s).slice(0, 15).map(r => { const o = { ...r }; delete o._h; delete o._s; return o; });
    }
    const sum = (rows, pred) => Array.isArray(rows) ? rows.reduce((a, r) => a + (pred(r) ? (VR.num(VR.rowVal(r, 'N')) || 0) : 0), 0) : 0;
    const flow = [{ New7: sum(slaRows, r => VR.rowVal(r, 'Age') === '0-7'), New30: sum(slaRows, r => ['0-7', '8-30'].includes(VR.rowVal(r, 'Age'))), Fixed: sum(statuses, r => String(VR.rowVal(r, 'St')).toLowerCase() === 'fixed'), Excluded: sum(statuses, r => String(VR.rowVal(r, 'St')).toLowerCase() === 'excluded'), Total: sum(statuses, () => true) }];
    const out = { generatedAt: new Date().toISOString(), sla: { crit: s.slaCritDays, high: s.slaHighDays, med: s.slaMedDays, low: s.slaLowDays }, statuses: norm(statuses), slaRows: norm(slaRows), signals: norm(signals), flow, assets: norm(assets), topHosts: norm(topHosts), trendTop: norm(trendTop), pdql: Q };
    try {
      const cves = (out.trendTop || []).map(r => r.CVE).filter(Boolean);
      if (cves.length) { const e = await VR.ext('enrich', { cves, skipNvd: true }); out.trendTop.forEach(r => { const x = e.results[r.CVE]; if (x) { r.epss = x.epss?.epss ?? null; r.kev = !!x.kev; } }); }
    } catch (_) {}
    if (deep) {
      try { out.past30 = norm(VR.rows(await VR.pdql(`timepoint(now()-30d) | filter(Host.@Vulners and Host.@Vulners.Status in ${OPEN}) | select(@Host, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St) | filter(St in ${OPEN}) | group(Sev, COUNT(*) as N)`, 20, 0))); }
      catch (e) { out.past30 = { error: e.message }; }
    }
    return out;
  };

  VR.computeMetrics = m => {
    const num = v => VR.num(v) || 0;
    const arr = v => Array.isArray(v) ? v : [];
    const st = {}; arr(m.statuses).forEach(r => { st[String(r.St).toLowerCase()] = num(r.N); });
    const total = Object.values(st).reduce((a, b) => a + b, 0);
    const open = total - (st.fixed || 0) - (st.excluded || 0);
    const bySev = {}; let overdue = 0, soonTotal = 0, critOver = 0, highOver = 0, critOpen = 0, highOpen = 0;
    const age = { '0-7': 0, '8-30': 0, '31-90': 0, '90+': 0 };
    arr(m.slaRows).forEach(r => {
      const sev = String(r.Sev).toLowerCase(), n = num(r.N), over = num(r.Over) === 1, soon = !over && num(r.Soon) === 1;
      const b = bySev[sev] || (bySev[sev] = { open: 0, over: 0, soon: 0, ok: 0 }); b.open += n; if (over) { b.over += n; overdue += n; } else if (soon) { b.soon += n; soonTotal += n; } else b.ok += n;
      if (sev === 'critical') { critOpen += n; if (over) critOver += n; }
      if (sev === 'high') { highOpen += n; if (over) highOver += n; }
      if (age[r.Age] != null) age[r.Age] += n;
    });
    let trend = 0, expl = 0, danger = 0, patch = 0;
    arr(m.signals).forEach(r => { const n = num(r.N); if (VR.bool(r.T)) trend += n; if (VR.bool(r.E)) expl += n; if (VR.bool(r.D)) danger += n; if (VR.bool(r.P)) patch += n; });
    const flow = (m.flow || [])[0] || {};
    let assets = 0, noImp = 0, stale = 0, obsolete = 0, highImp = 0;
    arr(m.assets).forEach(r => { const n = num(r.N); assets += n; if (!r.Imp || r.Imp === 'ND') noImp += n; if (r.Fresh === 'stale') stale += n; if (/Obsolete|NeverHappened/.test(r.Scan)) obsolete += n; if (r.Imp === 'H') highImp += n; });
    return { st, total, open, bySev, overdue, soon: soonTotal, critOver, highOver, critOpen, highOpen, age, trend, expl, danger, patch, new7: num(flow.New7), new30: num(flow.New30), fixed: num(flow.Fixed), excluded: num(flow.Excluded), assets, noImp, stale, obsolete, highImp };
  };

  // ── Риск активов v3: гибридная модель (0-1000) ─────────────────────────────
  // Четыре независимых компонента, каждый со своим потолком, плюс контекстный множитель:
  //   E экспозиция (0-400): лог-шкала от взвешенного объема открытых уязвимостей (critical x40, high x8, medium x1.5, low x0.3)
  //   V опасность (0-150): максимальный и средний CVSS открытых уязвимостей узла
  //   T угроза (0-250): трендовые (экспертиза PT), публичные эксплойты, RCE, KEV (если известен)
  //   F критичность по ФСТЭК (0-200): оценка худшей уязвимости узла по методике (CVSS x I x (Ii + Iat)), где I = kK + lL,
  //     kK по значимости актива в MaxPatrol (высокая 0.4 как критически важный, средняя 0.32 как сервер, низкая 0.2 как АРМ,
  //     не задана - по типу узла), Iat трендовость/эксплойт, Ii тип воздействия. Периметр в расчете не участвует.
  //   C контекст: значимость актива (H 1.2, M 1.0, L 0.8, ND 0.9) x устаревший скан 1.05
  //   risk = min(1000, (E + V + T + F) x C). Потолки настраиваются (riskWeights).
  const RISK_DEFAULT = { E: 400, V: 150, T: 250, F: 200, impH: 1.2, impM: 1.0, impL: 0.8, impND: 0.9, stale: 1.05 };
  const FSTEC_I_MAX = 0.52, FSTEC_MAX = 10 * FSTEC_I_MAX * 1.1; // худшая уязвимость: CVSS 10, kK 0.4, Ii 0.5 + Iat 0.6
  VR.riskDefaults = () => ({ ...RISK_DEFAULT });
  VR.assetRisk = async ({ limit = 1000, weights } = {}) => {
    const W = { ...RISK_DEFAULT, ...(weights || {}) };
    const pdql = `filter(Host.@Vulners) | select(@Host, Host.@Importance as Imp, Host.OsName as OS, Host.HostType as Type, Host.@AuditTime as Audit, Host.@Vulners.Score as Score, Host.@Vulners.Status as St, Host.@Vulners.IsTrend as T, Host.@Vulners.Metrics.Exploitable as E, Host.@Vulners.IsDanger as D, Host.@Vulners.Impact.PrimaryType as Impact)`
      + ` | filter(St in ${OPEN})`
      + ' | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 and Score < 9 then 1 else 0 as fH) | calc(if Score >= 4 and Score < 7 then 1 else 0 as fM) | calc(if Score < 4 then 1 else 0 as fL) | calc(if T = true then 1 else 0 as fT) | calc(if E = true then 1 else 0 as fE) | calc(if D = true then 1 else 0 as fD)'
      // Слагаемые оценки ФСТЭК: в then/else PDQL 28.0 принимает только литералы, скобки в арифметике не принимает,
      // имена полей уникальны без учета регистра. Поэтому флаг 0/1 и отдельное умножение.
      + ' | calc(if T = false and E = true then 1 else 0 as fEo) | calc(if T = false and E = false then 1 else 0 as fNo)'
      + ' | calc(if Impact = "RCE" or Impact = "LPE" then 1 else 0 as fRl) | calc(if Impact = "DoS" then 1 else 0 as fDos) | calc(if Impact = "RCE" or Impact = "LPE" or Impact = "DoS" then 0 else 1 as fOth) | calc(if Impact = "RCE" then 1 else 0 as fR)'
      + ' | calc(Score * fT as vTrend) | calc(Score * fEo as vExpl) | calc(Score * fNo as vRest) | calc(Score * fRl as vRce) | calc(Score * fDos as vDos) | calc(Score * fOth as vOther)'
      + ' | group(@Host, Imp, OS, Type, Audit, COUNT(*) as N, SUM(fC) as Crit, SUM(fH) as High, SUM(fM) as Med, SUM(fL) as Low, SUM(fT) as Trend, SUM(fE) as Expl, SUM(fD) as Danger, SUM(fR) as Rce, MAX(Score) as MaxScore, AVG(Score) as AvgScore, SUM(vTrend) as SumTrend, SUM(vExpl) as SumExpl, SUM(vRest) as SumRest, SUM(vRce) as SumRce, SUM(vDos) as SumDos, SUM(vOther) as SumOther, SUM(Score) as ScoreSum)';
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const cap = (x, max) => Math.max(0, Math.min(max, x));
    const assets = rows.map(r => {
      const h = VR.getVal(r, '@Host'); const S = k => VR.num(VR.rowVal(r, k)) || 0;
      const a = { host: h?.name || VR.rowVal(r, '@Host'), id: h?.id || '', imp: VR.rowVal(r, 'Imp') || 'ND', os: VR.rowVal(r, 'OS'), type: VR.rowVal(r, 'Type') || '', audit: VR.rowVal(r, 'Audit') || '', n: S('N'), crit: S('Crit'), high: S('High'), med: S('Med'), low: S('Low'), trend: S('Trend'), expl: S('Expl'), danger: S('Danger'), rce: S('Rce'), maxScore: S('MaxScore'), avgScore: S('AvgScore'), scoreSum: S('ScoreSum'), kev: 0 };
      a.staleScan = a.audit ? (Date.now() - Date.parse(a.audit)) > 30 * 864e5 : true;
      // ФСТЭК: kK по значимости актива, lL доля похожих узлов (константа), периметр не учитывается
      const kK = a.imp === 'H' ? 0.4 : a.imp === 'M' ? 0.32 : a.imp === 'L' ? 0.2 : (/server|network/i.test(a.type) ? 0.32 : 0.2), lL = 0.12;
      a.I = kK + lL; a.kK = kK;
      a.fstec = (0.6 * S('SumTrend') + 0.3 * S('SumExpl') + 0.1 * S('SumRest') + 0.5 * S('SumRce') + 0.26 * S('SumDos') + 0.12 * S('SumOther')) * a.I;
      const iat = a.trend ? 0.6 : a.expl ? 0.3 : 0.1, ii = a.rce ? 0.5 : 0.12;
      a.fstecMax = a.maxScore * a.I * (ii + iat);
      a.fstecLevel = a.fstecMax > 8 ? 'critical' : a.fstecMax >= 5 ? 'high' : a.fstecMax >= 2 ? 'medium' : 'low';
      // Компоненты
      const volume = a.crit * 40 + a.high * 8 + a.med * 1.5 + a.low * 0.3;
      // Логарифмические шкалы: 10 трендовых и 100 трендовых различимы, но потолок недостижим одним признаком
      const lg = (x, max) => cap(Math.log10(1 + x) / Math.log10(1 + max), 1);
      a.cE = Math.round(lg(volume, 100000) * W.E);
      a.cV = Math.round(cap(a.maxScore / 10, 1) * W.V * 0.65 + cap(a.avgScore / 10, 1) * W.V * 0.35);
      a.cT = Math.round(lg(a.trend, 100) * W.T * 0.45 + lg(a.expl, 500) * W.T * 0.3 + lg(a.rce, 2000) * W.T * 0.15 + cap(a.kev / 5, 1) * W.T * 0.1);
      a.cF = Math.round(cap(a.fstecMax / FSTEC_MAX, 1) * W.F);
      a.ctx = ({ H: W.impH, M: W.impM, L: W.impL }[a.imp] ?? W.impND) * (a.staleScan ? W.stale : 1);
      a.raw = a.cE + a.cV + a.cT + a.cF;
      a.risk = Math.min(1000, Math.round(a.raw * a.ctx));
      a.zone = a.risk >= 700 ? 'critical' : a.risk >= 500 ? 'high' : a.risk >= 300 ? 'medium' : 'low';
      a.components = [['экспозиция', a.cE, W.E], ['опасность', a.cV, W.V], ['угроза', a.cT, W.T], ['ФСТЭК', a.cF, W.F]];
      a.drivers = a.components.map(([k, v]) => [k, a.raw ? v / a.raw * 100 : 0]).filter(x => x[1] > 0).sort((x, y) => y[1] - x[1]);
      a.impWeight = a.ctx;
      a.why = [a.trend ? `${a.trend} трендовых` : '', a.expl ? `${a.expl} с эксплойтом` : '', a.crit ? `${a.crit} critical` : '', a.rce ? `${a.rce} RCE` : '', a.staleScan ? 'скан старше 30 дн' : ''].filter(Boolean).join(', ');
      return a;
    }).sort((x, y) => y.risk - x.risk);
    const agg = (fn) => { const m = {}; assets.forEach(a => { const k = fn(a); const b = m[k] || (m[k] = { key: k, n: 0, risk: 0, max: 0, trend: 0 }); b.n++; b.risk += a.risk; b.max = Math.max(b.max, a.risk); b.trend += a.trend; }); return Object.values(m).map(b => ({ ...b, avg: Math.round(b.risk / b.n) })).sort((x, y) => y.avg - x.avg); };
    return { assets, byImp: agg(a => a.imp), byOs: agg(a => a.os || '?'), byZone: agg(a => a.zone), byType: agg(a => a.type || '?'), weights: W, pdql, truncated: rows.length >= limit };
  };
  // Уточнение угрозы: KEV по трендовым CVE (один запрос к каталогу CISA через background), пересчет T
  VR.assetRiskKev = async (result, { limit = 300 } = {}) => {
    const top = result.assets.slice(0, limit).filter(a => a.trend || a.expl); if (!top.length) return result;
    const ids = top.map(a => a.id).filter(Boolean).slice(0, 200);
    const rows = VR.rows(await VR.pdql(`filter(Host.@Id in [${ids.join(', ')}] and Host.@Vulners.Metrics.Exploitable = true) | select(@Host, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Status as St) | filter(St in ${OPEN} and CVE like "CVE-%") | group(@Host, CVE, COUNT(*) as N)`, 50000, 0));
    const byHost = {}; rows.forEach(r => { const h = VR.getVal(r, '@Host')?.id; const c = VR.rowVal(r, 'CVE'); if (h && c) (byHost[h] || (byHost[h] = new Set())).add(c); });
    const allCves = [...new Set(Object.values(byHost).flatMap(s => [...s]))];
    if (!allCves.length) return result;
    const e = await VR.ext('enrich', { cves: allCves, skipNvd: true });
    const W = result.weights;
    const lg = (x, max) => Math.min(1, Math.log10(1 + x) / Math.log10(1 + max));
    result.assets.forEach(a => { const set = byHost[a.id]; if (!set) return; a.kev = [...set].filter(c => e.results[c]?.kev).length; a.cT = Math.round(lg(a.trend, 100) * W.T * 0.45 + lg(a.expl, 500) * W.T * 0.3 + lg(a.rce, 2000) * W.T * 0.15 + Math.min(1, a.kev / 5) * W.T * 0.1); a.raw = a.cE + a.cV + a.cT + a.cF; a.risk = Math.min(1000, Math.round(a.raw * a.ctx)); a.zone = a.risk >= 700 ? 'critical' : a.risk >= 500 ? 'high' : a.risk >= 300 ? 'medium' : 'low'; a.components = [['экспозиция', a.cE, W.E], ['опасность', a.cV, W.V], ['угроза', a.cT, W.T], ['ФСТЭК', a.cF, W.F]]; a.drivers = a.components.map(([k, v]) => [k, a.raw ? v / a.raw * 100 : 0]).filter(x => x[1] > 0).sort((x, y) => y[1] - x[1]); if (a.kev) a.why = `${a.kev} KEV, ` + a.why; });
    result.assets.sort((x, y) => y.risk - x.risk); result.kevChecked = allCves.length;
    return result;
  };

  // ── Реестр исключений и принятых рисков ───────────────────────────────────
  VR.exclusions = async ({ limit = 5000 } = {}) => {
    const pdql = 'filter(Host.@Vulners) | select(@Host, Host.@Importance as Imp, Host.@Vulners as Name, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.Status as St, Host.@Vulners.StatusReason as Reason, Host.@Vulners.StatusComment as Note, Host.@Vulners.IsTrend as T, Host.@Vulners.Metrics.Exploitable as E, Host.@Vulners.IsDanger as D, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.Id as Id) | filter(St = "excluded")';
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    // Строка = пара (экземпляр, CVE): экземпляр считаем один раз, CVE собираем через запятую
    const byId = new Map();
    rows.forEach(r => { const h = VR.getVal(r, '@Host'); const id = VR.rowVal(r, 'Id') || `${h?.id}|${VR.rowVal(r, 'Name')}`; const cve = VR.rowVal(r, 'CVE'); const cur = byId.get(id); if (cur) { if (cve && !cur.cves.includes(cve)) { cur.cves.push(cve); cur.cve = cur.cves.join(', '); } return; } byId.set(id, { host: h?.name || '', hostId: h?.id || '', imp: VR.rowVal(r, 'Imp') || 'ND', name: VR.rowVal(r, 'Name'), cve, cves: cve ? [cve] : [], score: VR.num(VR.rowVal(r, 'Score')) || 0, reason: VR.rowVal(r, 'Reason') || 'unknown', note: VR.rowVal(r, 'Note') || '', trend: VR.bool(VR.rowVal(r, 'T')), expl: VR.bool(VR.rowVal(r, 'E')), danger: VR.bool(VR.rowVal(r, 'D')), found: VR.rowVal(r, 'Found'), id: VR.rowVal(r, 'Id') }); });
    const items = [...byId.values()];
    const byReason = {}; items.forEach(i => { const b = byReason[i.reason] || (byReason[i.reason] = { reason: i.reason, n: 0, trend: 0, expl: 0, highImp: 0, noNote: 0 }); b.n++; if (i.trend) b.trend++; if (i.expl) b.expl++; if (i.imp === 'H') b.highImp++; if (!i.note) b.noNote++; });
    // Сомнительные: трендовые, с эксплойтом, на важных активах, с CVSS >= 9, без комментария
    const risky = items.filter(i => i.trend || i.expl || i.score >= 9 || (i.imp === 'H' && i.score >= 7)).sort((a, b) => (b.trend - a.trend) || (b.expl - a.expl) || (b.score - a.score));
    const byCve = {}; items.forEach(i => { const k = i.cves[0] || i.name; const b = byCve[k] || (byCve[k] = { key: k, cve: i.cves[0] || '', name: i.name, n: 0, hosts: new Set(), score: 0, trend: false, expl: false, ids: [] }); b.n++; b.hosts.add(i.host); b.score = Math.max(b.score, i.score); if (i.trend) b.trend = true; if (i.expl) b.expl = true; b.ids.push(i.id); });
    const groups = Object.values(byCve).map(b => ({ ...b, hosts: b.hosts.size })).sort((a, b) => (b.trend - a.trend) || (b.expl - a.expl) || (b.score - a.score) || (b.n - a.n));
    return { items, total: items.length, truncated: rows.length >= limit, byReason: Object.values(byReason).sort((a, b) => b.n - a.n), risky, groups, pdql };
  };

  // ── Проекты устранения: прогресс по меткам (jira:KEY, proj:NAME) ─────────
  VR.projects = async ({ prefix = '' } = {}) => {
    // Фильтр по коллекции до select отбирает экземпляры, а не строки: без повторного filter(Tag like ...) в выдачу
    // попадут все остальные метки тех же экземпляров
    const like = prefix ? ` and Host.@Vulners.Tags.Item like "${esc(prefix)}%"` : '';
    const post = prefix ? ` | filter(Tag like "${esc(prefix)}%")` : '';
    const pdql = `filter(Host.@Vulners and Host.@Vulners.Tags${like}) | select(Host.@Vulners.Tags.Item as Tag, Host.@Vulners.Status as St, @Host)${post} | group(Tag, St, COUNT(*) as N, COUNTUNIQUE(@Host) as Hosts)`;
    const rows = VR.rows(await VR.pdql(pdql, 2000, 0));
    const byTag = {};
    rows.forEach(r => { const tag = VR.rowVal(r, 'Tag'); if (!tag) return; const st = String(VR.rowVal(r, 'St')).toLowerCase(); const n = VR.num(VR.rowVal(r, 'N')) || 0; const b = byTag[tag] || (byTag[tag] = { tag, total: 0, fixed: 0, excluded: 0, open: 0, byStatus: {}, hosts: 0 }); b.total += n; b.byStatus[st] = (b.byStatus[st] || 0) + n; if (st === 'fixed') b.fixed += n; else if (st === 'excluded') b.excluded += n; else b.open += n; b.hosts = Math.max(b.hosts, VR.num(VR.rowVal(r, 'Hosts')) || 0); });
    const projects = Object.values(byTag).map(p => ({ ...p, progress: p.total ? Math.round((p.fixed + p.excluded) / p.total * 100) : 0, kind: /^jira:/i.test(p.tag) ? 'jira' : /^proj:/i.test(p.tag) ? 'proj' : 'tag' })).sort((a, b) => a.progress - b.progress || b.open - a.open);
    return { projects, pdql, limit: 2000, truncated: rows.length >= 2000 };
  };

  // ── Веб-сайты: уязвимости из PT BlackBox / веб-сканирования (на стендах без веб-скана пусто) ──
  VR.webVulns = async ({ limit = 2000 } = {}) => {
    const pdql = `filter(WebSite.@Vulners) | select(@WebSite, WebSite.@Vulners as Name, WebSite.@Vulners.CVEs.Item as CVE, WebSite.@Vulners.Score as Score, WebSite.@Vulners.SeverityRating as Sev, WebSite.@Vulners.Status as St, WebSite.@Vulners.DiscoveryTime as Found, WebSite.@Vulners.Id as Id) | filter(St in ${OPEN}) | sort(Score desc)`;
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const items = rows.map(r => { const w = VR.getVal(r, '@WebSite'); return { site: w?.name || VR.rowVal(r, '@WebSite'), siteId: w?.id || '', name: VR.rowVal(r, 'Name'), cve: VR.rowVal(r, 'CVE'), score: VR.num(VR.rowVal(r, 'Score')) || 0, sev: String(VR.rowVal(r, 'Sev') || '').toLowerCase(), st: VR.rowVal(r, 'St'), found: VR.rowVal(r, 'Found'), id: VR.rowVal(r, 'Id'), vulnId: VR.vulnGuid(VR.rowVal(r, 'Id')) }; });
    const sites = {}; items.forEach(i => { const s = sites[i.site] || (sites[i.site] = { site: i.site, n: 0, crit: 0, high: 0, maxScore: 0 }); s.n++; if (i.score >= 9) s.crit++; else if (i.score >= 7) s.high++; s.maxScore = Math.max(s.maxScore, i.score); });
    return { items, sites: Object.values(sites).sort((a, b) => b.n - a.n), pdql, truncated: rows.length >= limit };
  };
  // Сводка по образам контейнеров: сколько образов и пакетов с открытыми уязвимостями
  VR.imageSummary = async () => {
    const rows = VR.rows(await VR.pdql(`filter(ImageSet.Images.Packages.@Vulners and ImageSet.Images.Packages.@Vulners.Status in ${OPEN}) | select(@ImageSet, ImageSet.Images.Packages.@Vulners.Score as Score, ImageSet.Images.Packages.@Vulners.Status as St) | filter(St in ${OPEN}) | calc(if Score >= 9 then 1 else 0 as fC) | calc(if Score >= 7 then 1 else 0 as fH) | group(@ImageSet, COUNT(*) as N, MAX(Score) as MaxScore, SUM(fC) as Crit, SUM(fH) as High)`, 500, 0));
    return rows.map(r => { const s = VR.getVal(r, '@ImageSet'); return { image: s?.name || VR.rowVal(r, '@ImageSet'), id: s?.id || '', n: VR.num(VR.rowVal(r, 'N')) || 0, maxScore: VR.num(VR.rowVal(r, 'MaxScore')) || 0, crit: VR.num(VR.rowVal(r, 'Crit')) || 0, high: VR.num(VR.rowVal(r, 'High')) || 0 }; }).sort((a, b) => b.n - a.n);
  };

  // ── Авто-теги активов (инвентаризация): набор правил, применение по PDQL-выборке ──
  VR.autoTagRules = () => ([
    // Платформа
    { name: 'auto:os-windows', color: 'blue', group: 'Платформа', title: 'Windows', pdql: 'filter(Host.OsName like "Windows%") | select(@Host)' },
    { name: 'auto:os-linux', color: 'blue', group: 'Платформа', title: 'Linux и Unix', pdql: 'filter(Host.OsName like "%Linux%" or Host.OsName like "Debian%" or Host.OsName like "Ubuntu%" or Host.OsName like "CentOS%" or Host.OsName like "Red Hat%" or Host.OsName like "RHEL%" or Host.OsName like "Astra%" or Host.OsName like "ALT%" or Host.OsName like "РЕД%" or Host.OsName like "Oracle Linux%" or Host.OsName like "SUSE%" or Host.OsName like "FreeBSD%") | select(@Host)' },
    { name: 'auto:os-eol', color: 'red', group: 'Платформа', title: 'ОС снята с поддержки (Windows 2008/2012/7/XP, CentOS 6/7, Ubuntu 16/18, Debian 8/9)', pdql: 'filter(Host.OsName like "Windows 2008%" or Host.OsName like "Windows 2012%" or Host.OsName like "Windows 7%" or Host.OsName like "Windows XP%" or Host.OsName like "Windows 8%" or Host.OsName like "CentOS 6%" or Host.OsName like "CentOS 7%" or Host.OsName like "Ubuntu 16%" or Host.OsName like "Ubuntu 18%" or Host.OsName like "Debian 8%" or Host.OsName like "Debian 9%") | select(@Host)' },
    { name: 'auto:type-server', color: 'purple', group: 'Роль', title: 'Серверы', pdql: 'filter(Host.HostType = "Server") | select(@Host)' },
    { name: 'auto:type-workstation', color: 'purple', group: 'Роль', title: 'Рабочие станции', pdql: 'filter(Host.HostType = "Desktop" or Host.HostType = "Workstation") | select(@Host)' },
    { name: 'auto:type-network', color: 'purple', group: 'Роль', title: 'Сетевые устройства', pdql: 'filter(Host.HostType = "Network Device") | select(@Host)' },
    { name: 'auto:role-db', color: 'purple', group: 'Роль', title: 'Сервер БД (открыт 1433, 3306, 5432, 1521, 27017)', pdql: 'filter(Host.Endpoints<TransportEndpoint>.Port in [1433, 3306, 5432, 1521, 27017] and Host.Endpoints<TransportEndpoint>.Status = "Open") | select(@Host)' },
    { name: 'auto:role-web', color: 'purple', group: 'Роль', title: 'Веб-сервер (открыт 80, 443, 8080, 8443)', pdql: 'filter(Host.Endpoints<TransportEndpoint>.Port in [80, 443, 8080, 8443] and Host.Endpoints<TransportEndpoint>.Status = "Open") | select(@Host)' },
    { name: 'auto:rdp-open', color: 'yellow', group: 'Роль', title: 'Открыт RDP (3389)', pdql: 'filter(Host.Endpoints<TransportEndpoint>.Port = 3389 and Host.Endpoints<TransportEndpoint>.Status = "Open") | select(@Host)' },
    { name: 'auto:ssh-open', color: 'yellow', group: 'Роль', title: 'Открыт SSH (22)', pdql: 'filter(Host.Endpoints<TransportEndpoint>.Port = 22 and Host.Endpoints<TransportEndpoint>.Status = "Open") | select(@Host)' },
    // Расположение
    { name: 'auto:public-ip', color: 'red', group: 'Расположение', title: 'Публичный IP (не RFC 1918)', pdql: 'filter(not Host.IpAddress in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8]) | select(@Host)' },
    // Гигиена процесса
    { name: 'auto:no-importance', color: 'yellow', group: 'Гигиена', title: 'Без значимости', pdql: 'filter(not Host.@Importance or Host.@Importance = "ND") | select(@Host)' },
    { name: 'auto:stale-scan', color: 'yellow', group: 'Гигиена', title: 'Аудит старше 30 дней', pdql: 'filter(Host.@AuditTime < now()-30d) | select(@Host)' },
    { name: 'auto:never-scanned', color: 'yellow', group: 'Гигиена', title: 'Скан не выполнялся или устарел (ScanningInfo)', pdql: 'filter(Host.@ScanningInfo.Status in ["Obsolete", "NeverHappened"]) | select(@Host)' },
    // Угроза
    { name: 'auto:has-trending', color: 'red', group: 'Угроза', title: 'Есть трендовые уязвимости', pdql: 'filter(Host.@Vulners.IsTrend = true and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:has-critical', color: 'red', group: 'Угроза', title: 'Есть critical (CVSS 9+)', pdql: 'filter(Host.@Vulners.Score >= 9 and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:has-exploit', color: 'red', group: 'Угроза', title: 'Есть публичный эксплойт', pdql: 'filter(Host.@Vulners.Metrics.Exploitable = true and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:has-rce', color: 'red', group: 'Угроза', title: 'Есть RCE', pdql: 'filter(Host.@Vulners.Impact.PrimaryType = "RCE" and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    // Сроки
    { name: 'auto:sla-overdue-critical', color: 'red', group: 'Сроки', title: 'Просрочен critical (старше 1 дня, приказ 117)', pdql: 'filter(Host.@Vulners.SeverityRating = "critical" and Host.@Vulners.DiscoveryTime < now()-1d and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:sla-overdue-high', color: 'yellow', group: 'Сроки', title: 'Просрочен high (старше 7 дней)', pdql: 'filter(Host.@Vulners.SeverityRating = "high" and Host.@Vulners.DiscoveryTime < now()-7d and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:patch-available-90d', color: 'yellow', group: 'Сроки', title: 'Патч есть, уязвимость открыта дольше 90 дней', pdql: 'filter(Host.@Vulners.Metrics.HasPatch = true and Host.@Vulners.DiscoveryTime < now()-90d and Host.@Vulners.Status in ' + OPEN + ') | select(@Host)' },
    { name: 'auto:untouched-30d', color: 'yellow', group: 'Сроки', title: 'Есть уязвимости в статусе Новая старше 30 дней (никто не разбирал)', pdql: 'filter(Host.@Vulners.Status = "new" and Host.@Vulners.DiscoveryTime < now()-30d) | select(@Host)' },
  ]);
  // Теги по списку id активов (для тегов auto:risk-* по рассчитанному риску)
  // count: успешно обработанные активы, failed: активы с ошибкой PUT, requested: всего в выборке
  VR.assignAssetTagsByIds = async ({ ids, addIds = [], removeIds = [], onProgress }) => {
    const q = [...new Set((ids || []).filter(Boolean))]; const requested = q.length; let ok = 0, failed = 0, errors = [];
    const worker = async () => { while (q.length) { const id = q.shift(); try { await VR.put(`/api/tags/v1/entities/asset/${id}`, { tagIdsToAdd: addIds, tagIdsToRemove: removeIds }); ok++; } catch (e) { failed++; if (errors.length < 3) errors.push(e.message); } if (onProgress && (ok + failed) % 10 === 0) onProgress(ok + failed); } };
    await Promise.all(Array.from({ length: 8 }, worker));
    return { count: ok, failed, requested, errors };
  };
  // Теги зон риска: auto:risk-critical / high / medium / low по результату VR.assetRisk (старые снимаются)
  VR.applyRiskTags = async (result, { onProgress } = {}) => {
    const existing = await VR.assetTags(); const byName = {}; (existing || []).forEach(t => { byName[t.name] = t; });
    const zones = ['critical', 'high', 'medium', 'low'], colors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'grey' }, tagIds = {};
    for (const z of zones) { const name = 'auto:risk-' + z; let tag = byName[name]; if (!tag) { const c = await VR.createAssetTag(name, colors[z]); tag = { id: c.id, name }; } tagIds[z] = tag.id; }
    const out = [];
    for (const z of zones) { const ids = result.assets.filter(a => a.zone === z).map(a => a.id); const r = await VR.assignAssetTagsByIds({ ids, addIds: [tagIds[z]], removeIds: zones.filter(x => x !== z).map(x => tagIds[x]), onProgress }); out.push({ zone: z, ...r }); }
    return out;
  };
  VR.assetTags = () => VR.get('/api/tags/v1/asset/tags');
  VR.createAssetTag = (name, color) => VR.post('/api/tags/v1/asset/tags', { name, color: color || 'grey' });
  VR.deleteAssetTag = id => VR.del(`/api/tags/v1/asset/tags/${id}`);
  // Назначить/снять теги активам по PDQL-выборке. Батч по selectionId (как делает грид активов) сервер 28.0
  // принимает (202), но на стенде не применяет, поэтому надежный путь: список узлов по PDQL и PUT по каждому
  // (/api/tags/v1/entities/asset/{id}), 8 запросов параллельно. Возвращает число обработанных узлов.
  VR.assignAssetTags = async ({ pdql, addIds = [], removeIds = [], limit = 5000, onProgress }) => {
    const rows = VR.rows(await VR.pdql(pdql.replace(/\|\s*limit\(\d+\)\s*$/, ''), limit, 0));
    const ids = [...new Set(rows.map(r => VR.getVal(r, '@Host')?.id || VR.getVal(r, '@ImageSet')?.id || VR.getVal(r, '@WebSite')?.id).filter(Boolean))];
    const r = await VR.assignAssetTagsByIds({ ids, addIds, removeIds, onProgress });
    return { ...r, truncated: rows.length >= limit };
  };
  VR.applyAutoTags = async ({ rules, onProgress } = {}) => {
    const existing = await VR.assetTags();
    const byName = {}; (existing || []).forEach(t => { byName[t.name] = t; });
    const results = [];
    for (const rule of (rules || VR.autoTagRules())) {
      try {
        let tag = byName[rule.name];
        if (!tag) { const c = await VR.createAssetTag(rule.name, rule.color); tag = { id: c.id, name: rule.name }; byName[rule.name] = tag; }
        const r = await VR.assignAssetTags({ pdql: rule.pdql, addIds: [tag.id] });
        results.push({ rule: rule.name, ok: r.failed === 0, hasMatches: r.requested > 0, count: r.count, failed: r.failed, truncated: r.truncated, error: r.failed ? `ошибок ${r.failed}: ${(r.errors || []).join('; ')}` : undefined });
      } catch (e) { results.push({ rule: rule.name, ok: false, error: e.message }); }
      if (onProgress) onProgress(results.length);
    }
    return results;
  };
  // exact: удалить только тег с точно таким именем (для тестов и точечного удаления)
  VR.removeAutoTags = async ({ prefix = 'auto:', exact = false } = {}) => {
    const existing = (await VR.assetTags() || []).filter(t => exact ? String(t.name) === prefix : String(t.name).startsWith(prefix));
    const results = [];
    for (const tag of existing) {
      try { const r = await VR.assignAssetTags({ pdql: `filter(Host.@Tags.Item = "${esc(tag.name)}") | select(@Host)`, removeIds: [tag.id] }); await VR.deleteAssetTag(tag.id); results.push({ tag: tag.name, ok: true, count: r.count }); }
      catch (e) { results.push({ tag: tag.name, ok: false, error: e.message }); }
    }
    return results;
  };
  VR.tagCoverage = async () => {
    const rows = VR.rows(await VR.pdql('filter(Host.@Tags) | select(@Host, Host.@Tags.Item as Tag) | group(Tag, COUNT(*) as N)', 500, 0));
    return rows.map(r => { const v = VR.getVal(r, 'Tag'); return { tag: v && typeof v === 'object' ? (v.displayName || '') : String(v ?? ''), n: VR.num(VR.rowVal(r, 'N')) || 0 }; }).filter(x => x.tag).sort((a, b) => b.n - a.n);
  };

  // ── Задача Jira из группы очереди (разметка Jira wiki) ────────────────────
  VR.buildJiraIssue = ({ detail, group, enrich, sla, host, passports, assetsInfo }) => {
    const d = detail, g = group || {};
    // Целевая версия: из «Как исправить» паспортов CVE группы (максимальная упомянутая версия)
    const targets = Object.values(passports || {}).map(p => VR.targetVersionFromHowToFix(p?.howToFix, d.ver)).filter(Boolean);
    const targetVersion = targets.length ? targets.sort(VR.cmpVersion).pop() : null;
    const kev = [], trend = [], top = [];
    d.cves.forEach(c => { const r = enrich?.results?.[c.cve]; if (r?.kev) kev.push(c.cve); if (c.trend) trend.push(c.cve); });
    const level = kev.length ? 'P0' : trend.length ? 'P0' : (g.maxScore || 0) >= 9 ? 'P1' : (g.maxScore || 0) >= 7 ? 'P2' : 'P3';
    const days = level === 'P0' ? (sla?.slaCritDays ?? 1) : level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const dueDate = VR.plusDays(Math.max(1, days));
    const summary = `Обновить ${d.soft} ${d.ver}${targetVersion ? ' до ' + targetVersion : ''}: ${d.cves.length} CVE на ${d.hosts.length} узлах${kev.length ? ' [KEV]' : trend.length ? ' [трендовые]' : ''}`;
    const ai = assetsInfo || {};
    const impCount = { H: 0, M: 0, L: 0, ND: 0 }; const groupsCount = {}; const osCount = {};
    d.hosts.forEach(h => { const i = ai[h.id] || ai[h.host]; if (!i) return; impCount[i.imp || 'ND'] = (impCount[i.imp || 'ND'] || 0) + 1; (i.groups || []).forEach(gname => { groupsCount[gname] = (groupsCount[gname] || 0) + 1; }); if (i.os) osCount[i.os] = (osCount[i.os] || 0) + 1; });
    const topGroups = Object.entries(groupsCount).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k} (${v})`).join(', ');
    const topOs = Object.entries(osCount).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} (${v})`).join(', ');
    const patchLinks = []; d.cves.slice(0, 40).forEach(c => { const r = enrich?.results?.[c.cve]; (r?.nvd?.refs || []).filter(x => x.tags.some(tg => /patch|vendor advisory/i.test(tg))).slice(0, 2).forEach(x => { if (!patchLinks.includes(x.url)) patchLinks.push(x.url); }); });
    const howTo = Object.entries(passports || {}).slice(0, 3).map(([cve, p]) => p?.howToFix ? `*${cve}*: ${String(p.howToFix).replace(/\s+/g, ' ').slice(0, 400)}` : '').filter(Boolean);
    const cveRows = d.cves.slice(0, 40).map(c => { const r = enrich?.results?.[c.cve]; return `|${c.cve}|${c.score}|${r?.epss?.epss != null ? (r.epss.epss * 100).toFixed(0) + '%' : '-'}|${r?.kev ? 'да' : '-'}|${c.trend ? 'да' : '-'}|${c.exploit ? 'да' : '-'}|${c.n}|`; }).join('\n');
    const hostRows = d.hosts.slice(0, 100).map(h => `* ${h.host} (${h.n} уязв., max CVSS ${h.maxScore})`).join('\n');
    const description = [
      `h2. Что сделать`,
      `Обновить *${d.soft}* с версии *${d.ver}*${targetVersion ? ` до версии *${targetVersion}* или новее (по рекомендации Positive Technologies)` : ' до актуальной версии вендора'} на ${d.hosts.length} узлах. Одно обновление закрывает ${d.truncated ? 'не менее ' : ''}${d.rows} экземпляров уязвимостей (${d.cves.length} CVE).`,
      `Приоритет: *${level}*${kev.length ? `, ${kev.length} CVE в каталоге CISA KEV (эксплуатируются в атаках)` : ''}${trend.length ? `, ${trend.length} трендовых по экспертизе PT` : ''}. Срок: до ${dueDate} (${days} дн).`,
      ``,
      ...(howTo.length ? ['h2. Рекомендации по устранению (паспорт уязвимости)', ...howTo, ''] : []),
      ...(patchLinks.length ? ['h2. Патчи и бюллетени вендора (NVD)', ...patchLinks.slice(0, 8).map(u => `* ${u}`), ''] : []),
      `h2. Контекст активов`,
      `Значимость узлов: высокая ${impCount.H || 0}, средняя ${impCount.M || 0}, низкая ${impCount.L || 0}, не задана ${impCount.ND || 0}.${topOs ? ` ОС: ${topOs}.` : ''}${topGroups ? ` Группы: ${topGroups}.` : ''}`,
      ``,
      `h2. Уязвимости (топ ${Math.min(40, d.cves.length)} из ${d.cves.length})`,
      `||CVE||CVSS||EPSS||KEV||Трендовая||Эксплойт||Экз.||`,
      cveRows,
      ``,
      `h2. Узлы (${Math.min(100, d.hosts.length)} из ${d.hosts.length})`,
      hostRows,
      ``,
      `h2. Проверка`,
      `После обновления запустить задачу аудита по узлам; уязвимости группы должны перейти в статус «Устранена» в MaxPatrol VM.`,
      `Источник: MaxPatrol VM ${host || ''}, расширение «Устранение». Группа: ${d.soft} ${d.ver}.`,
    ].join('\n');
    const labels = ['mpvm-remediation', VR.jiraLabel(d.soft)];
    return { summary, description, priority: level, dueDate, labels, level, targetVersion };
  };

  // Полный CSV для вложения: те же данные, что в отчёте выбранной группы.
  VR.groupCsv = (detail, enrich, context = {}) => VR.reports.csv({
    title: `Группа: ${detail.soft} ${detail.ver}`,
    sections: VR.reports.dataSections('Группа устранения', { ...detail, enrichment: enrich, ...context })
  });

  // Задача Jira по активу: все открытые уязвимости узла
  VR.assetVulns = async assetId => {
    const pdql = `filter(Host.@Id = ${assetId} and Host.@Vulners and Host.@Vulners.Status in ${OPEN}) | select(@Host, Host.@Vulners as Name, Host.@Vulners.Ids.Item as Ids, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.IsTrend as Trend, Host.@Vulners.Metrics.Exploitable as Expl, Host.@Vulners.Metrics.HasPatch as HasPatch, Host.@Vulners.Id as Id) | filter(St in ${OPEN})`;
    const rows = VR.rows(await VR.pdql(pdql, 50000, 0));
    const host = rows[0] ? (VR.getVal(rows[0], '@Host')?.name || assetId) : assetId;
    const items = rows.map(r => ({ name: VR.rowVal(r, 'Name'), ids: VR.rowVal(r, 'Ids'), cve: VR.rowVal(r, 'CVE'), score: VR.num(VR.rowVal(r, 'Score')) || 0, sev: String(VR.rowVal(r, 'Sev')).toLowerCase(), st: VR.rowVal(r, 'St'), found: VR.rowVal(r, 'Found'), trend: VR.bool(VR.rowVal(r, 'Trend')), expl: VR.bool(VR.rowVal(r, 'Expl')), patch: VR.bool(VR.rowVal(r, 'HasPatch')), id: VR.rowVal(r, 'Id') }));
    return { assetId, host, items, pdql, limit: 50000, truncated: rows.length >= 50000 };
  };
  VR.buildAssetJiraIssue = ({ asset, sla, host }) => {
    const by = { critical: 0, high: 0, medium: 0, low: 0 }; let trend = 0, expl = 0;
    asset.items.forEach(i => { if (by[i.sev] != null) by[i.sev]++; if (i.trend) trend++; if (i.expl) expl++; });
    const level = trend ? 'P0' : by.critical ? 'P1' : by.high ? 'P2' : 'P3';
    const days = level === 'P0' || level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const dueDate = VR.plusDays(Math.max(1, days));
    const top = asset.items.slice().sort((a, b) => b.score - a.score).slice(0, 40);
    const description = [
      `h2. Что сделать`, `Устранить открытые уязвимости узла *${asset.host}*: всего ${asset.items.length}, critical ${by.critical}, high ${by.high}, medium ${by.medium}, low ${by.low}${trend ? `, трендовых ${trend}` : ''}${expl ? `, с публичным эксплойтом ${expl}` : ''}.`,
      `Приоритет *${level}*, срок до ${dueDate} (${days} дн). Полный список во вложении.`, ``,
      `h2. Самые опасные (топ ${top.length})`, `||Уязвимость||CVE||CVSS||Уровень||Трендовая||Эксплойт||Патч||`,
      ...top.map(i => `|${(i.name || i.ids || '').toString().slice(0, 60)}|${i.cve || '-'}|${i.score}|${i.sev}|${i.trend ? 'да' : '-'}|${i.expl ? 'да' : '-'}|${i.patch ? 'да' : '-'}|`), ``,
      `h2. Проверка`, `После установки обновлений запустить аудит узла в MaxPatrol VM; уязвимости должны перейти в статус «Устранена».`, `Источник: MaxPatrol VM ${host || ''}, расширение «Устранение».`,
    ].join('\n');
    const csv = VR.reports.csv({ title: 'Уязвимости актива: ' + asset.host, sections: VR.reports.dataSections('Актив', asset) });
    return { summary: `${asset.host}: ${asset.items.length} открытых уязвимостей${trend ? ' [трендовые]' : ''}`, description, priority: level, dueDate, labels: ['mpvm-remediation', 'mpvm-asset'], csv, ids: asset.items.map(i => i.id).filter(Boolean) };
  };

  // Значимость, ОС и группы узлов (для контекста задачи Jira)
  VR.assetsInfo = async hostIds => {
    const ids = (hostIds || []).filter(Boolean).slice(0, 300);
    if (!ids.length) return {};
    const rows = VR.rows(await VR.pdql(`filter(Host.@Id in [${ids.join(', ')}]) | select(@Host, Host.@Importance as Imp, Host.OsName as OS, Host.@Groups as G)`, 5000, 0));
    const out = {};
    rows.forEach(r => { const h = VR.getVal(r, '@Host'); const id = h?.id; if (!id) return; const o = out[id] || (out[id] = { imp: VR.rowVal(r, 'Imp') || 'ND', os: VR.rowVal(r, 'OS'), groups: [] }); const g = VR.rowVal(r, 'G'); if (g && !o.groups.includes(g)) o.groups.push(g); });
    return out;
  };

  // Метка jira:KEY на экземплярах уязвимостей
  VR.tagInstances = async (ids, tag, remove = false) => {
    ids = (ids || []).filter(Boolean); if (!ids.length) return null;
    const started = await VR.post(OPS_BASE, { type: 'ChangeTagsCommand', vulnerabilitiesInstancesIds: ids, addedTags: remove ? [] : [tag], removedTags: remove ? [tag] : [] });
    return started?.operationId || started?.id || started;
  };

  // ── Разбор выгрузки БДУ (XML или CSV/TXT) ─────────────────────────────────
  // Записи CSV по RFC 4180: перевод строки внутри кавычек не разрывает запись
  VR.csvRecords = text => {
    const out = []; let cur = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === '"') { q = !q; cur += ch; continue; }
      if (!q && (ch === '\n' || ch === '\r')) { if (ch === '\r' && text[i + 1] === '\n') i++; if (cur) out.push(cur); cur = ''; continue; }
      cur += ch;
    }
    if (cur) out.push(cur);
    return out;
  };
  VR.parseBdu = text => {
    const CVE_RE = /CVE-\d{4}-\d{4,}/gi, map = {};
    const add = (cve, rec) => { const list = map[cve] || (map[cve] = []); if (!list.some(x => x.id === rec.id)) list.push(rec); };
    const levelOf = s => (s.match(/Критическ|Высок|Средн|Низк|Critical|High|Medium|Low/i) || [''])[0];
    if (/<vul\b/i.test(text)) {
      for (const b of text.split(/<\/vul>/i)) {
        const bdu = b.match(/BDU:\d{4}-\d{5}/i); if (!bdu) continue;
        const level = (b.match(/<severity>([^<]*)<\/severity>/i) || [])[1] || levelOf(b.replace(/<description>[\s\S]*?<\/description>/gi, ''));
        const date = (b.match(/<identify_date>([^<]*)<\/identify_date>/i) || [])[1] || '';
        // CVE берем из идентификаторов записи, а не из описания («аналогично CVE-...»)
        const idsBlock = (b.match(/<identifiers>[\s\S]*?<\/identifiers>/i) || [])[0];
        const src = idsBlock != null ? idsBlock : b.replace(/<description>[\s\S]*?<\/description>/gi, '').replace(/<name>[\s\S]*?<\/name>/gi, '');
        new Set((src.match(CVE_RE) || []).map(x => x.toUpperCase())).forEach(c => add(c, { id: bdu[0].toUpperCase(), level, date }));
      }
      return map;
    }
    for (const line of VR.csvRecords(text)) {
      const bdu = line.match(/BDU:\d{4}-\d{5}/i); if (!bdu) continue;
      const date = (line.match(/\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2}/) || [''])[0];
      new Set((line.match(CVE_RE) || []).map(x => x.toUpperCase())).forEach(c => add(c, { id: bdu[0].toUpperCase(), level: levelOf(line), date }));
    }
    return map;
  };
})(window.VR);

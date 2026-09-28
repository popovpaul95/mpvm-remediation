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
    return { scope, minScore, pdql, groups: groups.sort((a, b) => b.risk - a.risk), products: Object.values(byProduct).sort((a, b) => b.risk - a.risk), totalGroups: groups.length };
  };

  VR.queueDetail = async ({ scope, soft, ver, limit = 20000, pkg }) => {
    scope = SCOPES.includes(scope) ? scope : 'softs';
    const pdql = detailPdql(scope, scope === 'images' ? (pkg || soft) : soft, ver);
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const hosts = {}, cves = {}, ids = new Set();
    rows.forEach(r => {
      const hostObj = VR.getVal(r, scope === 'images' ? '@ImageSet' : '@Host');
      const hostName = scope === 'packages' ? (VR.rowVal(r, 'Host') || VR.rowVal(r, 'Ip')) : (hostObj?.name || VR.rowVal(r, scope === 'images' ? '@ImageSet' : '@Host'));
      const hostId = scope === 'packages' ? VR.rowVal(r, 'HostId') : (hostObj?.id || '');
      const cve = VR.rowVal(r, 'CVE'), id = VR.rowVal(r, 'Id'), score = VR.num(VR.rowVal(r, 'Score'));
      const h = hosts[hostName] || (hosts[hostName] = { host: hostName, id: hostId, n: 0, maxScore: 0 });
      h.n++; h.maxScore = Math.max(h.maxScore, score || 0);
      if (cve) {
        const c = cves[cve] || (cves[cve] = { cve, n: 0, score: 0, trend: false, exploit: false, vulnId: VR.vulnGuid(id) });
        c.n++; c.score = Math.max(c.score, score || 0);
        if (VR.bool(VR.rowVal(r, 'T'))) c.trend = true;
        if (VR.bool(VR.rowVal(r, 'E'))) c.exploit = true;
      }
      if (id) ids.add(id);
    });
    return { scope, soft, ver, pdql, rows: rows.length, truncated: rows.length >= limit,
      hosts: Object.values(hosts).sort((a, b) => b.maxScore - a.maxScore || b.n - a.n),
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
  // Целевая версия из текста «Как исправить»: берем максимальную упомянутую версию
  VR.targetVersionFromHowToFix = (text, current) => {
    let vers = [...String(text || '').matchAll(/(\d+(?:\.\d+){1,3})/g)].map(m => m[1]);
    if (!vers.length) return null;
    const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };
    // Если известна текущая версия, берем версии ее ветки (совпадают первые компоненты кроме последнего) и старше текущей
    if (current) {
      const cur = String(current).split('.');
      for (let depth = cur.length; depth >= 1; depth--) {
        const prefix = cur.slice(0, depth).join('.') + '.';
        const same = vers.filter(v => v.startsWith(prefix) && cmp(v, String(current)) > 0);
        if (same.length) { vers = same; break; }
      }
    }
    return vers.sort(cmp).pop();
  };

  // ── Универсальная выборка (drill-down) по PDQL: уязвимости с узлами ─────────
  VR.drill = async ({ pdql, limit = 500 }) => {
    const rows = VR.rows(await VR.pdql(pdql, limit, 0));
    const items = rows.map(r => { const h = VR.getVal(r, '@Host'); const o = {}; Object.keys(r).forEach(k => { if (!k.startsWith('$')) o[k] = VR.rowVal(r, k); }); o.hostId = h?.id || ''; o.host = h?.name || o['@Host'] || ''; if (o.Id) o.vulnId = VR.vulnGuid(o.Id); return o; });
    return { items, truncated: rows.length >= limit, pdql };
  };
  // Готовые PDQL для показателей обзора и проектов
  VR.drillPdql = (kind, arg) => {
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
      case 'age': return `filter(Host.@Vulners) | ${base} | filter(${openF} and ${arg.from != null ? `Found <= now()-${arg.from}d` : 'Found > now()-0d'}${arg.to != null ? ` and Found > now()-${arg.to}d` : ''}) | sort(Found asc)`;
      case 'asset': return `filter(Host.@Id = ${arg}) | ${base} | filter(${openF}) | sort(Score desc)`;
      case 'noImportance': return `filter(Host.@Importance = "ND" or not Host.@Importance) | select(@Host, Host.OsName as OS, Host.@Importance as Imp, Host.@AuditTime as Audit)`;
      case 'staleScan': return `select(@Host, Host.OsName as OS, Host.@Importance as Imp, Host.@AuditTime as Audit, Host.@ScanningInfo.Status as Scan) | filter(Audit < now()-90d or Scan in ["Obsolete","NeverHappened"])`;
      default: return null;
    }
  };

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
    let state = started;
    if (opId) {
      for (let i = 0; i < 40; i++) {
        await new Promise(r => setTimeout(r, 800));
        try { state = await VR.get(`${OPS_BASE}/${opId}`); } catch (_) { break; }
        const total = VR.num(state?.totalCount), done = (VR.num(state?.succeedCount) || 0) + (VR.num(state?.failedCount) || 0);
        if (total != null && done >= total) break;
      }
    }
    return { count: ids.length, command, operationId: opId, succeed: VR.num(state?.succeedCount), failed: VR.num(state?.failedCount), total: VR.num(state?.totalCount) };
  };

  // ── Метрики процесса ──────────────────────────────────────────────────────
  const soon = d => Math.max(1, Math.round((VR.num(d) || 1) * 0.8));
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
    arr(m.signals).forEach(r => { const n = num(r.N); if (r.T === 'True') trend += n; if (r.E === 'True') expl += n; if (r.D === 'True') danger += n; if (r.P === 'True') patch += n; });
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
    const items = rows.map(r => { const h = VR.getVal(r, '@Host'); return { host: h?.name || '', hostId: h?.id || '', imp: VR.rowVal(r, 'Imp') || 'ND', name: VR.rowVal(r, 'Name'), cve: VR.rowVal(r, 'CVE'), score: VR.num(VR.rowVal(r, 'Score')) || 0, reason: VR.rowVal(r, 'Reason') || 'unknown', note: VR.rowVal(r, 'Note') || '', trend: VR.bool(VR.rowVal(r, 'T')), expl: VR.bool(VR.rowVal(r, 'E')), danger: VR.bool(VR.rowVal(r, 'D')), found: VR.rowVal(r, 'Found'), id: VR.rowVal(r, 'Id') }; });
    const byReason = {}; items.forEach(i => { const b = byReason[i.reason] || (byReason[i.reason] = { reason: i.reason, n: 0, trend: 0, expl: 0, highImp: 0, noNote: 0 }); b.n++; if (i.trend) b.trend++; if (i.expl) b.expl++; if (i.imp === 'H') b.highImp++; if (!i.note) b.noNote++; });
    // Сомнительные: трендовые, с эксплойтом, на важных активах, с CVSS >= 9, без комментария
    const risky = items.filter(i => i.trend || i.expl || i.score >= 9 || (i.imp === 'H' && i.score >= 7)).sort((a, b) => (b.trend - a.trend) || (b.expl - a.expl) || (b.score - a.score));
    const byCve = {}; items.forEach(i => { const k = i.cve || i.name; const b = byCve[k] || (byCve[k] = { key: k, cve: i.cve, name: i.name, n: 0, hosts: new Set(), score: 0, trend: false, expl: false, ids: [] }); b.n++; b.hosts.add(i.host); b.score = Math.max(b.score, i.score); if (i.trend) b.trend = true; if (i.expl) b.expl = true; b.ids.push(i.id); });
    const groups = Object.values(byCve).map(b => ({ ...b, hosts: b.hosts.size })).sort((a, b) => (b.trend - a.trend) || (b.expl - a.expl) || (b.score - a.score) || (b.n - a.n));
    return { total: items.length, truncated: rows.length >= limit, byReason: Object.values(byReason).sort((a, b) => b.n - a.n), risky, groups, pdql };
  };

  // ── Проекты устранения: прогресс по меткам (jira:KEY, proj:NAME) ─────────
  VR.projects = async ({ prefix = '' } = {}) => {
    const like = prefix ? ` and Host.@Vulners.Tags.Item like "${esc(prefix)}%"` : '';
    const pdql = `filter(Host.@Vulners and Host.@Vulners.Tags${like}) | select(Host.@Vulners.Tags.Item as Tag, Host.@Vulners.Status as St, @Host) | group(Tag, St, COUNT(*) as N, COUNTUNIQUE(@Host) as Hosts)`;
    const rows = VR.rows(await VR.pdql(pdql, 2000, 0));
    const byTag = {};
    rows.forEach(r => { const tag = VR.rowVal(r, 'Tag'); if (!tag) return; const st = String(VR.rowVal(r, 'St')).toLowerCase(); const n = VR.num(VR.rowVal(r, 'N')) || 0; const b = byTag[tag] || (byTag[tag] = { tag, total: 0, fixed: 0, excluded: 0, open: 0, byStatus: {}, hosts: 0 }); b.total += n; b.byStatus[st] = (b.byStatus[st] || 0) + n; if (st === 'fixed') b.fixed += n; else if (st === 'excluded') b.excluded += n; else b.open += n; b.hosts = Math.max(b.hosts, VR.num(VR.rowVal(r, 'Hosts')) || 0); });
    const projects = Object.values(byTag).map(p => ({ ...p, progress: p.total ? Math.round((p.fixed + p.excluded) / p.total * 100) : 0, kind: /^jira:/i.test(p.tag) ? 'jira' : /^proj:/i.test(p.tag) ? 'proj' : 'tag' })).sort((a, b) => a.progress - b.progress || b.open - a.open);
    return { projects, pdql };
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
  VR.assignAssetTagsByIds = async ({ ids, addIds = [], removeIds = [], onProgress }) => {
    const q = [...new Set((ids || []).filter(Boolean))]; let done = 0, failed = 0;
    const worker = async () => { while (q.length) { const id = q.shift(); try { await VR.put(`/api/tags/v1/entities/asset/${id}`, { tagIdsToAdd: addIds, tagIdsToRemove: removeIds }); } catch (_) { failed++; } done++; if (onProgress && done % 10 === 0) onProgress(done); } };
    await Promise.all(Array.from({ length: 8 }, worker));
    return { count: done, failed };
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
    let done = 0, failed = 0;
    const worker = async () => { while (ids.length) { const id = ids.shift(); try { await VR.put(`/api/tags/v1/entities/asset/${id}`, { tagIdsToAdd: addIds, tagIdsToRemove: removeIds }); } catch (_) { failed++; } done++; if (onProgress && done % 10 === 0) onProgress(done); } };
    await Promise.all(Array.from({ length: 8 }, worker));
    return { count: done, failed };
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
        results.push({ rule: rule.name, ok: true, hasMatches: r.count > 0, count: r.count, failed: r.failed });
      } catch (e) { results.push({ rule: rule.name, ok: false, error: e.message }); }
      if (onProgress) onProgress(results.length);
    }
    return results;
  };
  VR.removeAutoTags = async ({ prefix = 'auto:' } = {}) => {
    const existing = (await VR.assetTags() || []).filter(t => String(t.name).startsWith(prefix));
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
    const cmpV = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const dd = (x[i] || 0) - (y[i] || 0); if (dd) return dd; } return 0; };
    const targetVersion = targets.length ? targets.sort(cmpV).pop() : null;
    const kev = [], trend = [], top = [];
    d.cves.forEach(c => { const r = enrich?.results?.[c.cve]; if (r?.kev) kev.push(c.cve); if (c.trend) trend.push(c.cve); });
    const level = kev.length ? 'P0' : trend.length ? 'P0' : (g.maxScore || 0) >= 9 ? 'P1' : (g.maxScore || 0) >= 7 ? 'P2' : 'P3';
    const days = level === 'P0' ? (sla?.slaCritDays ?? 1) : level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const due = new Date(); due.setDate(due.getDate() + Math.max(1, days));
    const dueDate = due.toISOString().slice(0, 10);
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
    const labels = ['mpvm-remediation', `mpvm-${String(d.soft).toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40)}`];
    return { summary, description, priority: level, dueDate, labels, level, targetVersion };
  };

  // CSV для вложения в задачу: все CVE группы и все узлы
  VR.groupCsv = (detail, enrich) => {
    const q = v => { const s = String(v ?? ''); return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const lines = ['\uFEFFCVE;CVSS;EPSS;KEV;Трендовая;Эксплойт;Экземпляров'];
    detail.cves.forEach(c => { const r = enrich?.results?.[c.cve]; lines.push([c.cve, c.score, r?.epss?.epss != null ? (r.epss.epss * 100).toFixed(1) + '%' : '', r?.kev ? 'да' : '', c.trend ? 'да' : '', c.exploit ? 'да' : '', c.n].map(q).join(';')); });
    lines.push('', 'Узел;ID актива;Уязвимостей;Max CVSS');
    detail.hosts.forEach(h => lines.push([h.host, h.id, h.n, h.maxScore].map(q).join(';')));
    return lines.join('\n');
  };

  // Задача Jira по активу: все открытые уязвимости узла
  VR.assetVulns = async assetId => {
    const pdql = `filter(Host.@Id = ${assetId} and Host.@Vulners and Host.@Vulners.Status in ${OPEN}) | select(@Host, Host.@Vulners as Name, Host.@Vulners.Ids.Item as Ids, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.IsTrend as Trend, Host.@Vulners.Metrics.Exploitable as Expl, Host.@Vulners.Metrics.HasPatch as HasPatch, Host.@Vulners.Id as Id) | filter(St in ${OPEN})`;
    const rows = VR.rows(await VR.pdql(pdql, 50000, 0));
    const host = rows[0] ? (VR.getVal(rows[0], '@Host')?.name || assetId) : assetId;
    const items = rows.map(r => ({ name: VR.rowVal(r, 'Name'), ids: VR.rowVal(r, 'Ids'), cve: VR.rowVal(r, 'CVE'), score: VR.num(VR.rowVal(r, 'Score')) || 0, sev: String(VR.rowVal(r, 'Sev')).toLowerCase(), st: VR.rowVal(r, 'St'), found: VR.rowVal(r, 'Found'), trend: VR.bool(VR.rowVal(r, 'Trend')), expl: VR.bool(VR.rowVal(r, 'Expl')), patch: VR.bool(VR.rowVal(r, 'HasPatch')), id: VR.rowVal(r, 'Id') }));
    return { assetId, host, items };
  };
  VR.buildAssetJiraIssue = ({ asset, sla, host }) => {
    const by = { critical: 0, high: 0, medium: 0, low: 0 }; let trend = 0, expl = 0;
    asset.items.forEach(i => { if (by[i.sev] != null) by[i.sev]++; if (i.trend) trend++; if (i.expl) expl++; });
    const level = trend ? 'P0' : by.critical ? 'P1' : by.high ? 'P2' : 'P3';
    const days = level === 'P0' || level === 'P1' ? (sla?.slaCritDays ?? 1) : level === 'P2' ? (sla?.slaHighDays ?? 7) : (sla?.slaMedDays ?? 30);
    const due = new Date(); due.setDate(due.getDate() + Math.max(1, days)); const dueDate = due.toISOString().slice(0, 10);
    const top = asset.items.slice().sort((a, b) => b.score - a.score).slice(0, 40);
    const description = [
      `h2. Что сделать`, `Устранить открытые уязвимости узла *${asset.host}*: всего ${asset.items.length}, critical ${by.critical}, high ${by.high}, medium ${by.medium}, low ${by.low}${trend ? `, трендовых ${trend}` : ''}${expl ? `, с публичным эксплойтом ${expl}` : ''}.`,
      `Приоритет *${level}*, срок до ${dueDate} (${days} дн). Полный список во вложении.`, ``,
      `h2. Самые опасные (топ ${top.length})`, `||Уязвимость||CVE||CVSS||Уровень||Трендовая||Эксплойт||Патч||`,
      ...top.map(i => `|${(i.name || i.ids || '').toString().slice(0, 60)}|${i.cve || '-'}|${i.score}|${i.sev}|${i.trend ? 'да' : '-'}|${i.expl ? 'да' : '-'}|${i.patch ? 'да' : '-'}|`), ``,
      `h2. Проверка`, `После установки обновлений запустить аудит узла в MaxPatrol VM; уязвимости должны перейти в статус «Устранена».`, `Источник: MaxPatrol VM ${host || ''}, расширение «Устранение».`,
    ].join('\n');
    const q = v => { const s = String(v ?? ''); return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const csv = '\uFEFF' + ['Уязвимость;Идентификатор;CVE;CVSS;Уровень;Статус;Обнаружена;Трендовая;Эксплойт;Патч', ...asset.items.sort((a, b) => b.score - a.score).map(i => [i.name, i.ids, i.cve, i.score, i.sev, i.st, i.found, i.trend ? 'да' : '', i.expl ? 'да' : '', i.patch ? 'да' : ''].map(q).join(';'))].join('\n');
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
  VR.parseBdu = text => {
    const CVE_RE = /CVE-\d{4}-\d{4,}/gi, map = {};
    const add = (cve, rec) => { (map[cve] || (map[cve] = [])).push(rec); };
    const levelOf = s => (s.match(/Критическ|Высок|Средн|Низк|Critical|High|Medium|Low/i) || [''])[0];
    if (/<vul\b/i.test(text)) {
      for (const b of text.split(/<\/vul>/i)) {
        const bdu = b.match(/BDU:\d{4}-\d{5}/i); if (!bdu) continue;
        const level = (b.match(/<severity>([^<]*)<\/severity>/i) || [])[1] || levelOf(b);
        const date = (b.match(/<identify_date>([^<]*)<\/identify_date>/i) || [])[1] || '';
        new Set((b.match(CVE_RE) || []).map(x => x.toUpperCase())).forEach(c => add(c, { id: bdu[0].toUpperCase(), level, date }));
      }
      return map;
    }
    for (const line of text.split(/\r?\n/)) {
      const bdu = line.match(/BDU:\d{4}-\d{5}/i); if (!bdu) continue;
      const date = (line.match(/\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2}/) || [''])[0];
      new Set((line.match(CVE_RE) || []).map(x => x.toUpperCase())).forEach(c => add(c, { id: bdu[0].toUpperCase(), level: levelOf(line), date }));
    }
    return map;
  };
})(window.VR);

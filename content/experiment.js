'use strict';
// Вкладка «Эксперимент»: функции, закрывающие запросы заказчиков к продукту силами расширения.
// Все API проверены на стендах 28.0 и 27.6; отличия и ограничения помечены в комментариях.
// Пока всё лежит здесь одним слоем; после проверки пользой — раскидаем по логическим модулям.
window.VR = window.VR || {};
(function (VR) {
  const num = VR.num, rows = VR.rows, rowVal = VR.rowVal, getVal = VR.getVal;

  // ════════════════════════════════════════════════════════════════════════
  // 1. Аудит учетных записей для отчета по методике ФСТЭК (показатели K21/K23)
  //    MaxPatrol упомянут в методике, но штатного PDF-отчета нет. Собираем из
  //    результатов проверок подбора: по одному PDQL на тип проверки, свод и вывод.
  // ════════════════════════════════════════════════════════════════════════
  // Типы аргументов проверок, проверенные на 28.0 (возвращают Login/Password).
  // SSH и RDP покрывает RemoteAccess; отдельные Ssh*/Rdp(plain)/Snmp*/HttpAuth/Ldap на стенде не разворачиваются.
  const CRED_CHECKS = [
    ['RemoteAccessAccountBruteforceArgument', 'SSH/RDP'], ['SmbAccountBruteforceArgument', 'SMB'], ['FtpAccountBruteforceArgument', 'FTP'],
    ['TelnetAccountBruteforceArgument', 'Telnet'], ['VncAccountBruteforceArgument', 'VNC'],
    ['RadminAccountBruteforceArgument', 'Radmin'], ['RadminLoginBruteforceArgument', 'Radmin'],
    ['MsSqlAccountBruteforceArgument', 'MS SQL'], ['MsSqlLockedAccountBruteforceArgument', 'MS SQL'], ['MsSqlWindowsAccountBruteforceArgument', 'MS SQL'],
    ['MySqlAccountBruteforceArgument', 'MySQL'], ['OracleAccountBruteforceArgument', 'Oracle'], ['OracleLockedAccountBruteforceArgument', 'Oracle'],
    ['Db2AccountBruteforceArgument', 'DB2'], ['SybaseAccountBruteforceArgument', 'Sybase'],
    ['Pop3AccountBruteforceArgument', 'POP3'], ['SmtpAccountBruteforceArgument', 'SMTP'],
    ['RdpDisabledAccountBruteforceArgument', 'RDP'], ['RdpExpiredAccountBruteforceArgument', 'RDP'],
    ['RdpLockedAccountBruteforceArgument', 'RDP'], ['RdpLockedAdminAccountBruteforceArgument', 'RDP'],
    ['VmWareAccountBruteforceArgument', 'VMware'],
    ['PostgreSqlBruteForceAccountsCheckArgument', 'PostgreSQL', 'Accounts.'], ['SapAccountBruteforceArgument', 'SAP', 'Accounts.'],
  ];
  VR.credChecks = () => CRED_CHECKS.map(([type, service]) => ({ type, service }));
  // Фильтр по аргументу до select отбирает узлы; после select обязателен filter(Login) по алиасу.
  VR.credPdql = (type, sub = '', limit = 5000) => {
    const A = `Host.Endpoints<TransportEndpoint>.Service.Checks.Arguments<${type}>.${sub}`;
    return `filter(${A}Login) | select(@Host, Host.@Id as HostId, Host.@Importance as Imp, Host.OsName as OS, Host.Endpoints<TransportEndpoint>.Port as Port, Host.Endpoints<TransportEndpoint>.Protocol as Proto, Host.Endpoints<TransportEndpoint>.Service.Checks.DisplayName as Chk, ${A}Login as Login, ${A}Password as Pwd) | filter(Login) | limit(${limit})`;
  };
  // Классические значения по умолчанию у вендоров — короткий справочник для показателя K23.
  const VENDOR_DEFAULTS = new Set(['admin', 'password', 'root', 'toor', 'administrator', 'guest', 'user', 'test', 'changeme', 'default', 'sa', 'postgres', 'oracle', 'cisco', 'public', 'private', 'manager', 'system', 'ubnt', 'vagrant', 'zabbix']);
  // Вердикт по паролю. k21 — не соответствует требованиям (любой подобранный пароль таков). k23 — значение по умолчанию.
  VR.credVerdict = (login, password) => {
    const p = String(password ?? ''), l = String(login ?? '').toLowerCase().trim();
    const reasons = [];
    if (p === '') reasons.push('пустой пароль');
    else if (p.toLowerCase() === l && l) reasons.push('пароль совпадает с логином');
    else if (VENDOR_DEFAULTS.has(p.toLowerCase())) reasons.push('значение по умолчанию');
    const k23 = reasons.length > 0;
    if (!k23) {
      if (p.length < 8) reasons.push('короче 8 символов');
      const classes = [/[a-zа-яё]/.test(p), /[A-ZА-ЯЁ]/.test(p), /\d/.test(p), /[^\wЀ-ӿ]/.test(p)].filter(Boolean).length;
      if (classes < 3) reasons.push('менее трех классов символов');
    }
    return { k21: true, k23, reasons: reasons.length ? reasons : ['подобран при проверке'] };
  };
  VR.maskSecret = v => { const s = String(v ?? ''); return s === '' ? '(пусто)' : s.length <= 2 ? '*'.repeat(s.length) : s[0] + '*'.repeat(Math.min(10, s.length - 1)); };
  // Собрать учетные записи по всем типам проверок. onProgress(done, total). Пароли хранятся для вердикта.
  VR.auditCredentials = async ({ limit = 5000, onProgress } = {}) => {
    const items = [], failed = [], seen = new Set();
    for (let i = 0; i < CRED_CHECKS.length; i++) {
      const [type, service, sub] = CRED_CHECKS[i];
      try {
        for (const r of rows(await VR.pdql(VR.credPdql(type, sub || '', limit), limit, 0))) {
          const login = rowVal(r, 'Login'); if (login == null || login === '') continue;
          const host = getVal(r, '@Host');
          const it = { host: host?.name || '', hostId: rowVal(r, 'HostId') || host?.id || '', imp: rowVal(r, 'Imp'), os: rowVal(r, 'OS'), port: rowVal(r, 'Port'), proto: rowVal(r, 'Proto'), check: rowVal(r, 'Chk'), service, type, login: String(login), password: String(rowVal(r, 'Pwd') ?? '') };
          const key = [it.hostId || it.host, it.port, it.type, it.login, it.password].join('|');
          if (seen.has(key)) continue; seen.add(key);
          Object.assign(it, VR.credVerdict(it.login, it.password));
          items.push(it);
        }
      } catch (e) { failed.push({ type, service, error: e.message }); }
      if (onProgress) onProgress(i + 1, CRED_CHECKS.length);
    }
    const byService = {}; items.forEach(i => { byService[i.service] = (byService[i.service] || 0) + 1; });
    return { items, failed, generatedAt: new Date().toISOString(),
      summary: { accounts: items.length, hosts: new Set(items.map(i => i.hostId || i.host)).size, k23: items.filter(i => i.k23).length,
        byService: Object.entries(byService).map(([service, n]) => ({ service, n })).sort((a, b) => b.n - a.n) } };
  };
  // Разделы отчета для VR.reports (пароли маскируются, если не включен показ).
  VR.credReportSections = (data, { showPasswords = false, org = '', system = '', executor = '' } = {}) => {
    const R = VR.reports, pw = p => showPasswords ? (p === '' ? '(пусто)' : p) : VR.maskSecret(p);
    const map = i => ({ host: i.host, imp: i.imp, os: i.os, service: `${i.service} (${i.proto || ''}/${i.port || ''})`, login: i.login, password: pw(i.password), reasons: i.reasons.join('; ') });
    const cols = (withos, extra) => [['Узел', 'host'], ['Значимость', 'imp'], ...(withos ? [['ОС', 'os']] : []), ['Сервис', 'service'], ['Логин', 'login'], ['Пароль', 'password'], ['Основание', 'reasons']];
    const k23 = data.items.filter(i => i.k23);
    return [
      ...R.dataSections('Реквизиты отчёта', { Организация: org || '—', Система: system || '—', Исполнитель: executor || '—', Сформирован: data.generatedAt, Узлов: data.summary.hosts, 'Учётных записей': data.summary.accounts, 'Со значениями по умолчанию': data.summary.k23, Источник: 'MaxPatrol VM, результаты проверок подбора учётных записей', Основание: 'Методика оценки показателя защищённости КЗИ ФСТЭК России, показатели K21 и K23' }),
      R.table('Сводка по сервисам', data.summary.byService, [['Сервис', 'service'], ['Учётных записей', 'n']]),
      R.table('K21. Пароли, не соответствующие установленным требованиям', data.items.map(map), cols(true)),
      R.table('K23. Пароли, установленные по умолчанию', k23.map(map), cols(true)),
      ...(data.failed.length ? [R.table('Проверки, которые не удалось выгрузить', data.failed, [['Тип', 'type'], ['Сервис', 'service'], ['Ошибка', 'error']])] : []),
    ];
  };

  // ════════════════════════════════════════════════════════════════════════
  // 2. Сканирование по PDQL-выборке: цели задачи без создания динамической группы
  //    Kerberos на Windows работает по FQDN, поэтому приоритет FQDN над IP.
  // ════════════════════════════════════════════════════════════════════════
  VR.pdqlTargets = async ({ pdql, preferFqdn = true, limit = 5000 } = {}) => {
    let q = String(pdql || '').trim();
    if (!q) throw new Error('Укажите условие выборки, например filter(WindowsHost)');
    q = q.replace(/\|\s*select\s*\([^)]*\)\s*$/i, '').replace(/\|\s*limit\s*\(\d+\)\s*$/i, '').trim();
    const full = `${q} | select(@Host, Host.@Id as HostId, Host.Fqdn as Fqdn, Host.IpAddress as Ip, Host.OsName as OS, Host.@Importance as Imp) | limit(${limit})`;
    const seen = new Set(), targets = [], hosts = [];
    for (const r of rows(await VR.pdql(full, limit, 0))) {
      const h = getVal(r, '@Host'), fqdn = rowVal(r, 'Fqdn'), ip = rowVal(r, 'Ip');
      const target = (preferFqdn && fqdn) ? String(fqdn) : (ip ? String(ip) : (fqdn ? String(fqdn) : ''));
      hosts.push({ host: h?.name || '', id: rowVal(r, 'HostId') || h?.id || '', fqdn: fqdn || '', ip: ip || '', os: rowVal(r, 'OS'), imp: rowVal(r, 'Imp'), target });
      if (target && !seen.has(target.toLowerCase())) { seen.add(target.toLowerCase()); targets.push(target); }
    }
    return { pdql: full, hosts, targets, noTarget: hosts.filter(x => !x.target).length };
  };
  const TASKS = '/api/scanning/v3/scanner_tasks';
  VR.tasks = async () => {
    const d = await VR.get(TASKS, { limit: 500 });
    return (Array.isArray(d) ? d : d?.items || []).map(t => ({ id: t.id, name: t.name, status: t.status, profile: t.profile?.name || '', agent: t.agent?.name || '', module: t.module?.name || t.module?.id || '', targets: t.include?.targets || [], groups: (t.include?.assetsGroups || []).map(g => g.name), lastRun: t.lastRun }));
  };
  VR.task = id => VR.get(`${TASKS}/${id}`);
  // Тело для создания/правки задачи из исходной задачи-образца: меняем только цели.
  VR.taskBodyWithTargets = (src, targets, { name, description, preferFqdn } = {}) => ({
    name: name || src.name, description: description != null ? description : (src.description || ''),
    agent: src.agent?.id || src.agent || null,
    component: src.component || null,
    scope: src.scope?.id || src.scope,
    profile: src.profile?.id || src.profile,
    include: { assets: [], targets: [...targets], assetsGroups: [] },
    exclude: { assets: [], targets: [], assetsGroups: [] },
    isFqdnPriority: preferFqdn != null ? !!preferFqdn : (src.isFqdnPriority !== false),
    hostDiscovery: src.hostDiscovery || { enabled: false, profile: null },
    credentials: (src.credentials || []).map(c => (typeof c === 'string' ? c : c.id)),
    triggerParameters: { isEnabled: false, type: 'Daily', timeZone: '+03:00', atTime: '09:00:00', fromDate: VR.plusDays(0), daysOfWeek: ['monday'] },
  });
  VR.createTask = body => VR.post(TASKS, body);               // -> {id}
  VR.updateTask = (id, body) => VR.put(`${TASKS}/${id}`, body);
  VR.runTask = id => VR.post(`${TASKS}/${id}/start`, {});
  VR.deleteTask = id => VR.del(`${TASKS}/${id}`);

  // ════════════════════════════════════════════════════════════════════════
  // 3. Динамические группы: список, проверка и смена PDQL-запроса
  //    Правка — массивом команд [{type:'SetPredicateGroupCommand', value:'...'}] (28.0).
  //    На 27.6 чтение иерархии может вернуть 500: тогда работаем валидацией и счетом.
  // ════════════════════════════════════════════════════════════════════════
  const GRP_READ = '/api/assets_temporal_readmodel/v2/groups';
  const GRP_WRITE = '/api/assets_processing/v2/groups';
  VR.dynGroups = async () => {
    let flat = [];
    try {
      const tree = await VR.get(`${GRP_READ}/hierarchy`);
      const walk = n => { flat.push(n); (n.children || []).forEach(walk); };
      (Array.isArray(tree) ? tree : []).forEach(walk);
    } catch (e) {
      const all = await VR.get(GRP_READ).catch(() => null);
      if (!all) throw e;
      flat = Array.isArray(all) ? all : (all.items || []);
    }
    const dyn = flat.filter(g => g.groupType === 'dynamic').map(g => ({ id: g.id, name: g.name, treePath: g.treePath || g.name, predicate: g.predicate || '', isReadOnly: !!g.isReadOnly, isInvalid: !!g.isInvalidPredicate }));
    // Иерархия не содержит сам запрос: дотягиваем predicate по каждой группе (по 8 параллельно, best-effort).
    const need = dyn.filter(g => !g.predicate);
    for (let i = 0; i < need.length; i += 8) {
      await Promise.all(need.slice(i, i + 8).map(async g => {
        try { const info = await VR.groupInfo(g.id); g.predicate = info.predicate || ''; if (info.isInvalidPredicate) g.isInvalid = true; }
        catch (_) { g.predicateUnavailable = true; }
      }));
    }
    return dyn;
  };
  VR.groupInfo = id => VR.get(`${GRP_READ}/${id}`);
  VR.validatePredicate = predicate => VR.post(`${GRP_WRITE}/predicate/validate`, { predicate });   // -> {isValid, isPotentiallySlow}
  VR.predicateCount = predicate => VR.post(`${GRP_WRITE}/predicate`, { predicate });                // -> {count}
  VR.updateGroupPredicate = (id, predicate) => VR.put(`${GRP_WRITE}/${id}`, [{ type: 'SetPredicateGroupCommand', value: predicate }]);
  VR.createDynGroup = ({ name, predicate, description = '', parentId = '00000000-0000-0000-0000-000000000002' }) =>
    VR.post(GRP_WRITE, { name, parentId, description, groupType: 'dynamic', predicate, metadata: [{ sourceId: 'UserInput', typeId: 'Cvss', payload: '{"td": "ND", "cr": "ND", "cdp": "ND", "ar": "ND", "ir": "ND"}' }], organizationInformation: { contactUserId: null, address: null }, organizationInfrastructure: { usedNetworks: null, numberOfNodes: null, usedNetworkApplications: null, internetProviders: null, registeredDomains: null } });
  VR.removeGroup = id => VR.post(`${GRP_WRITE}/removeOperation`, { groupIds: [id] });

  // ════════════════════════════════════════════════════════════════════════
  // 4. Глобальные исключения из сканирования: список, очистка дубликатов, запись
  //    Тело записи: targets:{allModulesExclusion, moduleIds, assetGroupIds, assetIds, networkAddresses}.
  // ════════════════════════════════════════════════════════════════════════
  const EXCL = '/api/scanning/v1/global-exclusions';
  VR.exclusionList = async () => {
    const d = await VR.get(EXCL);
    return (Array.isArray(d) ? d : []).map(e => {
      const t = e.targets || {};
      const nets = t.networkAddresses || [];
      const dup = nets.length - new Set(nets.map(x => String(x).trim())).size;
      return { id: e.id, name: e.name, description: e.description || '', allModules: !!t.allModulesExclusion, modules: t.modules || [], assetGroups: t.assetGroups || [], assets: t.assets || [], networks: nets, counts: { groups: (t.assetGroups || []).length, assets: (t.assets || []).length, networks: nets.length, dupNetworks: dup } };
    });
  };
  const dedup = arr => { const seen = new Set(), out = []; for (const v of arr || []) { const k = String(v).trim(); if (k && !seen.has(k)) { seen.add(k); out.push(k); } } return out; };
  const dedupById = arr => { const seen = new Set(), out = []; for (const v of arr || []) { const id = v && v.id; if (id && !seen.has(id)) { seen.add(id); out.push(v); } } return out; };
  VR.exclusionBody = e => ({ name: e.name, description: e.description || '', targets: { allModulesExclusion: e.allModules !== false, moduleIds: (e.modules || []).map(m => m.id || m), assetGroupIds: dedupById(e.assetGroups).map(g => g.id), assetIds: dedupById(e.assets).map(a => a.id), networkAddresses: dedup(e.networks) } });
  VR.saveExclusion = (id, e) => id ? VR.put(`${EXCL}/${id}`, { id, ...VR.exclusionBody(e) }) : VR.post(EXCL, VR.exclusionBody(e));
  VR.deleteExclusion = id => VR.del(`${EXCL}/${id}`);
  // Снять дубликаты сетей, активов и групп в исключении и сохранить.
  VR.dedupExclusion = async e => {
    const before = { networks: (e.networks || []).length, assets: (e.assets || []).length, groups: (e.assetGroups || []).length };
    const cleaned = { ...e, networks: dedup(e.networks), assets: dedupById(e.assets), assetGroups: dedupById(e.assetGroups) };
    await VR.saveExclusion(e.id, cleaned);
    const after = { networks: cleaned.networks.length, assets: cleaned.assets.length, groups: cleaned.assetGroups.length };
    return { removed: { networks: before.networks - after.networks, assets: before.assets - after.assets, groups: before.groups - after.groups }, after };
  };

  // ════════════════════════════════════════════════════════════════════════
  // 5. Обозреватель модели актива: собранные поля и готовый путь для PDQL
  //    Метаданные модели: GET /api/assets/metadata/{ТипУзла}. Корень — Core.Host.
  // ════════════════════════════════════════════════════════════════════════
  VR.modelType = async type => VR.get(`/api/assets/metadata/${encodeURIComponent(type)}`);
  // Разворачиваем модель вглубь по ссылкам type до глубины depth. Возвращаем плоский список путей PDQL.
  VR.modelTree = async ({ root = 'Core.Host', depth = 2 } = {}) => {
    const cache = new Map(), out = [];
    const load = async t => { if (cache.has(t)) return cache.get(t); let d = null; try { d = await VR.modelType(t); } catch (_) {} cache.set(t, d); return d; };
    const prefixFor = name => name === 'Core.Host' ? 'Host' : name;
    const walk = async (type, path, d) => {
      const meta = await load(type); if (!meta) return;
      for (const p of meta.properties || []) {
        const kind = p.kind, isColl = p.isCollection;
        const pdqlPath = `${path}.${cap(p.name)}${isColl ? '' : ''}`;
        out.push({ path: pdqlPath, title: p.title || p.name, kind, type: p.type, collection: !!isColl, prop: p.name });
        if (d > 1 && (kind === 'entity' || kind === 'struct') && p.type) await walk(p.type, pdqlPath, d - 1);
      }
    };
    const cap = s => String(s || '').replace(/^(.)/, c => c.toUpperCase());
    await walk(root, prefixFor(root), depth);
    return out;
  };
  // Паспорт актива (метрики, значимость, владельцы). Не содержит сырых конфигов — для них модель + PDQL.
  VR.assetPassport = id => VR.get(`/api/assets_temporal_readmodel/v1/assets_info/${id}/passport`);

  // Признак доступности эксперимента на старых версиях (всё работает и на 27.6, см. комментарии).
  VR.experimentNotes = () => ({ legacyGroups: 'На 27.6 иерархия групп может отдавать ошибку сервера; валидация и счет работают.' });
})(window.VR);

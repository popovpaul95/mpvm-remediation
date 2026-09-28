'use strict';
// Доработки штатных экранов MaxPatrol VM (по итогам аудита интерфейса 28.0):
//  1. Карточка/паспорт уязвимости: блок "Внешний контекст" под штатными ссылками:
//     NVD, dbugs, Vulners, GitHub, поиск в БДУ; по кнопке EPSS, KEV, SSVC и прямые
//     ссылки на патчи и бюллетени вендора из NVD (теги Patch / Vendor Advisory).
//  2. Карточка актива, вкладка "Уязвимости": кнопка выгрузки уязвимостей актива в CSV.
//  3. Переходы с дашборда (window.open в новую вкладку) в текущей вкладке (опция).
(function (VR) {
  if (window.__VR_CARDS_MOUNTED) return;
  window.__VR_CARDS_MOUNTED = true;

  const CVE_RE = /CVE-\d{4}-\d{4,}/i;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = n => Number(n || 0).toLocaleString('ru-RU');
  const today = () => new Date().toISOString().slice(0, 10);

  const STYLE = `
.vr-cb { margin: var(--kbq-size-l, 16px) 0; padding: var(--kbq-size-m, 12px) var(--kbq-size-l, 16px); border: 1px solid var(--kbq-line-contrast-less, #e3e5ea); border-radius: 12px; background: var(--kbq-background-bg-secondary, transparent);
  font-family: var(--kbq-typography-text-normal-font-family, Inter, -apple-system, sans-serif); font-size: var(--kbq-typography-text-normal-font-size, 14px); line-height: var(--kbq-typography-text-normal-line-height, 20px); color: var(--kbq-foreground-contrast, inherit); }
.vr-cb .vr-title { margin: 0 0 var(--kbq-size-s, 8px); font-weight: 600; display: flex; align-items: center; gap: var(--kbq-size-s, 8px); }
.vr-cb .vr-title .vr-src { font-size: var(--kbq-typography-text-compact-font-size, 12px); font-weight: 400; color: var(--kbq-foreground-contrast-secondary, #6f7580); }
.vr-cb .vr-links { display: flex; flex-wrap: wrap; gap: var(--kbq-size-xxs, 4px) var(--kbq-size-l, 16px); }
.vr-cb .vr-links a { color: var(--kbq-link-text, #2f80ed); text-decoration: none; white-space: nowrap; }
.vr-cb .vr-links a:hover { text-decoration: underline; }
.vr-cb .vr-row { margin-top: var(--kbq-size-s, 8px); display: flex; gap: var(--kbq-size-s, 8px); align-items: center; flex-wrap: wrap; }
.vr-asset-export { display: block; width: 100%; box-sizing: border-box; margin: var(--kbq-size-s, 8px) 0 var(--kbq-size-m, 12px); padding: 0; background: transparent; border: none; }
.vr-asset-export .vr-row { margin-top: 0; } .vr-asset-export .vr-muted { margin-top: 4px; }
.vr-cb .vr-line { margin-top: var(--kbq-size-xs, 6px); }
.vr-cb .vr-muted { color: var(--kbq-foreground-contrast-secondary, #6f7580); font-size: var(--kbq-typography-text-compact-font-size, 12px); }
.vr-cb .vr-err { color: var(--kbq-foreground-error, #d23c3c); font-size: var(--kbq-typography-text-compact-font-size, 12px); }
.vr-cb .vr-b { display: inline-flex; align-items: center; height: 20px; font-size: var(--kbq-typography-text-compact-font-size, 12px); padding: 0 var(--kbq-size-xs, 6px); border-radius: 4px; font-weight: 500; margin-right: var(--kbq-size-xs, 6px); }
.vr-cb .P0 { background: var(--kbq-badge-filled-fade-off-error-background, #d23c3c); color: var(--kbq-badge-filled-fade-off-error-color, #fff); }
.vr-cb .P1 { background: var(--kbq-badge-filled-fade-off-warning-background, #f0883e); color: var(--kbq-badge-filled-fade-off-warning-color, #fff); }
.vr-cb .P2 { background: var(--kbq-badge-filled-fade-on-warning-background, #fdf1d6); color: var(--kbq-badge-filled-fade-on-warning-color, #8a5a00); }
.vr-cb .P3 { background: var(--kbq-badge-filled-fade-on-contrast-background, #e3e5ea); color: var(--kbq-badge-filled-fade-on-contrast-color, #262a35); }
.vr-cb .kev { background: var(--kbq-badge-filled-fade-off-error-background, #d23c3c); color: var(--kbq-badge-filled-fade-off-error-color, #fff); }
.vr-cb .tag { background: var(--kbq-badge-filled-fade-on-contrast-background, #eef0f3); color: var(--kbq-badge-filled-fade-on-contrast-color, inherit); }
.vr-cb ul { margin: var(--kbq-size-xxs, 4px) 0 0 18px; padding: 0; } .vr-cb li { margin: 2px 0; } .vr-cb li a { color: var(--kbq-link-text, #2f80ed); text-decoration: none; } .vr-cb li a:hover { text-decoration: underline; }
.vr-btn { font-family: inherit; font-size: var(--kbq-typography-text-normal-font-size, 14px); font-weight: 500; display: inline-flex; align-items: center; gap: var(--kbq-size-xs, 6px);
  height: var(--kbq-button-size-height, 32px); padding: 0 var(--kbq-button-size-horizontal-padding, 12px); border-radius: var(--kbq-button-size-border-radius, 8px);
  border: 1px solid var(--kbq-button-filled-contrast-fade-off-border, transparent); background: var(--kbq-button-filled-contrast-fade-off-background, #e3e5ea); color: var(--kbq-button-filled-contrast-fade-off-foreground, #262a35); cursor: pointer; white-space: nowrap; }
.vr-btn:hover { background: var(--kbq-button-filled-contrast-fade-off-states-hover-background, #d3d6dd); }
.vr-btn.acc { background: var(--kbq-background-theme, #2f80ed); color: var(--kbq-foreground-white, #fff); font-weight: 600; }
.vr-btn.acc:hover { filter: brightness(1.08); }
.vr-btn:disabled { background: var(--kbq-button-filled-contrast-fade-off-states-disabled-background, rgba(120,130,160,.16)); color: var(--kbq-button-filled-contrast-fade-off-states-disabled-foreground, rgba(120,130,160,.6)); cursor: default; filter: none; }
`;
  function ensureStyle() {
    if (document.getElementById('vr-cards-style')) return;
    const s = document.createElement('style'); s.id = 'vr-cards-style'; s.textContent = STYLE; document.head.appendChild(s);
  }

  // ── Обход DOM вместе с shadow-деревьями (карточки MaxPatrol живут в web-components) ──
  function deepAll(pred, limit) {
    const out = [];
    const walk = (root, d) => {
      if (!root || d > 40 || out.length >= (limit || 50)) return;
      const kids = root.children || [];
      for (const e of kids) {
        if (e.id === 'vr-root') continue;
        if (pred(e)) out.push(e);
        if (e.shadowRoot) walk(e.shadowRoot, d + 1);
        walk(e, d + 1);
      }
    };
    walk(document.body, 0);
    return out;
  }
  const norm = s => String(s || '').replace(/\s+/g, ' ').trim();
  // Стили кладем в тот корень (документ или shadow root), где стоит блок
  function ensureStyleIn(root) {
    const host = root && root.nodeType === Node.DOCUMENT_FRAGMENT_NODE ? root : document.head;
    if (host.querySelector && host.querySelector('#vr-cards-style')) return;
    const s = document.createElement('style'); s.id = 'vr-cards-style'; s.textContent = STYLE; host.appendChild(s);
  }
  function ensureStyle() { ensureStyleIn(document.head); }

  // Заголовок секции карточки/паспорта уязвимости: <div class="vulner-info-section__title">Ссылки</div>
  function findSectionTitles(rx) {
    return deepAll(e => e.children.length === 0 && /section__title|^h[1-6]$/i.test(e.className + ' ' + e.tagName) && rx.test(norm(e.textContent)) && !e.closest('.vr-cb'), 20);
  }
  function cardContainer(headingEl) {
    // Секция -> колонка карточки (.vulner__primary-info) -> вся карточка; нужен блок, где есть и "Описание", и "Ссылки"
    let el = headingEl.parentElement;
    for (let i = 0; i < 12 && el; i++) { const txt = el.textContent || ''; if (/Ссылки/.test(txt) && /Описание|Как исправить|Основная информация/.test(txt) && el !== headingEl.parentElement) return el; el = el.parentElement; }
    return headingEl.parentElement.parentElement || headingEl.parentElement;
  }
  function cardIdentity(container) {
    const text = container.textContent || '';
    const root = container.getRootNode();
    const headText = (root.querySelector && (root.querySelector('.vulner__title, .vulner-header, [class*="header"]')?.textContent)) || '';
    const cve = (headText.match(CVE_RE) || text.match(CVE_RE) || document.title.match(CVE_RE) || [])[0];
    const bdu = (headText.match(/BDU:\d{4}-\d{5}/i) || text.match(/BDU:\d{4}-\d{5}/i) || [])[0];
    const name = (document.title.match(/Уязвимость\s+([^·]+)/) || [])[1]?.trim() || norm(headText).slice(0, 80);
    return { cve: cve ? cve.toUpperCase() : null, bdu: bdu ? bdu.toUpperCase() : null, name };
  }

  function linksHtml(id) {
    const q = encodeURIComponent(id.cve || id.bdu || id.name);
    const L = [];
    if (id.cve) {
      L.push(['NVD', `https://nvd.nist.gov/vuln/detail/${id.cve}`], ['cve.org', `https://www.cve.org/CVERecord?id=${id.cve}`], ['dbugs (PT)', `https://dbu.gs/vulnerability/${id.cve}`],
        ['БДУ (поиск)', `https://bdu.fstec.ru/search?q=%22${id.cve}%22&yt0=%D0%98%D1%81%D0%BA%D0%B0%D1%82%D1%8C`], ['Vulners', `https://vulners.com/search?query=${id.cve}`], ['GitHub PoC', `https://github.com/search?q=${id.cve}&type=repositories`], ['EPSS', `https://api.first.org/data/v1/epss?cve=${id.cve}`]);
    } else {
      L.push(['Vulners', `https://vulners.com/search?query=${q}`]);
      if (id.bdu) L.push(['БДУ', `https://bdu.fstec.ru/vul/${id.bdu.replace('BDU:', '')}`]);
    }
    return L.map(([t, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener">${t}</a>`).join('');
  }

  function renderEnrich(cve, r) {
    const v = r.verdict || {}, n = r.nvd, out = [];
    out.push(`<div class="vr-line"><span class="vr-b ${esc(v.level || 'P3')}">${esc(v.level || '')}</span><b>${esc(v.title || '')}</b>${v.reasons?.length ? ': ' + esc(v.reasons.join('; ')) : ''}; рекомендуемый срок ${esc(v.slaDays)} дн</div>`);
    if (r.epss?.epss != null) out.push(`<div class="vr-line">EPSS <b>${(r.epss.epss * 100).toFixed(1)}%</b> (перцентиль ${(r.epss.percentile * 100).toFixed(0)}, ${esc(r.epss.date)})</div>`);
    if (r.kev) out.push(`<div class="vr-line"><a class="vr-b kev" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(id.cve || '')}" target="_blank" rel="noopener" style="text-decoration:none">CISA KEV</a> добавлена ${esc(r.kev.dateAdded)}, срок ${esc(r.kev.dueDate)}${r.kev.ransomware === 'Known' ? ', <b>используется в ransomware</b>' : ''}</div>`);
    if (n && !n.missing) {
      const p = [];
      if (n.cvss40) p.push(`CVSS 4.0 <b>${esc(n.cvss40.score)}</b>`); if (n.cvss31) p.push(`CVSS 3.1 <b>${esc(n.cvss31.score)}</b>`);
      if (n.ssvc?.exploitation) p.push(`SSVC: ${esc(n.ssvc.exploitation)} / ${esc(n.ssvc.automatable || '?')} / ${esc(n.ssvc.impact || '?')}`);
      if (p.length) out.push(`<div class="vr-line">NVD: ${p.join(' | ')}; опубликована ${esc((n.published || '').slice(0, 10))}</div>`);
      const patches = (n.refs || []).filter(x => x.tags.some(t => /patch/i.test(t)));
      const advis = (n.refs || []).filter(x => !x.tags.some(t => /patch/i.test(t)));
      if (patches.length) out.push(`<div class="vr-line"><b>Прямые ссылки на патчи (NVD, тег Patch):</b><ul>${patches.map(x => `<li><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.url.replace(/^https?:\/\//, '').slice(0, 90))}</a></li>`).join('')}</ul></div>`);
      if (advis.length) out.push(`<div class="vr-line"><b>Бюллетени вендора и советы:</b><ul>${advis.slice(0, 6).map(x => `<li><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.url.replace(/^https?:\/\//, '').slice(0, 90))}</a> <span class="vr-muted">${esc(x.tags.join(', '))}</span></li>`).join('')}</ul></div>`);
      if (!patches.length && !advis.length) out.push('<div class="vr-line vr-muted">NVD не содержит ссылок с тегами Patch или Vendor Advisory для этого CVE.</div>');
    } else if (n?.missing) out.push('<div class="vr-line vr-muted">В NVD запись не найдена.</div>');
    if (r.bdu?.length) out.push(`<div class="vr-line">БДУ (импорт): <b>${r.bdu.map(b => esc(b.id)).join(', ')}</b></div>`);
    return out.join('');
  }

  function mountVulnBlock() {
    const titles = findSectionTitles(/^Ссылки$/);
    for (const h of titles) {
      const section = h.parentElement;               // .vulner-info-section
      const column = section.parentElement;          // .vulner__primary-info
      if (!column || column.querySelector(':scope > .vr-cb[data-kind=vuln]')) continue;
      const container = cardContainer(h);
      const id = cardIdentity(container);
      if (!id.cve && !id.bdu && !id.name) continue;
      ensureStyleIn(h.getRootNode());
      const box = document.createElement('div');
      box.className = (section.className.includes('vulner-info-section') ? 'vulner-info-section ' : '') + 'vr-cb'; box.dataset.kind = 'vuln';
      box.innerHTML = `<div class="${section.className.includes('vulner-info-section') ? 'vulner-info-section__title' : ''} vr-title">Внешний контекст <span class="vr-src">расширение «Устранение»</span></div>
        <div class="vr-links">${linksHtml(id)}</div>
        ${id.cve ? `<div class="vr-row"><button class="vr-btn acc" data-act="enrich">EPSS, KEV, SSVC и ссылки на патчи</button><span class="vr-muted" data-role="st"></span></div><div data-role="out"></div>` : '<div class="vr-line vr-muted">У уязвимости нет CVE: внешние базы эксплуатации (EPSS, KEV, NVD) ее не описывают.</div>'}`;
      section.insertAdjacentElement('afterend', box);
      const btn = box.querySelector('[data-act=enrich]');
      if (btn) btn.addEventListener('click', async () => {
        btn.disabled = true; const st = box.querySelector('[data-role=st]'); st.textContent = 'запрос (NVD без ключа до 10 с)...';
        try {
          const r = await VR.ext('enrich', { cves: [id.cve], skipNvd: false });
          box.querySelector('[data-role=out]').innerHTML = renderEnrich(id.cve, r.results[id.cve]);
          st.textContent = '';
        } catch (e) { st.innerHTML = `<span class="vr-err">${esc(e.message)}</span>`; }
        btn.disabled = false;
      });
    }
  }

  // ── Кнопка выгрузки уязвимостей актива ────────────────────────────────────
  function assetIdFromUrl() { return new URLSearchParams(location.search).get('assetId'); }
  async function exportAssetVulns(assetId, btn, st) {
    btn.disabled = true; st.textContent = 'PDQL...';
    try {
      const pdql = `filter(Host.@Id = ${assetId} and Host.@Vulners) | select(@Host, Host.@Vulners as Name, Host.@Vulners.Ids.Item as Ids, Host.@Vulners.CVEs.Item as CVE, Host.@Vulners.Score as Score, Host.@Vulners.SeverityRating as Sev, Host.@Vulners.Status as St, Host.@Vulners.DiscoveryTime as Found, Host.@Vulners.IsTrend as Trend, Host.@Vulners.Metrics.Exploitable as Expl, Host.@Vulners.Metrics.HasPatch as HasPatch, Host.@Vulners.Patch.PatchLink as PatchLink, Host.@Vulners.FixType as FixType, Host.@Vulners.Impact.PrimaryType as Impact)`;
      const rows = VR.rows(await VR.pdql(pdql, 50000, 0));
      const host = rows[0] ? (VR.getVal(rows[0], '@Host')?.name || '') : assetId;
      const cols = [['Узел', r => VR.getVal(r, '@Host')?.name || ''], ['Уязвимость', r => VR.rowVal(r, 'Name')], ['Идентификатор', r => VR.rowVal(r, 'Ids')], ['CVE', r => VR.rowVal(r, 'CVE')], ['CVSS', r => VR.rowVal(r, 'Score')], ['Уровень', r => VR.rowVal(r, 'Sev')], ['Статус', r => VR.rowVal(r, 'St')], ['Обнаружена', r => VR.rowVal(r, 'Found')], ['Трендовая', r => VR.rowVal(r, 'Trend')], ['Эксплойт', r => VR.rowVal(r, 'Expl')], ['Есть патч', r => VR.rowVal(r, 'HasPatch')], ['Ссылка на патч', r => VR.rowVal(r, 'PatchLink')], ['Тип устранения', r => VR.rowVal(r, 'FixType')], ['Последствия', r => VR.rowVal(r, 'Impact')]];
      const q = v => { const s = String(v ?? ''); return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const csv = '﻿' + [cols.map(c => c[0]).join(';'), ...rows.map(r => cols.map(c => q(c[1](r))).join(';'))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' }); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `vulns_${String(host).replace(/[^\w.\-]+/g, '_').slice(0, 60)}_${today()}.csv`; document.body.appendChild(a); a.click(); setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 1500);
      st.textContent = `выгружено ${fmt(rows.length)} строк`;
    } catch (e) { st.textContent = 'ошибка: ' + e.message; }
    btn.disabled = false;
  }
  function mountAssetExport() {
    const assetId = assetIdFromUrl(); if (!assetId) return;
    if (deepAll(e => e.classList && e.classList.contains('vr-asset-export') && e.dataset.asset === assetId, 1).length) return;
    // Заголовки секций карточки актива, не вкладки: «Самые опасные уязвимости» (Сводка) или «Уязвимости ОС и ПО» (вкладка Уязвимости).
    // Само слово «Уязвимости» встречается и в переключателе вкладок, поэтому элементы с role=tab и внутри tab-контейнеров пропускаем.
    const isTab = e => !!(e.closest('[role="tab"], [role="tablist"], .kbq-tab-label, .mc-tab-label, [class*="tab-label"], [class*="tabs"], [class*="tab-link"]'));
    const heads = deepAll(e => e.children.length <= 1 && /^(Самые опасные уязвимости|Уязвимости ОС и ПО)$/.test(norm(e.textContent)) && !e.closest('.vr-cb') && e.getRootNode() !== document && !isTab(e), 10);
    for (const h of heads) {
      const container = h.parentElement; if (!container || container.querySelector('.vr-asset-export')) continue;
      ensureStyleIn(h.getRootNode());
      const row = document.createElement('div'); row.className = 'vr-asset-export vr-cb'; row.dataset.asset = assetId;
      row.innerHTML = `<div class="vr-row"><button class="vr-btn" data-act="csv">Выгрузить уязвимости в CSV</button><button class="vr-btn" data-act="jira">Задача в Jira</button></div><div class="vr-muted" data-role="st">Все открытые уязвимости узла с CVE, статусом, датой, признаками эксплойта и патча.</div>`;
      h.insertAdjacentElement('afterend', row);
      row.querySelector('[data-act=csv]').addEventListener('click', () => exportAssetVulns(assetId, row.querySelector('[data-act=csv]'), row.querySelector('[data-role=st]')));
      row.querySelector('[data-act=jira]').addEventListener('click', async () => {
        const btn = row.querySelector('[data-act=jira]'), st = row.querySelector('[data-role=st]');
        btn.disabled = true; st.textContent = 'собираем уязвимости узла...';
        try {
          const s = await VR.ext('settings-get');
          if (!s.jiraUrl || !s.jiraToken || !s.jiraProject) throw new Error('Заполните Jira в настройках расширения (пункт «Устранение», вкладка «Настройки»)');
          const asset = await VR.assetVulns(assetId);
          if (!asset.items.length) throw new Error('Открытых уязвимостей у узла нет');
          const issue = VR.buildAssetJiraIssue({ asset, sla: s, host: VR.config().host });
          if (!confirm(`Создать задачу в Jira (${s.jiraProject}):\n${issue.summary}\nСрок: ${issue.dueDate}`)) { btn.disabled = false; st.textContent = ''; return; }
          const r = await VR.ext('jira-create', issue);
          let note = '';
          try { await VR.ext('jira-attach', { key: r.key, filename: `mpvm_${String(asset.host).replace(/[^\w.\-]+/g, '_').slice(0, 50)}.csv`, content: issue.csv }); note += ', CSV приложен'; } catch (e) { note += ', вложение не удалось'; }
          if (s.jiraTagInstances !== false) { try { await VR.tagInstances(issue.ids, 'jira:' + r.key); note += `, метка на ${issue.ids.length} экз.`; } catch (e) { note += ', метку поставить не удалось'; } }
          st.innerHTML = `создана <a href="${esc(r.url)}" target="_blank" rel="noopener" style="color:#2f80ed">${esc(r.key)}</a>${esc(note)}`;
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
        btn.disabled = false;
      });
    }
  }

  // ── Переходы с дашборда в текущей вкладке ─────────────────────────────────
  function injectSameTab(enabled) {
    document.documentElement.dataset.vrSameTab = enabled ? '1' : '0';
    if (document.getElementById('vr-inject')) return;
    const s = document.createElement('script'); s.id = 'vr-inject'; s.src = chrome.runtime.getURL('content/inject.js'); (document.head || document.documentElement).appendChild(s);
  }

  // ── Запуск ────────────────────────────────────────────────────────────────
  let timer = null;
  function schedule() { clearTimeout(timer); timer = setTimeout(() => { const root = document.getElementById('vr-root'); if (root && root.style.display !== 'none') return; try { mountVulnBlock(); mountAssetExport(); } catch (e) { console.warn('[vr] cards:', e.message); } }, 600); }
  VR.loadConfig().then(async () => {
    if (!VR.isConfiguredHost()) return;
    try { const s = await VR.ext('settings-get'); injectSameTab(s.sameTabLinks !== false); } catch (_) {}
    schedule();
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
    chrome.storage.onChanged.addListener((ch, area) => { if (area === 'local' && ch.vr_settings) injectSameTab(ch.vr_settings.newValue?.sameTabLinks !== false); });
  });
})(window.VR);

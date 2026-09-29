// Отчёты используют загруженную модель, а не видимые строки DOM.
// Один spec для HTML, печати PDF и полного CSV; лимиты интерфейса здесь не применяются.
(function (VR) {
  'use strict';
  const labels = {
    cve: 'CVE', cves: 'CVE', verdict: 'Приоритет и рекомендации', level: 'Приоритет', title: 'Название', reasons: 'Обоснование', slaDays: 'Срок, дней',
    mp: 'MaxPatrol VM', epss: 'EPSS', percentile: 'Перцентиль EPSS', date: 'Дата', kev: 'CISA KEV', dateAdded: 'Добавлена в KEV', dueDate: 'Срок CISA', ransomware: 'Использование в ransomware', vendor: 'Вендор', product: 'Продукт',
    nvd: 'NVD', published: 'Опубликована', lastModified: 'Обновлена', status: 'Статус', cisaExploitAdd: 'Дата CISA', cvss40: 'CVSS 4.0', cvss31: 'CVSS 3.1', cvss2: 'CVSS 2.0', score: 'Оценка', vector: 'Вектор', severity: 'Уровень опасности',
    ssvc: 'SSVC', exploitation: 'Эксплуатация', automatable: 'Автоматизация', impact: 'Последствия', cwes: 'CWE', refs: 'Ссылки NVD', description: 'Описание', missing: 'Отсутствует в источнике',
    bdu: 'БДУ ФСТЭК', gh: 'GitHub', count: 'Количество', items: 'Записи', name: 'Название', url: 'Ссылка', stars: 'Звёзды', updated: 'Обновлено', ts: 'Время кеширования (Unix ms)', meta: 'Состояние источников', kevDate: 'Выпуск KEV', kevError: 'Ошибка KEV', nvdSkipped: 'NVD пропущен', source: 'Источник',
    instances: 'Экземпляры в MaxPatrol', summary: 'Сводка', selected: 'Выбранный экземпляр', pickedBy: 'Способ выбора экземпляра', loading: 'Загрузка выполняется', pendingId: 'Загружаемый экземпляр', error: 'Ошибка', errors: 'Ошибки загрузки',
    item: 'Экземпляр', host: 'Узел', hostId: 'ID узла', id: 'ID', imp: 'Значимость', os: 'ОС', vulnId: 'ID паспорта', sev: 'Уровень опасности', st: 'Статус', found: 'Обнаружена', trend: 'Трендовая', expl: 'Эксплойт', exploit: 'Эксплойт',
    patch: 'Патч', patchName: 'Название патча', patchUrl: 'Ссылка на патч', det: 'Установленное ПО и условия', release: 'Выпуск', arch: 'Архитектура', installType: 'Тип установки', versionLabel: 'Тип версии', current: 'Установленная версия', required: 'Требуемая версия', requiredStrict: 'Строго выше версии', conditions: 'Условия обнаружения', value: 'Значение', strict: 'Строго',
    fix: 'Исправление', options: 'Варианты исправления', version: 'Версия', kb: 'KB', min: 'Минимальная версия', recommended: 'Рекомендуемая версия', links: 'Ссылки', metrics: 'Метрики', overall: 'Итоговая оценка', base: 'Базовая оценка', environmental: 'Контекстная оценка', statusLog: 'История статусов', tags: 'Метки', lastFixedDate: 'Последнее устранение', type: 'Тип', passport: 'Паспорт уязвимости', howToFix: 'Рекомендации по устранению', stats: 'Статистика', urls: 'Карточки MaxPatrol', card: 'Экземпляр', asset: 'Актив',
    total: 'Всего', hosts: 'Узлы', open: 'Открыто', byStatus: 'По статусам', maxScore: 'Максимальный CVSS', pdql: 'PDQL выборки', truncated: 'Достигнут лимит выборки', limit: 'Лимит запроса', rows: 'Строк', rawRows: 'Строк до объединения', ids: 'ID экземпляров',
    groups: 'Группы', products: 'Продукты', totalGroups: 'Всего групп', scope: 'Область выборки', minScore: 'Минимальный CVSS', soft: 'ПО', ver: 'Версия', pkg: 'Пакет', image: 'Образ', n: 'Количество', risk: 'Риск', crit: 'Критических', high: 'Высоких',
    patches: 'Патчи', noLink: 'Исправления без ссылки на патч', noLinkVulns: 'Уязвимостей без ссылки', noLinkHosts: 'Узлов без ссылки', hostsCount: 'Узлов', vulns: 'Уязвимости', enrichment: 'Внешнее обогащение', enrichmentError: 'Ошибка обогащения', enrichmentLoading: 'Обогащение выполняется',
    assets: 'Активы', byImp: 'По значимости', byOs: 'По ОС', byZone: 'По зоне риска', byType: 'По типу', weights: 'Веса риска', why: 'Обоснование риска', zone: 'Зона риска', key: 'Группа', avg: 'Среднее', max: 'Максимум', kevChecked: 'Проверено CVE в KEV',
    byReason: 'По причинам', reason: 'Причина', note: 'Комментарий', risky: 'Сомнительные исключения', danger: 'Опасная', highImp: 'На значимых активах', noNote: 'Без комментария',
    projects: 'Проекты', tag: 'Метка', fixed: 'Устранено', excluded: 'Исключено', progress: 'Прогресс, %', kind: 'Тип', sites: 'Веб-сайты', site: 'Сайт', siteId: 'ID сайта',
    rule: 'Правило', ok: 'Успешно', hasMatches: 'Найдены активы', failed: 'Ошибок', color: 'Цвет', generatedAt: 'Время снимка', sla: 'Сроки SLA', statuses: 'Статусы', slaRows: 'Сроки экземпляров', signals: 'Сигналы', flow: 'Динамика обнаружения', topHosts: 'Узлы с наибольшим риском', trendTop: 'Трендовые CVE', past30: 'Данные 30 дней назад',
    selectedSla: 'Срок выбранного экземпляра', days: 'Срок, дней', due: 'Исправить до', overdue: 'Просрочено', selectionError: 'Ошибка загрузки экземпляра',
  };
  const label = key => labels[key] || key;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const valueText = value => {
    if (value == null) return 'Нет данных';
    if (typeof value === 'boolean') return value ? 'да' : 'нет';
    if (Array.isArray(value)) return value.length ? value.map((v, i) => typeof v === 'object' && v !== null ? `${i + 1}. ${valueText(v)}` : valueText(v)).join('\n') : 'Нет записей';
    if (typeof value === 'object') return Object.entries(value).map(([k, v]) => `${label(k)}: ${valueText(v)}`).join('\n') || 'Нет данных';
    return String(value);
  };
  const cell = (row, col) => valueText(typeof col[1] === 'function' ? col[1](row) : row[col[1]]);
  function linkedText(value) {
    return valueText(value).split(/(https?:\/\/[^\s<>"']+)/g).map(part => {
      if (!/^https?:\/\//i.test(part)) return esc(part);
      try { const url = new URL(part); return `<a href="${esc(url.href)}" rel="noopener noreferrer">${esc(part)}</a>`; }
      catch (_) { return esc(part); }
    }).join('');
  }
  // Сохраняем все поля, в том числе появившиеся в новых версиях API.
  // Широкие записи выводятся вертикально, чтобы PDF не обрезал правые столбцы.
  function table(title, rows, preferred = []) {
    rows = Array.isArray(rows) ? rows : [];
    const objects = rows.map(r => r !== null && typeof r === 'object' && !Array.isArray(r) ? r : { value: r });
    const cols = preferred.slice(), keys = new Set(cols.filter(c => typeof c[1] === 'string').map(c => c[1]));
    for (const row of objects) for (const key of Object.keys(row)) if (!keys.has(key)) { cols.push([label(key), key]); keys.add(key); }
    if (!cols.length) cols.push(['Значение', 'value']);
    return { title, rows: objects, cols, note: objects.some(r => r.truncated === true) ? LIMIT_NOTE : '' };
  }
  const LIMIT_NOTE = 'Достигнут лимит запроса к MaxPatrol. Отчёт содержит все загруженные записи; на сервере могут быть дополнительные данные.';
  function dataSections(title, data, group = title) {
    if (Array.isArray(data)) return [{ ...table(title, data), group }];
    if (!data || typeof data !== 'object') return [{ title, group, cols: [['Поле', 'field'], ['Значение', 'value']], rows: [{ field: title, value: data }] }];
    const scalars = [], nested = [];
    for (const [key, value] of Object.entries(data)) {
      if (value !== null && typeof value === 'object') nested.push(...dataSections(`${title} / ${label(key)}`, value, group));
      else scalars.push({ field: label(key), value });
    }
    return [...(scalars.length ? [{ title, group, note: data.truncated ? LIMIT_NOTE : '', cols: [['Поле', 'field'], ['Значение', 'value']], rows: scalars }] : []), ...nested];
  }
  function cveSections(enrich, contexts = {}, sla = {}) {
    const sections = [];
    for (const cve of enrich.cves || Object.keys(enrich.results || {})) {
      const r = enrich.results?.[cve] || {};
      sections.push(...dataSections(cve, r));
      const ctx = contexts[cve];
      if (ctx) {
        sections.push(...dataSections(`${cve} / MaxPatrol`, ctx, cve));
        const item = ctx.selected?.item;
        if (item) {
          // Одно правило срока по SLA с блоком экземпляра и задачей Jira: VR.slaDue
          const sd = (window.VR && VR.slaDue) ? VR.slaDue({ found: item.found, sev: item.sev, st: item.st, sla }) : null;
          if (sd && sd.due) sections.push(...dataSections(`${cve} / ${label('selectedSla')}`, { days: sd.days, due: sd.due.toISOString(), overdue: sd.overdue }, cve));
        }
      } else sections.push(...dataSections(`${cve} / MaxPatrol`, 'Контекст экземпляров не загружен', cve));
    }
    if (enrich.meta) sections.push(...dataSections('Состояние источников обогащения', enrich.meta));
    return sections;
  }
  const css = `*{box-sizing:border-box}body{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1120px;margin:40px auto;padding:0 32px;color:#252832;background:#fff}h1{font-size:28px;line-height:1.25;margin:0 0 8px}h2{font-size:18px;margin:28px 0 12px;border-bottom:1px solid #dfe2e8;padding-bottom:8px;overflow-wrap:anywhere}p{margin:8px 0}table{border-collapse:collapse;table-layout:fixed;width:100%;font-size:12px;margin:12px 0}th,td{border-bottom:1px solid #e4e7ec;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;white-space:pre-wrap}th{background:#f5f6f8;font-weight:600;color:#5e6677}thead{display:table-header-group}.facts th{width:29%}.record th{background:#e9edf3;color:#252832}a{color:#2463b4;overflow-wrap:anywhere}.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}.kpi{border:1px solid #e0e3e9;border-radius:8px;padding:16px}.kpi b{font-size:28px;display:block}.kpi span,.muted{font-size:12px;color:#646c7b}.bad{color:#c62714}.ok{color:#287914}.warn{color:#946000}.notice{border-left:3px solid #d19b26;padding:8px 12px;background:#fff7df}.brow{display:grid;grid-template-columns:75px 1fr 1fr 130px;gap:10px;align-items:center;font-size:12px;margin:8px 0}.bar{height:8px;background:#edf0f4;border-radius:4px;overflow:hidden}.bar i{display:block;height:100%}@media(max-width:700px){body{padding:0 16px;margin:24px auto}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}@media print{body{margin:0;padding:0;max-width:none;font-size:11px}h1{font-size:22px}h2,.record{break-after:avoid}tr{break-inside:auto}.kpi{break-inside:avoid}.kpi b{font-size:22px}th,.notice,.bar{-webkit-print-color-adjust:exact;print-color-adjust:exact}@page{size:A4;margin:16mm}}`;
  const disclosureCss = `
.report-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:24px 0 16px;padding:14px 0;border-top:1px solid #e0e3e9;border-bottom:1px solid #e0e3e9}
.report-toolbar p{margin:0;max-width:570px;color:#646c7b;font-size:12px}
.report-actions{display:flex;gap:8px;flex-wrap:wrap}.report-actions[hidden]{display:none}
.report-actions button{font:inherit;font-size:13px;font-weight:500;min-height:36px;padding:6px 12px;border:1px solid #cbd1dc;border-radius:6px;background:#fff;color:#252832;cursor:pointer}
.report-actions button:hover{background:#f0f4fa;border-color:#9daabe}
.report-actions button:focus-visible,.report-section>summary:focus-visible{outline:2px solid #0066ff;outline-offset:3px}
.report-section{border:1px solid #dfe2e8;border-radius:8px;margin:12px 0;background:#fff}
.report-section>summary{display:flex;align-items:center;gap:12px;list-style:none;cursor:pointer;padding:15px 18px;border-radius:8px;overflow-wrap:anywhere}
.report-section>summary::-webkit-details-marker{display:none}
.report-section>summary:before{content:"";width:7px;height:7px;flex:none;border-right:1.5px solid #5e6677;border-bottom:1.5px solid #5e6677;transform:rotate(-45deg)}
.report-section[open]>summary:before{transform:rotate(45deg)}
.report-section>summary:hover{background:#f5f7fa}
.report-section[open]>summary{border-bottom:1px solid #e4e7ec;border-radius:8px 8px 0 0}
.report-section>summary h2,.report-section>summary h3{font-size:15px;font-weight:600;line-height:1.4;border:0;padding:0;margin:0;flex:1;min-width:0}
.report-count{color:#646c7b;font-size:12px;font-weight:400;flex:none;font-variant-numeric:tabular-nums}
.report-flag{color:#946000;font-size:11px;flex:none}
.report-panel{padding:4px 18px 12px}.report-panel .report-section{border-radius:6px}
.report-panel .report-section>summary{padding:12px 14px}
.report-panel .report-section>summary h3{font-size:13px;font-weight:500}
@media(max-width:700px){.report-section>summary{padding:12px;gap:9px}.report-panel{padding:2px 10px 10px}.report-flag{max-width:70px}}
@media print{.report-toolbar{display:none}.report-section{border:0;border-radius:0;margin:20px 0}.report-section>summary,.report-panel .report-section>summary{padding:0 0 8px!important;border:0!important;border-bottom:1px solid #dfe2e8!important;border-radius:0;break-after:avoid}.report-section>summary:before,.report-flag{display:none}.report-section>summary h2{font-size:18px}.report-section>summary h3{font-size:14px}.report-panel{padding:0}.report-section::details-content{display:block;content-visibility:visible}.report-section>.report-panel{display:block!important}}
`;
  const controlsHtml = `<div class="report-toolbar"><p>Подробности свёрнуты. Нажмите на название раздела, чтобы раскрыть его. При печати все разделы раскрываются.</p><div class="report-actions" hidden><button type="button" data-report-action="expand">Раскрыть всё</button><button type="button" data-report-action="collapse">Свернуть всё</button></div></div>`;
  // Только статический код: значения API никогда не интерполируются в скрипт.
  // details/summary работают и при запрете JavaScript; кнопки появляются после инициализации.
  const scriptHtml = `<script id="report-controls-script">(function(){
    var sections = Array.from(document.querySelectorAll('details.report-section'));
    document.querySelectorAll('.report-actions').forEach(function(el){ el.hidden = false; });
    document.querySelectorAll('[data-report-action]').forEach(function(button){
      button.addEventListener('click', function(){
        var open = button.dataset.reportAction === 'expand';
        sections.forEach(function(section){ section.open = open; });
      });
    });
    var before = null;
    window.addEventListener('beforeprint', function(){
      if (before) return;
      before = sections.map(function(section){ return section.open; });
      sections.forEach(function(section){ section.open = true; });
    });
    window.addEventListener('afterprint', function(){
      if (!before) return;
      sections.forEach(function(section, index){ section.open = before[index]; });
      before = null;
    });
  })();</script>`;
  function disclosure(title, body, { count = '', note = false, nested = false } = {}) {
    const heading = nested ? 'h3' : 'h2';
    return `<details class="report-section"><summary><${heading}>${esc(title)}</${heading}>${note ? '<span class="report-flag">Есть примечание</span>' : ''}${count !== '' ? `<span class="report-count">${esc(count)}</span>` : ''}</summary><div class="report-panel">${body}</div></details>`;
  }
  function sectionsHtml(sections) {
    const groups = new Map(), ordered = [];
    for (const section of sections || []) {
      if (!section.group) { ordered.push({ sections: [section] }); continue; }
      if (!groups.has(section.group)) {
        const group = { title: section.group, sections: [] };
        groups.set(section.group, group); ordered.push(group);
      }
      groups.get(section.group).sections.push(section);
    }
    const render = (s, groupTitle) => {
      const rows = s.rows || [], wide = s.cols.length > 7;
      const body = rows.map((row, i) => wide
        ? `<tr class="record"><th colspan="2">Запись ${i + 1}</th></tr>${s.cols.map(col => `<tr><th scope="row">${esc(col[0])}</th><td>${linkedText(cell(row, col))}</td></tr>`).join('')}`
        : `<tr>${s.cols.map(col => `<td>${linkedText(cell(row, col))}</td>`).join('')}</tr>`).join('');
      const tableHtml = `${s.note ? `<p class="notice">${esc(s.note)}</p>` : ''}<table${wide ? ' class="facts"' : ''}><thead><tr>${(wide ? [['Поле'], ['Значение']] : s.cols).map(c => `<th scope="col">${esc(c[0])}</th>`).join('')}</tr></thead><tbody>${body || `<tr><td colspan="${wide ? 2 : s.cols.length}">Нет записей</td></tr>`}</tbody></table>`;
      const title = groupTitle && s.title === groupTitle ? 'Общие сведения' : groupTitle && s.title.startsWith(groupTitle + ' / ') ? s.title.slice(groupTitle.length + 3) : s.title;
      return disclosure(title, tableHtml, { count: `Записей: ${rows.length}`, note: !!s.note, nested: !!groupTitle });
    };
    return ordered.map(group => group.sections.length === 1
      ? render(group.sections[0])
      : disclosure(group.title, group.sections.map(s => render(s, group.title)).join(''), { count: `Разделов: ${group.sections.length}`, note: group.sections.some(s => s.note) })
    ).join('');
  }
  function html(spec) {
    const kpis = (spec.kpis || []).map(k => `<div class="kpi ${esc(k[2] || '')}"><b>${esc(k[0])}</b><span>${esc(k[1])}</span></div>`).join('');
    return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(spec.title)}</title><style>${css}${disclosureCss}</style></head><body><h1>${esc(spec.title)}</h1><p class="muted">${esc(spec.subtitle || '')}</p>${spec.note ? `<p class="notice">${esc(spec.note)}</p>` : ''}${kpis ? `<div class="kpis">${kpis}</div>` : ''}${controlsHtml}${sectionsHtml(spec.sections)}<p class="muted">Сформировано расширением «Устранение уязвимостей» для MaxPatrol VM, ${new Date().toLocaleString('ru-RU')}.</p>${scriptHtml}</body></html>`;
  }
  function csv(spec) {
    const rows = [{ section: 'Отчёт', record: '', field: 'Название', value: spec.title }, { section: 'Отчёт', record: '', field: 'Источник и время', value: spec.subtitle || '' }];
    if (spec.note) rows.push({ section: 'Отчёт', record: '', field: 'Примечание', value: spec.note });
    for (const k of spec.kpis || []) rows.push({ section: 'Показатели', record: '', field: k[1], value: k[0] });
    for (const s of spec.sections || []) {
      if (s.note) rows.push({ section: s.title, record: '', field: 'Примечание', value: s.note });
      if (!s.rows?.length) rows.push({ section: s.title, record: '', field: 'Записи', value: 'Нет записей' });
      for (const [i, row] of (s.rows || []).entries()) for (const col of s.cols) rows.push({ section: s.title, record: i + 1, field: col[0], value: cell(row, col) });
    }
    return VR.csv(rows, [['Раздел', 'section'], ['Запись', 'record'], ['Поле', 'field'], ['Значение', 'value']]);
  }
  VR.reports = { html, csv, css: css + disclosureCss, sectionsHtml, disclosure, controlsHtml, scriptHtml, table, dataSections, cveSections, valueText, LIMIT_NOTE };
})(window.VR);

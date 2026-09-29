'use strict';
// Точка входа в интерфейсе MaxPatrol VM: пункт "Устранение" в левом меню (клон пункта
// Koobiq navbar) и рабочая область поверх контента справа от меню.
(function (VR) {
  if (window.__VR_APP_MOUNTED) return;
  window.__VR_APP_MOUNTED = true;
  console.info('[vr] app.js загружен, версия расширения', (chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '?');

  const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = n => Number(n || 0).toLocaleString('ru-RU');
  const pct = (a, b) => b ? Math.round(a / b * 100) : 0;
  const today = () => VR.plusDays(0);
  const plusDays = d => VR.plusDays(d);
  const ICON = "<svg width=\"16\" height=\"16\" viewBox=\"16 16 96 96\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\" aria-hidden=\"true\"><g stroke=\"currentColor\" stroke-width=\"10\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M92 43V35a7 7 0 0 0-7-7H35a7 7 0 0 0-7 7v58a7 7 0 0 0 7 7h21\"/><path d=\"m52 66 17 17 34-35\"/></g></svg>";
  const LOGO = "<svg aria-hidden=\"true\" xmlns=\"http://www.w3.org/2000/svg\" width=\"128\" height=\"128\" viewBox=\"0 0 128 128\" fill=\"none\" color=\"#fff\"><rect x=\"4\" y=\"4\" width=\"120\" height=\"120\" rx=\"28\" fill=\"#0066ff\"/><g stroke=\"currentColor\" stroke-width=\"10\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M92 43V35a7 7 0 0 0-7-7H35a7 7 0 0 0-7 7v58a7 7 0 0 0 7 7h21\"/><path d=\"m52 66 17 17 34-35\"/></g></svg>";

  const MENU_ICON = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M8 1.5 2.5 3.6v4.1c0 3.3 2.3 5.6 5.5 6.8 3.2-1.2 5.5-3.5 5.5-6.8V3.6L8 1.5Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="m5.6 8 1.7 1.7 3.2-3.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  // Адаптация Koobiq: Content panel, Tabs underlined, Table, Empty state.
  const CSS = `
:host { all: initial; }
*, *::before, *::after { box-sizing: border-box; }
* { margin: 0; padding: 0; }
.root {
  --vr-bg: var(--kbq-background-bg, #fff);
  --vr-surface: var(--kbq-background-card, #fff);
  --vr-soft: var(--kbq-background-bg-secondary, #f4f5f7);
  --vr-text: var(--kbq-foreground-contrast, #21232b);
  --vr-muted: color-mix(in srgb, var(--kbq-foreground-contrast-secondary, #626878) 82%, var(--kbq-foreground-contrast, #21232b));
  --vr-line: var(--kbq-line-contrast-less, #e2e4e9);
  --vr-accent: color-mix(in srgb, var(--kbq-foreground-theme, #1769e0) 85%, var(--vr-text));
  --vr-error: color-mix(in srgb, var(--kbq-foreground-error, #bd2819) 90%, var(--vr-text));
  --vr-warning: color-mix(in srgb, var(--kbq-foreground-warning, #976000) 85%, var(--vr-text));
  --vr-success: color-mix(in srgb, var(--kbq-foreground-success, #278112) 90%, var(--vr-text));
  --vr-focus: var(--kbq-states-line-focus-theme, #3388ff);
  --vr-radius: var(--kbq-size-border-radius, 8px);
  position: absolute; inset: 0; display: flex; flex-direction: column; overflow: hidden;
  color: var(--vr-text); background: var(--vr-soft); container: workspace / inline-size;
  font: 14px/20px var(--kbq-typography-text-normal-font-family, 'Inter', -apple-system, 'Segoe UI', sans-serif);
  -webkit-font-smoothing: antialiased;
}
:host-context(.kbq-dark) .root { color-scheme: dark; }
:host-context(.kbq-light) .root { color-scheme: light; }
button, input, select, textarea { font: inherit; }
button, a, input, select, textarea, summary { -webkit-tap-highlight-color: transparent; }
button { touch-action: manipulation; }
button:not(:disabled), summary, select, input[type=checkbox] { cursor: pointer; }
:where(button, a, input, select, textarea, summary, [tabindex]):focus-visible { outline: 2px solid var(--vr-focus); outline-offset: 3px; }
svg { flex: none; vertical-align: middle; }
a { color: var(--vr-accent); text-decoration: none; text-underline-offset: 3px; }
a:hover { text-decoration: underline; }
.hdr { flex: none; display: flex; align-items: center; gap: 16px; padding: 18px 28px; background: var(--vr-bg); border-bottom: 1px solid var(--vr-line); min-width: 0; }
.app-mark { display: grid; place-items: center; width: 36px; height: 36px; flex: none; }
.app-mark svg { width: 36px; height: 36px; }
.header-title { min-width: 0; flex: 1; }
.crumbs { font: 600 16px/24px var(--kbq-typography-subheading-font-family, 'TT-Positive', 'Inter', sans-serif); display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.crumbs .sep { color: var(--vr-muted); font-weight: 400; }
.crumbs .cur { font-weight: 400; color: var(--vr-muted); }
.hdr .ver { display: block; font-size: 12px; line-height: 16px; color: var(--vr-muted); margin-top: 2px; }
.rep { display: flex; align-items: center; gap: 2px; flex: none; }
.rep .lbl { color: var(--vr-muted); font-size: 12px; margin-right: 8px; }
.rep .btn { background: transparent; min-height: 32px; padding: 0 10px; }
.rep .btn:not(:disabled):hover { background: var(--vr-soft); }
.close { display: grid; place-items: center; width: 32px; height: 32px; flex: none; border: 0; border-radius: var(--vr-radius); color: var(--vr-muted); background: transparent; font-size: 24px; }
.close:hover { background: var(--vr-soft); color: var(--vr-text); }
.tabs { display: flex; gap: 4px; flex: none; overflow-x: auto; overscroll-behavior-x: contain; padding: 0 28px; background: var(--vr-bg); border-bottom: 1px solid var(--vr-line); scrollbar-width: thin; }
.tabs button { display: inline-flex; gap: 8px; align-items: center; white-space: nowrap; min-height: 48px; padding: 0 12px; color: var(--vr-muted); border: 0; border-bottom: 2px solid transparent; background: transparent; flex: none; }
.tabs button:hover { color: var(--vr-text); background: var(--kbq-states-background-transparent-hover, #f4f5f7); }
.tabs button.active { color: var(--vr-accent); border-bottom-color: var(--kbq-line-theme, #3388ff); }
.tabs button:focus-visible { outline-offset: -4px; }
.tabs button[data-t=settings] { margin-left: auto; }
.body { flex: 1; min-height: 0; overflow: auto; overscroll-behavior: contain; padding: 28px 28px 48px; scrollbar-gutter: stable; }
.pane { display: none; flex-direction: column; gap: 20px; max-width: 1680px; margin: 0 auto; min-width: 0; }
.pane.active { display: flex; }
.page-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 0 0 2px; }
.page-heading h2 { font: 700 28px/36px var(--kbq-typography-title-font-family, 'TT-Positive', 'Inter', sans-serif); letter-spacing: -.5px; text-wrap: balance; }
.page-heading p { color: var(--vr-muted); margin-top: 6px; max-width: 860px; }
.box { background: var(--vr-surface); border: 1px solid var(--vr-line); border-radius: 12px; padding: 20px; display: flex; flex-direction: column; gap: 16px; min-width: 0; overflow-x: auto; }
.box h3 { font: 600 18px/26px var(--kbq-typography-subheading-font-family, 'TT-Positive', 'Inter', sans-serif); color: var(--vr-text); text-wrap: balance; }
.box h3:not(:first-child) { margin-top: 8px; padding-top: 20px; border-top: 1px solid var(--vr-line); }
.control-panel { gap: 14px; }
.method { font-size: 12px; color: var(--vr-muted); }
.method summary { width: fit-content; padding: 2px 0; color: var(--vr-muted); }
.method summary:hover { color: var(--vr-text); }
.method > .muted { font-size: 12px; line-height: 20px; max-width: 1040px; margin-top: 10px; }
.muted { color: var(--vr-muted); font-size: 13px; line-height: 20px; overflow-wrap: anywhere; }
.note { color: var(--vr-warning); font-size: 12px; }
.err { color: var(--vr-error); font-size: 13px; line-height: 20px; white-space: pre-wrap; overflow-wrap: anywhere; }
.err:not(:empty) { padding: 12px 16px; border-radius: 8px; background: var(--kbq-background-error-less, #fff0ed); }
.err:empty, .vf-chips:empty { display: none; }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; min-width: 0; }
.row label { display: inline-flex; align-items: center; gap: 8px; color: var(--vr-muted); font-size: 13px; max-width: 100%; }
.row > .muted[id$='info']:not(:empty) { flex-basis: 100%; font-size: 12px; }
input[type=text], input[type=number], input[type=date], input[type=password], input[type=email], select, textarea {
  min-width: 0; max-width: 100%; height: 36px; padding: 0 12px; color: var(--kbq-form-field-default-text, var(--vr-text));
  background-color: var(--kbq-form-field-default-background, var(--vr-bg)); border: 1px solid var(--kbq-form-field-default-border-color, #a9aeb8); border-radius: var(--vr-radius);
}
input::placeholder, textarea::placeholder { color: var(--kbq-form-field-default-placeholder, var(--vr-muted)); }
input:hover, select:hover, textarea:hover { border-color: var(--kbq-line-contrast-fade, #888f9e); }
input:focus, select:focus, textarea:focus { border-color: var(--kbq-line-theme, #3388ff); }
input[type=number] { width: 90px; } input[type=date] { width: 154px; }
input[type=checkbox] { width: 16px; height: 16px; flex: none; accent-color: var(--kbq-background-theme, #3388ff); }
textarea { width: 100%; min-height: 104px; height: auto; padding: 12px; resize: vertical; line-height: 20px; font-family: var(--kbq-font-family-mono, ui-monospace, monospace); }
select { padding-right: 32px; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4 6l4 4 4-4' fill='none' stroke='%237a8190' stroke-width='1.5'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 36px; padding: 6px 12px; border-radius: var(--vr-radius); border: 1px solid transparent; background: var(--kbq-background-contrast-fade, #edf0f4); color: var(--vr-text); font-weight: 500; line-height: 20px; white-space: nowrap; text-decoration: none; }
.btn:hover { background: var(--kbq-states-background-contrast-fade-hover, #e0e4e9); text-decoration: none; }
.btn:active { background: var(--kbq-states-background-contrast-fade-active, #d0d5de); }
.btn.acc { color: var(--kbq-foreground-on-contrast, #fff); background: var(--kbq-background-contrast, #242831); }
.btn.acc:hover { background: var(--kbq-states-background-contrast-hover, #3e4655); }
.btn.acc:active { background: var(--kbq-states-background-contrast-active, #151922); }
.btn:disabled, .btn.acc:disabled { color: var(--kbq-states-foreground-disabled, #9299a6); background: var(--kbq-states-background-disabled, #f0f1f4); cursor: default; }
.btn.danger { color: var(--vr-error); }
.link-button { border: 0; background: transparent; color: var(--vr-accent); padding: 4px; font: inherit; }
.link-button:hover { text-decoration: underline; }
.report-options { margin-left: auto; position: relative; }
.report-options > summary { list-style: none; }
.report-options > summary::-webkit-details-marker { display: none; }
.report-options[open] { flex-basis: 100%; margin-left: 0; }
.report-options .row { margin-top: 12px; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.kpi { position: relative; text-align: left; color: var(--vr-text); font: inherit; border: 1px solid var(--vr-line); border-radius: 10px; padding: 16px; background: var(--vr-surface); min-width: 0; }
.kpi .v { display: block; font: 600 26px/34px var(--kbq-typography-title-font-family, 'TT-Positive', 'Inter', sans-serif); letter-spacing: -.5px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.kpi .l { display: block; font-size: 12px; line-height: 18px; color: var(--vr-muted); margin-top: 6px; }
.kpi .l small { display: block; }
.kpi.bad .v { color: var(--vr-error); }
.kpi.warn .v { color: var(--vr-warning); }
.kpi.ok .v { color: var(--vr-success); }
.kpi.click:hover { border-color: var(--kbq-line-theme, #3388ff); background: var(--kbq-background-theme-less, #edf4ff); }
.kpi.click::after { content: '↗'; position: absolute; right: 12px; top: 12px; color: var(--vr-muted); font-size: 14px; }
.hero .kpi { padding: 20px; min-height: 130px; }
.hero .kpi .v { font-size: 36px; line-height: 44px; }
.hero .kpi.bad { border-top: 3px solid var(--kbq-line-error, #dc3825); padding-top: 18px; }
.hero .kpi.warn { border-top: 3px solid var(--kbq-line-warning, #e79b00); padding-top: 18px; }
.secondary .kpi { background: var(--vr-soft); border-color: transparent; }
.secondary .kpi .v { font-size: 22px; line-height: 28px; padding-right: 16px; }
.metrics-panel { background: transparent; border: 0; padding: 0; overflow: visible; gap: 12px; }
.metrics-panel > h3 { display: none; }
.metrics-note { font-size: 12px; padding: 4px 0; }
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; line-height: 20px; font-variant-numeric: tabular-nums; }
th { text-align: left; font-weight: 500; color: var(--vr-muted); background: var(--vr-surface); font-size: 12px; padding: 10px 26px 10px 8px; white-space: nowrap; position: relative; vertical-align: middle; border-bottom: 1px solid var(--vr-line); }
th.sortable { cursor: pointer; }
th.sortable:hover { color: var(--vr-text); background: var(--vr-soft); }
th .sort { display: inline-block; font-size: 9px; margin-left: 4px; color: var(--vr-accent); }
th .vf { position: absolute; right: 3px; top: 50%; transform: translateY(-50%); display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border: 0; border-radius: 4px; color: var(--vr-muted); background: transparent; opacity: .6; }
th:hover .vf, th:focus-within .vf, th .vf.on { opacity: 1; }
th .vf.on { color: var(--vr-accent); background: var(--kbq-background-theme-less, #edf4ff); }
th .vf:hover { background: var(--vr-soft); color: var(--vr-text); }
td { padding: 11px 10px; vertical-align: middle; border-bottom: 1px solid var(--vr-line); color: var(--vr-text); }
tr:last-child td { border-bottom: 0; }
td.n, th.n { text-align: right; } td.n { white-space: nowrap; }
td.ell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td.ver { max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td.sig { white-space: nowrap; }
tr.click { cursor: pointer; }
tr.click:hover, tbody tr:has(td):hover { background: var(--kbq-states-background-transparent-hover, #f6f7f9); }
tr.sel { background: var(--kbq-background-theme-less, #edf4ff); }
tr.hide { display: none; }
td a.lnk { white-space: nowrap; } a.lnk { color: var(--vr-accent); }
.scroll { max-height: 520px; overflow: auto; overscroll-behavior: contain; }
.scroll th { position: sticky; top: 0; z-index: 2; }
.tfilter { display: flex; align-items: center; gap: 12px; }
.tfilter input { flex: 1; max-width: 400px; }
.tfilter .tcnt { font-size: 12px; color: var(--vr-muted); white-space: nowrap; }
.vf-pop { position: fixed; z-index: 20; width: 288px; max-width: calc(100vw - 16px); max-height: min(380px, calc(100vh - 16px)); display: flex; flex-direction: column; background: var(--vr-surface); color: var(--vr-text); border: 1px solid var(--vr-line); border-radius: 12px; box-shadow: 0 8px 32px #0003; padding: 12px; gap: 10px; font-size: 13px; }
.vf-pop input[type=text] { width: 100%; flex: none; }
.vf-pop .lst { overflow: auto; display: flex; flex-direction: column; min-height: 0; max-height: 230px; }
.vf-pop label { display: flex; align-items: center; gap: 8px; padding: 7px 4px; border-radius: 4px; cursor: pointer; }
.vf-pop label:hover { background: var(--vr-soft); }
.vf-pop label span { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.vf-pop label i { font-style: normal; color: var(--vr-muted); font-size: 12px; }
.vf-pop .ft { display: flex; gap: 8px; justify-content: space-between; align-items: center; font-size: 12px; }
.vf-chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 12px; }
.vf-chips .chip { display: inline-flex; align-items: center; gap: 4px; min-height: 28px; padding: 0 4px 0 10px; border-radius: 6px; background: var(--kbq-background-theme-less, #edf4ff); color: var(--vr-accent); }
.vf-chips .chip b { font-weight: 500; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.vf-chips button { border: 0; background: transparent; color: inherit; padding: 4px; }
.vf-chips .clr { color: var(--vr-muted); font-size: 12px; }
.cnt { display: inline-block; min-width: 36px; padding: 2px 7px; border-radius: 5px; text-align: right; font-variant-numeric: tabular-nums; }
.cnt.red { background: var(--kbq-background-error-less, #fff0ed); color: var(--vr-error); }
.cnt.yellow { background: var(--kbq-background-warning-less, #fff5db); color: var(--vr-warning); }
.cnt.green { background: var(--kbq-background-success-less, #edf8e9); color: var(--vr-success); }
.cnt.grey { background: var(--vr-soft); color: var(--vr-muted); }
.badge, .zone { display: inline-flex; align-items: center; gap: 4px; min-height: 24px; font-size: 12px; line-height: 16px; padding: 3px 8px; border-radius: 5px; font-weight: 500; margin-right: 4px; white-space: nowrap; }
.badge.sm { min-height: 20px; padding: 2px 6px; }
.P0, .zone.critical, .tag.kev { background: var(--kbq-palette-red-40, #c91f06); color: var(--kbq-foreground-white, #fff); }
.P1, .zone.high { background: var(--kbq-background-warning-less, #fff0ce); color: var(--vr-warning); }
.P2, .zone.medium { background: var(--kbq-background-warning-less, #fff5db); color: var(--vr-warning); }
.P3, .tag, .zone.low { background: var(--vr-soft); color: var(--vr-muted); }
.tag.hot { background: var(--kbq-background-error-less, #fff0ed); color: var(--vr-error); }
.tag.trend { background: var(--kbq-background-theme-less, #edf4ff); color: var(--vr-accent); }
.ttag { color: var(--vr-error); white-space: nowrap; margin-right: 8px; font-size: 12px; }
.ttag.blue { color: var(--vr-accent); } .ttag.yellow { color: var(--vr-warning); } .ttag.green { color: var(--vr-success); }
.cves { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 480px), 1fr)); align-items: start; gap: 20px; }
.cve .mp { border-top: 1px solid var(--vr-line); padding-top: 16px; display: flex; flex-direction: column; gap: 16px; }
.cve .mp:empty { display: none; }
.mp-h { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
.mp-h h4, .mp-section h4 { font-size: 14px; line-height: 20px; font-weight: 600; }
.mp-signals { display: flex; gap: 4px; flex-wrap: wrap; }
.mp-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; background: var(--vr-soft); border-radius: 8px; padding: 12px; }
.mp-summary b { display: block; font-size: 20px; line-height: 28px; font-variant-numeric: tabular-nums; }
.mp-summary span { display: block; font-size: 12px; line-height: 18px; color: var(--vr-muted); }
.mp-picker { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.mp-picker label { color: var(--vr-muted); font-size: 12px; }
.mp-picker select { width: 100%; text-overflow: ellipsis; }
.mp-picker [data-role=mp-st]:empty { display: none; }
.mp-section { display: flex; flex-direction: column; gap: 10px; font-size: 13px; }
.mp-section dl { display: flex; flex-direction: column; gap: 10px; }
.mp-fact { display: grid; grid-template-columns: 112px minmax(0, 1fr); gap: 6px 16px; }
.mp-fact a { text-decoration: underline; }
.mp-fact dt { color: var(--vr-muted); }
.mp-fact dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.mp-fix { background: var(--kbq-background-theme-less, #edf4ff); border-radius: 8px; padding: 16px; }
.mp-actions { border-top: 1px solid var(--vr-line); padding-top: 12px; }
.mp-actions [role=status] { flex-basis: 100%; }
.mp-actions [role=status]:empty { display: none; }
.cve .btn { white-space: normal; max-width: 100%; }
@container cve (max-width: 420px) { .mp-fact { grid-template-columns: minmax(0, 1fr); gap: 2px; } .mp-summary { gap: 8px; } }
.cve { container: cve / inline-size; border: 1px solid var(--vr-line); border-radius: 12px; padding: 20px; display: flex; flex-direction: column; gap: 12px; background: var(--vr-surface); min-width: 0; }
.cve .hd { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; padding-bottom: 12px; border-bottom: 1px solid var(--vr-line); }
.cve .id { font-family: var(--kbq-font-family-mono, ui-monospace, monospace); font-size: 14px; font-weight: 600; color: var(--vr-accent); }
.cve .line { font-size: 13px; line-height: 20px; overflow-wrap: anywhere; }
.cve .links { display: flex; flex-wrap: wrap; gap: 8px 16px; padding-top: 12px; border-top: 1px solid var(--vr-line); margin-top: auto; font-size: 12px; }
.bar, .slabar, .drv, .pbar { height: 6px; background: var(--kbq-background-contrast-less, #e4e7ec); border-radius: 3px; overflow: hidden; }
.bar { margin-top: 6px; }
.bar i, .slabar i, .drv i, .pbar i { display: block; height: 100%; }
.bar i, .slabar .over { background: var(--kbq-background-error, #ce1b03); }
.slabar, .drv { display: flex; min-width: 90px; }
.slabar .ok, .pbar i { background: var(--kbq-background-success, #3a971f); }
.slabar .soon { background: var(--kbq-background-warning, #ffba30); }
.prog { display: flex; align-items: center; gap: 10px; } .prog .pbar { flex: 1; }
.two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 20px; }
.two > * { min-width: 0; }
#q-grid { grid-template-columns: minmax(0, 1fr); align-items: start; }
#q-grid:has(.detail-active) { grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); }
#q-detail:not(.detail-active) { display: none; }
@container workspace (max-width: 1480px) { #q-grid:has(.detail-active) { grid-template-columns: minmax(0, 1fr); } }
#q-out { max-height: 620px; }
[id$="-drill"]:empty { display: none; }
.row-action { border: 0; color: var(--vr-accent); background: transparent; padding: 0; text-align: left; font: inherit; }
.row-action:hover { text-decoration: underline; text-underline-offset: 3px; }
#q-sum { background: transparent; border: 0; padding: 0; }
/* Koobiq Content panel + Alert + Form: список и детали патча. */
#pt-sum { padding: 0; border: 0; background: transparent; overflow: visible; }
#pt-grid { display: flex; flex-direction: column; gap: 20px; }
#pt-grid[hidden], #pt-detail[hidden], .field[hidden] { display: none; }
.inline-notice { display: flex; align-items: flex-start; gap: 12px; padding: 14px 16px; border-radius: 8px; background: var(--kbq-background-warning-less, #fff5db); }
.inline-notice > svg { margin-top: 2px; color: var(--vr-warning); }
.inline-notice strong { font-size: 13px; font-weight: 500; }
.inline-notice p { color: var(--vr-muted); font-size: 12px; margin-top: 2px; }
.section-heading, .detail-heading { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
.section-heading p { margin-top: 4px; }
.eyebrow { display: block; font-size: 12px; line-height: 18px; color: var(--vr-muted); margin-bottom: 4px; }
#pt-out .patch-name { min-width: 240px; max-width: 420px; }
#pt-out .row-action { overflow-wrap: anywhere; font-weight: 500; }
#pt-out td.sig { white-space: normal; min-width: 160px; }
#pt-out .no-link { background: var(--vr-soft); }
#pt-out .no-link td:first-child { color: var(--vr-muted); }
#pt-detail { border-top: 3px solid var(--kbq-line-theme, #3388ff); scroll-margin-top: 20px; }
#pt-detail .detail-heading h3 { margin: 0; padding: 0; border: 0; font-size: 20px; line-height: 28px; overflow-wrap: anywhere; }
#pt-detail .btn { white-space: normal; }
.detail-facts { display: flex; flex-wrap: wrap; gap: 8px 24px; font-size: 13px; color: var(--vr-muted); }
.detail-facts b { color: var(--vr-text); font-variant-numeric: tabular-nums; }
.patch-actions { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr); gap: 16px; }
.action-panel { display: flex; flex-direction: column; align-items: flex-start; gap: 14px; padding: 20px; border: 1px solid var(--vr-line); border-radius: 8px; min-width: 0; }
.action-panel > :is(.field, .row, .status-fields) { width: 100%; }
.action-panel > .row:last-child { margin-top: auto; }
.status-fields { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
.status-fields > .field:first-child { flex: 1; min-width: min(100%, 220px); }
.patch-section { display: flex; flex-direction: column; gap: 12px; min-width: 0; padding-top: 20px; border-top: 1px solid var(--vr-line); }
.patch-section h4 { font-size: 16px; line-height: 24px; font-weight: 600; }
.patch-section h4 span { color: var(--vr-muted); margin-left: 8px; font-weight: 400; }
.patch-section .scroll { max-height: 360px; }
@container workspace (max-width: 1000px) { .patch-actions { grid-template-columns: minmax(0, 1fr); } }
.filter-bar { padding-top: 12px; border-top: 1px solid var(--vr-line); }
.filter-bar label:has(input:checked) { color: var(--vr-accent); }
.table-empty { text-align: center; color: var(--vr-muted); padding: 28px 16px; font-size: 13px; }
.table-empty[hidden] { display: none; }
#q-detail { border-top: 3px solid var(--kbq-line-theme, #3388ff); }
.chk { display: flex; align-items: flex-start; gap: 10px; } .chk input { margin-top: 2px; }
.field { display: flex; flex-direction: column; gap: 8px; }
.field > label, .field > span { font-size: 13px; color: var(--vr-muted); }
.rw { display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 14px; }
.rw label { display: flex; flex-direction: column; gap: 8px; color: var(--vr-muted); font-size: 12px; } .rw input { width: 100%; }
.drill { border-color: var(--kbq-line-theme, #3388ff); }
.drill h3 { display: flex; align-items: center; gap: 8px; }
.drill h3 .x { margin-left: auto; background: transparent; border: 0; width: 32px; height: 32px; color: var(--vr-muted); font-size: 22px; border-radius: 6px; }
.drill .x:hover { background: var(--vr-soft); }
.rules { display: flex; flex-direction: column; gap: 12px; }
.rules h4 { font-size: 14px; line-height: 22px; margin-top: 8px; }
.rules .grp { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 8px; }
.rules label { display: flex; gap: 10px; align-items: flex-start; padding: 12px; background: var(--vr-soft); border: 1px solid transparent; border-radius: 8px; line-height: 20px; cursor: pointer; }
.rules label:has(input:checked) { background: var(--kbq-background-theme-less, #edf4ff); border-color: var(--kbq-line-theme-less, #caddfb); }
.rules input { margin-top: 2px; }
.rules code { display: block; font-size: 11px; color: var(--vr-muted); overflow-wrap: anywhere; line-height: 16px; margin-top: 4px; }
.comp { display: flex; gap: 3px; align-items: flex-end; height: 18px; } .comp i { width: 12px; border-radius: 2px 2px 0 0; }
.comp i.e { background: var(--kbq-background-theme, #3388ff); } .comp i.v { background: var(--kbq-background-warning, #ffba30); } .comp i.t { background: var(--kbq-background-error, #ce1b03); } .comp i.f { background: #a06fff; }
.empty-state { grid-column: 1 / -1; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: 12px; min-height: 300px; padding: 36px 24px; border: 1px dashed var(--vr-line); border-radius: 12px; background: var(--vr-surface); }
.empty-icon { display: grid; place-items: center; color: var(--vr-muted); background: var(--vr-soft); width: 56px; height: 56px; border-radius: 16px; margin-bottom: 4px; }
.empty-icon svg { width: 28px; height: 28px; }
.empty-state h3 { font-size: 18px; line-height: 26px; font-weight: 600; }
.empty-state p { color: var(--vr-muted); max-width: 440px; }
.spin { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--vr-line); border-top-color: var(--kbq-icon-theme, #3388ff); border-radius: 50%; animation: vr-spin .8s linear infinite; vertical-align: -2px; margin-right: 6px; }
@keyframes vr-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; border-style: dotted; } }
@container workspace (max-width: 1150px) { .tabs { padding: 0 20px; } .tabs button { padding: 0 10px; } .tabs button svg { display: none; } .two, #q-grid { grid-template-columns: minmax(0, 1fr); } }
@container workspace (max-width: 800px) { .body { padding: 20px 16px 32px; } .hdr { padding: 14px 16px; gap: 10px; } .crumbs .cur, .crumbs .sep { display: none; } .rep .lbl { display: none; } .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } .box { padding: 16px; } .page-heading h2 { font-size: 24px; line-height: 32px; } }
@container workspace (max-width: 480px) { .app-mark { display: none; } .hdr { flex-wrap: wrap; } .header-title { flex-basis: calc(100% - 48px); } .hdr .close { order: 0; } .rep { order: 1; } .tabs { padding: 0 8px; } .body { padding: 16px 12px 28px; } .hero .kpi { padding: 14px; min-height: 110px; } .hero .kpi .v { font-size: 28px; line-height: 36px; } .kpi { padding: 12px; } .row { gap: 8px; } .row label { flex-wrap: wrap; } .report-options { margin-left: 0; } .tfilter { flex-wrap: wrap; } }
`;

  const HTML = `
<div class="root">
  <header class="hdr">
    <span class="app-mark" aria-hidden="true">${LOGO}</span>
    <div class="header-title">
      <div class="crumbs"><h1 style="font:inherit">Устранение уязвимостей</h1><span class="sep" aria-hidden="true">/</span><span class="cur" id="crumb">Обзор</span></div>
      <span class="ver" id="sub" title="Сервер и версия MaxPatrol VM">MaxPatrol VM</span>
    </div>
    <div class="rep" role="group" aria-label="Экспорт текущего раздела"><span class="lbl">Экспорт</span><button class="btn" id="r-html" title="Скачать отчёт в HTML" disabled>HTML</button><button class="btn" id="r-pdf" title="Печать или сохранение в PDF" disabled>PDF</button><button class="btn" id="r-csv" title="Скачать полный отчёт: раздел, запись, поле, значение" disabled>CSV</button></div>
    <button class="close" id="close" aria-label="Закрыть область устранения" title="Закрыть">×</button>
  </header>
  <div class="tabs" role="tablist" aria-label="Разделы устранения">
    <button data-t="overview" class="active">Обзор</button>
    <button data-t="queue">Очередь устранения</button>
    <button data-t="patches">Патчи</button>
    <button data-t="assets">Риск активов</button>
    <button data-t="excl">Исключения</button>
    <button data-t="proj">Проекты</button>
    <button data-t="cw">Контейнеры и веб</button>
    <button data-t="inv">Инвентаризация</button>
    <button data-t="cve">CVE-контекст</button>
    <button data-t="settings">Настройки</button>
  </div>
  <main class="body" aria-label="Рабочая область устранения">

    <div class="pane active" data-t="overview">
      <div class="box">
        <div class="row">
          <button class="btn acc" id="m-run">Обновить показатели</button>
          <label title="Исторический срез может загружаться несколько минут"><input type="checkbox" id="m-deep"> История за 30 дней</label>
          <details class="report-options"><summary class="btn">Отчёт для руководства ▾</summary><div class="row">
          <button class="btn" id="m-report" disabled>Отчет для руководства</button>
          <button class="btn" id="m-dl" disabled title="Сохранить отчет файлом .html">Скачать HTML</button>
          <button class="btn" id="m-print" disabled title="Открыть отчет и вызвать печать: сохраните как PDF">Печать / PDF</button>
          <button class="btn" id="m-json" disabled>JSON</button>
          </div></details>
          <span class="muted" id="m-info"></span>
        </div>
        <div class="muted">Срез по всем уязвимостям инфраструктуры: статусы, просрочки по срокам (приказ ФСТЭК 117: критические 1 день, высокие 7), возраст, сигналы эксплуатации, покрытие активов.</div>
        <div class="err" id="m-err"></div>
      </div>
      <div id="m-drill"></div>
      <div id="m-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="queue">
      <div class="box">
        <h3>Очередь устранения по решениям</h3>
        <div class="muted">Открытые уязвимости сгруппированы по ПО и версии (или по ОС и ее версии): одно обновление закрывает всю группу. Группы отсортированы по устраняемому риску (трендовые x8, KEV x12, эксплойт x3, critical x4). Клик по строке открывает детали: там можно сменить статус, создать задачу в Jira или проект.</div>
        <div class="row">
          <label>Источник <select id="q-scope"><option value="softs">ПО на узлах</option><option value="packages">Пакеты Unix</option><option value="os">Операционные системы</option></select></label>
          <label>CVSS от <input type="number" id="q-min" min="0" max="10" step="0.5" value="0"></label>
          <label>Групп <input type="number" id="q-limit" min="20" max="2000" value="300"></label>
          <button class="btn acc" id="q-run">Построить очередь</button>
          <label><input type="checkbox" id="q-byprod"> свернуть по продукту</label>
          <label title="Только группы с трендовыми уязвимостями"><input type="checkbox" id="q-f-trend" class="q-filter"> трендовые</label>
          <label title="Только группы с публичным эксплойтом"><input type="checkbox" id="q-f-expl" class="q-filter"> эксплойт</label>
          <label title="Только группы с critical"><input type="checkbox" id="q-f-crit" class="q-filter"> critical</label>
          <label title="Только группы с патчем"><input type="checkbox" id="q-f-patch" class="q-filter"> есть патч</label>
          <button class="btn" id="q-csv" disabled>CSV</button>
          <button class="btn" id="q-pdql" disabled>Скопировать PDQL</button>
          <span class="muted" id="q-info"></span>
        </div>
        <div class="err" id="q-err"></div>
      </div>
      <div class="box" id="q-sum" style="display:none"></div>
      <div class="two" id="q-grid" style="display:none">
        <div class="box scroll" id="q-out"></div>
        <div class="box" id="q-detail"><div class="muted">Выберите группу слева.</div></div>
      </div>
    </div>

    <div class="pane" data-t="patches">
      <div class="box">
        <h3>Патчи</h3>
        <div class="muted">Открытые уязвимости, у которых в паспорте MaxPatrol указан патч, сгруппированы по патчу. Строка показывает обновление вендора со ссылкой, сколько уязвимостей оно закроет и на какие узлы его ставить. Список отсортирован по числу уязвимостей. Клик по строке загружает узлы, CVE и экземпляры: оттуда можно создать задачу в Jira или проект, сменить статус, выгрузить CSV. Уязвимости, у которых патч есть, но нет названия и ссылки, показаны отдельной строкой без действий.</div>
        <div class="row">
          <button class="btn acc" id="pt-run">Собрать патчи</button>
          <button class="btn" id="pt-csv" disabled>CSV</button>
          <button class="btn" id="pt-pdql" disabled>Скопировать PDQL</button>
          <span class="muted" id="pt-info"></span>
        </div>
        <div class="err" id="pt-err"></div>
      </div>
      <div class="box" id="pt-sum"></div>
      <div id="pt-grid" hidden>
        <div class="box" id="pt-out"></div>
        <section class="box" id="pt-detail" aria-label="Детали выбранного патча" hidden></section>
      </div>
    </div>

    <div class="pane" data-t="assets">
      <div class="box">
        <h3>Риск активов</h3>
        <div class="muted">Гибридная оценка 0-1000 на узел из четырех компонентов с потолками: <b>экспозиция</b> (объем открытых уязвимостей: critical x40, high x8, medium x1.5, low x0.3, логарифмическая шкала), <b>опасность</b> (максимальный и средний CVSS), <b>угроза</b> (трендовые по экспертизе PT, публичные эксплойты, RCE, CISA KEV), <b>критичность по методике ФСТЭК</b> (оценка худшей уязвимости; коэффициент значимости kK берется из значимости актива в MaxPatrol: высокая 0.4, средняя 0.32, низкая 0.2). Сумма умножается на контекст: значимость актива и устаревший скан. Потолки и множители настраиваются во вкладке «Настройки». Клик по узлу открывает его открытые уязвимости.</div>
        <div class="row">
          <button class="btn acc" id="a-run">Рассчитать</button>
          <button class="btn" id="a-kev" disabled title="Проверить CVE с эксплойтом по каталогу CISA KEV и уточнить компонент «угроза»">Уточнить по KEV</button>
          <button class="btn" id="a-tags" disabled title="Поставить активам теги auto:risk-critical / high / medium / low по зоне риска">Теги зон риска</button>

          <label>Значимость <select id="a-imp"><option value="">все</option><option value="H">высокая</option><option value="M">средняя</option><option value="L">низкая</option><option value="ND">не задана</option></select></label>
          <label>Показать <input type="number" id="a-top" min="10" max="500" value="50"></label>
          <button class="btn" id="a-csv" disabled>CSV</button>
          <span class="muted" id="a-info"></span>
        </div>
        <div class="err" id="a-err"></div>
      </div>
      <div id="a-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="excl">
      <div class="box">
        <h3>Исключения и принятые риски</h3>
        <div class="muted">Реестр исключённых уязвимостей с причиной и комментарием. Отдельно «сомнительные» исключения: трендовые, с эксплойтом, CVSS 9+ или high на важных активах. Их стоит пересмотреть и вернуть в работу.</div>
        <div class="row"><button class="btn acc" id="x-run">Загрузить реестр</button><button class="btn" id="x-csv" disabled>CSV</button><span class="muted" id="x-info"></span></div>
        <div class="err" id="x-err"></div>
      </div>
      <div id="x-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="proj">
      <div class="box">
        <h3>Проекты устранения</h3>
        <div class="muted">Прогресс считается по факту сканирования, а не по отчету исполнителя. Проект = метка на экземплярах уязвимостей: <b>jira:KEY</b> ставится при создании задачи из очереди или карточки актива, <b>proj:название</b> можно ставить вручную в MaxPatrol. Прогресс = устранено + исключено / всего с меткой. Клик по строке показывает уязвимости и узлы проекта. Создать проект можно из деталей группы в очереди или из любой выборки (кнопка «В проект»).</div>
        <div class="row"><button class="btn acc" id="p-run">Обновить</button><label>Префикс метки <input type="text" id="p-prefix" placeholder="jira: или proj:" style="width:140px"></label><span class="muted" id="p-info"></span></div>
        <div class="err" id="p-err"></div>
      </div>
      <div id="p-drill"></div>
      <div id="p-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="cw">
      <div class="box">
        <h3>Образы контейнеров и веб-сайты</h3>
        <div class="muted">Отдельные типы активов MaxPatrol: наборы образов (ImageSet: образы и их пакеты) и веб-сайты (WebSite: результаты веб-сканирования). В основной очереди они не участвуют, потому что устраняются иначе: пересборкой образа и правкой приложения.</div>
        <div class="row">
          <button class="btn acc" id="w-images">Образы: сводка</button>
          <button class="btn" id="w-imgq">Образы: очередь по пакетам</button>
          <button class="btn" id="w-web">Веб-сайты</button>
          <label>CVSS от <input type="number" id="w-min" min="0" max="10" step="0.5" value="0"></label>
          <button class="btn" id="w-csv" disabled>CSV</button>
          <span class="muted" id="w-info"></span>
        </div>
        <div class="err" id="w-err"></div>
      </div>
      <div id="w-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="inv">
      <div class="box">
        <h3>Инвентаризация: автоматические теги активов</h3>
        <div class="muted">Модель MaxPatrol: актив (Host, ImageSet, WebSite) имеет группы (динамические по PDQL и статические), значимость, теги. Теги видны в списке активов, фильтруются в PDQL (<b>Host.@Tags.Item = "..."</b>), ими удобно строить дашборды и выборки. Тег ставится всем активам PDQL-выборки, результат проверяется по каждому активу. Отметьте нужные правила и нажмите «Применить». Повторное применение безопасно: тег не дублируется. Все теги с префиксом <b>auto:</b> удаляются одной кнопкой.</div>
        <div class="rules" id="i-rules"></div>
        <div class="row">
          <button class="btn acc" id="i-apply">Применить отмеченные</button>
          <button class="btn" id="i-cover">Покрытие тегами</button>
          <button class="btn" id="i-tags">Список тегов</button>
          <button class="btn" id="i-remove" style="color:var(--kbq-foreground-error,#d23c3c)">Удалить все auto:*</button>
          <span class="muted" id="i-info"></span>
        </div>
        <div class="row"><label>Свое правило: тег <input type="text" id="i-name" placeholder="auto:my-rule" style="width:160px"></label><label>PDQL <input type="text" id="i-pdql" placeholder='filter(Host.OsName like "Astra%") | select(@Host)' style="width:420px"></label><button class="btn" id="i-add">Добавить и применить</button></div>
        <div class="err" id="i-err"></div>
      </div>
      <div id="i-out" style="display:flex;flex-direction:column;gap:14px"></div>
    </div>

    <div class="pane" data-t="cve">
      <div class="box">
        <h3>Внешний контекст по CVE</h3>
        <div class="muted">EPSS (FIRST), CISA KEV, NVD (CVSS 4.0, SSVC), БДУ ФСТЭК (из импорта), PoC на GitHub. Вердикт P0-P3 и срок устранения по приказу ФСТЭК 117.</div>
        <div class="row">
          <button class="btn" id="c-scan">Найти CVE на открытой странице MaxPatrol</button>
          <span class="muted" id="c-scan-info"></span>
        </div>
        <textarea aria-label="Идентификаторы CVE или текст с уязвимостями" spellcheck="false" id="c-cves" placeholder="CVE-2021-44228, CVE-2020-1472 ... (можно вставить любой текст)"></textarea>
        <div class="row">
          <button class="btn acc" id="c-run">Обогатить</button>
          <label><input type="checkbox" id="c-skipnvd"> без NVD (быстрее)</label>
          <label title="Не искать экземпляры уязвимостей в MaxPatrol: без блока «В MaxPatrol», без задачи Jira на экземпляр"><input type="checkbox" id="c-skipmp"> без экземпляров MP VM (быстрее)</label>
          <span class="muted" id="c-info"></span>
        </div>
        <div class="err" id="c-err"></div>
      </div>
      <div class="cves" id="c-out"></div>
    </div>

    <div class="pane" data-t="settings">
      <div class="two">
        <div class="box">
          <h3>Внешние источники</h3>
          <label class="chk"><input type="checkbox" id="s-epss"> EPSS (api.first.org)</label>
          <label class="chk"><input type="checkbox" id="s-kev"> CISA KEV (каталог кэшируется на сутки)</label>
          <label class="chk"><input type="checkbox" id="s-nvd"> NVD (CVSS 4.0, SSVC; без ключа 5 CVE за запрос)</label>
          <div class="field"><span>NVD API key (необязательно)</span><input type="password" autocomplete="off" id="s-nvdkey" placeholder="uuid"></div>
          <label class="chk"><input type="checkbox" id="s-gh"> GitHub PoC (кнопка в карточке CVE)</label>
          <div class="field"><span>GitHub token (необязательно)</span><input type="password" autocomplete="off" id="s-ghtoken" placeholder="ghp_..."></div>
          <div class="row"><button class="btn" id="s-kevref">Обновить KEV сейчас</button><span class="muted" id="s-kevinfo"></span></div>
          <h3>Интерфейс MaxPatrol</h3>
          <label class="chk"><input type="checkbox" id="s-sametab"> переходы с дашборда открывать в текущей вкладке (Ctrl/Cmd+клик: в новой)</label>
          <div class="muted">Блок «Внешний контекст» в карточке уязвимости и кнопка «Выгрузить уязвимости в CSV» в карточке актива включены всегда.</div>
        </div>
        <div class="box">
          <h3>Сроки устранения (дней)</h3>
          <div class="row">
            <label>critical <input type="number" id="s-crit" min="0"></label>
            <label>high <input type="number" id="s-high" min="0"></label>
            <label>medium <input type="number" id="s-med" min="0"></label>
            <label>low <input type="number" id="s-low" min="0"></label>
          </div>
          <div class="muted">По приказу ФСТЭК 117: критические 24 часа, высокие 7 дней. Остальное внутренняя норма.</div>
          <h3>Модель риска активов</h3>
          <div class="muted">Потолки компонентов (сумма 1000 = максимум без контекста) и множители контекста.</div>
          <div class="rw">
            <label>Экспозиция E <input type="number" id="s-rw-E" min="0" max="1000"></label>
            <label>Опасность V <input type="number" id="s-rw-V" min="0" max="1000"></label>
            <label>Угроза T <input type="number" id="s-rw-T" min="0" max="1000"></label>
            <label>ФСТЭК F <input type="number" id="s-rw-F" min="0" max="1000"></label>
            <label>Значимость высокая <input type="number" id="s-rw-impH" step="0.05" min="0"></label>
            <label>Значимость средняя <input type="number" id="s-rw-impM" step="0.05" min="0"></label>
            <label>Значимость низкая <input type="number" id="s-rw-impL" step="0.05" min="0"></label>
            <label>Значимость не задана <input type="number" id="s-rw-impND" step="0.05" min="0"></label>
            <label>Скан старше 30 дн <input type="number" id="s-rw-stale" step="0.05" min="0"></label>
          </div>
          <div class="row"><button class="btn" id="s-rw-reset">По умолчанию</button></div>
          <h3>БДУ ФСТЭК (офлайн-импорт)</h3>
          <div class="muted">Сайт bdu.fstec.ru не отдает данные скриптам. Скачайте выгрузку вручную (vulxml.zip распаковать в XML, или vullist сохранить как CSV) и загрузите файл: построится карта CVE - BDU.</div>
          <div class="row">
            <input type="file" aria-label="Файл выгрузки БДУ" id="s-bdufile" style="display:none" accept=".xml,.csv,.txt,.tsv">
            <button class="btn" id="s-bdubtn">Загрузить файл БДУ</button>
            <span class="muted" id="s-bduinfo"></span>
          </div>
          <div class="row"><button class="btn acc" id="s-save">Сохранить настройки</button><span class="muted" id="s-info"></span></div>
          <div class="muted">Адрес сервера, порт и токен задаются в окне расширения на панели браузера.</div>
          <div class="muted">Расширение распространяется по лицензии MIT: свободное использование, изменение и встраивание с сохранением уведомления об авторских правах. Это не продукт Positive Technologies.</div>
        </div>
      </div>
      <div class="box">
        <h3>Jira</h3>
        <div class="muted">Задачи создаются из очереди устранения (одна на решение: ПО и версия), из вкладки «Патчи», из карточки CVE на экземпляр и из карточки актива. Cloud: email и API token (Basic). Server и Data Center: персональный токен (Bearer).</div>
        <div class="two">
          <div class="field"><span>Адрес Jira</span><input type="text" id="s-jurl" placeholder="https://jira.company.ru или https://xxx.atlassian.net"></div>
          <div class="field"><span>Тип аутентификации</span><select id="s-jauth"><option value="basic">Cloud: email + API token</option><option value="bearer">Server / DC: персональный токен</option></select></div>
          <div class="field"><span>Email (только Cloud)</span><input type="text" id="s-juser" placeholder="user@company.ru"></div>
          <div class="field"><span>API token или персональный токен</span><input type="password" id="s-jtoken" placeholder="..."></div>
          <div class="field"><span>Проект (ключ)</span><input type="text" id="s-jproject" placeholder="VM"></div>
          <div class="field"><span>Тип задачи</span><input type="text" id="s-jtype" placeholder="Task"></div>
          <div class="field"><span>Метки (через запятую)</span><input type="text" id="s-jlabels" placeholder="maxpatrol-vm"></div>
          <label class="chk"><input type="checkbox" id="s-jtag"> ставить метку jira:KEY на экземпляры уязвимостей в MaxPatrol</label>
        </div>
        <div class="row">
          <button class="btn acc" id="s-jsave">Сохранить Jira</button>
          <button class="btn" id="s-jtest">Проверить подключение</button>
          <button class="btn" id="s-jprojects">Список проектов</button>
          <span class="muted" id="s-jinfo"></span>
        </div>
      </div>
    </div>

  </main>
</div>`;

  // ── Сбор CVE со страницы ──────────────────────────────────────────────────
  function collectText(root, acc, depth) {
    if (!root || depth > 25) return;
    if (root.nodeType === Node.TEXT_NODE) { acc.push(root.nodeValue); return; }
    if (root.id === 'vr-root') return;
    if (root.shadowRoot) collectText(root.shadowRoot, acc, depth + 1);
    const kids = root.childNodes || [];
    for (let i = 0; i < kids.length; i++) collectText(kids[i], acc, depth + 1);
  }
  // Что открыто в MaxPatrol: карточка экземпляра, паспорт уязвимости или карточка актива
  function pageContext() { const q = new URLSearchParams(location.search); return { instanceId: q.get('vulnerabilityInstanceId') || '', vulnId: q.get('vulnerabilityId') || '', assetId: q.get('assetId') || '' }; }
  function scanPageCves() {
    const acc = [location.href, document.title];
    try { collectText(document.body, acc, 0); } catch (_) {}
    const set = new Set(); acc.join('\n').replace(CVE_RE, m => { set.add(m.toUpperCase()); return m; });
    return [...set];
  }

  // ── Файлы ─────────────────────────────────────────────────────────────────
  function download(name, content, type) {
    const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 1500);
  }
  const csv = (rows, cols) => {
    const section = VR.reports.table('', rows, cols);
    return VR.csv(section.rows, section.cols.map(([name, key]) => [name, row => VR.reports.valueText(typeof key === 'function' ? key(row) : row[key])]));
  };
  function openHtml(html, name) {
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    if (!w) download(name, html, 'text/html;charset=utf-8');
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  // ── Рендер: CVE ───────────────────────────────────────────────────────────
  // ── Таблицы как в Excel: сортировка по клику на заголовок, фильтр по значениям колонки (значок в заголовке),
  //    правый клик по ячейке = фильтр по этому значению, чипы активных фильтров, общий текстовый поиск ──
  const FILTER_ICON = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M2 3h12l-4.5 5.5V13l-3 1V8.5L2 3Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>';
  let vfPop = null;
  const closePop = (restoreFocus = false) => { if (vfPop) { const anchor = vfPop.__anchor; vfPop.remove(); vfPop = null; if (restoreFocus) anchor?.focus(); } };
  const cellText = td => (td.getAttribute('data-v') ?? td.textContent).replace(/\s+/g, ' ').trim();
  const numOf = s => { const x = parseFloat(String(s).replace(/\s/g, '').replace(',', '.')); return isNaN(x) ? null : x; };
  function tableState(table) {
    if (!table.__vf) table.__vf = { cols: {}, q: '', sort: null };
    return table.__vf;
  }
  function applyTable(table) {
    const st = tableState(table); const rows = [...table.querySelectorAll('tr')].filter(tr => tr.querySelector('td'));
    let shown = 0;
    rows.forEach(tr => {
      const tds = tr.children; let ok = true;
      for (const c in st.cols) { const set = st.cols[c]; if (set && !set.has(cellText(tds[c] || tr))) { ok = false; break; } }
      if (ok && st.q && !tr.textContent.toLowerCase().includes(st.q)) ok = false;
      tr.classList.toggle('hide', !ok); if (ok) shown++;
    });
    if (st.sort) {
      const { col, dir } = st.sort; const tbody = rows[0]?.parentElement; if (tbody) {
        const sorted = rows.slice().sort((a, b) => { const x = cellText(a.children[col] || a), y = cellText(b.children[col] || b); const nx = numOf(x), ny = numOf(y); const r = nx != null && ny != null ? nx - ny : x.localeCompare(y, 'ru'); return dir === 'asc' ? r : -r; });
        sorted.forEach(tr => tbody.appendChild(tr));
      }
    }
    table.querySelectorAll('th').forEach((th, i) => { th.setAttribute('aria-sort', st.sort?.col === i ? (st.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'); const s = th.querySelector('.sort'); if (s) s.textContent = st.sort && st.sort.col === i ? (st.sort.dir === 'asc' ? '▲' : '▼') : ''; const v = th.querySelector('.vf'); if (v) v.classList.toggle('on', st.cols[i] instanceof Set); });
    // Чипы активных фильтров
    let chips = table.__chips; if (!chips) { chips = table.__chips = document.createElement('div'); chips.className = 'vf-chips'; table.parentElement.insertBefore(chips, table); }
    const ths = [...table.querySelectorAll('th')];
    const active = Object.entries(st.cols).filter(([, s]) => s instanceof Set);
    chips.innerHTML = active.length ? active.map(([c, s]) => `<span class="chip">${esc((ths[c]?.textContent || '').replace(/[▲▼]/g, '').trim())}: <b title="${esc([...s].join(', '))}">${esc(s.size ? [...s].slice(0, 2).join(', ') : 'Нет значений')}${s.size > 2 ? ` +${s.size - 2}` : ''}</b><button data-c="${c}" title="Снять фильтр" aria-label="Снять фильтр">×</button></span>`).join('') + `<button class="clr">сбросить все</button>` : '';
    chips.querySelectorAll('.chip button').forEach(b => b.addEventListener('click', () => { delete st.cols[b.dataset.c]; applyTable(table); }));
    chips.querySelector('.clr')?.addEventListener('click', () => { st.cols = {}; applyTable(table); });
    const cnt = table.__cnt; if (cnt) cnt.textContent = shown !== rows.length ? `${fmt(shown)} из ${fmt(rows.length)}` : `${fmt(rows.length)} строк`;
    if (!table.__empty) {
      table.__empty = document.createElement('div'); table.__empty.className = 'table-empty'; table.__empty.setAttribute('role', 'status');
      table.insertAdjacentElement('afterend', table.__empty);
    }
    table.__empty.hidden = shown > 0;
    table.__empty.textContent = st.q || Object.values(st.cols).some(v => v instanceof Set) ? 'Совпадений нет. Измените поиск или сбросьте фильтры.' : 'Нет данных для отображения.';
    return shown;
  }
  function openValuePop(table, col, anchor) {
    closePop();
    const st = tableState(table); const rows = [...table.querySelectorAll('tr')].filter(tr => tr.querySelector('td'));
    const counts = {}; rows.forEach(tr => { const v = cellText(tr.children[col] || tr); counts[v] = (counts[v] || 0) + 1; });
    const values = Object.keys(counts).sort((a, b) => { const na = numOf(a), nb = numOf(b); return na != null && nb != null ? na - nb : a.localeCompare(b, 'ru'); });
    const sel = new Set(st.cols[col] instanceof Set ? st.cols[col] : values);
    const pop = document.createElement('div'); pop.className = 'vf-pop'; pop.setAttribute('role', 'dialog'); pop.setAttribute('aria-label', 'Фильтр по значениям'); pop.__anchor = anchor; pop.__t = Date.now(); vfPop = pop;
    const render = q => { const ql = q.toLowerCase(); pop.querySelector('.lst').innerHTML = values.filter(v => !ql || v.toLowerCase().includes(ql)).slice(0, 300).map(v => `<label><input type="checkbox" data-v="${esc(v)}" ${sel.has(v) ? 'checked' : ''}><span title="${esc(v)}">${esc(v || '(пусто)')}</span><i>${fmt(counts[v])}</i></label>`).join('') || '<div class="muted">нет значений</div>'; pop.querySelectorAll('input[type=checkbox]').forEach(c => c.addEventListener('change', () => { c.checked ? sel.add(c.dataset.v) : sel.delete(c.dataset.v); })); };
    pop.innerHTML = `<input type="text" aria-label="Поиск значений колонки" placeholder="Поиск среди ${values.length} значений…"><div class="ft"><span><button type="button" class="link-button" data-a="all">все</button> · <button type="button" class="link-button" data-a="none">ничего</button></span><span class="muted">${fmt(rows.length)} строк</span></div><div class="lst"></div><div class="ft"><button type="button" class="link-button" data-a="clear">сбросить</button><button class="btn acc" data-a="ok">Применить</button></div>`;
    render('');
    pop.querySelector('input[type=text]').addEventListener('input', e => render(e.target.value));
    pop.querySelector('[data-a=all]').addEventListener('click', () => { values.forEach(v => sel.add(v)); render(pop.querySelector('input[type=text]').value); });
    pop.querySelector('[data-a=none]').addEventListener('click', () => { sel.clear(); render(pop.querySelector('input[type=text]').value); });
    pop.querySelector('[data-a=clear]').addEventListener('click', () => { delete st.cols[col]; applyTable(table); closePop(true); });
    pop.querySelector('[data-a=ok]').addEventListener('click', () => { st.cols[col] = sel.size === values.length ? null : new Set(sel); applyTable(table); closePop(true); });
    pop.addEventListener('click', e => e.stopPropagation());
    sh.querySelector('.root').appendChild(pop);
    const r = anchor.getBoundingClientRect(), bounds = host.getBoundingClientRect();
    pop.style.maxWidth = Math.max(180, bounds.width - 16) + 'px';
    const pr = pop.getBoundingClientRect();
    pop.style.left = Math.max(bounds.left + 8, Math.min(r.left, bounds.right - pr.width - 8)) + 'px';
    pop.style.top = Math.max(8, Math.min(r.bottom + 6, innerHeight - pr.height - 8)) + 'px';
    pop.addEventListener('keydown', e => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePop(true); } });
    setTimeout(() => pop.querySelector('input[type=text]').focus(), 0);
  }
  function enhanceTable(table) {
    if (table.dataset.vf) return; table.dataset.vf = '1';
    const ths = [...table.querySelectorAll('th')]; if (!ths.length || table.dataset.plain != null) return;
    ths.forEach((th, i) => {
      if (!th.textContent.trim() || th.hasAttribute('data-nosort')) return;
      const tn = [...th.childNodes].find(n => n.nodeType === 3 && n.textContent.trim()); if (tn) tn.textContent = tn.textContent.replace(/^(\s*)(\S)/, (m, a, b) => a + b.toUpperCase());
      th.classList.add('sortable'); th.tabIndex = 0; th.setAttribute('scope', 'col'); th.setAttribute('aria-sort', 'none');
      th.insertAdjacentHTML('beforeend', `<span class="sort"></span><button type="button" class="vf" aria-label="Фильтр: ${esc(th.textContent.trim())}" title="Фильтр по значениям">${FILTER_ICON}</button>`);
      th.addEventListener('click', e => { if (e.target.closest('.vf')) return; const st = tableState(table); st.sort = st.sort && st.sort.col === i && st.sort.dir === 'asc' ? { col: i, dir: 'desc' } : { col: i, dir: 'asc' }; applyTable(table); });
      th.addEventListener('keydown', e => { if (e.target === th && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); th.click(); } });
      th.querySelector('.vf').addEventListener('click', e => { e.stopPropagation(); openValuePop(table, i, th.querySelector('.vf')); });
    });
    // Правый клик по ячейке: оставить только строки с этим значением в колонке (как «Фильтр по значению ячейки» в Excel)
    table.addEventListener('contextmenu', e => {
      const td = e.target.closest('td'); if (!td || e.target.closest('a, button')) return;
      e.preventDefault(); const col = [...td.parentElement.children].indexOf(td); const st = tableState(table);
      st.cols[col] = new Set([cellText(td)]); applyTable(table);
    });
    table.querySelectorAll('tr').forEach(tr => { if (tr.querySelector('td')) tr.classList.add('hasf'); });
    table.querySelectorAll('tr.click[data-soft], tr.click[data-tag], tr.click[data-i]').forEach(tr => {
      const cell = tr.querySelector('td'); if (!cell || cell.querySelector('button, a')) return;
      const button = document.createElement('button'); button.type = 'button'; button.className = 'row-action';
      while (cell.firstChild) button.append(cell.firstChild); cell.append(button);
      button.setAttribute('aria-label', `Открыть детали: ${cell.textContent.trim()}`);
    });
    table.title = table.title || 'Клик по заголовку сортирует. Значок в заголовке фильтрует по значениям. Правый клик по ячейке оставляет только это значение.';
  }
  function bindFilters(root) {
    root.querySelectorAll('.tfilter').forEach(f => {
      if (f.dataset.bound) return; f.dataset.bound = '1';
      const inp = f.querySelector('input'), cnt = f.querySelector('.tcnt');
      const table = f.nextElementSibling && (f.nextElementSibling.tagName === 'TABLE' ? f.nextElementSibling : f.nextElementSibling.querySelector('table'));
      if (!table) return;
      table.__cnt = cnt;
      inp.addEventListener('input', () => { tableState(table).q = inp.value.trim().toLowerCase(); applyTable(table); });
    });
    root.querySelectorAll('table').forEach(tb => { enhanceTable(tb); applyTable(tb); });
  }
  const tfilter = ph => `<div class="tfilter"><input type="text" aria-label="${esc(ph || 'Поиск по таблице')}" placeholder="${esc(ph || 'Поиск по таблице…')}" autocomplete="off"><span class="tcnt"></span></div>`;
  const cnt = (v, cls) => `<span class="cnt ${cls || (v > 0 ? 'red' : 'green')}">${fmt(v)}</span>`;
  const plink = (guid, text) => guid ? `<a class="lnk" href="${esc(VR.passportUrl(guid))}" title="Открыть паспорт уязвимости">${esc(text)}</a>` : esc(text);
  const alink = (id, text) => id ? `<a class="lnk" href="${esc(VR.assetUrl(id))}" title="Открыть карточку актива">${esc(text)}</a>` : esc(text);
  const kevBadge = cve => `<a class="badge tag kev" href="${esc(VR.kevUrl(cve))}" target="_blank" rel="noopener" title="Каталог CISA KEV">KEV</a>`;
  // Страница активов 28.0 принимает запрос в параметре pdqlQuery (так переходят виджеты дашборда); параметр pdql игнорируется
  const mpListUrl = pdql => `${location.origin}/mpx/common/am/assets?groupId=00000000-0000-0000-0000-000000000002&pdqlQuery=${encodeURIComponent(pdql)}`;
  const SEV_RU = { critical: 'критический', high: 'высокий', medium: 'средний', low: 'низкий' };
  const ST_RU = { new: 'Новая', inProgress: 'В работе', awaitingFix: 'Исправляется', overdue: 'Просрочена', stale: 'Устарела', fixed: 'Устранена', excluded: 'Исключена' };

  // Панель выборки (drill-down): таблица уязвимостей по PDQL с фильтром, CSV, ссылками и созданием проекта
  async function showDrill(container, title, pdql, opts = {}) {
    if (!pdql) return;
    const selection = { element: container, tab: container.closest('.pane')?.dataset.t, title, data: { loading: true, pdql } };
    state.drills[container.id] = selection;
    const clear = () => { if (state.drills[container.id] === selection) delete state.drills[container.id]; container.innerHTML = ''; };
    container.innerHTML = `<div class="box drill"><h3>${esc(title)}<button aria-label="Закрыть выборку" class="x" title="Закрыть">×</button></h3><div class="muted"><span class="spin"></span>выборка, до 30 секунд</div></div>`;
    container.querySelector('.x').addEventListener('click', clear);
    try {
      const d = await VR.drill({ pdql, limit: opts.limit || 500 });
      if (state.drills[container.id] !== selection || !container.isConnected) return;
      selection.data = d;
      const items = d.items;
      const hasHost = items.some(i => i.host);
      const rows = items.map(i => `<tr><td>${plink(i.vulnId, i.CVE || i.Name || '')}</td><td class="ell" title="${esc(i.Name || '')}">${esc(i.Name || '')}</td>${hasHost ? `<td class="ell">${alink(i.hostId, i.host)}</td>` : ''}<td class="n">${esc(i.Score ?? '')}</td><td>${esc(SEV_RU[String(i.Sev || '').toLowerCase()] || i.Sev || '')}</td><td>${esc(ST_RU[i.St] || i.St || '')}</td><td class="n">${esc(String(i.Found || '').slice(0, 10))}</td><td>${VR.bool(i.T) ? '<span class="badge tag kev sm">Трендовая</span>' : ''}${VR.bool(i.E) ? '<span class="ttag">Есть эксплойт</span>' : ''}</td></tr>`).join('');
      container.innerHTML = `<div class="box drill"><h3>${esc(title)}<button aria-label="Закрыть выборку" class="x" title="Закрыть">×</button></h3>
        <div class="muted">${fmt(items.length)} экземпляров${d.truncated ? ' (показаны первые ' + fmt(opts.limit || 500) + ', полный список в MaxPatrol по кнопке)' : ''}.</div>
        <div class="row"><a class="btn" href="${esc(mpListUrl(pdql))}" style="text-decoration:none">Открыть в MaxPatrol</a><button class="btn" data-a="csv">CSV</button><button class="btn" data-a="pdql">Скопировать PDQL</button><button class="btn" data-a="proj">В проект (метка proj:)</button><span class="muted" role="status" data-role="st"></span></div>
        ${tfilter('фильтр: CVE, узел, статус, уровень')}<div class="scroll" style="max-height:480px"><table><tr><th>CVE</th><th>уязвимость</th>${hasHost ? '<th>узел</th>' : ''}<th>CVSS</th><th>уровень</th><th>статус</th><th>обнаружена</th><th>сигналы</th></tr>${rows || '<tr><td colspan=8 class="muted">пусто</td></tr>'}</table></div></div>`;
      container.querySelector('.x').addEventListener('click', clear);
      bindFilters(container);
      container.querySelector('[data-a=csv]').addEventListener('click', () => download(`selection_${today()}.csv`, csv(items, [['CVE', 'CVE'], ['Уязвимость', 'Name'], ['Узел', 'host'], ['ID узла', 'hostId'], ['CVSS', 'Score'], ['Уровень', 'Sev'], ['Статус', 'St'], ['Обнаружена', 'Found'], ['Трендовая', i => VR.bool(i.T) ? 'да' : ''], ['Эксплойт', i => VR.bool(i.E) ? 'да' : ''], ['ID экземпляра', 'Id']]), 'text/csv;charset=utf-8'));
      container.querySelector('[data-a=pdql]').addEventListener('click', () => { navigator.clipboard.writeText(pdql).catch(() => {}); container.querySelector('[data-role=st]').textContent = 'PDQL скопирован'; });
      container.querySelector('[data-a=proj]').addEventListener('click', async () => {
        const ids = items.map(i => i.Id).filter(Boolean); if (!ids.length) return;
        const name = prompt(`Название проекта (метка proj:название) для ${ids.length} экземпляров:`); if (!name) return;
        const st = container.querySelector('[data-role=st]'); st.innerHTML = '<span class="spin"></span>ставим метку';
        try { await VR.tagInstances(ids, 'proj:' + name.trim()); st.textContent = `метка proj:${name.trim()} поставлена на ${fmt(ids.length)} экз. Прогресс во вкладке «Проекты».`; } catch (e) { st.textContent = 'ошибка: ' + e.message; }
      });
      container.scrollIntoView({ block: 'nearest' });
    } catch (e) { if (state.drills[container.id] !== selection || !container.isConnected) return; selection.data = { error: e.message, pdql }; container.innerHTML = `<div class="box drill"><h3>${esc(title)}<button aria-label="Закрыть выборку" class="x">×</button></h3><div class="err">${esc(e.message)}</div></div>`; container.querySelector('.x').addEventListener('click', clear); }
  }

  function renderCve(cve, r) {
    const v = r.verdict || {}, ep = r.epss?.epss, lines = [];
    if (r.mp) lines.push(`<div class="line">MP VM: <b>CVSS ${esc(r.mp.score ?? '?')}</b>${r.mp.trend ? ' <span class="badge tag trend">трендовая</span>' : ''}${r.mp.exploit ? ' <span class="badge tag hot">эксплойт</span>' : ''}</div>`);
    lines.push(ep != null ? `<div class="line">EPSS: <b>${(ep * 100).toFixed(1)}%</b> (перцентиль ${(r.epss.percentile * 100).toFixed(0)}, ${esc(r.epss.date)})<div class="bar"><i style="width:${Math.max(1, ep * 100)}%"></i></div></div>` : `<div class="line">EPSS: <span class="muted">${r.epss ? 'нет в базе' : 'не запрошено'}</span></div>`);
    lines.push(r.kev ? `<div class="line"><span class="badge tag kev">CISA KEV</span> добавлена ${esc(r.kev.dateAdded)}, срок ${esc(r.kev.dueDate)}${r.kev.ransomware === 'Known' ? ', <b>ransomware</b>' : ''}: ${esc(r.kev.vendor)} ${esc(r.kev.product)}</div>` : '<div class="line">KEV: <span class="muted">нет в каталоге</span></div>');
    if (r.nvd && !r.nvd.missing) {
      const n = r.nvd, p = [];
      if (n.cvss40) p.push(`CVSS 4.0 <b>${esc(n.cvss40.score)}</b> ${esc(n.cvss40.severity || '')}`);
      if (n.cvss31) p.push(`CVSS 3.1 <b>${esc(n.cvss31.score)}</b>`);
      if (n.ssvc?.exploitation) p.push(`SSVC: ${esc(n.ssvc.exploitation)} / ${esc(n.ssvc.automatable || '?')} / ${esc(n.ssvc.impact || '?')}`);
      lines.push(`<div class="line">NVD: ${p.join(' | ') || 'без метрик'}; опубликована ${esc((n.published || '').slice(0, 10))}${n.cwes?.length ? '; ' + esc(n.cwes.join(', ')) : ''}</div>`);
      if (n.description) lines.push(`<div class="line muted">${esc(n.description.slice(0, 260))}${n.description.length > 260 ? '...' : ''}</div>`);
    } else if (r.nvd?.missing) lines.push('<div class="line">NVD: <span class="muted">не найдена</span></div>');
    if (r.bdu?.length) lines.push(`<div class="line">БДУ: <b>${r.bdu.map(b => esc(b.id)).join(', ')}</b>${r.bdu[0].level ? ' (' + esc(r.bdu[0].level) + ')' : ''}</div>`);
    if (r.gh) lines.push(`<div class="line">GitHub: <b>${fmt(r.gh.count)}</b> репозиториев${r.gh.items?.length ? ': ' + r.gh.items.slice(0, 3).map(i => `<a href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.name)}</a> (${i.stars}*)`).join(', ') : ''}</div>`);
    const links = [['NVD', `https://nvd.nist.gov/vuln/detail/${cve}`], ['БДУ', `https://bdu.fstec.ru/search?q=%22${cve}%22&yt0=%D0%98%D1%81%D0%BA%D0%B0%D1%82%D1%8C`], ['PT dbugs', `https://dbu.gs/vulnerability/${cve}`], ['Vulners', `https://vulners.com/search?query=${cve}`], ['GitHub', `https://github.com/search?q=${cve}&type=repositories`]]
      .map(([t, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener">${t}</a>`).join('');
    return `<div class="cve" data-cve="${esc(cve)}"><div class="hd"><span class="id">${esc(cve)}</span><span><span class="badge ${esc(v.level || 'P3')}">${esc(v.level || '')}</span><span class="muted">срок ${esc(v.slaDays)} дн</span></span></div>
<div class="line"><b>${esc(v.title || '')}</b>${v.reasons?.length ? ': ' + esc(v.reasons.join('; ')) : ''}</div>${lines.join('')}
<div class="mp" data-mp="${esc(cve)}"></div>
<div class="links">${links}<a href="#" class="gh" data-cve="${esc(cve)}">PoC на GitHub?</a></div></div>`;
  }

  // ── Рендер: метрики ───────────────────────────────────────────────────────
  function renderMetrics(m) {
    const c = VR.computeMetrics(m);
    const kpi = (v, l, cls, drill) => `<button type="button" class="kpi ${cls || ''}${drill ? ' click' : ''}"${drill ? ` data-drill="${esc(drill)}" title="Показать выборку"` : ''}><span class="v">${v}</span><span class="l">${l}</span></button>`;
    const sevRows = ['critical', 'high', 'medium', 'low'].map(s => { const b = c.bySev[s] || { open: 0, over: 0, soon: 0, ok: 0 }; const w = v => b.open ? Math.round(v / b.open * 100) : 0; return `<tr><td>${SEV_RU[s]}</td><td class="n" data-v="${b.open}"><a class="lnk" href="#" data-drill="sev:${s}">${fmt(b.open)}</a></td><td class="n" data-v="${b.ok || 0}">${cnt(b.ok || 0, 'green')}</td><td class="n" data-v="${b.soon || 0}">${cnt(b.soon || 0, b.soon ? 'yellow' : 'grey')}</td><td class="n" data-v="${b.over}"><a class="lnk" href="#" data-drill="sevOverdue:${s}">${cnt(b.over, b.over ? 'red' : 'grey')}</a></td><td style="min-width:80px" title="просрочено ${pct(b.over, b.open)}%"><div class="slabar"><i class="ok" style="width:${w(b.ok || 0)}%"></i><i class="soon" style="width:${w(b.soon || 0)}%"></i><i class="over" style="width:${w(b.over)}%"></i></div></td></tr>`; }).join('');
    const ageRows = Object.entries(c.age).map(([k, v]) => `<tr><td><a class="lnk" href="#" data-drill="age:${esc(k)}">${k} дн</a></td><td class="n">${fmt(v)}</td><td class="n">${pct(v, c.open)}%</td></tr>`).join('');
    const impRu = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
    const hostRows = (Array.isArray(m.topHosts) ? m.topHosts : []).map(r => `<tr><td class="ell">${alink(r.HostId, r['@Host'])}</td><td>${esc(r.OS)}</td><td>${esc(impRu[r.Imp] || r.Imp || '')}</td><td class="n">${esc(r.CV)}</td><td><a class="lnk" href="#" data-drill="asset:${esc(r.HostId || '')}" title="Открытые уязвимости узла">уязвимости</a></td></tr>`).join('');
    const trendRows = (Array.isArray(m.trendTop) ? m.trendTop : []).map(r => `<tr><td><a class="lnk" href="#" data-passport="${esc(r.CVE)}" title="Открыть паспорт уязвимости">${esc(r.CVE)}</a></td><td class="n">${esc(r.Score)}</td><td class="n"><a class="lnk" href="#" data-drill="cve:${esc(r.CVE)}" title="Экземпляры на узлах">${fmt(r.Hosts)}</a></td><td class="n">${fmt(r.N)}</td><td>${r.kev ? kevBadge(r.CVE) : ''}${r.epss != null ? 'EPSS ' + (r.epss * 100).toFixed(0) + '%' : ''}</td></tr>`).join('');
    let past = '';
    if (m.past30 && !m.past30.error) {
      const p = {}; m.past30.forEach(r => { p[String(r.Sev).toLowerCase()] = VR.num(r.N) || 0; });
      past = `<div class="box"><h3>Динамика за 30 дней (открытые)</h3><table><tr><th>severity</th><th>30 дн назад</th><th>сейчас</th><th>изм.</th></tr>${['critical', 'high', 'medium', 'low'].map(s => { const a = p[s] || 0, b = (c.bySev[s] || {}).open || 0; return `<tr><td>${s}</td><td class="n">${fmt(a)}</td><td class="n">${fmt(b)}</td><td class="n">${b - a >= 0 ? '+' : ''}${fmt(b - a)}</td></tr>`; }).join('')}</table></div>`;
    } else if (m.past30?.error) past = `<div class="err">История: ${esc(m.past30.error)}</div>`;
    return `
<div class="box metrics-panel"><h3>Ключевые показатели</h3><div class="kpis hero">
  ${kpi(fmt(c.open), 'открытых уязвимостей', '', 'open')}
  ${kpi(fmt(c.overdue), 'просрочено по SLA (' + pct(c.overdue, c.open) + '%)', c.overdue ? 'bad' : 'ok', 'overdue')}
  ${kpi(fmt(c.soon), 'истекает (прошло 80% срока)', c.soon ? 'warn' : 'ok', 'soon')}
  ${kpi(fmt(c.trend), 'трендовых открыто', c.trend ? 'bad' : 'ok', 'trend')}
</div><div class="kpis secondary">
  ${kpi(fmt(c.critOver) + ' / ' + fmt(c.critOpen), 'Критические: просрочено / открыто', c.critOver ? 'bad' : 'ok', 'sevOverdue:critical')}
  ${kpi(fmt(c.highOver) + ' / ' + fmt(c.highOpen), 'Высокие: просрочено / открыто', c.highOver ? 'bad' : 'ok', 'sevOverdue:high')}
  ${kpi(fmt(c.expl), 'с публичным эксплойтом', 'warn', 'exploit')}
  ${kpi(fmt(c.new30), 'новых за 30 дней (' + fmt(c.new7) + ' за 7)', '', 'new30')}
  ${kpi(fmt(c.fixed), 'устранено всего, ' + fmt(c.excluded) + ' исключено', 'ok', 'status:fixed')}
  ${kpi(fmt(c.st.new || 0), 'в статусе Новая (' + pct(c.st.new || 0, c.open) + '% открытых)', pct(c.st.new || 0, c.open) > 50 ? 'bad' : 'warn', 'status:new')}
  ${kpi(fmt(c.noImp) + ' / ' + fmt(c.assets), 'активов без значимости', c.noImp ? 'warn' : 'ok', 'noImportance')}
  ${kpi(fmt(c.stale + c.obsolete), 'активов с устаревшим сканом', c.stale + c.obsolete ? 'warn' : 'ok', 'staleScan')}
</div><div class="muted metrics-note">Сроки: critical ${m.sla.crit} дн, high ${m.sla.high}, medium ${m.sla.med}, low ${m.sla.low}. Снимок ${esc(m.generatedAt.replace('T', ' ').slice(0, 16))} UTC. Клик по показателю открывает выборку: таблица, CSV, PDQL, переход в MaxPatrol.</div></div>
<div class="two">
  <div class="box"><h3>Соблюдение сроков по уровню опасности</h3><table><tr><th>уровень</th><th class="n">открыто</th><th class="n">в срок</th><th class="n">истекает</th><th class="n">просрочено</th><th data-nosort>Шкала</th></tr>${sevRows}</table><div class="muted">В срок · Истекает (80% срока) · Просрочено. Выберите число, чтобы открыть уязвимости.</div></div>
  <div class="box"><h3>Возраст открытых</h3><table><tr><th>возраст</th><th>штук</th><th>доля</th></tr>${ageRows}</table></div>
</div>
${past}
<div class="two">
  <div class="box"><h3>Трендовые уязвимости с наибольшим охватом</h3>${tfilter('фильтр по CVE')}<table><tr><th>CVE (паспорт)</th><th>CVSS</th><th>узлов</th><th>экземпляров</th><th>внешние сигналы</th></tr>${trendRows || '<tr><td colspan=5 class="muted">нет</td></tr>'}</table></div>
  <div class="box"><h3>Топ-10 узлов по интегральной уязвимости</h3><table><tr><th>узел (карточка)</th><th>ОС</th><th>значимость</th><th>оценка</th><th></th></tr>${hostRows}</table></div>
</div>`;
  }

  function reportHtml(m, host) {
    const c = VR.computeMetrics(m);
    const row = (a, b) => `<tr><td>${a}</td><td class="n">${b}</td></tr>`;
    const sev = ['critical', 'high', 'medium', 'low'].map(s => { const b = c.bySev[s] || { open: 0, over: 0 }; return `<tr><td>${s}</td><td class="n">${fmt(b.open)}</td><td class="n">${fmt(b.over)}</td><td class="n">${pct(b.over, b.open)}%</td></tr>`; }).join('');
    const age = Object.entries(c.age).map(([k, v]) => `<tr><td>${k} дн</td><td class="n">${fmt(v)}</td><td class="n">${pct(v, c.open)}%</td></tr>`).join('');
    const maxSev = Math.max(1, ...['critical', 'high', 'medium', 'low'].map(s => (c.bySev[s] || {}).open || 0));
    const bar = (v, color) => `<div class="bar"><i style="width:${Math.round(v / maxSev * 100)}%;background:${color}"></i></div>`;
    const sevBars = ['critical', 'high', 'medium', 'low'].map(s => { const b = c.bySev[s] || { open: 0, over: 0 }; return `<div class="brow"><span>${s}</span>${bar(b.open, '#c7c7c7')}${bar(b.over, '#d9534f')}<span class="n">${fmt(b.open)} / ${fmt(b.over)}</span></div>`; }).join('');
    const trend = (Array.isArray(m.trendTop) ? m.trendTop : []).map(r => `<tr><td>${esc(r.CVE || '')}</td><td class="n">${esc(r.Score)}</td><td class="n">${fmt(r.Hosts)}</td><td class="n">${fmt(r.N || '')}</td><td>${r.kev ? 'KEV' : ''}${r.epss != null ? ' EPSS ' + (r.epss * 100).toFixed(0) + '%' : ''}</td></tr>`).join('');
    const hosts = (Array.isArray(m.topHosts) ? m.topHosts : []).map(r => `<tr><td>${esc(r['@Host'])}</td><td>${esc(r.OS)}</td><td>${esc(r.Imp)}</td><td class="n">${esc(r.CV)}</td></tr>`).join('');
    const verdict117 = c.critOver || c.highOver ? `<p class="bad">Требования приказа ФСТЭК 117 по срокам не выполняются: критических просрочено ${fmt(c.critOver)}, высоких ${fmt(c.highOver)}.</p>` : '<p class="ok">Просроченных критических и высоких уязвимостей по срокам приказа ФСТЭК 117 нет.</p>';
    let past = '';
    if (m.past30 && !m.past30.error) { const p = {}; m.past30.forEach(r => { p[String(r.Sev).toLowerCase()] = VR.num(r.N) || 0; }); past = VR.reports.disclosure('Динамика за 30 дней', `<table><tr><th>severity</th><th>30 дней назад</th><th>сейчас</th><th>изменение</th></tr>${['critical', 'high', 'medium', 'low'].map(s => { const a = p[s] || 0, b = (c.bySev[s] || {}).open || 0; return `<tr><td>${s}</td><td class="n">${fmt(a)}</td><td class="n">${fmt(b)}</td><td class="n">${b - a >= 0 ? '+' : ''}${fmt(b - a)}</td></tr>`; }).join('')}</table>`); }
    return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Отчет по процессу управления уязвимостями</title>
<style>${REPORT_CSS}</style></head><body>
<h1>Отчет по процессу управления уязвимостями</h1>
<p class="muted">MaxPatrol VM, ${esc(host)}. Снимок ${esc(m.generatedAt.replace('T', ' ').slice(0, 16))} UTC. Сроки: critical ${m.sla.crit} дн, high ${m.sla.high} дн, medium ${m.sla.med} дн, low ${m.sla.low} дн.</p>
<h2>Резюме</h2><div class="kpis">
<div class="kpi"><b>${fmt(c.open)}</b><span>открытых уязвимостей</span></div>
<div class="kpi"><b class="${c.overdue ? 'bad' : 'ok'}">${fmt(c.overdue)}</b><span>просрочено по SLA (${pct(c.overdue, c.open)}%)</span></div>
<div class="kpi"><b class="${c.trend ? 'bad' : 'ok'}">${fmt(c.trend)}</b><span>трендовых открыто</span></div>
<div class="kpi"><b>${fmt(c.expl)}</b><span>с публичным эксплойтом</span></div>
<div class="kpi"><b>${fmt(c.new30)}</b><span>новых за 30 дней (${fmt(c.new7)} за 7)</span></div>
<div class="kpi"><b>${fmt(c.fixed)}</b><span>устранено всего, ${fmt(c.excluded)} исключено</span></div>
<div class="kpi"><b>${fmt(c.st.new || 0)}</b><span>в статусе Новая (${pct(c.st.new || 0, c.open)}% открытых)</span></div>
<div class="kpi"><b>${fmt(c.noImp)}</b><span>активов без значимости из ${fmt(c.assets)}</span></div></div>
${verdict117}
<p>Доля не разобранных уязвимостей (статус Новая) показывает, работает ли процесс: если она выше половины, политики обработки не настроены или не покрывают инфраструктуру. За 30 дней появилось ${fmt(c.new30)} уязвимостей при ${fmt(c.fixed)} устраненных за все время.</p>
${VR.reports.controlsHtml}
${VR.reports.disclosure('Просрочки по уровню опасности', `${sevBars}<p class="muted">Серая полоса: открыто, красная: просрочено.</p>
<table><tr><th>severity</th><th>открыто</th><th>просрочено</th><th>доля</th></tr>${sev}</table>`)}
${VR.reports.disclosure('Возраст открытых уязвимостей', `<table><tr><th>возраст</th><th>шт</th><th>доля</th></tr>${age}</table>`)}
${past}
${VR.reports.disclosure('Статусы', `<table>${Object.entries(c.st).map(([k, v]) => row(k, fmt(v))).join('')}</table>`)}
${VR.reports.disclosure('Трендовые уязвимости с наибольшим охватом', `<table><tr><th>CVE</th><th>CVSS</th><th>узлов</th><th>экземпляров</th><th>внешние сигналы</th></tr>${trend || '<tr><td colspan=5>нет</td></tr>'}</table>`)}
${VR.reports.disclosure('Покрытие активов', `<table>${row('Всего активов', fmt(c.assets))}${row('Без значимости', fmt(c.noImp))}${row('Высокой значимости', fmt(c.highImp))}${row('Аудит старше 90 дней', fmt(c.stale))}${row('Скан устарел или не выполнялся', fmt(c.obsolete))}</table>`)}
${VR.reports.disclosure('Топ-10 узлов по интегральной уязвимости', `<table><tr><th>узел</th><th>ОС</th><th>значимость</th><th>оценка</th></tr>${hosts}</table>`)}
${VR.reports.disclosure('Рекомендации', `<ul>
<li>Закрыть просроченные critical и high в первую очередь через очередь устранения по решениям: одно обновление ПО закрывает десятки уязвимостей.</li>
<li>Настроить политики статусов так, чтобы доля Новая не превышала 20% открытых: плановое устранение с датой для critical и high, исключения с причиной для ложных срабатываний и компенсирующих мер.</li>
<li>Присвоить значимость всем активам и восстановить сканирование там, где аудит старше 30 дней: без этого приоритизация по методике ФСТЭК не работает.</li>
<li>Для трендовых и KEV использовать срок 24 часа независимо от CVSS.</li></ul>`)}
</body></html>`;
  }

  // Общая модель экспорта находится в reports.js; PDF печатает тот же HTML.
  const REPORT_CSS = VR.reports.css;
  const buildReport = spec => VR.reports.html(spec);
  function printHtml(html, name) {
    const w = window.open('', '_blank');
    if (!w) { download(name, html, 'text/html;charset=utf-8'); return; }
    w.document.write(html); w.document.close();
    // Окно может наследовать CSP MaxPatrol и блокировать встроенный скрипт отчёта.
    // Раскрываем разделы до печати из content script, независимо от этой политики.
    w.document.querySelectorAll('details.report-section').forEach(section => { section.open = true; });
    setTimeout(() => { try { w.focus(); w.print(); } catch (_) {} }, 400);
  }
  const reportSubtitle = () => `MaxPatrol VM, ${VR.config().host || location.hostname}, ${new Date().toLocaleString('ru-RU')}`;

  // ── Снимки состояния вкладок: chrome.storage.local через background, живут сутки ──
  const SNAP_TTL = 24 * 3600 * 1000;
  const snapSave = (key, value) => VR.ext('cache-set', { key, value }).catch(() => {});
  const snapLoad = async key => { try { const c = await VR.ext('cache-get', { key }); return c && c.value && Date.now() - c.ts < SNAP_TTL ? c : null; } catch (_) { return null; } };
  const snapNote = ts => `снимок от ${new Date(ts).toLocaleString('ru-RU')}, обновление по кнопке`;

  // ── Рабочая область ───────────────────────────────────────────────────────
  let host = null, sh = null, opened = false;
  let restoreSnapshots = async () => {}, updateReportButtons = () => {}; // назначаются в bind()
  const state = { metrics: null, queue: null, detail: null, enrich: null, metricsLoaded: false, drills: {} };

  function $(id) { return sh.getElementById(id); }

  function positionRoot() {
    if (!host) return;
    // Реальный контейнер меню на 28.0: <platform-nav-bar> > kbq-vertical-navbar (241 px, сворачивается)
    const item = document.querySelector('.kbq-navbar-item:not(#vr-menu-item)');
    const nav = document.querySelector('platform-nav-bar, kbq-vertical-navbar, .kbq-vertical-navbar, .kbq-navbar, kbq-navbar')
      || (item && item.closest('platform-nav-bar, kbq-vertical-navbar, nav'));
    const left = nav ? Math.round(nav.getBoundingClientRect().right) : (item ? Math.round(item.getBoundingClientRect().right) : 0);
    host.style.left = left + 'px';
  }

  function mountRoot() {
    if (host) return;
    host = document.createElement('div');
    host.id = 'vr-root';
    host.style.cssText = 'position:fixed;top:0;right:0;bottom:0;left:0;z-index:950;display:none;';
    document.body.appendChild(host);
    sh = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style'); style.textContent = CSS; sh.appendChild(style);
    const wrap = document.createElement('div'); wrap.innerHTML = HTML; sh.appendChild(wrap);
    bind();
    sh.addEventListener('click', e => { if (vfPop && !e.target.closest('.vf-pop') && !e.target.closest('.vf')) closePop(); });
    sh.addEventListener('scroll', () => { if (vfPop && Date.now() - (vfPop.__t || 0) > 400) closePop(); }, true);
    window.addEventListener('resize', positionRoot);
  }

  function open() {
    mountRoot(); positionRoot();
    host.style.display = ''; opened = true;
    document.querySelectorAll('.kbq-navbar-item.kbq-selected, .kbq-navbar-item.kbq-active').forEach(el => { if (el.id !== 'vr-menu-item') { el.dataset.vrWasSelected = el.classList.contains('kbq-active') ? 'active' : 'selected'; el.classList.remove('kbq-selected', 'kbq-active'); } });
    const mi = document.getElementById('vr-menu-item'); if (mi) mi.classList.add('kbq-active');
    const c = VR.config(); $('sub').textContent = 'MaxPatrol VM'; $('sub').title = c.host || location.hostname;
    VR.systemInfo().then(d => { $('sub').textContent = `MaxPatrol VM ${d?.productVersion || ''}`; $('sub').title = `${c.host || location.hostname}, версия ${d?.productVersion || '?'}`; }).catch(e => { $('sub').textContent = 'нет подключения'; $('sub').title = e.message; });
    if (!state.metricsLoaded) {
      state.metricsLoaded = true;
      // Не нагружаем систему при каждом открытии: показываем последний снимок, обновление по кнопке
      snapLoad('metrics').then(c => {
        if (c) { state.metrics = c.value; $('m-out').innerHTML = renderMetrics(state.metrics); bindFilters($('m-out')); ['m-report', 'm-dl', 'm-print', 'm-json'].forEach(id => { $(id).disabled = false; }); $('m-info').textContent = snapNote(c.ts); }
        else $('m-info').textContent = 'снимка за сутки нет: нажмите «Обновить показатели»';
        updateReportButtons();
      });
      restoreSnapshots();
    }
  }
  function close() {
    if (!host || !opened) return;
    closePop(); host.style.display = 'none'; opened = false; document.getElementById('vr-menu-item')?.focus();
    const mi = document.getElementById('vr-menu-item'); if (mi) mi.classList.remove('kbq-selected', 'kbq-active');
    document.querySelectorAll('.kbq-navbar-item[data-vr-was-selected]').forEach(el => { el.classList.add(el.dataset.vrWasSelected === 'active' ? 'kbq-active' : 'kbq-selected'); delete el.dataset.vrWasSelected; });
  }

  // ── Пункт меню ────────────────────────────────────────────────────────────
  // Якорь: «Активы»; если меню свернуто и основные пункты спрятаны в «Еще», вставляем перед «Еще»/«Система»
  function findAnchorItem() {
    const items = [...document.querySelectorAll('.kbq-navbar-item')].filter(el => el.id !== 'vr-menu-item');
    const title = el => (el.querySelector('.kbq-navbar-title')?.textContent || '').replace(/\s+/g, ' ').trim();
    const byTitle = rx => items.find(el => rx.test(title(el)));
    const assets = byTitle(/^Активы$/i) || items.find(el => /\/assets(\b|$)/.test(el.getAttribute('href') || el.querySelector('a')?.getAttribute('href') || ''));
    if (assets) return { el: assets, where: 'afterend' };
    const dash = byTitle(/^Дашборды$/i); if (dash) return { el: dash, where: 'afterend' };
    const more = byTitle(/^(Еще|Ещё|More)$/i); if (more) return { el: more, where: 'beforebegin' };
    const sys = byTitle(/^Система$/i); if (sys) return { el: sys, where: 'beforebegin' };
    return null;
  }
  function ensureMenuItem() {
    try { return ensureMenuItemUnsafe(); }
    catch (e) { console.error('[vr] не удалось вставить пункт меню:', e); return false; }
  }
  function ensureMenuItemUnsafe() {
    if (document.getElementById('vr-menu-item')) return true;
    const found = findAnchorItem();
    if (!found) { if (!ensureMenuItem._warned && document.querySelectorAll('.kbq-navbar-item').length) { ensureMenuItem._warned = true; console.warn('[vr] пункты меню есть, но якорь не найден:', [...document.querySelectorAll('.kbq-navbar-item')].map(e => (e.querySelector('.kbq-navbar-title')?.textContent || '').trim()).join(' | ')); } return false; }
    const anchor = found.el;
    // Клонируем ссылочный пункт, если якорь не ссылка (у «Еще» нет href и есть вложенное меню)
    const template = anchor.tagName === 'A' ? anchor : ([...document.querySelectorAll('a.kbq-navbar-item')].find(a => a.id !== 'vr-menu-item') || anchor);
    const item = template.cloneNode(true);
    item.id = 'vr-menu-item';
    item.classList.remove('kbq-selected', 'kbq-active');
    item.querySelectorAll('.kbq-selected, .kbq-active').forEach(x => x.classList.remove('kbq-selected', 'kbq-active'));
    item.removeAttribute('ng-reflect-router-link'); item.removeAttribute('routerlink');
    item.querySelectorAll('[href]').forEach(a => a.setAttribute('href', '#vr-remediation'));
    if (item.tagName === 'A') item.setAttribute('href', '#vr-remediation');
    const title = item.querySelector('.kbq-navbar-title'); if (title) title.textContent = 'Устранение';
    const icon = item.querySelector('.kbq-icon-item, .kbq-icon, i');
    if (icon) { [...icon.classList].filter(c => /_\d+$|^kbq-[a-z-]+_[a-z]/.test(c)).forEach(c => icon.classList.remove(c)); icon.innerHTML = MENU_ICON; icon.style.display = 'inline-flex'; icon.style.alignItems = 'center'; }
    item.title = 'Устранение уязвимостей: очередь по решениям, внешние сигналы, метрики процесса';
    item.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); opened ? close() : open(); }, true);
    item.querySelectorAll('.kbq-navbar-item__arrow-icon, [class*="arrow"]').forEach(x => x.remove());
    anchor.insertAdjacentElement(found.where, item);
    return true;
  }

  // Клик по любому другому пункту меню или смена маршрута закрывает область
  document.addEventListener('click', e => {
    const it = e.target.closest && e.target.closest('.kbq-navbar-item');
    if (it && it.id !== 'vr-menu-item') close();
  }, true);
  window.addEventListener('popstate', close);

  // ── Обработчики UI ────────────────────────────────────────────────────────
  // Клик по показателю обзора или ссылке с data-drill: выборка в панели
  function drillFromMetrics(spec) {
    const m = state.metrics; if (!m) return;
    const sla = { slaCritDays: m.sla.crit, slaHighDays: m.sla.high, slaMedDays: m.sla.med, slaLowDays: m.sla.low };
    const soon = d => Math.max(1, Math.round(d * 0.8));
    const [kind, arg] = spec.split(':');
    const titles = { open: 'Открытые уязвимости', overdue: 'Просроченные по SLA', soon: 'Истекает срок (прошло 80%)', trend: 'Трендовые открытые', exploit: 'С публичным эксплойтом', new30: 'Новые за 30 дней', noImportance: 'Активы без значимости', staleScan: 'Активы с устаревшим сканом' };
    let pdql, title = titles[kind] || spec;
    switch (kind) {
      case 'open': case 'trend': case 'exploit': case 'new30': case 'noImportance': case 'staleScan': pdql = VR.drillPdql(kind); break;
      case 'overdue': pdql = VR.drillPdql('overdue', sla); break;
      case 'soon': pdql = VR.drillPdql('soon', { ...sla, h: soon(sla.slaHighDays), m: soon(sla.slaMedDays), l: soon(sla.slaLowDays) }); break;
      case 'sev': pdql = VR.drillPdql('sev', arg); title = `Открытые: ${SEV_RU[arg] || arg}`; break;
      case 'sevOverdue': { const days = { critical: sla.slaCritDays, high: sla.slaHighDays, medium: sla.slaMedDays, low: sla.slaLowDays }[arg]; pdql = VR.drillPdql('sevOverdue', { sev: arg, days }); title = `Просрочено: ${SEV_RU[arg] || arg} (старше ${days} дн)`; break; }
      case 'status': pdql = VR.drillPdql('status', arg); title = `Статус: ${ST_RU[arg] || arg}`; break;
      case 'cve': pdql = VR.drillPdql('cve', arg); title = `Экземпляры ${arg}`; break;
      case 'asset': if (!arg) return; pdql = VR.drillPdql('asset', arg); title = 'Открытые уязвимости узла'; break;
      case 'age': pdql = VR.drillPdql('age', arg); title = `Возраст ${arg} дн`; break;
    }
    showDrill($('m-drill'), title, pdql);
  }

  async function runMetrics() {
    $('m-err').textContent = ''; $('m-run').disabled = true;
    $('m-info').innerHTML = `<span class="spin"></span>${$('m-deep').checked ? 'сбор с историей: до 5 минут' : 'сбор показателей, 20-40 секунд'}`;
    try {
      state.metrics = await VR.metrics({ deep: $('m-deep').checked });
      snapSave('metrics', state.metrics);
      $('m-out').innerHTML = renderMetrics(state.metrics); bindFilters($('m-out'));
      $('m-info').textContent = 'готово'; ['m-report', 'm-dl', 'm-print', 'm-json'].forEach(id => { $(id).disabled = false; }); updateReportButtons();
    } catch (e) { $('m-err').textContent = e.message; $('m-info').textContent = ''; }
    $('m-run').disabled = false;
  }

  function renderQueue() {
    const q0 = state.queue; if (!q0) return;
    $('q-empty')?.remove();
    const fT = $('q-f-trend').checked, fE = $('q-f-expl').checked, fC = $('q-f-crit').checked, fP = $('q-f-patch').checked;
    const pass = g => (!fT || g.trend > 0) && (!fE || g.expl > 0) && (!fC || g.crit > 0) && (!fP || g.patch > 0);
    const q = { ...q0, groups: q0.groups.filter(pass), products: q0.products.filter(pass) };
    q.totalGroups = q.groups.length;
    const byProd = $('q-byprod').checked;
    const totalN = q.groups.reduce((a, g) => a + g.n, 0), trend = q.groups.reduce((a, g) => a + g.trend, 0);
    $('q-sum').style.display = '';
    $('q-sum').innerHTML = `<div class="kpis">
      <div class="kpi"><div class="v">${fmt(q.totalGroups)}${q.totalGroups !== q0.totalGroups ? ' <span class="muted">из ' + fmt(q0.totalGroups) + '</span>' : ''}</div><div class="l">решений (${q.scope === 'os' ? 'ОС + версия' : q.scope === 'images' ? 'образ + пакет' : 'ПО + версия'})</div></div>
      <div class="kpi"><div class="v">${fmt(totalN)}</div><div class="l">уязвимостей закроют</div></div>
      <div class="kpi ${trend ? 'bad' : 'ok'}"><div class="v">${fmt(trend)}</div><div class="l">из них трендовых</div></div>
      <div class="kpi"><div class="v">${pct(q.groups.slice(0, 5).reduce((a, g) => a + g.n, 0), totalN)}%</div><div class="l">закрывают топ-5 решений</div></div></div>`;
    const sig = g => `${g.trend ? '<span class="badge tag kev sm" title="трендовых">' + fmt(g.trend) + '</span>' : ''}${g.expl ? '<span class="ttag" title="с эксплойтом">' + fmt(g.expl) + ' expl</span>' : ''}${g.patch ? '<span class="ttag green" title="есть патч">патч</span>' : ''}`;
    const rows = byProd
      ? q.products.map(p => `<tr class="click" data-soft="${esc(p.soft)}" data-ver=""><td class="ell" title="${esc(p.soft)}">${esc(p.soft)}</td><td class="n">${p.versions} верс.</td><td class="n">${fmt(p.n)}</td><td class="n">${fmt(p.hosts)}</td><td class="n">${p.maxScore}</td><td class="sig">${sig(p)}</td></tr>`).join('')
      : q.groups.map(g => `<tr class="click${state.detail && state.detail.soft === g.soft && state.detail.ver === g.ver ? ' sel' : ''}" data-soft="${esc(g.soft)}" data-ver="${esc(g.ver)}"><td class="ell" title="${esc(g.soft)}">${esc(g.soft)}</td><td class="ver" title="${esc(g.ver)}">${esc(g.ver)}</td><td class="n">${fmt(g.n)}</td><td class="n">${fmt(g.hosts)}</td><td class="n">${g.maxScore ?? ''}</td><td class="sig">${sig(g)}</td></tr>`).join('');
    $('q-grid').style.display = '';
    const col1 = q.scope === 'os' ? 'ОС' : q.scope === 'images' ? 'образ : пакет' : q.scope === 'packages' ? 'пакет' : 'ПО';
    $('q-out').innerHTML = `${tfilter('фильтр по названию')}<table><tr><th>${col1}</th><th>${byProd ? '' : 'версия'}</th><th>уязвимостей</th><th>${q.scope === 'images' ? 'образов' : 'узлов'}</th><th>CVSS</th><th>сигналы</th></tr>${rows}</table>`;
    bindFilters($('q-out'));
    sh.querySelectorAll('#q-out tr.click').forEach(tr => tr.addEventListener('click', () => {
      if (!tr.dataset.ver) { $('q-byprod').checked = false; renderQueue(); return; }
      loadDetail(tr.dataset.soft, tr.dataset.ver);
    }));
  }

  async function loadDetail(soft, ver) {
    const box = $('q-detail'), queue = state.queue;
    const pending = { soft, ver, loading: true }; state.detail = pending; let current = pending;
    box.classList.add('detail-active');
    box.innerHTML = `<div class="muted"><span class="spin"></span>Детали: ${esc(soft)} ${esc(ver)}</div>`;
    try {
      const g0 = state.queue.groups.find(g => g.soft === soft && g.ver === ver);
      const d = await VR.queueDetail({ scope: state.queue.scope, soft, ver, pkg: g0?.pkg });
      if (state.detail !== pending || state.queue !== queue) return;
      state.detail = d; current = d; d.enrichmentLoading = true; delete d.enrichmentError;
      sh.querySelectorAll('#q-out tr.click').forEach(tr => tr.classList.toggle('sel', tr.dataset.soft === soft && tr.dataset.ver === ver));
      let enr = null;
      try { enr = await VR.ext('enrich', { cves: d.cves.map(c => c.cve), skipNvd: true, mp: Object.fromEntries(d.cves.map(c => [c.cve, { score: c.score, trend: c.trend, exploit: c.exploit }])) }); } catch (e) { d.enrichmentError = e.message; }
      if (state.detail !== d || state.queue !== queue) return;
      d.enrichment = enr; d.enrichmentLoading = false;
      const kevN = enr ? d.cves.filter(c => enr.results[c.cve]?.kev).length : 0;
      const cveRows = d.cves.slice(0, 80).map(c => { const r = enr?.results[c.cve]; return `<tr><td>${plink(c.vulnId, c.cve)}</td><td class="n">${c.score}</td><td class="n">${fmt(c.n)}</td><td>${r?.kev ? kevBadge(c.cve) : ''}${c.trend ? '<span class="badge tag trend">trend</span>' : ''}${c.exploit ? '<span class="badge tag hot">expl</span>' : ''}${r?.epss?.epss != null ? '<span class="muted">EPSS ' + (r.epss.epss * 100).toFixed(0) + '%</span>' : ''}</td></tr>`; }).join('');
      const hostRows = d.hosts.slice(0, 80).map(h => `<tr><td class="ell" title="${esc(h.host)}">${alink(h.id, h.host)}</td><td class="n">${fmt(h.n)}</td><td class="n">${h.maxScore}</td></tr>`).join('');
      box.innerHTML = `<h3>${esc(soft)} ${esc(ver)}</h3>
        <div class="muted">${fmt(d.rows)} экземпляров${d.truncated ? ' (выборка усечена до 20000)' : ''}, ${fmt(d.cves.length)} CVE, ${fmt(d.hosts.length)} узлов${kevN ? `, <b style="color:#d23c3c">${kevN} CVE в CISA KEV</b>` : ''}.</div>
        <div class="row"><button class="btn" id="d-csv">CSV узлов</button><button class="btn" id="d-copy">Скопировать список узлов</button><button class="btn" id="d-pdql">Скопировать PDQL</button><button class="btn" id="d-proj" title="Поставить метку proj:название на все экземпляры группы">В проект</button><span class="muted" id="d-proj-st"></span></div>
        <div class="box"><h3>Задача в Jira</h3>
          <div class="muted">Одна задача на решение: обновить ${esc(soft)} ${esc(ver)}. В описании таблица CVE с EPSS и KEV, список узлов, срок по приоритету.</div>
          <div class="row"><button class="btn acc" id="d-jira">Создать задачу в Jira</button><button class="btn" id="d-jira-find">Найти существующие</button><span class="muted" id="d-jira-st"></span></div>
          <div id="d-jira-out"></div>
        </div>
        <div class="box"><h3>Смена статуса экземпляров (${fmt(d.ids.length)})</h3>
          <div class="row">
            <select aria-label="Новый статус экземпляров" id="d-cmd"><option value="SwitchToInProgressStateCommand">В работе</option><option value="SwitchToAwaitingFixStateCommand">Исправляется до даты</option><option value="SwitchToExcludeStateCommand">Исключить</option><option value="SwitchToNewStateCommand">Вернуть в Новая</option></select>
            <input type="date" aria-label="Срок исправления" id="d-date" value="${plusDays(7)}">
            <select aria-label="Причина исключения" id="d-reason"><option value="acceptedAsLowRisk">низкий риск</option><option value="cannotFix">нельзя исправить</option><option value="compensatingControl">компенсирующая мера</option><option value="falsePositive">ложное срабатывание</option></select>
          </div>
          <input type="text" aria-label="Комментарий к статусу" id="d-note" placeholder="комментарий к статусу (необязательно)" style="width:100%">
          <div class="row"><button class="btn acc" id="d-apply">Применить в MaxPatrol VM</button><span class="muted" id="d-st"></span></div>
          <div class="note">Операция изменит статусы всех экземпляров группы. Нужны права на массовые операции у владельца токена.</div>
        </div>
        <div class="scroll">${tfilter('фильтр по CVE')}<table><tr><th>CVE (паспорт)</th><th>CVSS</th><th>экземпляров</th><th>сигналы</th></tr>${cveRows}</table></div>
        <div class="scroll">${tfilter('фильтр по узлу')}<table><tr><th>узел (карточка)</th><th>уязвимостей</th><th>max CVSS</th></tr>${hostRows}</table></div>`;
      bindFilters(box);
      box.scrollIntoView({ block: 'nearest' });
      $('d-proj').addEventListener('click', async () => {
        const name = prompt(`Название проекта (метка proj:название) для ${d.ids.length} экземпляров ${soft} ${ver}:`, String(soft).toLowerCase().replace(/[^a-zа-я0-9]+/gi, '-').slice(0, 30)); if (!name) return;
        $('d-proj-st').innerHTML = '<span class="spin"></span>';
        try { await VR.tagInstances(d.ids, 'proj:' + name.trim()); $('d-proj-st').textContent = `метка proj:${name.trim()} поставлена, прогресс во вкладке «Проекты»`; } catch (e) { $('d-proj-st').textContent = 'ошибка: ' + e.message; }
      });
      $('d-csv').addEventListener('click', () => download(`hosts_${soft}_${ver}_${today()}.csv`.replace(/[^\w.\-а-яА-Я]+/g, '_'), csv(d.hosts, [['Узел', 'host'], ['ID', 'id'], ['Уязвимостей', 'n'], ['Max CVSS', 'maxScore']]), 'text/csv;charset=utf-8'));
      $('d-copy').addEventListener('click', () => navigator.clipboard.writeText(d.hosts.map(h => h.host).join('\n')).catch(() => {}));
      $('d-pdql').addEventListener('click', () => navigator.clipboard.writeText(d.pdql).catch(() => {}));
      const jiraLabelForGroup = VR.jiraLabel(soft);
      $('d-jira').addEventListener('click', async () => {
        const st = $('d-jira-st'); $('d-jira').disabled = true; st.innerHTML = '<span class="spin"></span>создаем задачу';
        try {
          const s = await VR.ext('settings-get');
          if (!s.jiraUrl || !s.jiraToken || !s.jiraProject) throw new Error('Заполните Jira в настройках: адрес, токен, проект');
          st.innerHTML = '<span class="spin"></span>паспорта и контекст активов';
          // Целевая версия из паспортов топ-3 CVE (по CVSS) и контекст узлов (значимость, ОС, группы)
          const passports = {};
          for (const c of d.cves.slice().sort((a, b) => b.score - a.score).slice(0, 3)) { if (c.vulnId) { try { passports[c.cve] = await VR.passport(c.vulnId); } catch (_) {} } }
          let assetsInfo = {}; try { assetsInfo = await VR.assetsInfo(d.hosts.map(h => h.id)); } catch (_) {}
          const issue = VR.buildJiraIssue({ detail: d, group: state.queue.groups.find(g => g.soft === soft && g.ver === ver), enrich: enr, sla: s, host: VR.config().host || location.hostname, passports, assetsInfo });
          if (!confirm(`Создать задачу в Jira (${s.jiraProject}):\n${issue.summary}\nСрок: ${issue.dueDate}${issue.targetVersion ? '' : '\nЦелевая версия в паспортах не найдена: в задаче будет «до актуальной версии вендора»'}`)) { $('d-jira').disabled = false; st.textContent = ''; return; }
          const r = await VR.ext('jira-create', issue);
          let tagNote = '';
          try { await VR.ext('jira-attach', { key: r.key, filename: `mpvm_${soft}_${ver}.csv`.replace(/[^\w.\-]+/g, '_'), content: VR.groupCsv(d, enr, { passports, assetsInfo }) }); tagNote += ', CSV приложен'; } catch (e) { tagNote += `, вложение не удалось: ${e.message}`; }
          if (s.jiraTagInstances !== false) { try { await VR.tagInstances(d.ids, 'jira:' + r.key); tagNote = `, метка jira:${r.key} поставлена на ${fmt(d.ids.length)} экз.`; } catch (e) { tagNote = `, метку поставить не удалось: ${e.message}`; } }
          st.innerHTML = `создана <a href="${esc(r.url)}" target="_blank" rel="noopener" style="color:#2f80ed">${esc(r.key)}</a>${esc(tagNote)}`;
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
        $('d-jira').disabled = false;
      });
      $('d-jira-find').addEventListener('click', async () => {
        const st = $('d-jira-st'); st.innerHTML = '<span class="spin"></span>поиск';
        try {
          const list = await VR.ext('jira-search', { label: jiraLabelForGroup, max: 10 });
          $('d-jira-out').innerHTML = list.length ? `<table><tr><th>задача</th><th>статус</th><th>исполнитель</th><th>срок</th></tr>${list.map(i => `<tr><td><a href="${esc(i.url)}" target="_blank" rel="noopener" style="color:#2f80ed">${esc(i.key)}</a> ${esc(i.summary)}</td><td>${esc(i.status)}</td><td>${esc(i.assignee || '')}</td><td>${esc(i.due || '')}</td></tr>`).join('')}</table>` : '<div class="muted">задач с меткой ' + esc(jiraLabelForGroup) + ' нет</div>';
          st.textContent = '';
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
      });
      $('d-apply').addEventListener('click', async () => {
        const cmd = $('d-cmd').value;
        if (!confirm(`Изменить статус ${d.ids.length} экземпляров уязвимостей (${soft} ${ver}) в MaxPatrol VM?`)) return;
        $('d-apply').disabled = true; $('d-st').innerHTML = '<span class="spin"></span>выполняется';
        try {
          const r = await VR.changeStatus({ ids: d.ids, command: cmd, tillDate: $('d-date').value ? $('d-date').value + 'T00:00:00Z' : null, reason: $('d-reason').value, note: $('d-note').value });
          $('d-st').textContent = r.done === false ? `операция ${r.operationId} еще выполняется на сервере: обработано ${fmt((r.succeed || 0) + (r.failed || 0))} из ${fmt(r.total || r.count)}, проверьте статусы позже` : r.total != null ? `готово: успешно ${fmt(r.succeed || 0)} из ${fmt(r.total)}${r.failed ? ', ошибок ' + fmt(r.failed) : ''}` : `отправлено ${r.count} экз., операция ${r.operationId || 'без id'}`;
        } catch (e) { $('d-st').textContent = 'ошибка: ' + e.message; }
        $('d-apply').disabled = false;
      });
    } catch (e) { if (state.detail !== current || state.queue !== queue) return; state.detail = { soft, ver, error: e.message }; box.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }


  const PAGES = {
    overview: ['Состояние защищённости', 'Открытые уязвимости, сроки устранения и сигналы эксплуатации в одном срезе.', 'Показатели ещё не загружены', 'Обновите показатели, чтобы увидеть приоритеты и состояние инфраструктуры.', 'm-out', 'm-run'],
    queue: ['Очередь устранения', 'Устраняйте уязвимости группами: одно обновление закрывает несколько рисков.'],
    patches: ['Патчи', 'Один патч закрывает десятки уязвимостей: ставьте обновления вендора там, где эффект больше.', 'Соберите список патчей', 'Сгруппируйте открытые уязвимости по патчам из паспортов MaxPatrol: ссылка, число уязвимостей и узлы для установки.', 'pt-sum', 'pt-run'],
    assets: ['Риск активов', 'Оцените риск каждого узла и начните с активов, которым нужно внимание.', 'Оцените риск инфраструктуры', 'Рассчитайте риск, чтобы сравнить активы и увидеть основные источники угроз.', 'a-out', 'a-run'],
    excl: ['Исключения и принятые риски', 'Проверяйте обоснования и возвращайте опасные исключения в работу.', 'Реестр ещё не загружен', 'Загрузите исключения, чтобы проверить причины и найти риски для пересмотра.', 'x-out', 'x-run'],
    proj: ['Проекты устранения', 'Контролируйте результат по данным сканирования и задачам Jira.', 'Загрузите проекты', 'Прогресс по меткам jira: и proj: покажет, какие уязвимости уже устранены.', 'p-out', 'p-run'],
    cw: ['Контейнеры и веб-сайты', 'Уязвимости образов, пакетов и веб-приложений, которые устраняют отдельно от узлов.', 'Выберите область проверки', 'Загрузите сводку образов, очередь по пакетам или уязвимости веб-сайтов.', 'w-out', 'w-images'],
    inv: ['Инвентаризация активов', 'Объединяйте активы тегами по платформе, роли, угрозам и срокам.'],
    cve: ['Внешний контекст по CVE', 'Сопоставляйте EPSS, CISA KEV, NVD и БДУ, чтобы определить приоритет.', 'Добавьте уязвимости для анализа', 'Вставьте CVE или найдите их на открытой странице MaxPatrol. Затем нажмите «Обогатить».', 'c-out'],
    settings: ['Настройки', 'Источники данных, сроки устранения, модель риска и подключение Jira.']
  };
  function setupPresentation() {
    for (const [key, page] of Object.entries(PAGES)) {
      const pane = sh.querySelector(`.pane[data-t="${key}"]`);
      pane.id = `pane-${key}`; pane.setAttribute('role', 'tabpanel'); pane.setAttribute('aria-labelledby', `tab-${key}`); pane.tabIndex = 0;
      const heading = document.createElement('div'); heading.className = 'page-heading';
      heading.innerHTML = `<div><h2>${esc(page[0])}</h2><p>${esc(page[1])}</p></div>`; pane.prepend(heading);
      const panel = pane.querySelector(':scope > .box');
      if (panel && key !== 'settings') {
        panel.classList.add('control-panel'); panel.querySelector(':scope > h3')?.remove();
        const description = panel.querySelector(':scope > .muted');
        if (description) {
          const details = document.createElement('details'); details.className = 'method';
          details.innerHTML = '<summary>Как это работает</summary>'; details.append(description); panel.append(details);
        }
      }
      if (page[4]) {
        $(page[4]).innerHTML = `<div class="empty-state"><span class="empty-icon" aria-hidden="true">${ICON}</span><h3>${esc(page[2])}</h3><p>${esc(page[3])}</p>${page[5] ? `<button class="btn" data-start="${page[5]}">${esc($(page[5]).textContent)}</button>` : ''}</div>`;
      }
    }
    const queueControls = $('q-run').parentElement;
    const filterBar = document.createElement('div'); filterBar.className = 'row filter-bar';
    ['q-byprod', 'q-f-trend', 'q-f-expl', 'q-f-crit', 'q-f-patch'].forEach(id => filterBar.append($(id).closest('label')));
    queueControls.after(filterBar);
    const queueEmpty = document.createElement('div'); queueEmpty.id = 'q-empty'; queueEmpty.className = 'empty-state';
    queueEmpty.innerHTML = `<span class="empty-icon" aria-hidden="true">${ICON}</span><h3>Соберите очередь обновлений</h3><p>Выберите источник и постройте список решений с наибольшим снижением риска.</p><button class="btn" data-start="q-run">Построить очередь</button>`;
    sh.querySelector('.pane[data-t="queue"]').append(queueEmpty);
    sh.querySelectorAll('.tabs button').forEach(b => {
      b.id = `tab-${b.dataset.t}`; b.setAttribute('role', 'tab'); b.setAttribute('aria-controls', `pane-${b.dataset.t}`);
      b.setAttribute('aria-selected', String(b.classList.contains('active'))); b.tabIndex = b.classList.contains('active') ? 0 : -1;
      b.addEventListener('keydown', e => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
        e.preventDefault(); const tabs = [...sh.querySelectorAll('.tabs button')]; const i = tabs.indexOf(b);
        const next = e.key === 'Home' ? tabs[0] : e.key === 'End' ? tabs.at(-1) : tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
        next.click(); next.focus(); next.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      });
    });
    sh.querySelectorAll('.field').forEach(field => {
      const text = field.querySelector('span'), input = field.querySelector('input, select');
      if (text && input?.id) { const label = document.createElement('label'); label.htmlFor = input.id; label.textContent = text.textContent; text.replaceWith(label); }
    });
    sh.querySelectorAll('.err').forEach(el => el.setAttribute('role', 'alert'));
    sh.querySelectorAll('[id$="-info"], [id$="-scan-info"]').forEach(el => { el.setAttribute('role', 'status'); el.setAttribute('aria-live', 'polite'); });
    sh.addEventListener('click', e => { const trigger = e.target.closest('[data-start]'); if (trigger) $(trigger.dataset.start)?.click(); });
    sh.addEventListener('keydown', e => { if (e.key === 'Escape' && vfPop) { e.preventDefault(); closePop(true); } });
  }

  function bind() {
    setupPresentation();
    $('close').addEventListener('click', close);
    sh.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => {
      closePop();
      sh.querySelectorAll('.tabs button').forEach(x => { x.classList.toggle('active', x === b); x.setAttribute('aria-selected', String(x === b)); x.tabIndex = x === b ? 0 : -1; });
      sh.querySelectorAll('.pane').forEach(p => p.classList.toggle('active', p.dataset.t === b.dataset.t));
      $('crumb').textContent = b.textContent; sh.querySelector('.body').scrollTop = 0; updateReportButtons();
      if (b.dataset.t === 'cve' && !$('c-cves').value) { const c = scanPageCves(); if (c.length) { $('c-cves').value = c.join(', '); $('c-scan-info').textContent = `найдено на странице: ${c.length}`; } }
    }));

    // Обзор
    $('m-run').addEventListener('click', runMetrics);
    $('m-report').addEventListener('click', () => { if (state.metrics) openHtml(REPORTS.overview.html(), `vm_report_${today()}.html`); });
    $('m-json').addEventListener('click', () => { if (state.metrics) download(`vm_metrics_${today()}.json`, JSON.stringify(state.metrics, null, 2), 'application/json'); });
    $('m-dl').addEventListener('click', () => { if (state.metrics) download(`vm_report_${today()}.html`, REPORTS.overview.html(), 'text/html;charset=utf-8'); });
    $('m-print').addEventListener('click', () => { if (state.metrics) printHtml(REPORTS.overview.html(), `vm_report_${today()}.html`); });
    $('m-out').addEventListener('click', async e => {
      const k = e.target.closest('[data-drill]'); if (k) { e.preventDefault(); drillFromMetrics(k.dataset.drill); return; }
      const pp = e.target.closest('[data-passport]');
      if (pp) { e.preventDefault(); pp.textContent = pp.dataset.passport + ' …'; try { const g = await VR.guidByCve(pp.dataset.passport); if (g) location.assign(VR.passportUrl(g)); else pp.textContent = pp.dataset.passport + ' (паспорт не найден)'; } catch (err) { pp.textContent = pp.dataset.passport + ' (' + err.message + ')'; } }
    });

    // Очередь
    $('q-byprod').addEventListener('change', renderQueue);
    sh.querySelectorAll('.q-filter').forEach(el => el.addEventListener('change', renderQueue));
    $('q-run').addEventListener('click', async () => {
      $('q-err').textContent = ''; $('q-run').disabled = true; $('q-info').innerHTML = '<span class="spin"></span>PDQL выполняется, 10-60 секунд';
      try {
        state.detail = null; $('q-detail').classList.remove('detail-active'); $('q-detail').innerHTML = '<div class="muted">Выберите группу слева.</div>';
        state.queue = await VR.queue({ scope: $('q-scope').value, minScore: $('q-min').value, limit: parseInt($('q-limit').value) || 300 });
        $('q-info').textContent = `готово: ${state.queue.totalGroups} групп`; $('q-csv').disabled = false; $('q-pdql').disabled = false;
        snapSave('queue', { queue: state.queue, scope: $('q-scope').value, minScore: $('q-min').value, limit: $('q-limit').value });
        renderQueue(); updateReportButtons();
      } catch (e) { $('q-err').textContent = e.message; $('q-info').textContent = ''; }
      $('q-run').disabled = false;
    });
    $('q-csv').addEventListener('click', () => { if (state.queue) download(`remediation_queue_${today()}.csv`, REPORTS.queue.csv(), 'text/csv;charset=utf-8'); });
    $('q-pdql').addEventListener('click', () => { if (state.queue) navigator.clipboard.writeText(state.queue.pdql).catch(() => {}); $('q-info').textContent = 'PDQL скопирован'; });

    // Патчи
    let patchRequest = 0;
    const selectPatchRow = name => sh.querySelectorAll('#pt-out tr.click').forEach(tr => {
      const selected = tr.dataset.patch === name;
      tr.classList.toggle('sel', selected);
      tr.querySelector('.row-action').setAttribute('aria-expanded', String(selected));
    });
    const closePatch = () => {
      ++patchRequest; state.patchDetail = null; $('pt-detail').hidden = true; $('pt-detail').innerHTML = '';
      selectPatchRow(null);
    };
    const renderPatches = () => {
      const d = state.patches; if (!d) return;
      $('pt-grid').hidden = false; $('pt-csv').disabled = false; $('pt-pdql').disabled = false;
      $('pt-sum').innerHTML = `<div class="kpis">
        <div class="kpi"><span class="v">${fmt(d.total.patchesWithLink ?? d.total.patches)}</span><span class="l">патчей со ссылкой${d.total.patchesWithLink != null && d.total.patchesWithLink !== d.total.patches ? ` из ${fmt(d.total.patches)}` : ''}</span></div>
        <div class="kpi"><span class="v">${fmt(d.total.vulns)}</span><span class="l">уязвимостей закроют</span></div>
        <div class="kpi"><span class="v">${fmt(d.total.hosts)}</span><span class="l">узлов для установки</span></div>
        <div class="kpi"><span class="v">${pct(d.patches.slice(0, 5).reduce((s, p) => s + p.n, 0), d.total.vulns)}%</span><span class="l">закрывают топ-5 патчей</span></div></div>
        ${d.total.noLinkVulns ? `<div class="inline-notice"><svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M10 2 19 18H1L10 2Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M10 7v5m0 2v1" stroke="currentColor" stroke-width="1.5"/></svg><div><strong>Для ${fmt(d.total.noLinkVulns)} уязвимостей на ${fmt(d.total.noLinkHosts)} узлах не указана ссылка на патч</strong><p>Исправление есть в паспорте. Уточните обновление у вендора; эта группа не входит в показатели патчей выше.</p></div></div>` : ''}
        ${d.truncated ? '<div class="note">Пар «патч × узел» больше 5 000: список усечён.</div>' : ''}`;
      const sig = p => `${p.trend ? '<span class="badge tag kev sm">Трендовые · ' + fmt(p.trend) + '</span>' : ''}${p.expl ? '<span class="badge tag hot sm">С эксплойтом · ' + fmt(p.expl) + '</span>' : ''}` || '<span class="muted">—</span>';
      const rows = d.patches.map(p => `<tr class="click" data-patch="${esc(p.patch)}"><td class="patch-name"><button type="button" class="row-action" aria-controls="pt-detail" aria-expanded="false">${esc(p.patch)}</button></td><td>${p.url ? `<a class="lnk" href="${esc(p.url)}" target="_blank" rel="noopener" title="Открыть страницу вендора: ${esc(p.url)}">${esc(p.kb || 'Вендор')} ↗</a>` : '<span class="muted">—</span>'}</td><td class="n" data-v="${esc(String(p.date || '').slice(0, 10))}">${esc(String(p.date || '').slice(0, 10)) || '—'}</td><td class="n">${fmt(p.n)}</td><td class="n">${fmt(p.hostsCount)}</td><td class="n">${p.crit ? cnt(p.crit, 'red') : '0'}</td><td class="n">${esc(p.maxScore ?? '—')}</td><td class="sig">${sig(p)}</td></tr>`).join('');
      // Ячейки совпадают с колонками: colspan ломает сортировку и фильтры.
      const noLink = d.noLink ? `<tr class="no-link"><td class="patch-name">Патч есть, но название и ссылка не указаны</td><td>—</td><td data-v="">—</td><td class="n">${fmt(d.noLink.n)}</td><td class="n">${fmt(d.noLink.hostsCount)}</td><td class="n">${d.noLink.crit == null ? '—' : fmt(d.noLink.crit)}</td><td class="n">${esc(d.noLink.maxScore ?? '—')}</td><td class="sig">${sig(d.noLink)}</td></tr>` : '';
      $('pt-out').innerHTML = `<div class="section-heading"><div><h3>Обновления вендоров</h3><p class="muted">Выберите патч, чтобы посмотреть узлы и CVE и запланировать установку.</p></div></div>${tfilter('Найти патч или KB…')}<div class="scroll"><table aria-label="Патчи для установки"><tr><th>патч</th><th>ссылка</th><th class="n">выпущен</th><th class="n">уязвимостей</th><th class="n">узлов</th><th class="n">critical</th><th class="n">CVSS</th><th>сигналы</th></tr>${rows}${noLink}</table></div>`;
      bindFilters($('pt-out')); selectPatchRow(state.patchDetail?.patch);
      sh.querySelectorAll('#pt-out tr.click').forEach(tr => tr.addEventListener('click', e => {
        if (!e.target.closest('a')) loadPatch(tr.dataset.patch);
      }));
    };
    async function loadPatch(name) {
      const p = state.patches?.patches.find(x => x.patch === name); if (!p) return;
      const request = ++patchRequest, box = $('pt-detail'); state.patchDetail = { patch: name, loading: true };
      box.hidden = false; box.innerHTML = `<div class="muted" role="status"><span class="spin" aria-hidden="true"></span>Загружаем узлы и CVE для ${esc(name)}…</div>`;
      selectPatchRow(name);
      try {
        const d = await VR.patchDetail({ patch: name }); if (request !== patchRequest) return;
        state.patchDetail = d; snapSave('patches', { patches: state.patches, detail: d });
        await renderPatchDetail(p, d, request);
        if (request === patchRequest && sh.querySelector('#tab-patches.active')) {
          $('pt-d-title')?.focus({ preventScroll: true }); box.scrollIntoView({ block: 'start' });
        }
      } catch (e) {
        if (request !== patchRequest) return;
        state.patchDetail = { patch: name, error: e.message };
        box.innerHTML = `<div class="err" role="alert">${esc(e.message)}</div><div><button class="btn" id="pt-retry">Повторить загрузку</button></div>`;
        $('pt-retry').addEventListener('click', () => loadPatch(name));
      }
    }
    async function renderPatchDetail(p, d, request = patchRequest) {
      const box = $('pt-detail');
      d.enrichmentLoading = true; delete d.enrichmentError;
      let enr = null; try { enr = await VR.ext('enrich', { cves: d.cves.map(c => c.cve), skipNvd: true, mp: Object.fromEntries(d.cves.map(c => [c.cve, { score: c.score, trend: c.trend, exploit: c.exploit }])) }); } catch (e) { d.enrichmentError = e.message; }
      if (request !== patchRequest || state.patchDetail !== d) return;
      d.enrichment = enr; d.enrichmentLoading = false; snapSave('patches', { patches: state.patches, detail: d });
      box.hidden = false; selectPatchRow(p.patch);
      const kevN = enr ? d.cves.filter(c => enr.results[c.cve]?.kev).length : 0;
      const impRu = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
      const hostRows = d.hosts.slice(0, 200).map(h => `<tr><td class="ell" title="${esc(h.host)}">${alink(h.id, h.host)}</td><td>${esc(h.os || '')}</td><td>${esc(impRu[h.imp] || h.imp)}</td><td class="n">${fmt(h.n)}</td><td class="n">${h.maxScore}</td></tr>`).join('');
      const cveRows = d.cves.slice(0, 100).map(c => { const r = enr?.results[c.cve]; return `<tr><td>${plink(c.vulnId, c.cve)}</td><td class="n">${c.score}</td><td class="n">${fmt(c.n)}</td><td>${r?.kev ? kevBadge(c.cve) : ''}${c.trend ? '<span class="badge tag kev sm">Трендовая</span>' : ''}${c.exploit ? '<span class="ttag">Есть эксплойт</span>' : ''}${r?.epss?.epss != null ? '<span class="muted">EPSS ' + (r.epss.epss * 100).toFixed(0) + '%</span>' : ''}</td></tr>`; }).join('');
      box.innerHTML = `<div class="detail-heading"><div><span class="eyebrow">Выбранный патч${p.date ? ' · выпущен ' + esc(String(p.date).slice(0, 10)) : ''}</span><h3 id="pt-d-title" tabindex="-1">${p.url ? `<a class="lnk" href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.patch)} ↗</a>` : esc(p.patch)}</h3></div><button type="button" class="close" id="pt-d-close" aria-label="Закрыть детали патча">×</button></div>
        <div class="detail-facts"><span>Экземпляров: <b>${fmt(d.rows)}</b></span><span>Узлов: <b>${fmt(d.hosts.length)}</b></span><span>CVE: <b>${fmt(d.cves.length)}</b></span><span>Уязвимостей: <b>${fmt(d.vulns.length)}</b></span>${kevN ? `<span class="badge tag kev sm">CISA KEV · ${fmt(kevN)} CVE</span>` : ''}</div>
        ${d.truncated ? '<div class="note">Показаны первые 20 000 экземпляров. Действия применяются только к загруженной выборке.</div>' : ''}
        <div class="row"><button class="btn" id="pt-d-csv">CSV узлов и CVE</button><button class="btn" id="pt-d-copy">Скопировать узлы</button><a class="btn" href="${esc(mpListUrl(d.pdql))}">Открыть в MaxPatrol</a><button class="btn" id="pt-d-proj" title="Метка proj:название на все экземпляры патча">В проект</button><span class="muted" id="pt-d-proj-st" role="status"></span></div>
        <div class="patch-actions">
          <section class="action-panel" aria-labelledby="pt-jira-title"><h3 id="pt-jira-title">Запланировать установку</h3><p class="muted">Создайте одну задачу в Jira на ${fmt(d.hosts.length)} узлах. В неё войдут ссылка на патч, список CVE с KEV и EPSS, узлы и CSV во вложении.</p><p class="muted">Если включено в настройках, экземпляры получат метку jira:KEY для отслеживания задачи.</p><div class="row"><button class="btn acc" id="pt-d-jira">Создать задачу в Jira</button><span class="muted" id="pt-d-jira-st" role="status"></span></div></section>
          <section class="action-panel" aria-labelledby="pt-status-title"><h3 id="pt-status-title">Изменить статус</h3><p class="muted">Для ${fmt(d.ids.length)} экземпляров выбранного патча в MaxPatrol VM.</p>
            <div class="status-fields"><div class="field"><label for="pt-d-cmd">Новый статус</label><select id="pt-d-cmd"><option value="SwitchToInProgressStateCommand">В работе</option><option value="SwitchToAwaitingFixStateCommand">Исправляется до даты</option><option value="SwitchToNewStateCommand">Новая</option></select></div><div class="field" id="pt-date-field" hidden><label for="pt-d-date">Исправить до</label><input type="date" id="pt-d-date" required value="${plusDays(7)}"></div></div>
            <div class="field"><label for="pt-d-note">Комментарий <span class="muted">(необязательно)</span></label><input type="text" id="pt-d-note" placeholder="Например, согласовано окно обновления" autocomplete="off"></div>
            <div class="row"><button class="btn" id="pt-d-apply">Применить статус</button><span class="muted" id="pt-d-st" role="status"></span></div></section>
        </div>
        <section class="patch-section" aria-labelledby="pt-hosts-title"><h4 id="pt-hosts-title">Узлы для установки <span>${fmt(d.hosts.length)}</span></h4>${d.hosts.length > 200 ? '<p class="muted">Первые 200 узлов. Полный список доступен в CSV.</p>' : ''}${tfilter('Найти узел…')}<div class="scroll"><table aria-labelledby="pt-hosts-title"><tr><th>узел (карточка)</th><th>ОС</th><th>значимость</th><th class="n">уязвимостей</th><th class="n">max CVSS</th></tr>${hostRows}</table></div></section>
        <section class="patch-section" aria-labelledby="pt-cves-title"><h4 id="pt-cves-title">Уязвимости CVE <span>${fmt(d.cves.length)}</span></h4>${d.cves.length > 100 ? '<p class="muted">Первые 100 CVE. Полный список доступен в CSV.</p>' : ''}${tfilter('Найти CVE…')}<div class="scroll"><table aria-labelledby="pt-cves-title"><tr><th>CVE (паспорт)</th><th class="n">CVSS</th><th class="n">экземпляров</th><th>сигналы</th></tr>${cveRows}</table></div></section>`;
      bindFilters(box);
      $('pt-d-cmd').addEventListener('change', () => { $('pt-date-field').hidden = $('pt-d-cmd').value !== 'SwitchToAwaitingFixStateCommand'; });
      $('pt-d-close').addEventListener('click', () => {
        const row = [...sh.querySelectorAll('#pt-out tr.click')].find(tr => tr.dataset.patch === p.patch);
        closePatch(); snapSave('patches', { patches: state.patches, detail: null });
        (row?.querySelector('.row-action') || $('pt-run')).focus();
      });
      $('pt-d-csv').addEventListener('click', () => download(`patch_${(p.kb || p.patch).replace(/[^\w.-]+/g, '_').slice(0, 40)}_${today()}.csv`, VR.reports.csv(makeSpec('Выбранный патч ' + p.patch, detailSections('Патч', d))), 'text/csv;charset=utf-8'));
      $('pt-d-copy').addEventListener('click', () => navigator.clipboard.writeText(d.hosts.map(h => h.host).join('\n')).catch(() => {}));
      if (!d.ids.length) ['pt-d-proj', 'pt-d-jira', 'pt-d-apply'].forEach(id => { $(id).disabled = true; });
      $('pt-d-proj').addEventListener('click', async event => {
        const btn = event.currentTarget, st = $('pt-d-proj-st');
        const name = prompt(`Название проекта (метка proj:название) для ${d.ids.length} экземпляров патча:`, (p.kb || p.patch).toLowerCase().replace(/[^a-zа-я0-9]+/gi, '-').slice(0, 30)); if (!name) return;
        btn.disabled = true; st.innerHTML = '<span class="spin" aria-hidden="true"></span>Добавляем в проект…';
        try { await VR.tagInstances(d.ids, 'proj:' + name.trim()); st.textContent = `метка proj:${name.trim()} поставлена, прогресс во вкладке «Проекты»`; }
        catch (e) { st.textContent = 'ошибка: ' + e.message; }
        finally { btn.disabled = false; }
      });
      $('pt-d-jira').addEventListener('click', async () => {
        const st = $('pt-d-jira-st'), btn = $('pt-d-jira'); btn.disabled = true; st.innerHTML = '<span class="spin" aria-hidden="true"></span>Готовим задачу…';
        try {
          const s = await VR.ext('settings-get');
          if (!s.jiraUrl || !s.jiraToken || !s.jiraProject) throw new Error('Заполните Jira в настройках: адрес, токен, проект');
          const issue = VR.buildPatchJiraIssue({ patch: p, detail: d, enrich: enr, sla: s, host: VR.config().host || location.hostname });
          if (!confirm(`Создать задачу в Jira (${s.jiraProject}):\n${issue.summary}\nСрок: ${issue.dueDate}`)) { btn.disabled = false; st.textContent = ''; return; }
          const r = await VR.ext('jira-create', issue);
          let note = '';
          try { await VR.ext('jira-attach', { key: r.key, filename: `mpvm_patch_${(p.kb || 'patch').replace(/[^\w.-]+/g, '_')}.csv`, content: issue.csv }); note += ', CSV приложен'; } catch (e) { note += ', вложение не удалось'; }
          if (s.jiraTagInstances !== false) { try { await VR.tagInstances(d.ids, 'jira:' + r.key); note += `, метка jira:${r.key} на ${fmt(d.ids.length)} экз.`; } catch (e) { note += ', метку поставить не удалось'; } }
          st.innerHTML = `создана <a href="${esc(r.url)}" target="_blank" rel="noopener" class="lnk">${esc(r.key)}</a>${esc(note)}`;
          btn.textContent = 'Задача создана'; btn.dataset.done = '1';
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
        if (!btn.dataset.done) btn.disabled = false;
      });
      $('pt-d-apply').addEventListener('click', async event => {
        // Сохраняем элементы текущей панели: пользователь может закрыть её во время запроса.
        const btn = event.currentTarget, st = $('pt-d-st'), cmd = $('pt-d-cmd').value;
        const date = $('pt-d-date'), note = $('pt-d-note').value;
        if (cmd === 'SwitchToAwaitingFixStateCommand' && !date.reportValidity()) return;
        if (!confirm(`Изменить статус ${d.ids.length} экземпляров уязвимостей патча «${p.patch}» в MaxPatrol VM?`)) return;
        btn.disabled = true; st.innerHTML = '<span class="spin" aria-hidden="true"></span>Выполняется…';
        try {
          const r = await VR.changeStatus({ ids: d.ids, command: cmd, tillDate: cmd === 'SwitchToAwaitingFixStateCommand' && date.value ? date.value + 'T00:00:00Z' : null, note });
          st.textContent = r.done === false ? `операция ${r.operationId} еще выполняется: обработано ${fmt((r.succeed || 0) + (r.failed || 0))} из ${fmt(r.total || r.count)}` : r.total != null ? `готово: успешно ${fmt(r.succeed || 0)} из ${fmt(r.total)}${r.failed ? ', ошибок ' + fmt(r.failed) : ''}` : `отправлено ${r.count} экз.`;
        } catch (e) { st.textContent = 'ошибка: ' + e.message; }
        finally { btn.disabled = false; }
      });
    }
    $('pt-run').addEventListener('click', async () => {
      $('pt-err').textContent = ''; $('pt-run').disabled = true; $('pt-info').innerHTML = '<span class="spin"></span>PDQL по всем открытым уязвимостям с патчем, 15-60 секунд';
      try {
        const patches = await VR.patches({});
        closePatch(); state.patches = patches;
        $('pt-info').textContent = `готово: ${fmt(state.patches.total.patches)} патчей`;
        snapSave('patches', { patches: state.patches, detail: null }); renderPatches(); updateReportButtons();
      } catch (e) { $('pt-err').textContent = e.message; $('pt-info').textContent = ''; }
      $('pt-run').disabled = false;
    });
    $('pt-csv').addEventListener('click', () => { if (state.patches) download(`patches_${today()}.csv`, REPORTS.patches.csv(), 'text/csv;charset=utf-8'); });
    $('pt-pdql').addEventListener('click', () => { if (state.patches) navigator.clipboard.writeText(state.patches.pdql).catch(() => {}); $('pt-info').textContent = 'PDQL скопирован'; });

    // Риск активов
    const renderAssets = () => {
      const d = state.assetRisk; if (!d) return;
      const imp = $('a-imp').value, top = parseInt($('a-top').value) || 50;
      const list = d.assets.filter(a => !imp || a.imp === imp).slice(0, top);
      const maxRisk = Math.max(1, ...list.map(a => a.risk));
      const impName = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
      const colors = { 'трендовые': 'var(--kbq-background-error, #d23c3c)', 'critical': 'var(--kbq-background-warning, #f0883e)', 'эксплойт': '#b86e00', 'важные': '#6f42c1', 'high': '#c7a200', 'прочие': 'var(--kbq-background-contrast-fade, #9aa1b1)' };
      const zoneRuS = { critical: 'критическая', high: 'высокая', medium: 'средняя', low: 'низкая' };
      const compBar = a => `<div class="comp" title="${esc(a.components.map(([k, v, m]) => `${k} ${v} из ${m}`).join(', ') + `; сумма ${a.raw} x контекст ${a.ctx.toFixed(2)}`)}">${a.components.map(([k, v, m], i) => `<i class="${'evtf'[i]}" style="height:${Math.max(2, Math.round(v / m * 18))}px"></i>`).join('')}</div>`;
      const rows = list.map(a => `<tr><td class="ell" title="${esc(a.host)}">${alink(a.id, a.host)}</td><td>${esc(a.os)}</td><td>${esc(impName[a.imp] || a.imp)}</td><td class="n" data-v="${a.risk}" title="${esc(a.why)}"><b>${a.risk}</b></td><td data-v="${zoneRuS[a.zone]}"><span class="zone ${a.zone}">${zoneRuS[a.zone]}</span></td><td data-v="${a.fstecLevel}"><span class="zone ${a.fstecLevel}" title="уровень худшей уязвимости по методике ФСТЭК, оценка ${a.fstecMax.toFixed(1)}">${a.fstecLevel}</span></td><td data-v="${a.raw}">${compBar(a)}</td><td class="n">${fmt(a.n)}</td><td class="n">${fmt(a.crit)}</td><td class="n">${fmt(a.high)}</td><td class="n" data-v="${a.trend}">${a.trend ? cnt(a.trend, 'red') : ''}</td><td class="n" data-v="${a.expl}">${a.expl ? cnt(a.expl, 'yellow') : ''}</td><td class="n" data-v="${a.kev}">${a.kev ? cnt(a.kev, 'red') : ''}</td><td><a class="lnk" href="#" data-asset="${esc(a.id)}" data-host="${esc(a.host)}">уязвимости</a></td></tr>`).join('');
      const zoneRu = { critical: 'критическая (700+)', high: 'высокая (500-699)', medium: 'средняя (300-499)', low: 'низкая (до 300)' };
      const aggTable = (title, rowsArr, keyName, keyFn) => `<div class="box"><h3>${title}</h3><table><tr><th>${keyName}</th><th>активов</th><th>средний риск</th><th>max риск</th><th>трендовых</th></tr>${rowsArr.slice(0, 12).map(b => `<tr><td>${keyFn ? keyFn(b.key) : esc(b.key)}</td><td class="n">${fmt(b.n)}</td><td class="n"><b>${b.avg}</b></td><td class="n">${b.max}</td><td class="n">${fmt(b.trend)}</td></tr>`).join('')}</table></div>`;
      const zoneCards = ['critical', 'high', 'medium', 'low'].map(z => { const b = d.byZone.find(x => x.key === z) || { n: 0 }; return `<div class="kpi ${z === 'critical' ? 'bad' : z === 'high' ? 'warn' : z === 'low' ? 'ok' : ''}"><div class="v">${fmt(b.n)}</div><div class="l">${zoneRu[z]}</div></div>`; }).join('');
      $('a-out').innerHTML = `<div class="box"><h3>Зоны риска</h3><div class="kpis">${zoneCards}</div>${d.truncated ? '<div class="note">Показаны первые 1000 узлов по PDQL.</div>' : ''}</div>
        <div class="two">${aggTable('По значимости', d.byImp, 'значимость', k => esc(impName[k] || k))}${aggTable('По типу актива', d.byType, 'тип')}</div>
        <div class="two">${aggTable('По операционной системе', d.byOs, 'ОС')}<div class="box"><h3>Как читать</h3><div class="muted">Средний риск по группе показывает, где процесс отстает: старые ОС, серверы без патч-менеджмента, рабочие станции без значимости. Зона «критическая» требует немедленной реакции: там трендовые и эксплуатируемые уязвимости на важных узлах. Колонка «ФСТЭК» показывает уровень худшей уязвимости узла по методике оценки критичности; значимость актива входит в расчет.</div></div></div>
        <div class="box"><h3>Топ активов по риску</h3><div class="muted">Компоненты: <span style="color:#4d94ff">■</span> экспозиция (E, до ${d.weights.E}), <span style="color:#ffb433">■</span> опасность CVSS (V, до ${d.weights.V}), <span style="color:#fc4d36">■</span> угроза (T, до ${d.weights.T}), <span style="color:#a06fff">■</span> ФСТЭК (F, до ${d.weights.F}). Риск = (E + V + T + F) x контекст; точные значения в подсказке к столбикам, причины в подсказке к риску, полностью в CSV.${d.kevChecked ? ` KEV проверен по ${fmt(d.kevChecked)} CVE.` : ' Колонка KEV заполняется кнопкой «Уточнить по KEV».'}</div>${tfilter('фильтр: узел, ОС, значимость, зона')}<div class="scroll" style="max-height:640px"><table><tr><th>узел (карточка)</th><th>ОС</th><th>значимость</th><th class="n">риск</th><th>зона</th><th>ФСТЭК</th><th>компоненты</th><th class="n">открыто</th><th class="n">critical</th><th class="n">high</th><th class="n">трендовых</th><th class="n">эксплойт</th><th class="n">KEV</th><th></th></tr>${rows}</table></div></div>
        <div id="a-drill"></div>`;
      bindFilters($('a-out'));
      sh.querySelectorAll('#a-out [data-asset]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); showDrill($('a-drill'), `Открытые уязвимости: ${a.dataset.host}`, VR.drillPdql('asset', a.dataset.asset)); }));
    };
    $('a-run').addEventListener('click', async () => {
      $('a-err').textContent = ''; $('a-run').disabled = true; $('a-info').innerHTML = '<span class="spin"></span>PDQL по всем узлам, 10-30 секунд';
      try { const s = await VR.ext('settings-get').catch(() => ({})); state.assetRisk = await VR.assetRisk({ limit: 1000, weights: s.riskWeights || null }); $('a-info').textContent = `узлов: ${state.assetRisk.assets.length}`; ['a-csv', 'a-kev', 'a-tags'].forEach(i => { $(i).disabled = false; }); snapSave('assetRisk', state.assetRisk); renderAssets(); updateReportButtons(); }
      catch (e) { $('a-err').textContent = e.message; $('a-info').textContent = ''; }
      $('a-run').disabled = false;
    });
    $('a-imp').addEventListener('change', renderAssets); $('a-top').addEventListener('change', renderAssets);
    $('a-kev').addEventListener('click', async () => { if (!state.assetRisk) return; $('a-kev').disabled = true; $('a-info').innerHTML = '<span class="spin"></span>CVE с эксплойтом по каталогу KEV'; try { await VR.assetRiskKev(state.assetRisk, { limit: 300 }); $('a-info').textContent = `KEV проверен по ${fmt(state.assetRisk.kevChecked || 0)} CVE`; snapSave('assetRisk', state.assetRisk); renderAssets(); } catch (e) { $('a-err').textContent = e.message; } $('a-kev').disabled = false; });
    $('a-tags').addEventListener('click', async () => { if (!state.assetRisk) return; const z = state.assetRisk.byZone; if (!confirm(`Поставить теги auto:risk-critical / high / medium / low на ${fmt(state.assetRisk.assets.length)} активов по зонам риска? Старые теги зон снимаются.`)) return; $('a-tags').disabled = true; $('a-info').innerHTML = '<span class="spin"></span>теги зон'; try { const r = await VR.applyRiskTags(state.assetRisk, { onProgress: n => { $('a-info').innerHTML = `<span class="spin"></span>теги: ${n}`; } }); $('a-info').textContent = 'теги зон: ' + r.map(x => `${x.zone} ${fmt(x.count)}`).join(', '); } catch (e) { $('a-err').textContent = e.message; } $('a-tags').disabled = false; });
    $('a-csv').addEventListener('click', () => { if (state.assetRisk) download(`asset_risk_${today()}.csv`, REPORTS.assets.csv(), 'text/csv;charset=utf-8'); });

    // Исключения
    const REASON = { acceptedAsLowRisk: 'принят низкий риск', cannotFix: 'нельзя исправить', compensatingControl: 'компенсирующая мера', falsePositive: 'ложное срабатывание', unknown: 'не указана' };
    const renderExcl = () => {
        const d = state.excl; if (!d) return;
        $('x-csv').disabled = false;
        const reasonRows = d.byReason.map(r => `<tr><td>${esc(REASON[r.reason] || r.reason)}</td><td class="n">${fmt(r.n)}</td><td class="n">${fmt(r.trend)}</td><td class="n">${fmt(r.expl)}</td><td class="n">${fmt(r.highImp)}</td><td class="n">${fmt(r.noNote)}</td></tr>`).join('');
        const riskyRows = d.groups.filter(g => g.trend || g.expl || g.score >= 9).slice(0, 60).map(g => `<tr class="click" data-key="${esc(g.key)}"><td class="ell" title="${esc(g.name)}">${plink(VR.vulnGuid(g.ids?.[0]), g.cve || g.name)}</td><td class="n">${g.score}</td><td class="n">${fmt(g.n)}</td><td class="n">${fmt(g.hosts)}</td><td>${g.trend ? '<span class="badge tag trend">trend</span>' : ''}${g.expl ? '<span class="badge tag hot">expl</span>' : ''}</td><td><button class="btn x-return" data-key="${esc(g.key)}">Вернуть в работу</button></td></tr>`).join('');
        $('x-out').innerHTML = `<div class="box"><h3>По причинам</h3><table><tr><th>причина</th><th>исключено</th><th>трендовых</th><th>с эксплойтом</th><th>на важных активах</th><th>без комментария</th></tr>${reasonRows}</table></div>
          <div class="box"><h3>Сомнительные исключения (пересмотреть)</h3><div class="muted">Трендовые, с публичным эксплойтом или CVSS 9+. Кнопка возвращает все экземпляры в статус «Новая» (команда SwitchToNewStateCommand).</div>${tfilter('фильтр по CVE или названию')}<div class="scroll"><table><tr><th>CVE / уязвимость (паспорт)</th><th>CVSS</th><th>экземпляров</th><th>узлов</th><th>сигналы</th><th></th></tr>${riskyRows || '<tr><td colspan=6 class="muted">нет</td></tr>'}</table></div></div>`;
        bindFilters($('x-out'));
        sh.querySelectorAll('#x-out .x-return').forEach(b => b.addEventListener('click', async e => {
          e.stopPropagation(); const g = d.groups.find(x => x.key === b.dataset.key); if (!g) return;
          if (!confirm(`Вернуть ${g.ids.length} экземпляров «${g.cve || g.name}» из исключений в статус «Новая»?`)) return;
          b.disabled = true; b.textContent = 'выполняется';
          try { const r = await VR.changeStatus({ ids: g.ids, command: 'SwitchToNewStateCommand' }); b.textContent = `готово: ${fmt(r.succeed || 0)}/${fmt(r.total || g.ids.length)}`; }
          catch (err) { b.textContent = 'ошибка'; $('x-err').textContent = err.message; b.disabled = false; }
        }));
    };
    $('x-run').addEventListener('click', async () => {
      $('x-err').textContent = ''; $('x-run').disabled = true; $('x-info').innerHTML = '<span class="spin"></span>загрузка исключений';
      try {
        const d = state.excl = await VR.exclusions({ limit: 5000 });
        $('x-info').textContent = `исключено: ${fmt(d.total)}${d.truncated ? ' (первые 5000)' : ''}, сомнительных: ${fmt(d.risky.length)}`;
        snapSave('excl', d); renderExcl(); updateReportButtons();
      } catch (e) { $('x-err').textContent = e.message; $('x-info').textContent = ''; }
      $('x-run').disabled = false;
    });
    $('x-csv').addEventListener('click', () => { if (state.excl) download(`exclusions_${today()}.csv`, REPORTS.excl.csv(), 'text/csv;charset=utf-8'); });

    // Проекты
    const renderProjects = () => {
        const d = state.projects; if (!d) return;
        const rows = d.projects.map(p => `<tr class="click" data-tag="${esc(p.tag)}"><td><b>${esc(p.tag)}</b>${p.kind === 'jira' ? ' <span class="badge tag">Jira</span>' : ''}</td><td style="min-width:200px"><div class="prog"><div class="pbar"><i style="width:${p.progress}%"></i></div><span>${p.progress}%</span></div></td><td class="n">${fmt(p.total)}</td><td class="n">${fmt(p.fixed)}</td><td class="n">${fmt(p.excluded)}</td><td class="n">${fmt(p.open)}</td><td class="n">${fmt(p.hosts)}</td><td class="muted">${esc(Object.entries(p.byStatus).map(([k, v]) => (ST_RU[k] || k) + ' ' + fmt(v)).join(', '))}</td><td><button class="btn p-close" data-tag="${esc(p.tag)}" title="Снять метку со всех экземпляров: проект исчезнет из списка">Закрыть</button></td></tr>`).join('');
        $('p-out').innerHTML = `<div class="box">${tfilter('фильтр по названию проекта')}<table><tr><th>проект (метка)</th><th>прогресс</th><th>всего</th><th>устранено</th><th>исключено</th><th>открыто</th><th>узлов</th><th>статусы</th><th></th></tr>${rows || '<tr><td colspan=8 class="muted">Меток на уязвимостях нет. Создайте задачу Jira из очереди (метка jira:KEY ставится автоматически) или поставьте метку proj:название в MaxPatrol.</td></tr>'}</table></div>`;
        bindFilters($('p-out'));
        sh.querySelectorAll('#p-out tr.click').forEach(tr => tr.addEventListener('click', () => showDrill($('p-drill'), `Проект ${tr.dataset.tag}: уязвимости и узлы`, VR.drillPdql('tag', tr.dataset.tag), { limit: 1000 })));
        sh.querySelectorAll('#p-out .p-close').forEach(b => b.addEventListener('click', async e => {
          e.stopPropagation(); const tag = b.dataset.tag;
          if (!confirm(`Закрыть проект ${tag}: снять метку со всех экземпляров? Статусы уязвимостей не меняются.`)) return;
          b.disabled = true; b.textContent = 'снимаем';
          try { const sel = await VR.drill({ pdql: VR.drillPdql('tag', tag), limit: 20000 }); const ids = sel.items.map(i => i.Id).filter(Boolean); await VR.tagInstances(ids, tag, true); b.textContent = `снято с ${fmt(ids.length)}`; }
          catch (err) { b.textContent = 'ошибка'; b.disabled = false; $('p-err').textContent = err.message; }
        }));
    };
    $('p-run').addEventListener('click', async () => {
      $('p-err').textContent = ''; $('p-run').disabled = true; $('p-info').innerHTML = '<span class="spin"></span>';
      try {
        const d = state.projects = await VR.projects({ prefix: $('p-prefix').value.trim() });
        $('p-info').textContent = `проектов: ${d.projects.length}`;
        snapSave('projects', d); renderProjects(); updateReportButtons();
      } catch (e) { $('p-err').textContent = e.message; $('p-info').textContent = ''; }
      $('p-run').disabled = false;
    });

    // Контейнеры и веб
    const wRun = async (btn, fn) => { $('w-err').textContent = ''; btn.disabled = true; $('w-info').innerHTML = '<span class="spin"></span>PDQL'; try { await fn(); } catch (e) { $('w-err').textContent = e.message; $('w-info').textContent = ''; } btn.disabled = false; };
    const IMG_COLS = [['Набор образов', 'image'], ['ID', 'id'], ['Уязвимостей', 'n'], ['Critical', 'crit'], ['High', 'high'], ['Max CVSS', 'maxScore']];
    const IMGQ_COLS = [['Образ', 'image'], ['Пакет', 'pkg'], ['Версия', 'ver'], ['Уязвимостей', 'n'], ['Critical', 'crit'], ['High', 'high'], ['Max CVSS', 'maxScore']];
    const WEB_COLS = [['Сайт', 'site'], ['Уязвимость', 'name'], ['CVE', 'cve'], ['CVSS', 'score'], ['Уровень', 'sev'], ['Статус', 'st'], ['Обнаружена', 'found']];
    const W_SPEC = {
      images: { title: 'Наборы образов', cols: IMG_COLS, rows: d => d, csvName: 'images' },
      imgQueue: { title: 'Очередь по пакетам образов', cols: IMGQ_COLS, rows: d => d.groups, csvName: 'image_packages' },
      web: { title: 'Уязвимости веб-сайтов', cols: WEB_COLS, rows: d => d.items, csvName: 'web_vulns' },
    };
    const renderImages = list => {
      $('w-csv').disabled = false; state.wCsv = () => download(`images_${today()}.csv`, REPORTS.cw.csv(), 'text/csv;charset=utf-8');
      $('w-out').innerHTML = `<div class="box"><h3>Наборы образов</h3>${tfilter('фильтр по образу')}<table><tr><th>набор образов</th><th>открытых уязвимостей</th><th>critical</th><th>high</th><th>max CVSS</th></tr>${list.map(i => `<tr><td class="ell" title="${esc(i.image)}">${alink(i.id, i.image)}</td><td class="n">${fmt(i.n)}</td><td class="n">${fmt(i.crit)}</td><td class="n">${fmt(i.high)}</td><td class="n">${i.maxScore}</td></tr>`).join('') || '<tr><td colspan=5 class="muted">образов с открытыми уязвимостями нет</td></tr>'}</table></div>`;
      bindFilters($('w-out'));
    };
    $('w-images').addEventListener('click', () => wRun($('w-images'), async () => {
      const list = await VR.imageSummary(); $('w-info').textContent = `образов с открытыми уязвимостями: ${list.length}`;
      state.cw = { kind: 'images', data: list }; snapSave('cw', state.cw); renderImages(list); updateReportButtons();
    }));
    const renderImgQueue = q => {
      $('w-csv').disabled = false; state.wCsv = () => download(`image_packages_${today()}.csv`, REPORTS.cw.csv(), 'text/csv;charset=utf-8');
      $('w-out').innerHTML = `<div class="box"><h3>Очередь по пакетам образов</h3><div class="muted">Пакет и версия внутри образа: обновление базового образа или пакета в Dockerfile закрывает всю группу. Клик по строке показывает CVE.</div>${tfilter('фильтр: образ, пакет')}<div class="scroll" style="max-height:520px"><table><tr><th>образ</th><th>пакет</th><th>версия</th><th>уязвимостей</th><th>critical</th><th>high</th><th>max CVSS</th></tr>${q.groups.map((g, i) => `<tr class="click" data-i="${i}"><td class="ell" title="${esc(g.image || '')}">${esc(g.image || '')}</td><td class="ell">${esc(g.pkg || '')}</td><td class="ver">${esc(g.ver)}</td><td class="n">${fmt(g.n)}</td><td class="n">${fmt(g.crit)}</td><td class="n">${fmt(g.high)}</td><td class="n">${g.maxScore}</td></tr>`).join('') || '<tr><td colspan=7 class="muted">пусто</td></tr>'}</table></div></div><div id="w-drill"></div>`;
      bindFilters($('w-out'));
      sh.querySelectorAll('#w-out tr.click').forEach(tr => tr.addEventListener('click', async () => {
        const g = q.groups[parseInt(tr.dataset.i)]; const box = $('w-drill'), cw = state.cw, pending = { loading: true, soft: g.pkg, ver: g.ver }; cw.detail = pending; box.innerHTML = '<div class="box"><span class="spin"></span>детали</div>';
        try { const d = await VR.queueDetail({ scope: 'images', soft: g.pkg, ver: g.ver, pkg: g.pkg }); if (state.cw !== cw || cw.detail !== pending || !box.isConnected) return; cw.detail = d; box.innerHTML = `<div class="box drill"><h3>${esc(g.pkg)} ${esc(g.ver)}<button aria-label="Закрыть выборку" class="x">×</button></h3><div class="muted">${fmt(d.rows)} экземпляров, ${d.cves.length} CVE, ${d.hosts.length} наборов образов</div><div class="two"><div class="scroll"><table><tr><th>CVE (паспорт)</th><th>CVSS</th><th>экземпляров</th></tr>${d.cves.slice(0, 100).map(c => `<tr><td>${plink(c.vulnId, c.cve)}</td><td class="n">${c.score}</td><td class="n">${fmt(c.n)}</td></tr>`).join('')}</table></div><div class="scroll"><table><tr><th>набор образов</th><th>уязвимостей</th></tr>${d.hosts.slice(0, 100).map(h => `<tr><td class="ell">${alink(h.id, h.host)}</td><td class="n">${fmt(h.n)}</td></tr>`).join('')}</table></div></div></div>`; box.querySelector('.x').addEventListener('click', () => { delete cw.detail; box.innerHTML = ''; }); }
        catch (e) { if (state.cw !== cw || cw.detail !== pending || !box.isConnected) return; cw.detail = { error: e.message }; box.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
      }));
    };
    $('w-imgq').addEventListener('click', () => wRun($('w-imgq'), async () => {
      const q = await VR.queue({ scope: 'images', minScore: $('w-min').value, limit: 500 }); $('w-info').textContent = `групп (образ + пакет + версия): ${q.totalGroups}`;
      state.cw = { kind: 'imgQueue', data: q }; snapSave('cw', state.cw); renderImgQueue(q); updateReportButtons();
    }));
    const renderWeb = w => {
      $('w-csv').disabled = false; state.wCsv = () => download(`web_vulns_${today()}.csv`, REPORTS.cw.csv(), 'text/csv;charset=utf-8');
      $('w-out').innerHTML = `<div class="box"><h3>Веб-сайты</h3>${w.sites.length ? '' : '<div class="muted">Активов типа WebSite с открытыми уязвимостями нет: веб-сканирование (PT BlackBox или профиль веб-аудита) в этой системе не выполнялось.</div>'}<table><tr><th>сайт</th><th>открытых</th><th>critical</th><th>high</th><th>max CVSS</th></tr>${w.sites.map(s => `<tr><td>${esc(s.site)}</td><td class="n">${fmt(s.n)}</td><td class="n">${fmt(s.crit)}</td><td class="n">${fmt(s.high)}</td><td class="n">${s.maxScore}</td></tr>`).join('')}</table></div>
        ${w.items.length ? `<div class="box"><h3>Уязвимости веб-сайтов</h3>${tfilter('фильтр: сайт, уязвимость, CVE')}<div class="scroll" style="max-height:520px"><table><tr><th>сайт</th><th>уязвимость (паспорт)</th><th>CVE</th><th>CVSS</th><th>уровень</th><th>статус</th><th>обнаружена</th></tr>${w.items.slice(0, 1000).map(i => `<tr><td class="ell">${esc(i.site)}</td><td class="ell" title="${esc(i.name)}">${plink(i.vulnId, i.name)}</td><td>${esc(i.cve || '')}</td><td class="n">${i.score}</td><td>${esc(SEV_RU[i.sev] || i.sev)}</td><td>${esc(ST_RU[i.st] || i.st)}</td><td class="n">${esc(String(i.found || '').slice(0, 10))}</td></tr>`).join('')}</table></div></div>` : ''}`;
      bindFilters($('w-out'));
    };
    $('w-web').addEventListener('click', () => wRun($('w-web'), async () => {
      const w = await VR.webVulns({}); $('w-info').textContent = `веб-сайтов с открытыми уязвимостями: ${w.sites.length}, экземпляров ${fmt(w.items.length)}`;
      state.cw = { kind: 'web', data: w }; snapSave('cw', state.cw); renderWeb(w); updateReportButtons();
    }));
    const renderCw = () => { const c = state.cw; if (!c) return; ({ images: renderImages, imgQueue: renderImgQueue, web: renderWeb })[c.kind]?.(c.data); };
    $('w-csv').addEventListener('click', () => { if (state.wCsv) state.wCsv(); });

    // Инвентаризация: авто-теги
    const renderRules = () => { const all = VR.autoTagRules(); const groups = [...new Set(all.map(r => r.group || 'Прочее'))]; $('i-rules').innerHTML = groups.map(g => `<h4>${esc(g)}</h4><div class="grp">${all.map((r, i) => r.group === g ? `<label><input type="checkbox" class="i-rule" data-i="${i}" ${['Платформа', 'Роль', 'Гигиена'].includes(g) ? 'checked' : ''}><span><b>${esc(r.name)}</b> ${esc(r.title)}<code>${esc(r.pdql)}</code></span></label>` : '').join('')}</div>`).join('') + '<div class="muted">Правила по угрозе и срокам зависят от текущего состояния уязвимостей: применяйте их заново после сканирования. Старые теги остаются на активах, которые уже не подходят под правило: снимите их кнопкой «Удалить все auto:*» и примените правила снова. Теги зон риска ставятся во вкладке «Риск активов».</div>'; };
    renderRules();
    const iRun = async (btn, fn) => { $('i-err').textContent = ''; btn.disabled = true; try { await fn(); } catch (e) { $('i-err').textContent = e.message; $('i-info').textContent = ''; } btn.disabled = false; };
    const showResults = (title, res, fromSnap) => { if (!fromSnap) { state.inv = { kind: 'results', title, data: res }; snapSave('inv', state.inv); updateReportButtons(); } $('i-out').innerHTML = `<div class="box"><h3>${esc(title)}</h3><table><tr><th>тег / правило</th><th>результат</th></tr>${res.map(r => `<tr><td>${esc(r.rule || r.tag)}</td><td>${r.ok ? '<span class="badge tag" style="background:#d9f2e2;color:#1b8f4a">выполнено</span>' + (r.count != null ? ` <span class="muted">${fmt(r.count)} активов${r.failed ? ', ошибок ' + fmt(r.failed) : ''}</span>` : '') + (r.hasMatches === false ? ' <span class="muted">(выборка пустая)</span>' : '') : '<span class="badge tag hot">ошибка</span> ' + esc(r.error || '')}</td></tr>`).join('')}</table><div class="muted">Теги назначены точечно каждому активу выборки: сразу видны в списке активов и в PDQL (<b>Host.@Tags.Item = "имя"</b>).</div></div>`; };
    $('i-apply').addEventListener('click', () => iRun($('i-apply'), async () => {
      const all = VR.autoTagRules(); const rules = [...sh.querySelectorAll('.i-rule:checked')].map(c => all[parseInt(c.dataset.i)]);
      if (!rules.length) throw new Error('Отметьте хотя бы одно правило');
      if (!confirm(`Создать ${rules.length} тегов и назначить их активам по PDQL-выборкам?`)) return;
      $('i-info').innerHTML = '<span class="spin"></span>0 из ' + rules.length;
      const res = await VR.applyAutoTags({ rules, onProgress: n => { $('i-info').innerHTML = `<span class="spin"></span>правило ${n} из ${rules.length}`; } });
      $('i-info').textContent = `готово: ${res.filter(r => r.ok).length} из ${res.length}`; showResults('Применение правил', res);
    }));
    $('i-add').addEventListener('click', () => iRun($('i-add'), async () => {
      const name = $('i-name').value.trim(), pdql = $('i-pdql').value.trim();
      if (!name || !pdql) throw new Error('Укажите имя тега и PDQL с select(@Host)');
      $('i-info').innerHTML = '<span class="spin"></span>';
      const res = await VR.applyAutoTags({ rules: [{ name, color: 'grey', title: 'свое правило', pdql }] });
      $('i-info').textContent = res[0].ok ? 'готово' : 'ошибка'; showResults('Свое правило', res);
    }));
    $('i-remove').addEventListener('click', () => iRun($('i-remove'), async () => {
      const tags = (await VR.assetTags() || []).filter(t => String(t.name).startsWith('auto:'));
      if (!tags.length) { $('i-info').textContent = 'тегов auto:* нет'; return; }
      if (!confirm(`Снять с активов и удалить ${tags.length} тегов: ${tags.map(t => t.name).join(', ')}?`)) return;
      $('i-info').innerHTML = '<span class="spin"></span>удаление';
      const res = await VR.removeAutoTags({ prefix: 'auto:' }); $('i-info').textContent = `удалено ${res.filter(r => r.ok).length} из ${res.length}`; showResults('Удаление auto:*', res);
    }));
    $('i-cover').addEventListener('click', () => iRun($('i-cover'), async () => {
      $('i-info').innerHTML = '<span class="spin"></span>'; const cov = await VR.tagCoverage(); $('i-info').textContent = `тегов в использовании: ${cov.length}`;
      state.inv = { kind: 'coverage', title: 'Покрытие активов тегами', data: cov }; snapSave('inv', state.inv); renderCoverage(cov); updateReportButtons();
    }));
    const renderCoverage = cov => {
      $('i-out').innerHTML = `<div class="box"><h3>Покрытие активов тегами</h3>${tfilter('фильтр по тегу')}<table><tr><th>тег</th><th>активов</th><th></th></tr>${cov.map(c => `<tr><td>${esc(c.tag)}</td><td class="n">${fmt(c.n)}</td><td><a class="lnk" href="${esc(mpListUrl(`filter(Host.@Tags.Item = "${c.tag.replace(/"/g, '\\"')}") | select(@Host, Host.OsName, Host.@Importance)`))}">открыть в MaxPatrol</a></td></tr>`).join('') || '<tr><td colspan=3 class="muted">тегов на активах нет</td></tr>'}</table></div>`;
      bindFilters($('i-out'));
    };
    $('i-tags').addEventListener('click', () => iRun($('i-tags'), async () => {
      const tags = await VR.assetTags() || []; $('i-info').textContent = `тегов в системе: ${tags.length}`;
      state.inv = { kind: 'tags', title: 'Теги активов', data: tags }; snapSave('inv', state.inv); renderTags(tags); updateReportButtons();
    }));
    const renderTags = tags => {
      $('i-out').innerHTML = `<div class="box"><h3>Теги активов</h3>${tfilter('фильтр по тегу')}<table><tr><th>тег</th><th>цвет</th><th>описание</th><th></th></tr>${tags.map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.color || '')}</td><td>${esc(t.description || '')}</td><td>${String(t.name).startsWith('auto:') ? `<button class="btn i-del" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Удалить</button>` : ''}</td></tr>`).join('')}</table></div>`;
      bindFilters($('i-out'));
      sh.querySelectorAll('#i-out .i-del').forEach(b => b.addEventListener('click', async () => { if (!confirm(`Снять с активов и удалить тег ${b.dataset.name}?`)) return; b.disabled = true; try { await VR.assignAssetTags({ pdql: `filter(Host.@Tags.Item = "${b.dataset.name.replace(/"/g, '\\"')}") | select(@Host)`, removeIds: [b.dataset.id] }); await VR.deleteAssetTag(b.dataset.id); const index = tags.findIndex(t => t.id === b.dataset.id); if (index >= 0) tags.splice(index, 1); if (state.inv?.data === tags) snapSave('inv', state.inv); b.closest('tr').remove(); } catch (e) { $('i-err').textContent = e.message; b.disabled = false; } }));
    };
    const renderInv = () => { const c = state.inv; if (!c) return; if (c.kind === 'results') showResults(c.title, c.data, true); else if (c.kind === 'coverage') renderCoverage(c.data); else if (c.kind === 'tags') renderTags(c.data); };

    // CVE
    $('c-scan').addEventListener('click', () => { const c = scanPageCves(); $('c-cves').value = c.join(', '); $('c-scan-info').textContent = c.length ? `найдено: ${c.length}` : 'CVE на странице не найдены'; });
    $('c-run').addEventListener('click', async () => {
      const cves = [...new Set(($('c-cves').value.match(CVE_RE) || []).map(x => x.toUpperCase()))];
      $('c-err').textContent = '';
      if (!cves.length) { $('c-err').textContent = 'Укажите хотя бы один CVE'; return; }
      $('c-run').disabled = true; $('c-info').innerHTML = `<span class="spin"></span>запрос по ${cves.length} CVE`;
      try {
        // Экземпляры в MaxPatrol: по открытой карточке экземпляра, по открытому активу, иначе все экземпляры CVE
        const pc = pageContext(); const mpCtx = {}, mp = {};
        const skipMp = $('c-skipmp').checked;
        if (!skipMp) $('c-info').innerHTML = `<span class="spin"></span>экземпляры в MaxPatrol по ${Math.min(cves.length, 10)} CVE`;
        await Promise.all((skipMp ? [] : cves.slice(0, 10)).map(async cve => {
          try {
            const ctx = await VR.instanceContext({ cve, instanceId: pc.instanceId || undefined, assetId: !pc.instanceId && pc.assetId ? pc.assetId : undefined, limit: 50 });
            mpCtx[cve] = ctx;
            const s = ctx.instances.summary; if (s.total) mp[cve] = { score: s.maxScore, trend: s.trend > 0, exploit: s.expl > 0 };
          } catch (e) { mpCtx[cve] = { error: e.message }; }
        }));
        $('c-info').innerHTML = `<span class="spin"></span>внешние источники по ${cves.length} CVE`;
        const r = await VR.ext('enrich', { cves, skipNvd: $('c-skipnvd').checked, mp });
        state.enrich = r; state.mpCtx = mpCtx; snapSave('cve', { enrich: r, text: $('c-cves').value, mpCtx });
        renderCves(); updateReportButtons();
        const meta = r.meta || {};
        $('c-info').textContent = `готово: ${r.cves.length} CVE; KEV от ${meta.kevDate ? meta.kevDate.slice(0, 10) : 'нет'}${meta.nvdSkipped ? '; NVD пропущено ' + meta.nvdSkipped + ' (лимит без ключа)' : ''}${meta.bdu ? '; БДУ ' + fmt(meta.bdu.rows) + ' CVE' : '; БДУ не импортирована'}`;
      } catch (e) { $('c-err').textContent = e.message; }
      $('c-run').disabled = false;
      if ($('c-err').textContent) $('c-info').textContent = '';
    });
    // ── Блок «В MaxPatrol» в карточке CVE: экземпляры, выбранный экземпляр, задача Jira ──
    const impRuS = { H: 'высокая', M: 'средняя', L: 'низкая', ND: 'не задана' };
    const cveSnap = () => snapSave('cve', { enrich: state.enrich, text: $('c-cves').value, mpCtx: Object.fromEntries(Object.entries(state.mpCtx || {}).map(([cve, { loading, pendingId, ...ctx }]) => [cve, ctx])) });
    function mpBlockHtml(cve) {
      const c = state.mpCtx?.[cve]; if (!c) return '';
      if (c.error) return `<div class="line muted">MaxPatrol: ${esc(c.error)}</div>`;
      const inst = c.instances, s = inst.summary, sel = c.selected;
      if (!s.total) return '<div class="line muted">В MaxPatrol экземпляров этой уязвимости нет.</div>';
      const head = `<div class="mp-h"><h4>В MaxPatrol VM</h4><div class="mp-signals">${s.trend ? '<span class="badge tag kev sm">Трендовая</span>' : ''}${s.expl ? '<span class="badge tag hot sm">Есть эксплойт</span>' : ''}${s.patch ? '<span class="badge tag sm"><span class="ttag green">Есть патч</span></span>' : ''}</div></div>
        <div class="mp-summary"><div><b>${fmt(s.total)}</b><span>экземпляров на ${fmt(s.hosts)} узлах</span></div><div><b>${fmt(s.open)}</b><span>открытых</span></div><div><b>${esc(s.maxScore ?? '—')}</b><span>макс. оценка MP</span></div></div>${inst.truncated ? `<p class="note">Показаны первые ${fmt(inst.items.length)} экземпляров.</p>` : ''}`;
      const opts = inst.items.map(i => `<option value="${esc(i.id)}"${(c.loading ? c.pendingId === i.id : sel?.item.id === i.id) ? ' selected' : ''}>${esc(i.host)} · ${i.score} · ${esc(ST_RU[i.st] || i.st)}</option>`).join('');
      const pick = `<div class="mp-picker"><label for="mp-pick-${esc(cve)}">Экземпляр на активе</label><select id="mp-pick-${esc(cve)}" class="mp-pick" data-cve="${esc(cve)}"${c.loading ? ' disabled' : ''}><option value="" disabled${!sel && !c.loading ? ' selected' : ''}>Выберите актив…</option>${opts}</select>${c.pickedBy === 'instance' || c.pickedBy === 'asset' ? `<span class="muted">Выбран из открытой карточки ${c.pickedBy === 'instance' ? 'экземпляра' : 'актива'}</span>` : ''}<span class="muted" data-role="mp-st" role="status">${c.loading ? '<span class="spin" aria-hidden="true"></span>Загружаем детали экземпляра…' : ''}</span></div>`;
      if (c.loading) return head + pick;
      if (!sel) return head + pick + '<p class="muted">Выберите актив, чтобы увидеть версии, срок по SLA и создать задачу на конкретный экземпляр.</p>';
      const it = sel.item, d = sel.det, f = sel.fix, st = sel.status;
      const sd = VR.slaDue({ found: it.found, sev: it.sev, st: it.st, sla: state.sla }); const due = sd.due, over = sd.overdue;
      const rows = [
        ['Актив', `${alink(it.hostId, it.host)}, значимость ${esc(impRuS[it.imp] || it.imp)}${it.os ? ', ' + esc(it.os) : ''}`],
        ['Статус', `${esc(ST_RU[st?.status || it.st] || it.st)}${st?.statusReason ? ' (' + esc(st.statusReason) + ')' : ''}, обнаружена ${esc(String(it.found || '').slice(0, 10))}${due ? `, срок по SLA от обнаружения ${VR.localDate(due)}${over ? ' <span class="ttag">просрочен</span>' : ''}` : ''}`],
        ['Оценка MP', `<b>${esc(sel.metrics?.overall ?? it.score)}</b>${state.enrich?.results?.[cve]?.nvd?.cvss31?.score != null ? ` (базовая CVSS 3.1 по NVD ${esc(state.enrich.results[cve].nvd.cvss31.score)})` : ''}${sel.metrics?.vector ? ` <span class="muted" title="${esc(sel.metrics.vector)}">вектор для актива</span>` : ''}`],
        d ? ['Где найдена', `${esc(d.product)}${d.os ? ', ' + esc(d.os) : ''}${d.release ? ' ' + esc(d.release) : ''}${d.arch ? ', ' + esc(d.arch) : ''}${d.current ? `; ${esc(d.versionLabel)} <b>${esc(d.current)}</b>${d.required ? ' &lt; требуется ' + esc(d.required) : ''}` : ''}`] : null,
        ['Целевая версия', f.min ? `не ниже <b>${esc(f.min.version)}</b>${f.min.kb ? ' (' + esc(f.min.kb) + ')' : ''}${f.recommended && f.recommended.version !== f.min.version ? `, рекомендуется <b>${esc(f.recommended.version)}</b>${f.recommended.kb ? ' (' + esc(f.recommended.kb) + ')' : ''}` : ''}` : '<span class="muted">в паспорте не указана</span>'],
        ['Патч', sel.patch ? `${sel.patch.url ? `<a href="${esc(sel.patch.url)}" target="_blank" rel="noopener">${esc(sel.patch.name)}</a>` : esc(sel.patch.name)}${sel.patch.date ? ' от ' + esc(String(sel.patch.date).slice(0, 10)) : ''}` : '<span class="muted">нет</span>'],
        sel.bdu.length ? ['БДУ', sel.bdu.map(b => `<a href="https://bdu.fstec.ru/vul/${esc(b.replace(/^BDU:/, ''))}" target="_blank" rel="noopener">${esc(b)}</a>`).join(', ')] : null,
        ['Ссылки', `<a href="${esc(sel.urls.card)}">карточка экземпляра</a> · <a href="${esc(sel.urls.passport)}">паспорт</a>${sel.links.slice(0, 3).map(u => { let h = u; try { h = new URL(u).hostname; } catch (_) {} return ` · <a href="${esc(u)}" target="_blank" rel="noopener">${esc(h)}</a>`; }).join('')}`],
      ].filter(Boolean);
      const facts = items => `<dl>${items.map(([k, v]) => `<div class="mp-fact"><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>`;
      return head + pick + `<section class="mp-section"><h4>Экземпляр</h4>${facts(rows.filter(([k]) => ['Актив', 'Статус', 'Оценка MP', 'Где найдена'].includes(k)))}</section>
        <section class="mp-section mp-fix"><h4>Устранение</h4>${facts(rows.filter(([k]) => ['Целевая версия', 'Патч'].includes(k)))}</section>
        <div class="mp-section">${facts(rows.filter(([k]) => ['БДУ', 'Ссылки'].includes(k)))}</div>${sel.errors?.length ? `<div class="note">Не все данные получены: ${esc(sel.errors.join('; '))}</div>` : ''}
        <div class="row mp-actions"><button class="btn acc mp-jira" data-cve="${esc(cve)}" aria-label="Задача в Jira на экземпляр ${esc(cve)} на ${esc(it.host)}">Задача в Jira</button><button class="btn mp-work" data-cve="${esc(cve)}" ${/^(fixed|excluded|inProgress)$/.test(it.st) ? 'disabled' : ''}>В работу</button><span class="muted" data-role="mp-jira-st" role="status"></span></div>`;
    }
    function mountMpBlocks(onlyCve) {
      const focusId = sh.activeElement?.classList.contains('mp-pick') ? sh.activeElement.id : null;
      const blocks = [...sh.querySelectorAll('#c-out .mp[data-mp]')].filter(el => !onlyCve || el.dataset.mp === onlyCve);
      blocks.forEach(el => {
        el.innerHTML = mpBlockHtml(el.dataset.mp);
        el.querySelectorAll('.mp-pick').forEach(s => s.addEventListener('change', () => { if (s.value) loadInstance(s.dataset.cve, s.value); }));
        el.querySelectorAll('.mp-jira').forEach(b => b.addEventListener('click', () => jiraForInstance(b.dataset.cve, b, b.parentElement.querySelector('[data-role=mp-jira-st]'))));
        el.querySelectorAll('.mp-work').forEach(b => b.addEventListener('click', async () => {
          const sel = state.mpCtx?.[b.dataset.cve]?.selected; if (!sel) return;
          if (!confirm(`Перевести экземпляр ${b.dataset.cve} на ${sel.item.host} в статус «В работе»?`)) return;
          const st = b.parentElement.querySelector('[data-role=mp-jira-st]'); b.disabled = true; st.innerHTML = '<span class="spin"></span>';
          try {
            const r = await VR.changeStatus({ ids: [sel.item.id], command: 'SwitchToInProgressStateCommand' });
            const ok = r.done !== false && (r.succeed || 0) >= 1 && !(r.failed || 0);
            if (!ok) { st.textContent = r.done === false ? `операция ${r.operationId} еще выполняется на сервере, проверьте статус позже` : `статус не изменен: успешно ${fmt(r.succeed || 0)} из ${fmt(r.total ?? 1)}${r.failed ? ', ошибок ' + fmt(r.failed) : ''}`; b.disabled = false; return; }
            st.textContent = 'статус изменен: В работе'; sel.item.st = 'inProgress'; if (sel.status) sel.status.status = 'inProgress'; cveSnap();
          }
          catch (e) { st.textContent = 'ошибка: ' + e.message; b.disabled = false; }
        }));
      });
      if (focusId && $(focusId) && !$(focusId).disabled) $(focusId).focus({ preventScroll: true });
    }
    async function loadInstance(cve, id) {
      const c = state.mpCtx?.[cve]; const item = c?.instances?.items.find(i => i.id === id); if (!item) return;
      const restoreFocus = sh.activeElement?.classList.contains('mp-pick') && sh.activeElement.dataset.cve === cve;
      c.loading = true; c.selected = null; delete c.selectionError; c.pendingId = id; mountMpBlocks(cve);
      try {
        const selected = await VR.instanceDetailContext(item);
        if (state.mpCtx?.[cve] !== c) return;
        c.selected = selected; c.pickedBy = 'manual';
      } catch (e) {
        if (state.mpCtx?.[cve] !== c) return;
        c.selected = null; c.loading = false; c.selectionError = e.message; delete c.pendingId; cveSnap(); mountMpBlocks(cve);
        const el = $('mp-pick-' + cve)?.parentElement.querySelector('[data-role=mp-st]');
        if (el) el.textContent = 'Не удалось загрузить экземпляр: ' + e.message;
        if (restoreFocus && !sh.activeElement) $('mp-pick-' + cve)?.focus({ preventScroll: true });
        return;
      }
      c.loading = false; delete c.pendingId; cveSnap(); mountMpBlocks(cve);
      if (restoreFocus && !sh.activeElement) $('mp-pick-' + cve)?.focus({ preventScroll: true });
    }
    async function jiraForInstance(cve, btn, st) {
      const sel = state.mpCtx?.[cve]?.selected; if (!sel) return;
      btn.disabled = true; st.innerHTML = '<span class="spin"></span>';
      try {
        const s = await VR.ext('settings-get');
        if (!s.jiraUrl || !s.jiraToken || !s.jiraProject) throw new Error('Заполните Jira в настройках: адрес, токен, проект');
        const issue = VR.buildInstanceJiraIssue({ ctx: { ...sel, cve }, enrich: state.enrich, sla: s, host: VR.config().host || location.hostname });
        if (!confirm(`Создать задачу в Jira (${s.jiraProject}):\n${issue.summary}\nСрок: ${issue.dueDate}`)) { btn.disabled = false; st.textContent = ''; return; }
        const r = await VR.ext('jira-create', issue);
        let note = '';
        if (s.jiraTagInstances !== false) { try { await VR.tagInstances(issue.ids, 'jira:' + r.key); note = `, метка jira:${r.key} на экземпляре`; } catch (e) { note = ', метку поставить не удалось: ' + e.message; } }
        st.innerHTML = `создана <a href="${esc(r.url)}" target="_blank" rel="noopener" class="lnk">${esc(r.key)}</a>${esc(note)}`;
        btn.textContent = 'Задача создана'; btn.dataset.done = '1'; // повторный клик создал бы дубликат
      } catch (e) { st.textContent = 'ошибка: ' + e.message; }
      if (!btn.dataset.done) btn.disabled = false;
    }
    const CVE_COLS = [['CVE', 'cve'], ['Приоритет', r => r.verdict?.level], ['Вердикт', r => r.verdict?.title], ['Срок, дн', r => r.verdict?.slaDays], ['CVSS MP', r => r.mp?.score], ['CVSS 3.1', r => r.nvd?.cvss31?.score], ['CVSS 4.0', r => r.nvd?.cvss40?.score], ['EPSS %', r => r.epss?.epss != null ? +(r.epss.epss * 100).toFixed(1) : ''], ['KEV с', r => r.kev?.dateAdded || ''], ['KEV срок', r => r.kev?.dueDate || ''], ['Трендовая', r => r.mp?.trend ? 'да' : ''], ['Эксплойт', r => r.mp?.exploit ? 'да' : ''], ['SSVC', r => r.nvd?.ssvc ? `${r.nvd.ssvc.exploitation || ''}/${r.nvd.ssvc.automatable || ''}/${r.nvd.ssvc.impact || ''}` : ''], ['БДУ', r => (r.bdu || []).map(b => b.id || b).join(' ')]];
    const cveRows = () => { const r = state.enrich; if (!r) return []; return r.cves.slice().sort((a, b) => (r.results[a].verdict.level > r.results[b].verdict.level ? 1 : -1)).map(c => ({ cve: c, ...r.results[c] })); };
    const renderCves = () => {
        const r = state.enrich; if (!r) return;
        const order = r.cves.slice().sort((a, b) => (r.results[a].verdict.level > r.results[b].verdict.level ? 1 : -1));
        $('c-out').innerHTML = order.map(c => renderCve(c, r.results[c])).join('');
        mountMpBlocks();
        sh.querySelectorAll('#c-out .gh').forEach(a => a.addEventListener('click', async e => {
          e.preventDefault(); a.textContent = 'ищем...';
          // Перерисовываем все карточки целиком: блок «В MaxPatrol», обработчики и снимок сохраняются
          try { const g = await VR.ext('github', { cve: a.dataset.cve }); state.enrich.results[a.dataset.cve].gh = g; cveSnap(); renderCves(); }
          catch (err) { a.textContent = 'GitHub: ' + err.message; }
        }));
    };

    // ── Восстановление снимков всех вкладок (сутки) ──
    restoreSnapshots = async function () {
      const [q, a, x, pj, cw, inv, cv, pt] = await Promise.all(['queue', 'assetRisk', 'excl', 'projects', 'cw', 'inv', 'cve', 'patches'].map(snapLoad));
      if (pt && pt.value.patches) { state.patches = pt.value.patches; $('pt-info').textContent = snapNote(pt.ts); renderPatches(); if (pt.value.detail) { const p = state.patches.patches.find(x => x.patch === pt.value.detail.patch); if (p) { state.patchDetail = pt.value.detail; renderPatchDetail(p, pt.value.detail); } } }
      if (q && q.value.queue) { state.queue = q.value.queue; if (q.value.scope) $('q-scope').value = q.value.scope; if (q.value.minScore != null) $('q-min').value = q.value.minScore; if (q.value.limit) $('q-limit').value = q.value.limit; $('q-csv').disabled = false; $('q-pdql').disabled = false; $('q-info').textContent = snapNote(q.ts); renderQueue(); }
      if (a) { state.assetRisk = a.value; ['a-csv', 'a-kev', 'a-tags'].forEach(i => { $(i).disabled = false; }); $('a-info').textContent = snapNote(a.ts); renderAssets(); }
      if (x) { state.excl = x.value; $('x-info').textContent = snapNote(x.ts); renderExcl(); }
      if (pj) { state.projects = pj.value; $('p-info').textContent = snapNote(pj.ts); renderProjects(); }
      if (cw) { state.cw = cw.value; $('w-info').textContent = snapNote(cw.ts); renderCw(); }
      if (inv) { state.inv = inv.value; $('i-info').textContent = snapNote(inv.ts); renderInv(); }
      if (cv && cv.value.enrich) { state.enrich = cv.value.enrich; state.mpCtx = cv.value.mpCtx || {}; if (cv.value.text) $('c-cves').value = cv.value.text; $('c-info').textContent = snapNote(cv.ts); renderCves(); }
      updateReportButtons();
    };

    // ── Отчеты по вкладкам: HTML (файл), PDF (печать), CSV ──
    const reportData = VR.reports.dataSections;
    const loadedNote = 'В отчёт включены все загруженные данные раздела и открытая детализация. Поиск, фильтры таблицы и ограничения отображения не сокращают экспорт. Незагруженные сведения нужно сначала запросить в интерфейсе.';
    const makeSpec = (title, sections, note = '') => ({ title, subtitle: reportSubtitle(), note: [loadedNote, note].filter(Boolean).join(' '), sections });
    const detailSections = (title, detail) => {
      if (!detail) return [];
      const { enrichment, ...data } = detail;
      return [...reportData(title, data), ...(enrichment ? VR.reports.cveSections(enrichment) : [])];
    };
    const REPORTS = {
      overview: { ready: () => !!state.metrics, name: 'vm_report',
        spec: () => makeSpec('Отчет по процессу управления уязвимостями', [
          ...reportData('Показатели процесса', VR.computeMetrics(state.metrics)),
          ...reportData('Данные снимка', state.metrics)
        ]) },
      queue: { ready: () => !!state.queue, name: 'remediation_queue',
        spec: () => makeSpec('Очередь устранения по решениям', [
          ...reportData('Очередь', state.queue), ...detailSections('Выбранная группа', state.detail)
        ]) },
      patches: { ready: () => !!state.patches, name: 'patches',
        spec: () => makeSpec('Патчи для установки', [
          ...reportData('Патчи', state.patches), ...detailSections('Выбранный патч', state.patchDetail)
        ]) },
      assets: { ready: () => !!state.assetRisk, name: 'asset_risk',
        spec: () => makeSpec('Риск активов', reportData('Риск активов', state.assetRisk)) },
      excl: { ready: () => !!state.excl, name: 'exclusions',
        spec: () => makeSpec('Исключения и принятые риски', reportData('Реестр исключений', state.excl),
          state.excl.items ? '' : 'Старый снимок не содержит полного списка экземпляров. Нажмите «Загрузить реестр», чтобы получить все исключения.') },
      proj: { ready: () => !!state.projects, name: 'projects',
        spec: () => makeSpec('Проекты устранения', reportData('Проекты', state.projects)) },
      cw: { ready: () => !!state.cw, name: () => W_SPEC[state.cw.kind].csvName,
        spec: () => makeSpec(W_SPEC[state.cw.kind].title, [
          ...reportData(W_SPEC[state.cw.kind].title, state.cw.data), ...detailSections('Выбранный пакет образа', state.cw.detail)
        ], state.cw.kind === 'images' && state.cw.data.length >= 500 ? VR.reports.LIMIT_NOTE : '') },
      inv: { ready: () => !!state.inv, name: () => 'inventory_' + state.inv.kind,
        spec: () => makeSpec('Инвентаризация: ' + state.inv.title, reportData(state.inv.title, state.inv.data)) },
      cve: { ready: () => !!state.enrich, name: 'cve_context',
        spec: () => {
          const rows = cveRows();
          const spec = makeSpec('Внешний контекст по CVE', [
            { title: 'Сводка CVE', cols: CVE_COLS, rows },
            ...VR.reports.cveSections(state.enrich, state.mpCtx, state.sla)
          ]);
          spec.kpis = [[rows.length, 'CVE'], [rows.filter(r => r.verdict?.level === 'P0').length, 'P0: немедленно'], [rows.filter(r => r.verdict?.level === 'P1').length, 'P1'], [rows.filter(r => r.kev).length, 'в CISA KEV']];
          return spec;
        } },
    };
    for (const [tab, report] of Object.entries(REPORTS)) {
      const getSpec = report.spec;
      report.spec = () => {
        const spec = getSpec();
        if (tab === 'queue') {
          const groups = state.queue.groups, total = groups.reduce((n, g) => n + g.n, 0);
          spec.kpis = [[groups.length, 'решений'], [total, 'уязвимостей закроют'], [groups.reduce((n, g) => n + g.trend, 0), 'трендовых'], [pct(groups.slice(0, 5).reduce((n, g) => n + g.n, 0), total) + '%', 'закрывают топ-5']];
        } else if (tab === 'patches') {
          const t = state.patches.total;
          spec.kpis = [[t.patchesWithLink ?? t.patches, 'патчей со ссылкой'], [t.vulns, 'уязвимостей закроют'], [t.hosts, 'узлов'], [t.noLinkVulns, 'исправление без ссылки']];
        } else if (tab === 'assets') {
          spec.kpis = ['critical', 'high', 'medium', 'low'].map(z => [(state.assetRisk.byZone.find(v => v.key === z) || {}).n || 0, 'Риск: ' + (SEV_RU[z] || z)]);
        } else if (tab === 'excl') {
          spec.kpis = [[state.excl.total, 'исключено всего'], [state.excl.risky.length, 'сомнительных'], [state.excl.groups.length, 'групп']];
        }
        for (const [id, drill] of Object.entries(state.drills || {})) if (drill.tab === tab && $(id) === drill.element && drill.element.hasChildNodes()) spec.sections.push(...reportData(drill.title, drill.data));
        return spec;
      };
      report.html = () => {
        const spec = report.spec();
        // Сохраняем аналитическое резюме обзора и дополняем его полными данными снимка.
        return tab === 'overview'
          ? reportHtml(state.metrics, VR.config().host || location.hostname).replace('</body>', `<p class="notice">${esc(spec.note)}</p>${VR.reports.sectionsHtml(spec.sections)}${VR.reports.scriptHtml}</body>`)
          : buildReport(spec);
      };
      report.csv = () => VR.reports.csv(report.spec());
    }
    function currentTab() { return sh.querySelector('.tabs button.active')?.dataset.t; }
    updateReportButtons = function () { const r = REPORTS[currentTab()]; const ok = !!(r && r.ready()); ['r-html', 'r-pdf', 'r-csv'].forEach(id => { $(id).disabled = !ok; }); };
    const repName = r => (typeof r.name === 'function' ? r.name() : r.name) + '_' + today();
    $('r-html').addEventListener('click', () => { const r = REPORTS[currentTab()]; if (r && r.ready()) download(repName(r) + '.html', r.html(), 'text/html;charset=utf-8'); });
    $('r-pdf').addEventListener('click', () => { const r = REPORTS[currentTab()]; if (r && r.ready()) printHtml(r.html(), repName(r) + '.html'); });
    $('r-csv').addEventListener('click', () => { const r = REPORTS[currentTab()]; if (r && r.ready()) download(repName(r) + '.csv', r.csv(), 'text/csv;charset=utf-8'); });

    // Настройки
    const S = { epssEnabled: 's-epss', kevEnabled: 's-kev', nvdEnabled: 's-nvd', ghEnabled: 's-gh', sameTabLinks: 's-sametab', nvdApiKey: 's-nvdkey', ghToken: 's-ghtoken', slaCritDays: 's-crit', slaHighDays: 's-high', slaMedDays: 's-med', slaLowDays: 's-low' };
    const fill = s => Object.entries(S).forEach(([k, id]) => { const el = $(id); if (!el) return; if (el.type === 'checkbox') el.checked = k === 'sameTabLinks' ? s[k] !== false : !!s[k]; else el.value = s[k] ?? ''; });
    const read = () => { const o = {}; Object.entries(S).forEach(([k, id]) => { const el = $(id); if (!el) return; o[k] = el.type === 'checkbox' ? el.checked : (el.type === 'number' ? parseInt(el.value) || 0 : el.value.trim()); }); return o; };
    const RW = Object.keys(VR.riskDefaults());
    const fillRw = w => RW.forEach(k => { const el = $('s-rw-' + k); if (el) el.value = w[k]; });
    const readRw = () => { const o = {}; RW.forEach(k => { const el = $('s-rw-' + k); const v = parseFloat(el?.value); if (!isNaN(v)) o[k] = v; }); return o; };
    VR.ext('settings-get').then(s => { state.sla = s; fill(s); fillRw({ ...VR.riskDefaults(), ...(s.riskWeights || {}) }); }).catch(() => {});
    $('s-rw-reset').addEventListener('click', () => fillRw(VR.riskDefaults()));
    VR.ext('bdu-info').then(m => { if (m) $('s-bduinfo').textContent = `импортировано ${fmt(m.rows)} CVE (${new Date(m.ts).toLocaleDateString('ru-RU')})`; }).catch(() => {});
    $('s-save').addEventListener('click', async () => { try { await VR.ext('settings-set', { settings: { ...read(), riskWeights: readRw() } }); $('s-info').textContent = 'сохранено'; } catch (e) { $('s-info').textContent = e.message; } });
    const J = { jiraUrl: 's-jurl', jiraAuth: 's-jauth', jiraUser: 's-juser', jiraToken: 's-jtoken', jiraProject: 's-jproject', jiraIssueType: 's-jtype', jiraLabels: 's-jlabels', jiraTagInstances: 's-jtag' };
    const fillJ = s => Object.entries(J).forEach(([k, id]) => { const el = $(id); if (!el) return; if (el.type === 'checkbox') el.checked = s[k] !== false; else el.value = s[k] ?? ''; });
    const readJ = () => { const o = {}; Object.entries(J).forEach(([k, id]) => { const el = $(id); if (!el) return; o[k] = el.type === 'checkbox' ? el.checked : el.value.trim(); }); return o; };
    VR.ext('settings-get').then(fillJ).catch(() => {});
    $('s-jsave').addEventListener('click', async () => { try { await VR.ext('settings-set', { settings: readJ() }); $('s-jinfo').textContent = 'сохранено'; } catch (e) { $('s-jinfo').textContent = e.message; } });
    $('s-jtest').addEventListener('click', async () => {
      $('s-jinfo').innerHTML = '<span class="spin"></span>проверка';
      try { await VR.ext('settings-set', { settings: readJ() }); const r = await VR.ext('jira-test'); $('s-jinfo').textContent = `подключено: ${r.user}, Jira ${r.version} (${r.deploymentType})`; }
      catch (e) { $('s-jinfo').textContent = e.message; }
    });
    $('s-jprojects').addEventListener('click', async () => {
      $('s-jinfo').innerHTML = '<span class="spin"></span>запрос';
      try { await VR.ext('settings-set', { settings: readJ() }); const list = await VR.ext('jira-projects'); $('s-jinfo').textContent = list.length ? 'проекты: ' + list.slice(0, 25).map(p => `${p.key} (${p.name})`).join(', ') : 'проектов не найдено'; }
      catch (e) { $('s-jinfo').textContent = e.message; }
    });
    $('s-kevref').addEventListener('click', async () => { $('s-kevinfo').textContent = 'загрузка...'; try { const r = await VR.ext('kev-refresh'); $('s-kevinfo').textContent = r.error ? 'ошибка: ' + r.error : `${fmt(r.count)} записей, выпуск ${(r.dateReleased || '').slice(0, 10)}`; } catch (e) { $('s-kevinfo').textContent = e.message; } });
    $('s-bdubtn').addEventListener('click', () => $('s-bdufile').click());
    $('s-bdufile').addEventListener('change', () => {
      const f = $('s-bdufile').files[0]; if (!f) return;
      if (/\.xlsx?$/i.test(f.name)) { $('s-bduinfo').textContent = 'XLSX не поддерживается: сохраните как CSV'; return; }
      $('s-bduinfo').textContent = 'разбор файла...';
      const rd = new FileReader();
      rd.onload = async () => { try { const r = await VR.ext('bdu-import', { map: VR.parseBdu(String(rd.result || '')), source: f.name }); $('s-bduinfo').textContent = `импортировано ${fmt(r.rows)} CVE из ${f.name}`; } catch (e) { $('s-bduinfo').textContent = 'ошибка: ' + e.message; } };
      rd.readAsText(f);
    });
  }

  // ── Запуск ────────────────────────────────────────────────────────────────
  VR.loadConfig().then(() => {
    console.info('[vr] настройки прочитаны, хост', VR.config().host || '(пусто)', 'страница', location.hostname);
    if (!VR.isConfiguredHost()) { console.info('[vr] хост страницы не совпадает с настройками расширения, модуль не активен'); return; }
    let tries = 0;
    const tick = () => { if (ensureMenuItem()) { console.info('[vr] пункт меню "Устранение" добавлен'); return; } if (++tries < 240) setTimeout(tick, 500); else console.warn('[vr] левое меню не найдено за 120 с'); };
    tick();
    // Angular может перерисовать меню: следим и восстанавливаем пункт
    let moQueued = false;
    new MutationObserver(() => {
      if (moQueued) return; moQueued = true;
      requestAnimationFrame(() => {
        moQueued = false;
        const mi = document.getElementById('vr-menu-item');
        if (!mi) ensureMenuItem();
        else { const f = findAnchorItem(); if (f && f.where === 'afterend' && mi.previousElementSibling !== f.el) f.el.insertAdjacentElement('afterend', mi); }
        if (opened) positionRoot();
      });
    }).observe(document.body, { childList: true, subtree: true });
  });
  chrome.storage.onChanged.addListener((ch, area) => { if (area === 'sync' && (ch.host || ch.token || ch.port)) VR.loadConfig(); });
})(window.VR);

import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { parseCsv } from './csv-helper.mjs';
const require = createRequire(import.meta.url);

test.beforeEach(async ({ context, page }) => {
  await context.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
  await page.goto('/tests/uitest/');
  await page.locator('#vr-menu-item').click();
});
async function run(page, id) {
  await page.locator('#' + id).click();
  await expect(page.locator('#' + id)).toBeEnabled();
}
async function download(page, id = 'r-html') {
  const event = page.waitForEvent('download');
  await page.locator('#' + id).click();
  const file = await event;
  return fs.readFileSync(await file.path(), 'utf8');
}
async function printable(page) {
  await page.evaluate(() => {
    window.__printed = '';
    window.open = () => ({ document: { write: text => { window.__printed = text; }, close() {}, querySelectorAll() { return []; } }, focus() {}, print() {} });
  });
  await page.locator('#r-pdf').click();
  return page.evaluate(() => window.__printed);
}
function completeCsv(csv) {
  const rows = parseCsv(csv);
  expect(rows[0]).toEqual(['Раздел', 'Запись', 'Поле', 'Значение']);
  expect(rows.every(r => r.length === 4)).toBe(true);
  return rows;
}

test('CVE: полное обогащение, выбранный экземпляр и GitHub во всех форматах и после восстановления', async ({ page }, testInfo) => {
  await page.evaluate(() => {
    const ext = VR.ext;
    VR.ext = async (op, args) => {
      const result = await ext(op, args);
      if (op === 'enrich') {
        const r = result.results['CVE-2025-49723'];
        r.nvd = { description: 'Описание уязвимости '.repeat(40) + 'КОНЕЦ_ПОЛНОГО_ОПИСАНИЯ', published: '2025-07-08', cvss31: { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }, cwes: ['CWE-787'], refs: [{ url: 'https://vendor.example/advisory?full=1&lang=ru', tags: ['Vendor Advisory'] }] };
        r.epss = { epss: 0.12345678, percentile: 0.99876, date: '2026-09-29' };
        r.kev = { dateAdded: '2026-09-01', dueDate: '2026-09-20', vendor: 'ВЕНДОР_ОБОГАЩЕНИЯ', product: 'Windows', ransomware: 'Known' };
        r.verdict.reasons = ['ПОЛНОЕ_ОБОСНОВАНИЕ_ПРИОРИТЕТА'];
        r.extraSource = { additional: 'НОВОЕ_ПОЛЕ_ОБОГАЩЕНИЯ' };
      }
      return result;
    };
    const detail = VR.instanceDetailContext;
    VR.instanceDetailContext = async item => {
      const ctx = await detail(item);
      ctx.statusLog = [{ status: 'new', comment: 'КОММЕНТАРИЙ_ИСТОРИИ' }];
      ctx.tags = ['proj:export-check'];
      ctx.errors = ['ПРЕДУПРЕЖДЕНИЕ_ИСТОЧНИКА'];
      ctx.urls.card = 'https://mp.example/card/instance';
      return ctx;
    };
  });
  await page.locator('#tab-cve').click();
  await page.locator('#c-cves').fill('CVE-2025-49723');
  await run(page, 'c-run');
  await page.locator('.mp-pick').selectOption({ index: 2 });
  await expect(page.locator('.mp-jira')).toBeVisible();
  await page.locator('#c-out .gh').click();
  await expect(page.locator('#c-out')).toContainText('GitHub:');
  const html = await download(page), csv = await download(page, 'r-csv'), pdfHtml = await printable(page);
  completeCsv(csv);
  const markers = ['КОНЕЦ_ПОЛНОГО_ОПИСАНИЯ', 'ВЕНДОР_ОБОГАЩЕНИЯ', '0.12345678', '0.99876', 'Known', 'CWE-787', 'CVSS:3.1/AV:N/AC:L', 'ПОЛНОЕ_ОБОСНОВАНИЕ_ПРИОРИТЕТА', 'НОВОЕ_ПОЛЕ_ОБОГАЩЕНИЯ', 'КОММЕНТАРИЙ_ИСТОРИИ', 'proj:export-check', 'ПРЕДУПРЕЖДЕНИЕ_ИСТОЧНИКА', 'second.host', '10.0.20348.3207', '10.0.20348.3932', '10.0.20348.5622', 'KB5122882', 'BDU:2025-08330', 'https://github.com/fullhunt/log4j-scan', 'https://mp.example/card/instance', 'Обновите до'];
  for (const result of [html, csv, pdfHtml]) for (const marker of markers) expect(result).toContain(marker);
  expect(html).toContain('href="https://vendor.example/advisory?full=1&amp;lang=ru"');
  await testInfo.attach('Полный HTML CVE', { body: html, contentType: 'text/html' });
  fs.writeFileSync(testInfo.outputPath('cve-export.html'), html);
  await page.waitForTimeout(300); // Снимок тестового хранилища записывается асинхронно.
  await page.reload();
  await page.locator('#vr-menu-item').click();
  await page.locator('#tab-cve').click();
  await expect(page.locator('.mp-jira')).toBeVisible();
  const restored = await download(page);
  for (const marker of markers) expect(restored).toContain(marker);
});

test('Все разделы и подвиды: HTML, печать, общий и локальный CSV', async ({ page }) => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  for (const [tab, button, title, localCsv] of [
    ['overview', 'm-run', 'Отчет по процессу управления уязвимостями'],
    ['queue', 'q-run', 'Очередь устранения по решениям', 'q-csv'],
    ['patches', 'pt-run', 'Патчи для установки', 'pt-csv'],
    ['assets', 'a-run', 'Риск активов', 'a-csv'],
    ['excl', 'x-run', 'Исключения и принятые риски', 'x-csv'],
    ['proj', 'p-run', 'Проекты устранения'],
    ['cw', 'w-images', 'Наборы образов', 'w-csv'],
    ['cw', 'w-imgq', 'Очередь по пакетам образов', 'w-csv'],
    ['cw', 'w-web', 'Уязвимости веб-сайтов', 'w-csv'],
    ['inv', 'i-cover', 'Покрытие активов тегами'],
    ['inv', 'i-tags', 'Теги активов'],
    ['inv', 'i-apply', 'Инвентаризация']
  ]) {
    await test.step(tab + '/' + button, async () => {
      await page.locator('#tab-' + tab).click();
      if (button === 'i-apply') page.once('dialog', d => d.accept());
      await run(page, button);
      expect(await download(page)).toContain(title);
      const csv = await download(page, 'r-csv');
      completeCsv(csv);
      expect(await printable(page)).toContain(title);
      // Метка времени формирования может отличаться на секунду.
      const stable = rows => rows.filter(r => r[2] !== 'Источник и время');
      if (localCsv) expect(stable(completeCsv(await download(page, localCsv)))).toEqual(stable(completeCsv(csv)));
    });
  }
  expect(errors).toEqual([]);
});

test('Выбранные группы, патчи и открытые выборки включены; закрытые выборки убираются', async ({ page }) => {
  await page.locator('#tab-queue').click();
  await run(page, 'q-run');
  await page.locator('#q-out .row-action').first().click();
  await expect(page.locator('#d-csv')).toBeVisible();
  for (const output of [await download(page), await download(page, 'r-csv')]) {
    expect(output).toContain('Выбранная группа');
    expect(output).toContain('EPSS');
    expect(output).toContain('ID экземпляров');
  }
  expect(parseCsv(await download(page, 'd-csv'))[0]).toContain('Узел');
  await page.locator('#tab-patches').click();
  await run(page, 'pt-run');
  await page.locator('#pt-out .row-action').first().click();
  await expect(page.locator('#pt-d-csv')).toBeVisible();
  for (const output of [await download(page), await download(page, 'r-csv'), await download(page, 'pt-d-csv')]) {
    expect(output).toContain('CVE-2025-49723');
    expect(output).toContain('a.plat.form');
    expect(output).toContain('EPSS');
    expect(output).toContain('Несанкционированные операции');
  }
  expect(await download(page)).toContain('Исправления без ссылки на патч');
  await page.locator('#pt-d-close').click();
  expect(await download(page)).not.toContain('Выбранный патч');
  await page.locator('#tab-proj').click();
  await run(page, 'p-run');
  await page.locator('#p-out .row-action').first().click();
  await expect(page.locator('#p-drill table')).toBeVisible();
  const title = (await page.locator('#p-drill h3').innerText()).replace('×', '').trim();
  expect(await download(page)).toContain(title);
  expect(await download(page, 'r-csv')).toContain(title);
  await page.locator('#p-drill .x').click();
  expect(await download(page)).not.toContain(title);
  await page.locator('#tab-cw').click();
  await run(page, 'w-imgq');
  await page.locator('#w-out .row-action').first().click();
  await expect(page.locator('#w-drill table').first()).toBeVisible();
  expect(await download(page)).toContain('Выбранный пакет образа');
  await page.locator('#w-drill .x').click();
  expect(await download(page)).not.toContain('Выбранный пакет образа');
});

test('Более 1000 загруженных строк: последняя запись есть в HTML, CSV и печати', async ({ page }) => {
  await page.evaluate(() => {
    VR.webVulns = async () => ({ sites: [{ site: 'FULL_SITE_SUMMARY', n: 1105 }], items: Array.from({ length: 1105 }, (_, i) => ({ site: 'example.test', name: 'WEB_RECORD_' + i, cve: 'CVE-2026-12345', score: 5, sev: 'medium', st: 'new', found: '2026-09-29', extra: i === 1104 ? 'LAST_EXTRA_VALUE' : '' })), truncated: true, pdql: 'WEB_QUERY' });
  });
  await page.locator('#tab-cw').click();
  await run(page, 'w-web');
  for (const output of [await download(page), await download(page, 'r-csv'), await printable(page)]) {
    for (const marker of ['WEB_RECORD_1104', 'LAST_EXTRA_VALUE', 'FULL_SITE_SUMMARY', 'Достигнут лимит запроса']) expect(output).toContain(marker);
  }
});

test('Удалённый тег исчезает из экспорта и восстановленного снимка', async ({ page }) => {
  await page.locator('#tab-inv').click();
  await run(page, 'i-tags');
  expect(await download(page)).toContain('auto:os-windows');
  page.once('dialog', d => d.accept());
  await page.locator('.i-del').click();
  await expect(page.locator('.i-del')).toHaveCount(0);
  expect(await download(page)).not.toContain('auto:os-windows');
  expect(await download(page, 'r-csv')).not.toContain('auto:os-windows');
  await page.waitForTimeout(300);
  await page.reload();
  await page.locator('#vr-menu-item').click();
  await page.locator('#tab-inv').click();
  await expect(page.locator('#r-html')).toBeEnabled();
  expect(await download(page)).not.toContain('auto:os-windows');
});

test('CSV штатной карточки актива: все строки и поля, многострочный текст, безопасные формулы', async ({ page }) => {
  await page.locator('#close').click();
  await page.evaluate(() => {
    history.replaceState(null, '', '?assetId=11111111-1111-1111-1111-111111111111');
    const card = document.createElement('div');
    card.attachShadow({ mode: 'open' }).innerHTML = '<section><h2>Уязвимости ОС и ПО</h2></section>';
    document.querySelector('main').append(card);
    chrome.runtime.getURL = path => '/' + path;
    VR.pdql = async () => ({ records: [
      { '@Host': { name: 'native-host', id: 'host-id' }, Name: 'Полное имя; с кавычкой " и\r\nновой строкой', Ids: 'ID-1', CVE: 'CVE-2026-12345', Score: 9.8, Sev: 'critical', St: 'new', Found: '2026-09-29', Trend: true, Expl: true, HasPatch: true, PatchLink: 'https://vendor.example/patch', FixType: 'Обновить', Impact: 'Последствия полностью' },
      { '@Host': { name: 'native-host' }, Name: '=HYPERLINK("test")', CVE: 'CVE-2026-54321', St: 'fixed' }
    ] });
  });
  await page.addScriptTag({ url: '/content/cards.js' });
  const event = page.waitForEvent('download');
  await page.locator('.vr-asset-export [data-act=csv]').click();
  const file = await event, rows = parseCsv(fs.readFileSync(await file.path(), 'utf8'));
  expect(rows).toHaveLength(3);
  expect(rows[1]).toContain('Полное имя; с кавычкой " и\nновой строкой');
  expect(rows[1]).toContain('https://vendor.example/patch');
  expect(rows[1]).toContain('Последствия полностью');
  expect(rows[2]).toContain('\'=HYPERLINK("test")');
  expect(rows[2]).toContain('fixed');
  expect(rows.every(r => r.length === rows[0].length)).toBe(true);
});

test('HTML: свёрнутые группы CVE, клавиатура, общие кнопки и полный PDF с восстановлением состояния', async ({ page, context }, testInfo) => {
  await page.locator('#tab-cve').click();
  await page.locator('#c-cves').fill('CVE-2025-49723');
  await run(page, 'c-run');
  await page.locator('.mp-pick').selectOption({ index: 1 });
  await expect(page.locator('.mp-jira')).toBeVisible();
  const html = await download(page);
  const report = await context.newPage();
  await report.setContent(html);
  const sections = report.locator('details.report-section'), roots = report.locator('body > details.report-section');
  const total = await sections.count();
  expect(total).toBeGreaterThan(10);
  expect(await roots.count()).toBeLessThan(6);
  await expect(report.locator('details[open]')).toHaveCount(0);
  await expect(report.locator('.kpis')).toBeVisible();
  expect(await report.locator('table').evaluateAll(els => els.every(el => !el.checkVisibility()))).toBe(true);
  await report.screenshot({ path: testInfo.outputPath('report-collapsed.png'), fullPage: true });

  const group = roots.filter({ has: report.locator('summary > h2', { hasText: /^CVE-2025-49723$/ }) });
  const summary = group.locator(':scope > summary');
  await summary.focus(); await report.keyboard.press('Enter');
  await expect(group).toHaveAttribute('open', '');
  await report.keyboard.press('Space');
  await expect(group).not.toHaveAttribute('open');
  await report.getByRole('button', { name: 'Раскрыть всё', exact: true }).click();
  await expect(report.locator('details[open]')).toHaveCount(total);
  expect(await report.locator('table').evaluateAll(els => els.every(el => el.checkVisibility()))).toBe(true);
  await report.getByRole('button', { name: 'Свернуть всё', exact: true }).click();
  await expect(report.locator('details[open]')).toHaveCount(0);
  await summary.click();
  await group.locator('.report-section > summary').first().click();
  await report.addScriptTag({ path: require.resolve('axe-core/axe.min.js') });
  expect(await report.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })).violations.map(v => v.id))).toEqual([]);
  await report.setViewportSize({ width: 390, height: 844 });
  expect(await report.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await report.setViewportSize({ width: 1120, height: 1000 });
  await report.screenshot({ path: testInfo.outputPath('report-expanded.png') });
  const before = await sections.evaluateAll(els => els.map(e => e.open));
  await report.evaluate(() => {
    addEventListener('beforeprint', () => { window.__allVisibleAtPrint = [...document.querySelectorAll('details')].every(e => e.open); });
  });
  await report.pdf({ path: testInfo.outputPath('report-full.pdf'), printBackground: true, preferCSSPageSize: true });
  expect(await report.evaluate(() => window.__allVisibleAtPrint)).toBe(true);
  expect(await sections.evaluateAll(els => els.map(e => e.open))).toEqual(before);
  fs.writeFileSync(testInfo.outputPath('report.html'), html);
  await report.close();
});

test('Обзор: аналитические разделы сворачиваются; печать работает при блокировке скрипта отчёта', async ({ page, context }) => {
  await run(page, 'm-run');
  const report = await context.newPage();
  const html = await download(page);
  await report.setContent(html);
  await expect(report.locator('.kpis')).toBeVisible();
  await expect(report.locator('details[open]')).toHaveCount(0);
  const section = report.locator('details').filter({ has: report.locator('summary > h2', { hasText: 'Просрочки по уровню опасности' }) });
  await section.locator('summary').click();
  await expect(section.locator('table')).toBeVisible();
  await report.close();
  // Имитируем унаследованную CSP MaxPatrol в окне печати.
  await page.evaluate(() => {
    const open = window.open;
    window.open = (...args) => {
      const popup = open(...args), write = popup.document.write.bind(popup.document);
      popup.document.write = html => write(html.replace('<head>', '<head><meta http-equiv="Content-Security-Policy" content="script-src \'none\'">'));
      popup.print = () => { window.__allPrinted = popup.document.querySelectorAll('details').length > 0 && [...popup.document.querySelectorAll('details')].every(e => e.open); };
      return popup;
    };
  });
  const opened = page.waitForEvent('popup');
  await page.locator('#r-pdf').click();
  const popup = await opened;
  await expect.poll(() => page.evaluate(() => window.__allPrinted)).toBe(true);
  await expect(popup.locator('.report-actions')).toBeHidden();
  expect(await popup.locator('table').evaluateAll(els => els.every(el => el.checkVisibility()))).toBe(true);
  // Без скрипта сохраняется стандартное раскрытие details/summary.
  const first = popup.locator('details').first();
  await first.locator(':scope > summary').click();
  await expect(first).not.toHaveAttribute('open');
  await first.locator(':scope > summary').click();
  await expect(first).toHaveAttribute('open', '');
  await popup.close();
});

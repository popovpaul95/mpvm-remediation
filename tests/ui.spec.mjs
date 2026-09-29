// Все операции MaxPatrol/Jira заменены моками в tests/uitest/index.html.
// Для проверки нужны локальные fixtures.json; см. раздел «Тесты» в README.
import { test, expect } from '@playwright/test';
import { createRequire } from 'node:module';
import fs from 'node:fs';
const require = createRequire(import.meta.url);
const axePath = require.resolve('axe-core/axe.min.js');

async function openWorkspace(page, theme = 'light') {
  await page.goto(`/tests/uitest/?theme=${theme}`);
  await page.locator('#vr-menu-item').click();
}
async function run(page, id) {
  await page.locator(`#${id}`).click();
  await expect(page.locator(`#${id}`)).toBeEnabled();
}
async function audit(page, selector = '#vr-root') {
  await page.addScriptTag({ path: axePath });
  const violations = await page.evaluate(async selector => {
    const result = await axe.run(selector ? document.querySelector(selector) : document, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] }
    });
    return result.violations.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) }));
  }, selector);
  expect(violations).toEqual([]);
}
async function noPageOverflow(page) {
  const dimensions = await page.locator('.body').evaluate(e => [e.clientWidth, e.scrollWidth]);
  expect(dimensions[1]).toBeLessThanOrEqual(dimensions[0]);
}

test.beforeEach(async ({ context }) => {
  // Защита от случайного обращения к реальному серверу из теста.
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
});

for (const theme of ['light', 'dark']) {
  test(`Все разделы: тема ${theme}, доступность и адаптивность`, async ({ page }) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await openWorkspace(page, theme);
    await expect(page.locator('#m-out .empty-state')).toBeVisible();
    const tabs = [
      ['overview', 'm-run', '#m-out .kpi'], ['queue', 'q-run', '#q-out table'],
      ['patches', 'pt-run', '#pt-out table'],
      ['assets', 'a-run', '#a-out table'], ['excl', 'x-run', '#x-out table'],
      ['proj', 'p-run', '#p-out table'], ['cw', 'w-images', '#w-out table'],
      ['inv', null, '#i-rules .grp'], ['cve', 'c-run', '#c-out .cve'], ['settings', null, '#s-save']
    ];
    for (const [name, action, ready] of tabs) {
      await test.step(name, async () => {
        await page.locator(`#tab-${name}`).click();
        if (action) await run(page, action);
        await expect(page.locator(ready).first()).toBeVisible();
        await audit(page);
        await noPageOverflow(page);
      });
    }
    await page.locator('#tab-queue').click();
    await page.locator('#q-out .row-action').first().click();
    await expect(page.locator('#d-apply')).toBeVisible();
    await audit(page);
    await page.locator('#tab-proj').click();
    await page.locator('#p-out .row-action').first().click();
    await expect(page.locator('#p-drill table')).toBeVisible();
    await audit(page);
    await page.locator('#tab-patches').click();
    await page.locator('#pt-out .row-action').first().click();
    await expect(page.locator('#pt-d-apply')).toBeVisible();
    await audit(page);
    await page.getByLabel('Новый статус', { exact: true }).selectOption('SwitchToAwaitingFixStateCommand');
    await expect(page.getByLabel('Исправить до', { exact: true })).toBeVisible();
    await audit(page);
    await page.locator('#tab-cve').click();
    await page.locator('.mp-pick').first().selectOption({ index: 1 });
    await expect(page.locator('.mp-jira').first()).toBeVisible();
    await audit(page);
    for (const width of [1280, 1024, 768]) {
      await page.setViewportSize({ width, height: 900 });
      for (const name of ['overview', 'queue', 'patches', 'settings', 'inv', 'cve']) {
        await page.locator(`#tab-${name}`).click();
        await noPageOverflow(page);
      }
    }
    expect(errors).toEqual([]);
  });
}

test('Клавиатура, фильтры, экспорт, сохранение снимка при ошибке', async ({ page }) => {
  await openWorkspace(page);
  await page.locator('#tab-overview').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#tab-queue')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('End');
  await expect(page.locator('#tab-settings')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Home');
  await expect(page.locator('#tab-overview')).toHaveAttribute('aria-selected', 'true');
  await run(page, 'm-run');
  await page.locator('#m-out [data-drill="overdue"]').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#m-drill table')).toBeVisible();
  await page.locator('#m-drill .x').click();
  await page.locator('#tab-queue').click();
  await run(page, 'q-run');
  const rows = page.locator('#q-out tr.hasf');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
  const search = page.locator('#q-out .tfilter input');
  await search.fill('NO_SUCH_PRODUCT_93847');
  await expect(page.locator('#q-out .table-empty')).toBeVisible();
  await search.fill('');
  await expect(page.locator('#q-out .table-empty')).toBeHidden();
  const header = page.locator('#q-out th').nth(2);
  await header.focus();
  await page.keyboard.press('Enter');
  await expect(header).toHaveAttribute('aria-sort', 'ascending');
  await page.keyboard.press('Enter');
  await expect(header).toHaveAttribute('aria-sort', 'descending');
  const filter = page.locator('#q-out th .vf').first();
  await filter.click();
  const rect = await page.locator('.vf-pop').boundingBox();
  const workspace = await page.locator('#vr-root').boundingBox();
  expect(rect.x).toBeGreaterThanOrEqual(workspace.x);
  expect(rect.x + rect.width).toBeLessThanOrEqual(1600);
  expect(rect.y + rect.height).toBeLessThanOrEqual(1100);
  await page.locator('.vf-pop [data-a=none]').click();
  await page.locator('.vf-pop [data-a=ok]').click();
  await expect(page.locator('#q-out tr.hasf:not(.hide)')).toHaveCount(0);
  await expect(page.locator('#q-out .vf-chips')).toContainText('Нет значений');
  await filter.click();
  await expect(page.locator('.vf-pop input[type=checkbox]:checked')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(filter).toBeFocused();
  await page.locator('#q-out .vf-chips .clr').click();
  await expect(page.locator('#q-out tr.hasf:not(.hide)')).toHaveCount(count);
  await page.locator('#q-out .row-action').first().focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#d-apply')).toBeVisible();
  await page.locator('#tab-overview').click();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#r-html').click();
  const download = await downloadPromise;
  const html = fs.readFileSync(await download.path(), 'utf8');
  expect(html).toContain('<table>');
  expect(html).toContain('Отчет по процессу управления уязвимостями');
  await page.locator('#close').click();
  await expect(page.locator('#vr-menu-item')).toBeFocused();
  await page.locator('#vr-menu-item').click();
  await expect(page.locator('#m-out .kpi')).toHaveCount(12);
  await page.locator('#tab-settings').click();
  await page.locator('#s-save').click();
  await expect(page.locator('#s-info')).toHaveText('сохранено');
  await page.locator('#tab-overview').click();
  await page.evaluate(() => { window.VR.metrics = async () => { throw new Error('Сервер недоступен. Повторите запрос.'); }; });
  await run(page, 'm-run');
  await expect(page.locator('#m-err')).toContainText('Сервер недоступен');
  await expect(page.locator('#m-out .kpi')).toHaveCount(12);
});

test('Popup: светлая и тёмная тема, валидация, сохранение', async ({ page }) => {
  await page.addInitScript(() => {
    const local = {}, sync = {};
    window.chrome = {
      storage: {
        sync: { get: (keys, cb) => cb(sync), set: (data, cb) => { Object.assign(sync, data); cb?.(); } },
        local: { get: (keys, cb) => cb(local), set: data => Object.assign(local, data), remove: key => delete local[key] }
      }, tabs: { query: (q, cb) => cb([]) }, runtime: {}
    };
    window.fetch = async () => ({ ok: true, status: 200, json: async () => ({ productVersion: '28.0 (мок)' }) });
  });
  await page.goto('/popup.html');
  await audit(page, null);
  await page.locator('#save').click();
  await expect(page.locator('#host')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#host')).toBeFocused();
  await page.locator('#host').fill('demo.example');
  await page.locator('#token').fill('test-only');
  await page.locator('#port').fill('99999');
  await page.locator('#save').click();
  await expect(page.locator('#port')).toBeFocused();
  await page.locator('#port').fill('');
  await page.locator('#save').click();
  await expect(page.locator('#st')).toHaveClass('st ok');
  await page.locator('#test').click();
  await expect(page.locator('#st')).toContainText('Подключено');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('html')).toHaveClass('kbq-dark');
  await audit(page, null);
});

test('Внешний контекст штатной карточки: CVE из CISA KEV', async ({ page }) => {
  await page.goto('/tests/uitest/?theme=light');
  await page.locator('#vr-menu-item').waitFor();
  await page.evaluate(() => {
    document.querySelector('main').innerHTML = '<div class="vulner__primary-info"><h1 class="vulner__title">CVE-2021-44228</h1><section class="vulner-info-section"><h2 class="vulner-info-section__title">Описание</h2><p>Тестовая карточка уязвимости</p></section><section class="vulner-info-section"><h2 class="vulner-info-section__title">Ссылки</h2><p>Источники</p></section></div>';
    chrome.runtime.getURL = path => '/' + path;
  });
  await page.addScriptTag({ url: '/content/cards.js' });
  await page.locator('.vr-cb [data-act=enrich]').click();
  await expect(page.locator('.vr-cb [data-role=out]')).toContainText('CISA KEV');
  await expect(page.locator('.vr-cb .vr-err')).toHaveCount(0);
  await expect(page.locator('.vr-cb .kev')).toHaveAttribute('href', /CVE-2021-44228/);
});

test('Опасные действия: отмена ничего не отправляет, подтверждение отправляет один раз', async ({ page }) => {
  await openWorkspace(page);
  await page.evaluate(() => {
    window.__calls = { status: [], tags: [] };
    const s = window.VR.changeStatus; window.VR.changeStatus = async a => { window.__calls.status.push({ command: a.command, n: a.ids.length }); await new Promise(r => setTimeout(r, 400)); return s(a); };
    const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__calls.tags.push({ n: ids.length, tag }); return t(ids, tag); };
  });
  await page.locator('#tab-queue').click();
  await run(page, 'q-run');
  await page.locator('#q-out .row-action').first().click();
  await expect(page.locator('#d-apply')).toBeVisible();
  page.once('dialog', d => d.dismiss());
  await page.locator('#d-apply').click();
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__calls.status.length)).toBe(0);
  await page.locator('#d-cmd').selectOption('SwitchToInProgressStateCommand');
  page.once('dialog', d => d.accept());
  await page.locator('#d-apply').click();
  await expect(page.locator('#d-apply')).toBeDisabled();
  await page.locator('#d-apply').click({ force: true, timeout: 500 }).catch(() => {});
  await expect(page.locator('#d-st')).toContainText('готово');
  const calls = await page.evaluate(() => window.__calls.status);
  expect(calls).toHaveLength(1);
  expect(calls[0].command).toBe('SwitchToInProgressStateCommand');
  expect(calls[0].n).toBeGreaterThan(0);
  page.once('dialog', d => d.dismiss());
  await page.locator('#d-proj').click();
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__calls.tags.length)).toBe(0);
  page.once('dialog', d => d.accept('test-proj'));
  await page.locator('#d-proj').click();
  await expect(page.locator('#d-proj-st')).toContainText('proj:test-proj');
  const tags = await page.evaluate(() => window.__calls.tags);
  expect(tags).toHaveLength(1);
  expect(tags[0].tag).toBe('proj:test-proj');
});

test('CVE-контекст: экземпляры из MaxPatrol, выбор актива, задача Jira на экземпляр', async ({ page }) => {
  await openWorkspace(page);
  await page.evaluate(() => { window.__jira = []; const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__jira.push({ ids, tag }); return t(ids, tag); }; });
  await page.locator('#tab-cve').click();
  await page.locator('#c-cves').fill('CVE-2025-49723');
  await run(page, 'c-run');
  const mp = page.locator('#c-out .cve[data-cve="CVE-2025-49723"] .mp');
  await expect(mp.locator('.mp-summary')).toContainText('экземпляров на 2 узлах');
  await expect(mp.locator('.mp-summary b').first()).toHaveText('2');
  await expect(mp.locator('.mp-jira')).toHaveCount(0);
  await mp.locator('.mp-pick').selectOption({ index: 1 });
  await expect(mp).toContainText('Целевая версия');
  await expect(mp).toContainText('не ниже 10.0.20348.3932');
  await expect(mp).toContainText('рекомендуется 10.0.20348.5622');
  await expect(mp).toContainText('KB5122882');
  await expect(mp).toContainText('BDU:2025-08330');
  await expect(mp).toContainText('Версия ядра 10.0.20348.3207');
  page.once('dialog', d => d.dismiss());
  await mp.locator('.mp-jira').click();
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__jira.length)).toBe(0);
  page.once('dialog', d => d.accept());
  await mp.locator('.mp-jira').click();
  await expect(mp.locator('[data-role=mp-jira-st]')).toContainText('создана');
  await expect(mp.locator('[data-role=mp-jira-st]')).toContainText('jira:VM-101');
  const calls = await page.evaluate(() => window.__jira);
  expect(calls).toHaveLength(1);
  expect(calls[0].ids).toEqual(['1e5566a8e0c000010000000000000012_1e5566a8e0c000010000000000000012_1e1e0794348140010000000000052b21']);
  // «PoC на GitHub?» не теряет блок MaxPatrol, приоритет и обработчики
  await page.locator('#c-out .cve[data-cve="CVE-2025-49723"] .gh').click();
  await expect(page.locator('#c-out .cve[data-cve="CVE-2025-49723"]')).toContainText('GitHub:');
  await expect(mp).toContainText('Целевая версия');
  await expect(page.locator('#c-out .cve[data-cve="CVE-2025-49723"] .hd .badge')).toHaveCount(1);
  await expect(mp.locator('.mp-jira')).toHaveCount(1);
  await page.waitForTimeout(500); // мок хранилища пишет снимок с задержкой
  await page.reload();
  await page.locator('#vr-menu-item').click();
  await page.locator('#tab-cve').click();
  await expect(page.locator('#c-out .cve[data-cve="CVE-2025-49723"] .mp')).toContainText('Целевая версия');
  await expect(page.locator('#c-out .cve[data-cve="CVE-2025-49723"]')).toContainText('GitHub:');
  // без экземпляров MP VM: блока нет, обогащение быстрее
  await expect(page.locator('#c-cves')).toHaveValue('CVE-2025-49723');
  await page.locator('#c-skipmp').check();
  await run(page, 'c-run');
  await expect(page.locator('#c-out .cve[data-cve="CVE-2025-49723"] .mp')).toBeEmpty();
});

test('Патчи: список со ссылками, детали с узлами и CVE, задача Jira и смена статуса с подтверждением', async ({ page }) => {
  await openWorkspace(page);
  await page.evaluate(() => { window.__calls = { status: [], tags: [], jira: [] }; const s = window.VR.changeStatus; window.VR.changeStatus = async a => { window.__calls.status.push({ command: a.command, n: a.ids.length }); return s(a); }; const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__calls.tags.push({ n: ids.length, tag }); return t(ids, tag); }; });
  await page.locator('#tab-patches').click();
  await expect(page.locator('#pt-sum .empty-state')).toBeVisible();
  await run(page, 'pt-run');
  await expect(page.locator('#pt-sum .kpi')).toHaveCount(4);
  await expect(page.locator('#pt-sum')).toContainText('776 255');
  const rows = page.locator('#pt-out tr.click');
  await expect(rows).toHaveCount(3);
  await expect(rows.first()).toContainText('KB5122876');
  await expect(rows.first().locator('a.lnk')).toHaveAttribute('href', /KB5122876/);
  await expect(page.locator('#pt-out table tr').last()).toContainText('ссылка не указана');
  await rows.first().locator('.row-action').click();
  await expect(page.locator('#pt-detail .detail-facts')).toContainText('Экземпляров: 3');
  await expect(page.locator('#pt-detail table')).toHaveCount(2);
  await expect(page.locator('#pt-detail')).toContainText('CVE-2025-49723');
  await expect(page.locator('#pt-detail a[href*="pdqlQuery"]')).toHaveCount(1);
  page.once('dialog', d => d.dismiss());
  await page.locator('#pt-d-jira').click();
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.__calls.tags.length)).toBe(0);
  page.once('dialog', d => d.accept());
  await page.locator('#pt-d-jira').click();
  await expect(page.locator('#pt-d-jira-st')).toContainText('VM-101');
  expect(await page.evaluate(() => window.__calls.tags)).toEqual([{ n: 3, tag: 'jira:VM-101' }]);
  page.once('dialog', d => d.accept());
  await page.locator('#pt-d-apply').click();
  await expect(page.locator('#pt-d-st')).toContainText('готово');
  expect(await page.evaluate(() => window.__calls.status)).toEqual([{ command: 'SwitchToInProgressStateCommand', n: 3 }]);
  await page.locator('#tab-patches').click();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#r-csv').click();
  const dl = await downloadPromise;
  expect(fs.readFileSync(await dl.path(), 'utf8')).toContain('KB5122876');
});


test('Патчи: сортировка без ссылки, поиск, клавиатура и возврат к выбранной строке', async ({ page }) => {
  await openWorkspace(page);
  await page.locator('#tab-patches').click();
  await run(page, 'pt-run');
  const table = page.locator('#pt-out table');
  await expect(table).not.toContainText('undefined');
  const header = table.locator('th').nth(3);
  await header.focus(); await page.keyboard.press('Enter');
  await expect(table.locator('tr.hasf').first()).toContainText('libcurl4');
  await expect(table.locator('tr.hasf').last()).toContainText('ссылка не указана');
  await page.keyboard.press('Enter');
  await expect(table.locator('tr.hasf').first()).toContainText('ссылка не указана');
  await page.locator('#pt-out .tfilter input').fill('5122882');
  await expect(table.locator('tr.hasf:not(.hide)')).toHaveCount(1);
  const patch = table.locator('tr:not(.hide) .row-action');
  await patch.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#pt-d-title')).toBeFocused();
  await expect(patch).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#pt-d-date')).toBeHidden();
  await page.locator('#pt-d-cmd').selectOption('SwitchToAwaitingFixStateCommand');
  await expect(page.locator('#pt-d-date')).toBeVisible();
  await page.locator('#pt-d-cmd').selectOption('SwitchToNewStateCommand');
  await expect(page.locator('#pt-d-date')).toBeHidden();
  await page.locator('#pt-d-close').click();
  await expect(page.locator('#pt-detail')).toBeHidden();
  await expect(patch).toBeFocused();
  await expect(patch).toHaveAttribute('aria-expanded', 'false');
});

test('Патчи: актуальный выбор при задержке ответа, ошибка с повтором и пустой список', async ({ page }) => {
  await openWorkspace(page);
  await page.locator('#tab-patches').click();
  await run(page, 'pt-run');
  await page.evaluate(() => {
    const original = VR.patchDetail;
    window.__patchRequests = [];
    window.__finishPatch = async name => {
      const request = window.__patchRequests.find(r => r.name === name);
      request.resolve(await original({ patch: name }));
    };
    VR.patchDetail = ({ patch }) => new Promise(resolve => window.__patchRequests.push({ name: patch, resolve }));
  });
  const rows = page.locator('#pt-out tr.click');
  const firstName = await rows.nth(0).getAttribute('data-patch');
  const secondName = await rows.nth(1).getAttribute('data-patch');
  await rows.nth(0).locator('.row-action').click();
  await rows.nth(1).locator('.row-action').click();
  await page.evaluate(name => window.__finishPatch(name), secondName);
  await expect(page.locator('#pt-d-title')).toContainText(secondName);
  await page.evaluate(name => window.__finishPatch(name), firstName);
  await expect(page.locator('#pt-d-title')).toContainText(secondName);
  await expect(rows.nth(1)).toHaveClass(/sel/);
  await page.evaluate(() => { VR.patchDetail = async () => { throw new Error('Сервер недоступен'); }; });
  await rows.nth(0).locator('.row-action').click();
  await expect(page.locator('#pt-detail [role=alert]')).toContainText('Сервер недоступен');
  await page.evaluate(() => { VR.patchDetail = async ({ patch }) => ({ patch, rows: 0, ids: [], hosts: [], cves: [], vulns: [], pdql: '' }); });
  await page.locator('#pt-retry').click();
  await expect(page.locator('#pt-d-title')).toContainText(firstName);
  await expect(page.locator('#pt-detail .table-empty')).toHaveCount(2);
  await page.evaluate(() => { VR.patches = async () => ({ patches: [], noLink: null, total: { patches: 0, vulns: 0, hosts: 0, noLinkVulns: 0, noLinkHosts: 0 }, pdql: '' }); });
  await run(page, 'pt-run');
  await expect(page.locator('#pt-detail')).toBeHidden();
  await expect(page.locator('#pt-out .table-empty')).toBeVisible();
  await expect(page.locator('#pt-sum .inline-notice')).toHaveCount(0);
  await audit(page);
});

test('Экземпляр CVE: доступная загрузка, ошибка и сохранение фокуса при повторном выборе', async ({ page }) => {
  await openWorkspace(page);
  await page.locator('#tab-cve').click();
  await page.locator('#c-cves').fill('CVE-2025-49723');
  await run(page, 'c-run');
  await page.evaluate(() => {
    const original = VR.instanceDetailContext;
    window.__instanceRequests = [];
    VR.instanceDetailContext = item => new Promise((resolve, reject) => window.__instanceRequests.push({ item, resolve, reject }));
    window.__finishInstance = async () => {
      const request = window.__instanceRequests.at(-1); request.resolve(await original(request.item));
    };
  });
  const picker = page.locator('.mp-pick');
  await picker.focus(); await picker.selectOption({ index: 1 });
  await expect(picker).toBeDisabled();
  await expect(page.locator('[data-role=mp-st]')).toContainText('Загружаем');
  await expect(page.locator('.mp-jira')).toHaveCount(0);
  await page.evaluate(() => window.__instanceRequests.at(-1).reject(new Error('Ошибка соединения')));
  await expect(picker).toBeEnabled(); await expect(picker).toBeFocused();
  await expect(page.locator('[data-role=mp-st]')).toContainText('Ошибка соединения');
  await picker.selectOption({ index: 2 });
  await page.evaluate(() => window.__finishInstance());
  await expect(page.locator('.mp-section').first()).toContainText('second.host');
  await expect(picker).toBeFocused();
  await expect(page.locator('.mp-jira')).toHaveCount(1);
  await audit(page);
});


test('Патчи: закрытие панели во время операции не обновляет другой патч', async ({ page }) => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await openWorkspace(page);
  await page.locator('#tab-patches').click(); await run(page, 'pt-run');
  await page.locator('#pt-out .row-action').first().click();
  await expect(page.locator('#pt-d-apply')).toBeVisible();
  await page.evaluate(() => { VR.changeStatus = () => new Promise(resolve => { window.__completeStatus = resolve; }); });
  page.once('dialog', d => d.accept());
  await page.locator('#pt-d-apply').click();
  await expect(page.locator('#pt-d-apply')).toBeDisabled();
  await page.locator('#pt-d-close').click();
  await page.locator('#pt-out .row-action').nth(1).click();
  await expect(page.locator('#pt-d-title')).toContainText('KB5122882');
  await page.evaluate(() => window.__completeStatus({ done: true, total: 3, succeed: 3 }));
  await expect(page.locator('#pt-d-st')).toBeEmpty();
  await expect(page.locator('#pt-d-apply')).toBeEnabled();
  expect(errors).toEqual([]);
});

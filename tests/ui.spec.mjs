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

test('Popup: несколько серверов, миграция старых настроек, валидация, черновик, темы', async ({ page }) => {
  await page.addInitScript(() => {
    // Хранилище переживает перезагрузку окна (как настоящее chrome.storage): держим его в sessionStorage
    const store = name => ({ read: () => JSON.parse(sessionStorage.getItem(name) || 'null'), write: v => sessionStorage.setItem(name, JSON.stringify(v)) });
    const S = store('sync'), L = store('local');
    if (!S.read()) S.write({ host: 'legacy.example', port: '', token: 'legacy-token' });
    if (!L.read()) L.write({});
    Object.defineProperty(window, '__sync', { get: () => S.read() });
    window.chrome = {
      storage: {
        sync: { get: (keys, cb) => cb(S.read()), set: (data, cb) => { S.write({ ...S.read(), ...data }); cb?.(); }, remove: (keys, cb) => { const v = S.read(); keys.forEach(k => delete v[k]); S.write(v); cb?.(); } },
        local: { get: (keys, cb) => cb(L.read()), set: data => L.write({ ...L.read(), ...data }), remove: key => { const v = L.read(); delete v[key]; L.write(v); } }
      }, tabs: { query: (q, cb) => cb(q.active ? [{ url: 'https://second.example/#/assets' }] : []) }, runtime: {}
    };
    window.fetch = async url => ({ ok: true, status: 200, json: async () => ({ productVersion: url.includes('second.example') ? '27.6 (мок)' : '28.0 (мок)' }) });
  });
  await page.goto('/popup.html');
  await audit(page, null);
  // Старые ключи host/token показаны как единственный сервер, кнопки удаления у единственного нет
  await expect(page.locator('.srv')).toHaveCount(1);
  await expect(page.locator('#host-0')).toHaveValue('legacy.example');
  await expect(page.locator('#token-0')).toHaveValue('legacy-token');
  await expect(page.locator('#del-0')).toBeHidden();
  // Второй сервер: валидация пустых полей, порта и дубликата адреса
  await page.locator('#add').click();
  await expect(page.locator('.srv')).toHaveCount(2);
  await expect(page.locator('#host-1')).toBeFocused();
  await page.locator('#save').click();
  await expect(page.locator('#host-1')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#st')).toContainText('Сервер 2');
  await page.locator('#host-1').fill('https://Legacy.example/');
  await page.locator('#token-1').fill('t2');
  await page.locator('#save').click();
  await expect(page.locator('#st')).toContainText('уже есть в списке');
  await page.locator('#host-1').fill('second.example');
  await expect(page.locator('.srv').nth(1).locator('.srv-badge')).toBeVisible();
  await page.locator('#port-1').fill('99999');
  await page.locator('#save').click();
  await expect(page.locator('#port-1')).toBeFocused();
  await page.locator('#port-1').fill('');
  await page.locator('#save').click();
  await expect(page.locator('#st')).toHaveClass('st ok');
  await expect(page.locator('#st')).toContainText('2 сервера');
  // В хранилище массив servers без старых ключей
  expect(await page.evaluate(() => window.__sync)).toEqual({ servers: [{ host: 'legacy.example', port: '', token: 'legacy-token' }, { host: 'second.example', port: '', token: 't2' }] });
  // Проверка подключения конкретного сервера
  await page.locator('#test-1').click();
  await expect(page.locator('.srv').nth(1).locator('.srv-st')).toContainText('27.6');
  await expect(page.locator('.srv').nth(0).locator('.srv-st')).toBeEmpty();
  // Черновик: несохраненный третий сервер восстанавливается после закрытия окна
  await page.locator('#add').click();
  await page.locator('#host-2').fill('draft.example');
  await page.waitForTimeout(300);
  await page.reload();
  await expect(page.locator('.srv')).toHaveCount(3);
  await expect(page.locator('#host-2')).toHaveValue('draft.example');
  await expect(page.locator('#st')).toContainText('Восстановлен');
  // Удаление сервера
  await page.locator('#del-2').click();
  await expect(page.locator('.srv')).toHaveCount(2);
  await page.locator('#save').click();
  expect(await page.evaluate(() => window.__sync.servers.length)).toBe(2);
  await page.screenshot({ path: 'tests/out/popup-servers.png', fullPage: true });
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
    window.__calls = { status: [], tags: [], jira: [] };
    const s = window.VR.changeStatus; window.VR.changeStatus = async a => { window.__calls.status.push({ command: a.command, n: a.ids.length }); await new Promise(r => setTimeout(r, 400)); return s(a); };
    const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__calls.tags.push({ n: ids.length, tag }); return t(ids, tag); };
    const x = window.VR.ext; window.VR.ext = async (op, p) => { if (op === 'jira-create') window.__calls.jira.push(p); return x(op, p); };
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
  await page.evaluate(() => { window.__jira = []; window.__created = []; window.__status = []; const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__jira.push({ ids, tag }); return t(ids, tag); }; const x = window.VR.ext; window.VR.ext = async (op, p) => { if (op === 'jira-create') window.__created.push(p); return x(op, p); }; const s = window.VR.changeStatus; window.VR.changeStatus = async a => { window.__status.push(a); return window.__statusReply || s(a); }; });
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
  // содержимое задачи, а не только факт вызова
  const created = await page.evaluate(() => window.__created);
  expect(created).toHaveLength(1);
  expect(created[0].summary).toContain('Устранить CVE-2025-49723 на kuopzhfvwq.rf.plat.form: установить Накопительное обновление KB5122882');
  expect(created[0].summary).toContain('не ниже 10.0.20348.3932, рекомендуется 10.0.20348.5622');
  expect(created[0].labels).toEqual(['mpvm-remediation', 'mpvm-instance', 'mpvm-microsoft-windows']);
  expect(created[0].ids).toEqual(calls[0].ids);
  expect(created[0].dueDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  // повторный клик не создает дубликат (D22)
  await expect(mp.locator('.mp-jira')).toBeDisabled();
  await expect(mp.locator('.mp-jira')).toHaveText('Задача создана');
  // «В работу»: отмена ничего не шлет; отказ сервера не меняет статус (D19)
  page.once('dialog', d => d.dismiss());
  await mp.locator('.mp-work').click();
  await page.waitForTimeout(200);
  expect(await page.evaluate(() => window.__status.length)).toBe(0);
  await page.evaluate(() => { window.__statusReply = { done: true, total: 1, succeed: 0, failed: 1, count: 1 }; });
  page.once('dialog', d => d.accept());
  await mp.locator('.mp-work').click();
  await expect(mp.locator('[data-role=mp-jira-st]')).toContainText('статус не изменен');
  await expect(mp.locator('.mp-work')).toBeEnabled();
  expect(await page.evaluate(() => window.__status.length)).toBe(1);
  await page.evaluate(() => { window.__statusReply = { done: true, total: 1, succeed: 1, failed: 0, count: 1 }; });
  page.once('dialog', d => d.accept());
  await mp.locator('.mp-work').click();
  await expect(mp.locator('[data-role=mp-jira-st]')).toContainText('статус изменен');
  await expect(mp.locator('.mp-work')).toBeDisabled();
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
  await page.evaluate(() => { window.__calls = { status: [], tags: [], jira: [] }; const s = window.VR.changeStatus; window.VR.changeStatus = async a => { window.__calls.status.push({ command: a.command, n: a.ids.length }); return s(a); }; const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__calls.tags.push({ n: ids.length, tag }); return t(ids, tag); }; const x = window.VR.ext; window.VR.ext = async (op, p) => { if (op === 'jira-create') window.__calls.jira.push(p); return x(op, p); }; });
  await page.locator('#tab-patches').click();
  await expect(page.locator('#pt-sum .empty-state')).toBeVisible();
  await run(page, 'pt-run');
  await expect(page.locator('#pt-sum .kpi')).toHaveCount(4);
  await expect(page.locator('#pt-sum')).toContainText('300 000');
  const rows = page.locator('#pt-out tr.click');
  await expect(rows).toHaveCount(3);
  await expect(rows.first()).toContainText('KB5122876');
  await expect(rows.first().locator('a.lnk')).toHaveAttribute('href', /KB5122876/);
  await expect(page.locator('#pt-out table tr').last()).toContainText('ссылка не указаны');
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
  const created = await page.evaluate(() => window.__calls.jira);
  expect(created).toHaveLength(1);
  expect(created[0].summary).toBe('Установить Накопительное обновление KB5122876 на 3 узлах: закрывает 3 уязвимостей (2 CVE) [KEV]');
  expect(created[0].labels).toEqual(['mpvm-remediation', 'mpvm-patch', 'mpvm-kb5122876']);
  expect(created[0].ids).toHaveLength(3);
  expect(created[0].csv).toContain('KB5122876');
  await expect(page.locator('#pt-d-jira')).toBeDisabled();
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
  await expect(table.locator('tr.hasf').last()).toContainText('ссылка не указаны');
  await page.keyboard.press('Enter');
  await expect(table.locator('tr.hasf').first()).toContainText('ссылка не указаны');
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

test('Штатная карточка экземпляра: кнопка Jira читает экземпляр из адреса в момент клика (D20)', async ({ page }) => {
  const A = '1e5566a8e0c000010000000000000012_1e5566a8e0c000010000000000000012_1e1e0794348140010000000000052b21';
  const B = A.replace(/12_/g, '13_');
  await page.goto('/tests/uitest/?theme=light&vulnerabilityId=1e1e0794-3481-4001-0000-000000052b21&vulnerabilityInstanceId=' + A);
  await page.locator('#vr-menu-item').waitFor();
  await page.evaluate(() => {
    document.querySelector('main').innerHTML = '<div class="vulner__primary-info"><h1 class="vulner__title">CVE-2025-49723</h1><section class="vulner-info-section"><h2 class="vulner-info-section__title">Описание</h2><p>Карточка экземпляра</p></section><section class="vulner-info-section"><h2 class="vulner-info-section__title">Ссылки</h2><p>Источники</p></section></div>';
    chrome.runtime.getURL = path => '/' + path;
    window.__created = []; window.__tags = [];
    const x = window.VR.ext; window.VR.ext = async (op, p) => { if (op === 'jira-create') window.__created.push(p); return x(op, p); };
    const t = window.VR.tagInstances; window.VR.tagInstances = async (ids, tag) => { window.__tags.push({ ids, tag }); return t(ids, tag); };
  });
  await page.addScriptTag({ url: '/content/cards.js' });
  const btn = page.locator('.vr-cb [data-act=jira-inst]');
  await expect(btn).toHaveCount(1);
  page.once('dialog', d => d.dismiss());
  await btn.click();
  await expect(btn).toBeEnabled();
  expect(await page.evaluate(() => window.__created.length)).toBe(0);
  // переход внутри интерфейса к другому экземпляру: блок не пересоздается, идентификатор берется из адреса при клике
  await page.evaluate(b => history.pushState({}, '', '?theme=light&vulnerabilityId=1e1e0794-3481-4001-0000-000000052b21&vulnerabilityInstanceId=' + b), B);
  page.once('dialog', d => d.accept());
  await btn.click();
  await expect(page.locator('.vr-cb [data-role=st]')).toContainText('VM-101');
  const created = await page.evaluate(() => window.__created);
  expect(created).toHaveLength(1);
  expect(created[0].ids).toEqual([B]);
  expect(await page.evaluate(() => window.__tags)).toEqual([{ ids: [B], tag: 'jira:VM-101' }]);
  await expect(btn).toBeDisabled();
});

test('Интерфейс 27.x: пункт в горизонтальном меню, область под шапкой, инвентаризация недоступна, hash-маршруты', async ({ page }) => {
  await page.goto('/tests/uitest/?ui=legacy&theme=light#/assets?viewMode=list&assetId=a-1&tabName=summary');
  // Пункт «Устранение» вставлен в shadow DOM меню сразу после «Активы»
  const item = page.locator('ipn-navbar #vr-menu-item');
  await expect(item).toHaveText(/Устранение/);
  // Пункт стоит в собственной секции меню сразу после секции «Активы» (внутри одной секции пункты встают столбиком)
  expect(await item.evaluate(el => [el.parentElement.tagName, el.parentElement.children.length, el.parentElement.previousElementSibling?.textContent.trim()])).toEqual(['IPN-NAVBAR-SECTION', 1, 'Активы']);
  const rows = await page.locator('ipn-navbar a.mc-navbar-item').evaluateAll(els => new Set(els.map(e => Math.round(e.getBoundingClientRect().top))).size);
  expect(rows).toBe(1);
  await item.click();
  await expect(page.locator('#vr-root')).toBeVisible();
  // Область занимает всю ширину под меню высотой 48 px
  const box = await page.locator('#vr-root').evaluate(el => { const r = el.getBoundingClientRect(); return [Math.round(r.top), Math.round(r.left)]; });
  expect(box).toEqual([48, 0]);
  await expect(item).toHaveClass(/mc-active/);
  await expect(page.locator('ipn-navbar a.mc-navbar-item', { hasText: 'Активы' })).not.toHaveClass(/mc-active/);
  await expect(page.locator('#sub')).toHaveText(/27\.6\.33103/);
  // Инвентаризация: вместо правил объяснение, что теги активов появились в 28.0
  await page.locator('.tabs button[data-t="inv"]').click();
  await expect(page.locator('#i-legacy')).toBeVisible();
  await expect(page.locator('#i-legacy')).toContainText('27.6.33103');
  await expect(page.locator('#i-main')).toBeHidden();
  // Выборка по показателю: ссылка в список активов с hash-маршрутом, queryId «Все активы» и select
  await page.locator('.tabs button[data-t="overview"]').click();
  await run(page, 'm-run');
  await page.locator('#m-out [data-drill="overdue"]').click();
  const link = page.locator('#m-drill a.btn', { hasText: 'Открыть в MaxPatrol' });
  await expect(link).toBeVisible();
  const href = await link.getAttribute('href');
  expect(href).toMatch(/\/#\/assets\?groupId=00000000-0000-0000-0000-000000000002&queryId=q-all&pdqlQuery=/);
  expect(decodeURIComponent(href)).toMatch(/select\(/);
  await expect(page.locator('#m-drill a.lnk[href*="vulnerability-passport"]').first()).toHaveAttribute('href', /\/#\/assets\/vulnerability-passport\?vulnerabilityId=/);
  await expect(page.locator('#m-drill a.lnk[href*="assetId="]').first()).toHaveAttribute('href', /\/#\/assets\?viewMode=list&groupId=.*&assetId=/);
  // Проекты (метки экземпляров) в 27.x доступны: кнопка «В проект» на месте
  await expect(page.locator('#m-drill [data-a=proj]')).toBeVisible();
  await audit(page);
  // Клик по другому пункту меню закрывает область и возвращает ему активность
  await page.locator('ipn-navbar a.mc-navbar-item', { hasText: 'Активы' }).click();
  await expect(page.locator('#vr-root')).toBeHidden();
  await expect(page.locator('ipn-navbar a.mc-navbar-item', { hasText: 'Активы' })).toHaveClass(/mc-active/);
  await expect(item).not.toHaveClass(/mc-active/);
  // Повторное открытие с клавиатуры
  await item.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#vr-root')).toBeVisible();
});

test('Интерфейс 27.x: блок в карточке экземпляра внутри shadow DOM, экземпляр из hash', async ({ page }) => {
  const A = '1e5566a8e0c000010000000000000012_1e5566a8e0c000010000000000000012_1e1e0794348140010000000000052b21';
  await page.goto('/tests/uitest/?ui=legacy&theme=light#/assets/vulnerability-card?vulnerabilityId=1e1e0794-3481-4001-0000-000000052b21&vulnerabilityInstanceId=' + A);
  await page.locator('ipn-navbar #vr-menu-item').waitFor();
  await page.evaluate(() => {
    // Оболочка 27.x: контент внутри shadow root, как ips-shell-remote-app
    const host = document.createElement('div'); host.id = 'legacy-shell'; host.attachShadow({ mode: 'open' });
    document.querySelector('main').appendChild(host);
    chrome.runtime.getURL = path => '/' + path;
    window.__created = [];
    const x = window.VR.ext; window.VR.ext = async (op, p) => { if (op === 'jira-create') window.__created.push(p); return x(op, p); };
  });
  await page.addScriptTag({ url: '/content/cards.js' });
  // Карточка отрисовывается позже и только внутри shadow root: наблюдатель за document.body этого не видит
  await page.waitForTimeout(1500);
  await page.evaluate(() => {
    document.getElementById('legacy-shell').shadowRoot.innerHTML = '<div class="vulner"><div class="vulner__title">Уязвимость CVE-2025-49723</div><div class="vulner__primary-info"><div class="vulner-info-section"><div class="vulner-info-section__title">Описание</div><div>Описание</div></div><div class="vulner-info-section"><div class="vulner-info-section__title">Как исправить</div><div>Обновите</div></div><div class="vulner-info-section"><div class="vulner-info-section__title">Ссылки</div><div><a href="https://nvd.nist.gov/vuln/detail/CVE-2025-49723">nvd</a></div></div></div></div>';
  });
  const btn = page.locator('#legacy-shell .vr-cb [data-act=jira-inst]');
  await expect(btn).toHaveCount(1, { timeout: 8000 });
  await expect(page.locator('#legacy-shell .vr-cb')).toHaveCount(1);
  page.once('dialog', d => d.accept());
  await btn.click();
  await expect(page.locator('#legacy-shell .vr-cb [data-role=st]')).toContainText('VM-101');
  const created = await page.evaluate(() => window.__created);
  expect(created).toHaveLength(1);
  expect(created[0].ids).toEqual([A]);
  // Повторные проверки по таймеру не дублируют блок
  await page.waitForTimeout(2500);
  await expect(page.locator('#legacy-shell .vr-cb')).toHaveCount(1);
});

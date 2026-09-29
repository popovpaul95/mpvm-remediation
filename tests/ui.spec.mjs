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
    for (const width of [1280, 1024, 768]) {
      await page.setViewportSize({ width, height: 900 });
      for (const name of ['overview', 'queue', 'settings', 'inv', 'cve']) {
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

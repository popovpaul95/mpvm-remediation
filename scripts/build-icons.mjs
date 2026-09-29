// Исходник — icons/logo.svg. PNG для Chrome и inline SVG берутся из одного знака.
// Запуск: npm run icons (использует установленный Chrome и dev-зависимость Playwright).
import { chromium } from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const svg = (await fs.readFile(path.join(root, 'icons/logo.svg'), 'utf8')).trim();
const symbol = svg.match(/<g id="remediation-symbol"[\s\S]*?<\/g>/)?.[0];
if (!symbol) throw new Error('В logo.svg не найден знак remediation-symbol');
const compact = s => s.replace(/>\s+</g, '><').trim();
const icon = compact(`<svg width="16" height="16" viewBox="16 16 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">${symbol.replace(' id="remediation-symbol"', '')}</svg>`);
const logo = compact(svg.replace('<svg ', '<svg aria-hidden="true" ').replace(' id="remediation-symbol"', ''));
const appPath = path.join(root, 'content/app.js');
let app = await fs.readFile(appPath, 'utf8');
if (!/^  const ICON = .*;$/m.test(app)) throw new Error('Не найдена константа ICON в content/app.js');
app = app.replace(/^  const ICON = .*;\n(?:  const LOGO = .*;\n)?/m, `  const ICON = ${JSON.stringify(icon)};\n  const LOGO = ${JSON.stringify(logo)};\n`);

const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const page = await browser.newPage();
  for (const size of [16, 24, 32, 48, 128]) {
    const data = await page.evaluate(async ({ svg, size }) => {
      const image = new Image();
      image.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
      await image.decode();
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = size;
      canvas.getContext('2d').drawImage(image, 0, 0, size, size);
      return canvas.toDataURL('image/png').split(',')[1];
    }, { svg, size });
    await fs.writeFile(path.join(root, `icons/icon${size}.png`), Buffer.from(data, 'base64'));
  }
  await fs.writeFile(appPath, app);
  console.log('Готово: PNG 16/24/32/48/128 px и SVG для интерфейса.');
} finally {
  await browser.close();
}

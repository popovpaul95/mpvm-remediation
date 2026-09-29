import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: ['ui.spec.mjs', 'exports.spec.mjs'],
  outputDir: './tests/out/ui',
  timeout: 90_000,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:18765',
    channel: 'chrome',
    viewport: { width: 1600, height: 1100 },
    headless: true,
    screenshot: 'only-on-failure'
  },
  webServer: {
    command: 'python3 -m http.server 18765 --bind 127.0.0.1',
    url: 'http://127.0.0.1:18765/tests/uitest/',
    reuseExistingServer: !process.env.CI
  }
});

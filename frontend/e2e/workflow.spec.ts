import { expect, test } from '@playwright/test';

test('register, analyze real source and diff, inspect reports and quality gates', async ({ page }) => {
  const email = `e2e-${Date.now()}@example.com`;
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('e2e-password-long-enough');
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  await page.getByRole('link', { name: /Code analysis/ }).click();
  await page.locator('.monaco-editor').click();
  await page.keyboard.press('Control+A');
  await page.keyboard.insertText('import os\nprint("ready")\n');
  await page.getByLabel('File name').fill('sample.py');
  await page.getByRole('button', { name: /Run analysis/ }).click();
  await expect(page.getByText('Unused import: os')).toBeVisible();
  await expect(page.getByText('Checks passed')).toBeVisible();

  await page.getByRole('button', { name: 'Preview safe patch' }).click();
  await expect(page.getByText(/Proposed change · source not modified/)).toBeVisible();
  await expect(page.locator('.patch-diff')).toContainText('-import os');
  await page.getByRole('button', { name: 'Mark accepted' }).click();
  await expect(page.getByText(/Decision recorded/)).toBeVisible();

  await page.getByRole('link', { name: /Code analysis/ }).click();
  await page.getByLabel('Language').selectOption('javascript');
  await page.locator('.monaco-editor').click();
  await page.keyboard.press('Control+A');
  await page.keyboard.insertText('const unusedValue = 1;\n');
  await page.getByRole('button', { name: /Run analysis/ }).click();
  await expect(
    page.getByRole('article').getByText(/assigned a value but never used/).first(),
  ).toBeVisible();
  await expect(page.getByText(/Analyzers: eslint, secret-patterns/)).toBeVisible();

  await page.getByRole('link', { name: /Code analysis/ }).click();
  await page.getByLabel('File name').fill('../outside.py');
  await page.getByRole('button', { name: /Run analysis/ }).click();
  await expect(page.locator('.error-banner')).toContainText('cannot traverse directories');

  await page.getByRole('link', { name: /Analysis history/ }).click();
  await expect(page.getByRole('link', { name: 'sample.py', exact: true })).toBeVisible();
  await page.getByRole('link', { name: /Diff review/ }).click();
  await page.getByLabel('Unified diff').fill(
    'diff --git a/src/change.py b/src/change.py\n' +
    '--- a/src/change.py\n+++ b/src/change.py\n@@ -0,0 +1,2 @@\n' +
    '+import json\n+print("change")\n',
  );
  await page.getByRole('button', { name: /Analyze changes/ }).click();
  await expect(page.getByRole('heading', { name: 'diff: src/change.py' })).toBeVisible();
  await expect(page.getByText('Checks passed')).toBeVisible();

  await page.getByRole('link', { name: /Dependencies/ }).click();
  await page.getByLabel('Ecosystem').selectOption('npm');
  await page.getByLabel('Dependency manifest').fill('{"dependencies":{"sample-package":"^1.0.0"}}');
  await page.getByRole('button', { name: /Inventory & scan/ }).click();
  await expect(page.getByRole('heading', { name: /Scan report/ })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'sample-package' })).toBeVisible();
  await expect(page.getByText(/No exact resolved versions were supplied/)).toBeVisible();

  const unauthorizedStatus = await page.evaluate(async () => (await fetch('/api/analyses')).status);
  expect(unauthorizedStatus).toBe(401);

  await page.route('**/api/analytics/overview', route => route.abort());
  await page.route('**/api/analyses*', route => route.abort());
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Email address').fill(`second-${Date.now()}@example.com`);
  await page.getByLabel('Password').fill('second-account-password');
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await expect(page.getByText('Analyses run', { exact: true })).toHaveCount(0);
});

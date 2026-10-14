import { test, expect, Page } from '@playwright/test';
import fixtures from './fixtures/openssl.json' with { type: 'json' };
async function select(page: Page, label: string, option: string) {
  await page.getByRole('combobox', { name: label, exact: true }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}
async function open(page: Page, id = 'aes') {
  await page.goto(`#/tool/${id}`);
  await expect(page.locator('h1')).toBeVisible();
}
const output = (page: Page) => page.getByRole('textbox', { name: '输出结果', exact: true });
async function run(page: Page, label = '执行加密') {
  await page.getByRole('button', { name: label + ' →', exact: true }).click();
  await expect(output(page)).toBeVisible();
}
test('AES GCM worker encrypts, refills and decrypts Unicode', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await open(page);
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
  await expect(page.getByRole('textbox', { name: '输出认证标签' })).not.toHaveValue('');
  await page.getByRole('button', { name: '回填输入' }).click();
  await run(page, '执行解密');
  await expect(output(page)).toHaveValue('Hello, Cipher Lab! 你好 🔐');
  expect(errors).toEqual([]);
});
test('bad parameters recover; old output becomes stale and cannot be copied', async ({ page }) => {
  await open(page);
  await page.getByRole('button', { name: /执行加密/ }).click();
  await expect(page.getByRole('alert')).toContainText('密钥');
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
  await page.getByRole('textbox', { name: '输入内容' }).fill('changed');
  await expect(page.getByRole('status')).toContainText('结果已失效');
  await expect(page.getByRole('button', { name: '复制结果' })).toBeDisabled();
  await expect(page.getByRole('button', { name: '回填输入' })).toBeDisabled();
  await run(page);
  await expect(page.getByRole('status')).toContainText('计算完成');
});
test('GCM authentication failure recovers', async ({ page }) => {
  await open(page);
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
  await page.getByRole('button', { name: '回填输入' }).click();
  await page.getByRole('textbox', { name: /认证标签 TAG/ }).fill('AAAAAAAAAAAAAAAAAAAAAA==');
  await page.getByRole('button', { name: /执行解密/ }).click();
  await expect(page.getByRole('alert')).toContainText('认证失败');
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
});
test('RSA OAEP decrypts OpenSSL PKCS8 fixture in browser', async ({ page }) => {
  await open(page, 'rsa');
  await page.getByRole('button', { name: /^解密/ }).click();
  await select(page, '输入编码', 'Hex');
  await page.getByRole('textbox', { name: '输入内容' }).fill(fixtures.rsa['oaep-sha256']);
  await page.getByRole('textbox', { name: '私钥', exact: true }).fill(fixtures.rsa.privateKey);
  await run(page, '执行解密');
  await expect(output(page)).toHaveValue(fixtures.rsa.plaintext);
});
test('RSA generates keys in worker and encrypts', async ({ page }) => {
  await open(page, 'rsa');
  await page.getByRole('button', { name: '生成密钥对' }).click();
  await expect(page.getByRole('textbox', { name: '私钥', exact: true })).toHaveValue(
    /BEGIN PRIVATE KEY/,
    { timeout: 30000 },
  );
  await page.getByRole('textbox', { name: '输入内容' }).fill('worker RSA 🔐');
  await run(page);
  await page.getByRole('button', { name: '回填输入' }).click();
  await run(page, '执行解密');
  await expect(output(page)).toHaveValue('worker RSA 🔐');
});
test('SM2 generation and Unicode decrypt work in actual worker', async ({ page }) => {
  await open(page, 'sm2');
  await page.getByRole('button', { name: '载入示例' }).click();
  await expect(page.getByRole('textbox', { name: '私钥', exact: true })).toHaveValue(
    /^[a-f0-9]{64}$/,
  );
  await run(page);
  await page.getByRole('button', { name: '回填输入' }).click();
  await run(page, '执行解密');
  await expect(output(page)).toHaveValue('Hello, Cipher Lab! 你好 🔐');
});
test('DES, 3DES, SM4, digests and HMAC lazy adapters execute', async ({ page }) => {
  for (const id of [
    'des',
    '3des',
    'sm4',
    'md5',
    'sha1',
    'sha256',
    'sha384',
    'sha512',
    'sm3',
    'hmac',
  ]) {
    await open(page, id);
    await page.getByRole('button', { name: '载入示例' }).click();
    await run(page, ['des', '3des', 'sm4'].includes(id) ? '执行加密' : '计算摘要');
    await expect(output(page)).not.toHaveValue('');
  }
});
test('hash route refresh and responsive layout preserve subpath', async ({ page }) => {
  await open(page, 'sm3');
  await page.reload();
  await expect(page.locator('h1')).toContainText('SM3');
  await expect(page).toHaveURL(/\/online-encryption\/#\/tool\/sm3$/);
  await page.getByRole('textbox', { name: '输入内容' }).fill('abc');
  await run(page, '计算摘要');
  await expect(output(page)).toHaveValue(
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
  );
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
});
test('encoding is reversible, clipboard works where supported, clear removes secrets', async ({
  page,
  browserName,
}) => {
  await open(page, 'encoding');
  await page.getByRole('textbox', { name: '输入内容' }).fill('你好 🔐');
  await run(page, '转换编码');
  await expect(output(page)).toHaveValue('5L2g5aW9IPCflJA=');
  if (browserName === 'chromium') {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.getByRole('button', { name: '复制结果' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('5L2g5aW9IPCflJA=');
  }
  await page.getByRole('button', { name: '回填输入' }).click();
  await select(page, '输出编码', 'UTF-8 文本');
  await run(page, '转换编码');
  await expect(output(page)).toHaveValue('你好 🔐');
  await open(page);
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
  await page.getByRole('button', { name: '清空' }).click();
  await expect(page.getByRole('textbox', { name: /原始密钥/ })).toHaveValue('');
  await expect(page.getByRole('textbox', { name: '输入内容' })).toHaveValue('');
  await expect(output(page)).toHaveCount(0);
});
test('operations use only local GET assets and do not persist input or keys', async ({ page }) => {
  await open(page);
  const requests: { url: string; method: string; data: string | null }[] = [];
  page.on('request', (r) =>
    requests.push({ url: r.url(), method: r.method(), data: r.postData() }),
  );
  const secret = 'PRIVATE_PROBE_7af1';
  await page.getByRole('button', { name: '载入示例' }).click();
  await page.getByRole('textbox', { name: '输入内容' }).fill(secret);
  await run(page);
  await open(page, 'sm2');
  await page.getByRole('button', { name: '载入示例' }).click();
  await run(page);
  expect(
    requests.every(
      (r) =>
        new URL(r.url).origin === 'http://127.0.0.1:4173' &&
        r.method === 'GET' &&
        !r.url.includes(secret) &&
        r.data === null,
    ),
  ).toBe(true);
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    cookies: document.cookie,
    indexedDB: (await indexedDB.databases()).length,
    cache: (await caches.keys()).length,
  }));
  expect(storage).toEqual({ local: 0, session: 0, cookies: '', indexedDB: 0, cache: 0 });
  await page.reload();
  await expect(page.getByRole('textbox', { name: '私钥', exact: true })).toHaveValue('');
  await expect(page.getByRole('textbox', { name: '输入内容' })).toHaveValue('');
});

test('SM2 empty-message authentication is checked in the browser worker', async ({ page }) => {
  await open(page, 'sm2');
  await page.getByRole('textbox', { name: '公钥', exact: true }).fill(fixtures.sm2.publicKey);
  await page.getByRole('textbox', { name: '私钥', exact: true }).fill(fixtures.sm2.privateKey);
  await run(page);
  const ciphertext = await output(page).inputValue();
  await page.getByRole('button', { name: '回填输入' }).click();
  await run(page, '执行解密');
  await expect(output(page)).toHaveValue('');
  const corrupt = Buffer.from(ciphertext, 'base64');
  corrupt[65] ^= 1; // First byte of C3, after 04 + X + Y.
  await page.getByRole('textbox', { name: '输入内容' }).fill(corrupt.toString('base64'));
  await page.getByRole('button', { name: '执行解密 →', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('完整性验证失败');
});

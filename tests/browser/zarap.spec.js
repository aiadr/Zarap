import { expect, test } from '@playwright/test';

const validLink = 'vless://123e4567-e89b-42d3-a456-426614174000@proxy.example.test:443?encryption=none&security=reality&sni=cdn.example.test&fp=chrome&pbk=0123456789abcdefghijklmnopqrstuvwxyzABCDE&type=tcp';

async function openZarap(page) {
  await page.goto('/');
  await expect.poll(() => page.locator('body').getAttribute('data-ready')).toBe('true');
}

test('renders status and enforces private MAC restriction', async ({ page }) => {
  await openZarap(page);

  await expect(page.getByRole('heading', { name: 'Zarap' })).toBeVisible();
  await expect(page.getByText('sing-box работает')).toBeVisible();
  await expect(page.getByText('TProxy слушает')).toBeVisible();
  await expect(page.getByText('kill switch активен')).toBeVisible();
  await expect(page.getByText('маршрутизация активна')).toBeVisible();

  await expect(page.getByText('Захват трафика: интерфейс br-lan')).toBeVisible();

  await expect(page.locator('#zarap-devices tbody tr')).toHaveCount(3);
  const privateDevice = page.locator('tr[data-mac="02:AA:BB:CC:DD:EE"]');
  await expect(privateDevice).toContainText('Приватный MAC');
  // Not named by any rule, so it carries no lease to edit and no kill switch.
  await expect(privateDevice.locator('input[data-field="ip"]')).toHaveCount(0);
  await expect(privateDevice).not.toContainText('kill switch');

  const guarded = page.locator('tr[data-mac="00:11:22:33:44:55"]');
  await expect(guarded).toContainText('kill switch');
  await expect(guarded).toContainText('Нидерланды');
  await expect(guarded.locator('input[data-field="ip"]')).toHaveValue('192.168.1.50');

  await expect(page.locator('#zarap-outbounds tbody tr')).toHaveCount(2);
  await expect(page.locator('#zarap-rules tbody tr')).toHaveCount(2);
  await expect(page.getByText('Остальной трафик: напрямую')).toBeVisible();

  await expect(page.locator('body')).not.toContainText('123e4567-e89b-42d3-a456-426614174000');
  await expect(page.locator('body')).not.toContainText('0123456789abcdefghijklmnopqrstuvwxyzABCDE');
  await expect(page.getByText(/vless:\/\/\*\*\*\*\*\*\*\*@proxy\.example\.test/)).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'devices')).toBe(false);
});

test('sends the leases of guarded devices and keeps saved connections masked', async ({ page }) => {
  await openZarap(page);

  await page.getByLabel('Добавить подключение').fill(validLink);
  const tablet = page.locator('tr[data-mac="10:20:30:40:50:60"]');
  await tablet.locator('input[data-field="name"]').fill('Планшет ребёнка');
  await tablet.locator('input[data-field="ip"]').fill('192.168.1.62');

  await page.getByRole('button', { name: 'Проверить конфигурацию', exact: true }).click();
  await expect(page.getByText('Конфигурация корректна')).toBeVisible();

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[0]).toBe(true);
  // Saved connections round-trip by tag with an empty link, so their secrets
  // never leave the router; the pasted one is the only link on the wire.
  expect(apply.args[1]).toEqual([
    { tag: 'out_1', label: 'Нидерланды', link: '' },
    { tag: 'out_2', label: 'Германия', link: '' },
    { tag: '', label: '', link: validLink }
  ]);
  expect(apply.args[2]).toEqual([
    { clients: ['00:11:22:33:44:55'], target: 'out_1' },
    { clients: ['10:20:30:40:50:60'], target: 'block' }
  ]);
  // Only devices a rule names carry a lease.
  expect(apply.args[3]).toEqual([
    { mac: '00:11:22:33:44:55', name: 'Телевизор', ip: '192.168.1.50' },
    { mac: '10:20:30:40:50:60', name: 'Планшет ребёнка', ip: '192.168.1.62' }
  ]);
  expect(apply.args[3].some(client => client.mac === '02:AA:BB:CC:DD:EE')).toBe(false);
  expect(apply.args[4]).toBe('direct');
});

test('shows backend validation errors without applying configuration', async ({ page }) => {
  await openZarap(page);
  await page.evaluate(() => { window.__mockState.validateError = 'MVP поддерживает только транспорт TCP'; });
  await page.getByLabel('Добавить подключение').fill(validLink.replace('type=tcp', 'type=ws'));
  await page.getByRole('button', { name: 'Проверить конфигурацию', exact: true }).click();

  await expect(page.getByText('MVP поддерживает только транспорт TCP')).toBeVisible();
  await expect(page.getByText(/Ошибка входных данных/)).toBeVisible();
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('refreshes both components and confirms each update separately', async ({ page }) => {
  await openZarap(page);
  await expect(page.getByRole('button', { name: 'Обновить' })).toHaveCount(0);

  await page.getByRole('button', { name: 'Проверить обновления' }).click();
  await expect(page.getByText('Списки репозиториев обновлены')).toBeVisible();
  await expect(page.locator('#zarap-components-body').getByRole('button', { name: 'Обновить' })).toHaveCount(2);

  const zarapRow = page.locator('#zarap-components-body tr').filter({ hasText: 'Zarap' });
  await zarapRow.getByRole('button', { name: 'Обновить' }).click();
  await expect(page.getByRole('dialog')).toContainText('APK обновит только компонент Zarap');
  await page.getByRole('dialog').getByRole('button', { name: 'Отмена' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);

  let calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'update_component')).toBe(false);

  await zarapRow.getByRole('button', { name: 'Обновить' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Обновить' }).click();
  await expect(page.getByText('Zarap обновлён')).toBeVisible();

  calls = await page.evaluate(() => window.__rpcCalls);
  const update = calls.find(call => call.method === 'update_component');
  expect(update.args).toEqual(['luci-app-zarap']);
  expect(calls.filter(call => call.method === 'updates' && call.args[0] === true)).toHaveLength(1);
});

test('copies the scrubbed log to the clipboard', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await openZarap(page);

  await page.getByRole('button', { name: 'Скопировать журнал' }).click();
  await expect(page.getByText('Журнал скопирован в буфер обмена')).toBeVisible();

  const clipboard = await page.evaluate(() => navigator.clipboard.readText());
  expect(clipboard).toContain('sing-box запущен');
  expect(clipboard).toContain('[скрыто]');
});

test('shows what apk reported when the update check fails', async ({ page }) => {
  await openZarap(page);
  await page.evaluate(() => {
    window.__mockState.updatesError = 'ERROR: unable to select packages: no repositories available';
  });

  await page.getByRole('button', { name: 'Проверить обновления' }).click();

  await expect(page.getByText('apk не смог обновить списки репозиториев')).toBeVisible();
  await expect(page.getByText('no repositories available')).toBeVisible();
  await expect(page.getByText('Неизвестная ошибка')).toHaveCount(0);
});

test('keeps an action pair aligned instead of at opposite edges', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openZarap(page);

  const check = page.getByRole('button', { name: 'Проверить конфигурацию', exact: true });
  const apply = page.getByRole('button', { name: 'Сохранить и применить' });
  const checkBox = await check.boundingBox();
  const applyBox = await apply.boundingBox();

  // The theme floats the neutral button left while the save button stays
  // right-aligned; both must end up against the same edge instead.
  expect(Math.abs(checkBox.x + checkBox.width - (applyBox.x + applyBox.width))).toBeLessThan(2);
});

test('names the failure when the update RPC itself does not complete', async ({ page }) => {
  await openZarap(page);
  // A failed ubus call resolves with the status code, not an object.
  await page.evaluate(() => { window.__mockState.updatesRpcStatus = 7; });

  await page.getByRole('button', { name: 'Проверить обновления' }).click();

  await expect(page.getByText('Запрос к роутеру не выполнен')).toBeVisible();
  await expect(page.getByText(/Timeout \(7\)/)).toBeVisible();
  await expect(page.getByText('Неизвестная ошибка')).toHaveCount(0);
});

test('keeps showing the kill switch while Zarap is switched off', async ({ page }) => {
  // The kill switch holds regardless of the master switch, so hiding its
  // badges here told the user the device was free when it was still blocked.
  await page.addInitScript(() => {
    window.__statusOverride = { enabled: false, running: false, listener: false, routing: false };
  });
  await openZarap(page);

  await expect(page.getByText('kill switch активен')).toBeVisible();
  const held = page.locator('tr[data-mac="00:11:22:33:44:55"]');
  await expect(held).toContainText('kill switch');
  // Only deleting the rule releases it, which stage 1 does not offer yet.
  await expect(page.getByText(/Редактирование правил появится/)).toBeVisible();
});

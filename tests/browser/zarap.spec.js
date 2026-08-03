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

  await expect(page.locator('#zarap-devices tbody tr')).toHaveCount(3);
  const privateDevice = page.locator('tr[data-mac="02:AA:BB:CC:DD:EE"]');
  await expect(privateDevice.getByRole('checkbox')).toBeDisabled();
  await expect(privateDevice).toContainText('Приватный MAC');

  const selectedDevice = page.locator('tr[data-mac="00:11:22:33:44:55"]');
  await expect(selectedDevice.getByRole('checkbox')).toBeChecked();
  await expect(selectedDevice).toContainText('kill switch');

  await expect(page.locator('body')).not.toContainText('123e4567-e89b-42d3-a456-426614174000');
  await expect(page.locator('body')).not.toContainText('0123456789abcdefghijklmnopqrstuvwxyzABCDE');
  await expect(page.getByText(/vless:\/\/\*\*\*\*\*\*\*\*@proxy\.example\.test/)).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'devices')).toBe(false);
});

test('validates and applies the exact selected devices', async ({ page }) => {
  await openZarap(page);

  await page.getByLabel('VLESS Reality-ссылка').fill(validLink);
  const tablet = page.locator('tr[data-mac="10:20:30:40:50:60"]');
  await tablet.getByRole('checkbox').check();
  await tablet.locator('input[data-field="name"]').fill('Планшет ребёнка');
  await tablet.locator('input[data-field="ip"]').fill('192.168.1.62');

  await page.getByRole('button', { name: 'Проверить конфигурацию', exact: true }).click();
  await expect(page.getByText('Ссылка и список устройств корректны')).toBeVisible();

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const validate = calls.find(call => call.method === 'validate');
  const apply = calls.find(call => call.method === 'apply');
  expect(validate.args[0]).toBe(validLink);
  expect(apply.args[0]).toBe(validLink);
  expect(apply.args[1]).toBe(true);
  expect(apply.args[2]).toEqual([
    { mac: '00:11:22:33:44:55', name: 'Телевизор', ip: '192.168.1.50' },
    { mac: '10:20:30:40:50:60', name: 'Планшет ребёнка', ip: '192.168.1.62' }
  ]);
  expect(apply.args[2].some(client => client.mac === '02:AA:BB:CC:DD:EE')).toBe(false);
});

test('shows backend validation errors without applying configuration', async ({ page }) => {
  await openZarap(page);
  await page.evaluate(() => { window.__mockState.validateError = 'MVP поддерживает только транспорт TCP'; });
  await page.getByLabel('VLESS Reality-ссылка').fill(validLink.replace('type=tcp', 'type=ws'));
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

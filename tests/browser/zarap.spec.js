import { expect, test } from '@playwright/test';

// What the fixture has the router return for a saved connection, rebuilt from
// its section: the page shows this and sends it straight back.
function savedLink(tag) {
  const uuid = tag === 'out_1'
    ? '123e4567-e89b-42d3-a456-426614174000'
    : '123e4567-e89b-42d3-a456-426614174002';
  const host = tag === 'out_1' ? 'proxy.example.test' : 'de.example.test';
  return `vless://${uuid}@${host}:443?encryption=none&security=reality&type=tcp`
    + '&sni=cdn.example.test&fp=chrome&pbk=0123456789abcdefghijklmnopqrstuvwxyzABCDE';
}

const validLink = 'vless://123e4567-e89b-42d3-a456-426614174000@proxy.example.test:443?encryption=none&security=reality&sni=cdn.example.test&fp=chrome&pbk=0123456789abcdefghijklmnopqrstuvwxyzABCDE&type=tcp';

async function openZarap(page) {
  await page.goto('/');
  await expect.poll(() => page.locator('body').getAttribute('data-ready')).toBe('true');
}

// Components and the log live on the second tab; configuration is on the first.
async function openMaintenance(page) {
  await page.getByRole('link', { name: 'Обслуживание' }).click();
  await expect(page.locator('#zarap-tab-maintenance')).toBeVisible();
}

test('renders status and enforces private MAC restriction', async ({ page }) => {
  await openZarap(page);

  await expect(page.getByRole('heading', { name: 'Zarap' })).toBeVisible();
  await expect(page.getByText('sing-box работает')).toBeVisible();
  await expect(page.getByText('TProxy слушает')).toBeVisible();
  await expect(page.getByText('kill switch активен')).toBeVisible();
  await expect(page.getByText('маршрутизация активна')).toBeVisible();

  await expect(page.getByText('Захват трафика: интерфейс br-lan')).toBeVisible();

  // Configuration opens first; maintenance is a click away.
  await expect(page.locator('#zarap-tab-setup')).toBeVisible();
  await expect(page.locator('#zarap-tab-maintenance')).toBeHidden();

  await expect(page.locator('#zarap-devices tbody tr')).toHaveCount(5);
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

  // The link is on the page but folded away: a screenshot of the table catches
  // the row, not the uuid or the Reality key.
  await expect(page.locator('body')).not.toContainText('123e4567-e89b-42d3-a456-426614174000');
  await expect(page.locator('body')).not.toContainText('0123456789abcdefghijklmnopqrstuvwxyzABCDE');
  await expect(page.locator('tr[data-tag="out_1"] code[data-field="link"]')).toHaveText(/^vless:\/\/•+$/);

  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'devices')).toBe(false);
});

test('sends the leases of guarded devices and the connections as they stand', async ({ page }) => {
  await openZarap(page);

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
  // Saved or added a moment ago, a connection goes out the same way: its tag,
  // its name and its link.
  expect(apply.args[1]).toEqual([
    { tag: 'out_1', label: 'Нидерланды', link: savedLink('out_1') },
    { tag: 'out_2', label: 'Германия', link: savedLink('out_2') }
  ]);
  // Every condition goes back, including the ones the page cannot edit yet:
  // what is submitted is the list held here, so anything dropped on the way in
  // would be deleted from the router on the way out.
  expect(apply.args[2]).toEqual([
    { clients: ['00:11:22:33:44:55'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'out_1' },
    { clients: ['10:20:30:40:50:60'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'block' }
  ]);
  // Only devices a rule names carry a lease.
  expect(apply.args[4]).toEqual([
    { mac: '00:11:22:33:44:55', name: 'Телевизор', ip: '192.168.1.50' },
    { mac: '10:20:30:40:50:60', name: 'Планшет ребёнка', ip: '192.168.1.62' }
  ]);
  expect(apply.args[4].some(client => client.mac === '02:AA:BB:CC:DD:EE')).toBe(false);
  expect(apply.args[5]).toBe('direct');
});

test('shows backend validation errors without applying configuration', async ({ page }) => {
  await openZarap(page);
  await page.evaluate(() => { window.__mockState.validateError = 'MVP поддерживает только транспорт TCP'; });
  await page.getByRole('button', { name: 'Проверить конфигурацию', exact: true }).click();

  await expect(page.getByText('MVP поддерживает только транспорт TCP')).toBeVisible();
  await expect(page.getByText(/Ошибка входных данных/)).toBeVisible();
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('adds a connection without the router and lets a rule use it', async ({ page }) => {
  await openZarap(page);

  await page.getByLabel('Добавить подключение').fill(validLink);
  await page.locator('#zarap-add-outbound').click();
  await expect(page.getByText(/Подключение добавлено/)).toBeVisible();

  // Listed at once, marked as living only on this page until an apply.
  const added = page.locator('tr[data-tag="out_3"]');
  await expect(added).toContainText('не сохранено');
  // Emptied, or the same link would go out a second time as another connection.
  await expect(page.getByLabel('Добавить подключение')).toHaveValue('');

  // Nothing reached the router: the whole thing happened in the page.
  let calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.every(call => ['status', 'updates', 'logs'].includes(call.method))).toBe(true);

  // The point of adding before applying: a rule can point at it now.
  await page.getByRole('button', { name: 'Добавить правило' }).click();
  const rule = page.locator('#zarap-rules-body tr[data-rule="2"]');
  await rule.getByRole('button', { name: 'Устройства…' }).click();
  await page.locator('#zarap-picker input[data-mac="AA:BB:CC:DD:EE:FF"]').check();
  await page.getByRole('button', { name: 'Готово' }).click();
  await rule.locator('select').selectOption('out_3');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  // Nameless until the router reads the link, and sent alongside the saved ones
  // in exactly the same shape.
  expect(apply.args[1]).toContainEqual({ tag: 'out_3', label: '', link: validLink });
  expect(apply.args[2]).toContainEqual(
    { clients: ['AA:BB:CC:DD:EE:FF'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'out_3' });
});

test('keeps a link folded away until it is asked for', async ({ page }) => {
  await openZarap(page);

  const row = page.locator('tr[data-tag="out_1"]');
  const link = row.locator('code[data-field="link"]');
  await expect(link).toHaveText(/^vless:\/\/•+$/);

  await row.getByRole('button', { name: 'Показать' }).click();
  await expect(link).toHaveText(savedLink('out_1'));

  await row.getByRole('button', { name: 'Скрыть' }).click();
  await expect(link).toHaveText(/^vless:\/\/•+$/);
});

test('refuses to apply a link that was never added', async ({ page }) => {
  await openZarap(page);

  await page.getByLabel('Добавить подключение').fill(validLink);
  await page.getByRole('button', { name: 'Сохранить и применить' }).click();

  // The field is not what gets submitted, so dropping it silently would lose
  // the connection the user thought they were saving.
  await expect(page.getByText(/подключение ещё не добавлено/)).toBeVisible();
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('refreshes both components and confirms each update separately', async ({ page }) => {
  await openZarap(page);
  await openMaintenance(page);
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
  await openMaintenance(page);

  await page.getByRole('button', { name: 'Скопировать журнал' }).click();
  await expect(page.getByText('Журнал скопирован в буфер обмена')).toBeVisible();

  const clipboard = await page.evaluate(() => navigator.clipboard.readText());
  expect(clipboard).toContain('sing-box запущен');
  expect(clipboard).toContain('[скрыто]');
});

test('shows what apk reported when the update check fails', async ({ page }) => {
  await openZarap(page);
  await openMaintenance(page);
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
  await openMaintenance(page);
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
});

test('shows conditions by destination and hands them back untouched', async ({ page }) => {
  // Ranges, ports and protocol can only be written in /etc/config/zarap for
  // now. The page still submits the whole rule list, so a condition it failed
  // to carry would be a condition deleted by the next save — and a rule shown
  // as if it covered everything the device does would be a lie in the meantime.
  await page.addInitScript(() => {
    window.__statusOverride = {
      rulesets: [
        { tag: 'rs_1', label: 'Реклама', url: 'https://example.org/ads.srs',
          detour: 'direct', update_interval: '1d', in_use: true }
      ],
      rules: [
        { clients: ['00:11:22:33:44:55'], domains: ['youtube.com'],
          rule_sets: ['rs_1'], ip_cidr: ['149.154.160.0/20'],
          ports: ['443', '1000:2000'], network: 'udp', target: 'out_1' },
        { clients: ['10:20:30:40:50:60'], target: 'block' }
      ]
    };
  });
  await openZarap(page);

  const conditioned = page.locator('#zarap-rules-body tr[data-rule="0"]');
  await expect(conditioned.locator('[data-field="destination"]'))
    .toHaveText('youtube.com · список «Реклама» · 149.154.160.0/20 · порт 443, 1000:2000 · udp');
  await expect(page.locator('#zarap-rules-body tr[data-rule="1"] [data-field="destination"]'))
    .toHaveText('любой адрес');

  // The device is named by a rule that only covers part of its traffic, so the
  // column says where the rest goes and which rule catches the part.
  const tv = page.locator('tr[data-mac="00:11:22:33:44:55"]');
  await expect(tv.locator('[data-field="target"]')).toContainText('напрямую');
  await expect(tv.locator('[data-field="partial"]')).toHaveText(' кроме правил 1');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const sent = calls.find(call => call.method === 'apply');
  expect(sent.args[3]).toEqual([
    { tag: 'rs_1', label: 'Реклама', url: 'https://example.org/ads.srs',
      detour: 'direct', update_interval: '1d' }
  ]);
  expect(sent.args[2]).toEqual([
    { clients: ['00:11:22:33:44:55'], domains: ['youtube.com'],
      rule_sets: ['rs_1'], ip_cidr: ['149.154.160.0/20'],
      ports: ['443', '1000:2000'], network: 'udp', target: 'out_1' },
    { clients: ['10:20:30:40:50:60'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'block' }
  ]);
});

test('edits the destination of a rule and sends what was typed', async ({ page }) => {
  await openZarap(page);

  const rule = page.locator('#zarap-rules-body tr[data-rule="0"]');
  await rule.getByRole('button', { name: 'Куда…' }).click();

  await page.locator('textarea[data-field="Домены"]').fill('YouTube.com\n.googlevideo.com');
  await page.locator('textarea[data-field="Диапазоны адресов"]').fill('149.154.160.0/20');
  await page.locator('textarea[data-field="Порты"]').fill('443\n1000:2000');
  await page.locator('select[data-field="network"]').selectOption('udp');
  await page.locator('input[data-ruleset="rs_1"]').check();
  await page.locator('button[data-action="save-destination"]').click();

  // Записи нормализуются так же, как их принял бы роутер.
  await expect(rule.locator('[data-field="destination"]'))
    .toHaveText('youtube.com, .googlevideo.com · список «Реклама» · 149.154.160.0/20 · порт 443, 1000:2000 · udp');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.find(call => call.method === 'apply').args[2][0]).toEqual({
    clients: ['00:11:22:33:44:55'],
    domains: ['youtube.com', '.googlevideo.com'],
    rule_sets: ['rs_1'],
    ip_cidr: ['149.154.160.0/20'],
    ports: ['443', '1000:2000'],
    network: 'udp',
    target: 'out_1'
  });
});

test('refuses a domain that is not one, in the words the router would use', async ({ page }) => {
  // Круг запроса ради опечатки никому не нужен, а формулировка должна совпадать
  // с той, что вернул бы бэкенд, иначе это выглядит как две разные ошибки.
  await openZarap(page);
  await page.locator('#zarap-rules-body tr[data-rule="0"]')
    .getByRole('button', { name: 'Куда…' }).click();

  await page.locator('textarea[data-field="Домены"]').fill('*.example.com');
  await page.locator('button[data-action="save-destination"]').click();
  await expect(page.getByText(/Звёздочка не нужна/)).toBeVisible();

  await page.locator('textarea[data-field="Домены"]').fill('https://example.com');
  await page.locator('button[data-action="save-destination"]').click();
  await expect(page.getByText(/без схемы и пути/)).toBeVisible();

  await page.locator('textarea[data-field="Домены"]').fill('example.com');
  await page.locator('textarea[data-field="Диапазоны адресов"]').fill('2001:db8::/32');
  await page.locator('button[data-action="save-destination"]').click();
  await expect(page.getByText(/IPv6-диапазон/)).toBeVisible();

  // Ничего не сохранилось: окно осталось открытым, правило нетронуто.
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('adds a rule set and points a rule at it', async ({ page }) => {
  await openZarap(page);

  await page.locator('#zarap-ruleset-url').fill('https://example.org/geosite-ru.srs');
  await page.locator('#zarap-ruleset-label').fill('Заблокированное');
  await page.locator('#zarap-add-ruleset').click();

  const added = page.locator('tr[data-ruleset="rs_2"]');
  await expect(added).toContainText('Заблокированное');
  // Источники списков заблокированы там же, где и всё остальное, поэтому по
  // умолчанию предлагается подключение.
  await expect(added).toContainText('Нидерланды');

  // Ничего не ушло на роутер: список уезжает вместе с применением.
  let calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.every(call => ['status', 'updates', 'logs'].includes(call.method))).toBe(true);

  const rule = page.locator('#zarap-rules-body tr[data-rule="1"]');
  await rule.getByRole('button', { name: 'Куда…' }).click();
  await page.locator('input[data-ruleset="rs_2"]').check();
  await page.locator('button[data-action="save-destination"]').click();
  await expect(rule.locator('[data-field="destination"]')).toHaveText('список «Заблокированное»');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[3]).toContainEqual({
    tag: 'rs_2', label: 'Заблокированное', url: 'https://example.org/geosite-ru.srs',
    detour: 'out_1', update_interval: '1d'
  });
  expect(apply.args[2][1].rule_sets).toEqual(['rs_2']);
});

test('refuses to delete a rule set a rule still points at', async ({ page }) => {
  await openZarap(page);

  const rule = page.locator('#zarap-rules-body tr[data-rule="0"]');
  await rule.getByRole('button', { name: 'Куда…' }).click();
  await page.locator('input[data-ruleset="rs_1"]').check();
  await page.locator('button[data-action="save-destination"]').click();

  const remove = page.locator('tr[data-ruleset="rs_1"] button[data-action="remove-ruleset"]');
  await expect(remove).toBeDisabled();
  await expect(remove).toHaveAttribute('title', /правило 1/);
});

test('blocking everything for the whole LAN is confirmed first', async ({ page }) => {
  // Правило без устройств действует на весь дом, и «заблокировать» в нём —
  // это «этого не будет ни у кого».
  await openZarap(page);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  const added = page.locator('#zarap-rules-body tr[data-rule="2"]');
  await added.getByRole('button', { name: 'Куда…' }).click();
  await page.locator('textarea[data-field="Домены"]').fill('example.com');
  await page.locator('button[data-action="save-destination"]').click();

  await added.locator('select').selectOption('block');
  await expect(page.getByText('Заблокировать для всех?')).toBeVisible();
  await page.getByRole('button', { name: 'Отмена' }).click();
  await expect(page.locator('#zarap-rules-body tr[data-rule="2"] select')).not.toHaveValue('block');
});

test('says whether names are resolved through the proxy', async ({ page }) => {
  // Доменное правило меняет путь, но не точку назначения, поэтому без резолва
  // через прокси оно обходит только DPI — и молчать об этом нельзя.
  await openZarap(page);
  await expect(page.locator('#zarap-dns-note')).toContainText('не спасает, если домен блокируется в DNS');

  await page.addInitScript(() => { window.__statusOverride = { dns: { forwarded: 3 } }; });
  await page.reload();
  await expect.poll(() => page.locator('body').getAttribute('data-ready')).toBe('true');
  await expect(page.locator('#zarap-dns-note')).toContainText('резолвится имён: 3');
});

test('says how much room the rule set cache leaves', async ({ page }) => {
  await page.addInitScript(() => {
    window.__statusOverride = { cache: { size: 6291456, free: 4194304 } };
  });
  await openZarap(page);

  await expect(page.locator('#zarap-cache')).toContainText('6.0 МиБ');
  await expect(page.locator('[data-field="cache-warning"]')).toBeVisible();
});

test('adds a rule and picks its devices without touching the router', async ({ page }) => {
  await openZarap(page);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await expect(page.locator('#zarap-rules-body tr')).toHaveCount(3);

  const added = page.locator('#zarap-rules-body tr[data-rule="2"]');
  await expect(added).toContainText('устройства не выбраны');
  await added.getByRole('button', { name: 'Устройства…' }).click();

  // The phone is unguarded before this and has no address field.
  await expect(page.locator('tr[data-mac="02:AA:BB:CC:DD:EE"] input[data-field="ip"]')).toHaveCount(0);
  await page.locator('#zarap-picker input[data-mac="10:20:30:40:50:60"]').check();
  await page.getByRole('button', { name: 'Готово' }).click();

  await expect(added).toContainText('10:20:30:40:50:60');
  // Nothing reaches the router until the configuration is applied.
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('a device added to a rule immediately gets an address field', async ({ page }) => {
  await openZarap(page);
  const phone = page.locator('tr[data-mac="02:AA:BB:CC:DD:EE"]');
  await expect(phone.locator('input[data-field="ip"]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();
  // A private MAC cannot be pinned by a lease, so it is refused here rather
  // than after an apply.
  await expect(page.locator('#zarap-picker input[data-mac="02:AA:BB:CC:DD:EE"]')).toBeDisabled();
  await page.getByRole('button', { name: 'Отмена' }).click();

  // A device that can be pinned gets the field as soon as a rule names it.
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();
  await page.locator('#zarap-picker input[data-mac="AA:BB:CC:DD:EE:FF"]').check();
  await page.getByRole('button', { name: 'Готово' }).click();
  await expect(page.locator('tr[data-mac="AA:BB:CC:DD:EE:FF"] input[data-field="ip"]')).toHaveCount(1);
});

test('names a device while picking it for a rule', async ({ page }) => {
  await openZarap(page);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();

  const row = page.locator('#zarap-picker tr')
    .filter({ has: page.locator('input[data-mac="AA:BB:CC:DD:EE:FF"]') });
  // The name lives in the lease, and only a device a rule names has one.
  await expect(row.locator('input[data-field="name"]')).toBeDisabled();
  await page.locator('#zarap-picker input[data-mac="AA:BB:CC:DD:EE:FF"]').check();
  await expect(row.locator('input[data-field="name"]')).toBeEnabled();
  await row.locator('input[data-field="name"]').fill('realme');
  await page.getByRole('button', { name: 'Готово' }).click();

  // One device, one name: the table shows what was typed in the picker.
  const named = page.locator('tr[data-mac="AA:BB:CC:DD:EE:FF"]');
  await expect(named.locator('input[data-field="name"]')).toHaveValue('realme');
  await named.locator('input[data-field="ip"]').fill('192.168.1.81');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[4]).toContainEqual({
    mac: 'AA:BB:CC:DD:EE:FF', name: 'realme', ip: '192.168.1.81'
  });
});

test('a device with no lease is offered a free address when a rule names it', async ({ page }) => {
  await openZarap(page);

  // Nothing to show and nothing to edit until a rule names it.
  const phone = page.locator('tr[data-mac="FC:D2:02:D3:28:63"]');
  await expect(phone.locator('input[data-field="ip"]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();
  await page.locator('#zarap-picker input[data-mac="FC:D2:02:D3:28:63"]').check();
  await page.getByRole('button', { name: 'Готово' }).click();

  // The field is answerable straight away rather than an empty box that only
  // fails on apply.
  await expect(phone.locator('input[data-field="ip"]')).toHaveValue('192.168.1.90');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[4]).toContainEqual({
    mac: 'FC:D2:02:D3:28:63', name: 'Устройство FC:D2:02:D3:28:63', ip: '192.168.1.90'
  });
});

test('refuses to send a rule whose device has no address', async ({ page }) => {
  await openZarap(page);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();
  // A MAC typed by hand is on no lease and has no suggestion behind it.
  await page.getByPlaceholder('00:11:22:33:44:55').fill('10:34:56:78:9a:bc');
  await page.getByRole('dialog').getByRole('button', { name: 'Добавить', exact: true }).click();
  await page.getByRole('button', { name: 'Готово' }).click();

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  // The router can only name the MAC in its refusal, and only after a round
  // trip; the page says which device and puts the cursor in the field.
  await expect(page.getByText(/10:34:56:78:9A:BC нужен статический IPv4-адрес/)).toBeVisible();
  await expect(page.locator('tr[data-mac="10:34:56:78:9A:BC"] input[data-field="ip"]')).toBeFocused();

  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.some(call => call.method === 'apply')).toBe(false);
});

test('a MAC typed by hand gets a row to carry its address', async ({ page }) => {
  await openZarap(page);

  await page.getByRole('button', { name: 'Добавить правило' }).click();
  await page.locator('#zarap-rules-body tr[data-rule="2"]')
    .getByRole('button', { name: 'Устройства…' }).click();

  await page.getByPlaceholder('00:11:22:33:44:55').fill('10:34:56:78:9a:bc');
  await page.getByRole('dialog').getByRole('button', { name: 'Добавить', exact: true }).click();
  const row = page.locator('#zarap-picker tr')
    .filter({ has: page.locator('input[data-mac="10:34:56:78:9A:BC"]') });
  await row.locator('input[data-field="name"]').fill('Кладовка');
  await page.getByRole('button', { name: 'Готово' }).click();

  // Without a row there is nowhere to enter the address the apply demands.
  const added = page.locator('tr[data-mac="10:34:56:78:9A:BC"]');
  await expect(added.locator('input[data-field="name"]')).toHaveValue('Кладовка');
  await added.locator('input[data-field="ip"]').fill('192.168.1.99');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[4]).toContainEqual({
    mac: '10:34:56:78:9A:BC', name: 'Кладовка', ip: '192.168.1.99'
  });
});

test('reorders rules and applies them in the shown order', async ({ page }) => {
  await openZarap(page);

  const first = page.locator('#zarap-rules-body tr[data-rule="0"]');
  await first.getByRole('button', { name: '↓' }).click();

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  await expect(page.getByText('Конфигурация применена')).toBeVisible();

  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[2]).toEqual([
    { clients: ['10:20:30:40:50:60'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'block' },
    { clients: ['00:11:22:33:44:55'], domains: [], rule_sets: [], ip_cidr: [], ports: [], network: '', target: 'out_1' }
  ]);
});

test('refuses to delete a connection a rule still points at', async ({ page }) => {
  await openZarap(page);

  const used = page.locator('#zarap-outbounds-body tr[data-tag="out_1"]');
  const spare = page.locator('#zarap-outbounds-body tr[data-tag="out_2"]');
  const usedButton = used.getByRole('button', { name: 'Удалить' });
  await expect(usedButton).toBeDisabled();
  // The refusal has to name the reference, or there is nothing to act on.
  await expect(usedButton).toHaveAttribute('title', /правило 1/);

  await spare.getByRole('button', { name: 'Удалить' }).click();
  await expect(page.locator('#zarap-outbounds-body tr')).toHaveCount(1);

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  const calls = await page.evaluate(() => window.__rpcCalls);
  const apply = calls.find(call => call.method === 'apply');
  expect(apply.args[1]).toEqual([{ tag: 'out_1', label: 'Нидерланды', link: savedLink('out_1') }]);
});

test('a connection stops being deletable once the remainder points at it', async ({ page }) => {
  await openZarap(page);

  const spare = page.locator('#zarap-outbounds-body tr[data-tag="out_2"]');
  await expect(spare.getByRole('button', { name: 'Удалить' })).toBeEnabled();

  await page.locator('#zarap-final select').selectOption('out_2');
  await expect(spare.getByRole('button', { name: 'Удалить' })).toBeDisabled();
  await expect(spare.getByRole('button', { name: 'Удалить' }))
    .toHaveAttribute('title', /остальной трафик/);
  // Routing everyone through a proxy guards nobody; the page has to say so.
  await expect(page.locator('#zarap-final'))
    .toContainText('kill switch от этого ни у кого не появляется');
});

test('blocking the remainder is confirmed and can be backed out of', async ({ page }) => {
  await openZarap(page);

  await page.locator('#zarap-final select').selectOption('block');
  await expect(page.locator('#modal')).toContainText('Без интернета останется весь дом');
  await page.locator('#modal').getByRole('button', { name: 'Отмена' }).click();
  await expect(page.locator('#zarap-final select')).toHaveValue('direct');

  await page.locator('#zarap-final select').selectOption('block');
  await page.locator('#modal').getByRole('button', { name: 'Заблокировать' }).click();
  await expect(page.locator('#zarap-final select')).toHaveValue('block');

  await page.getByRole('button', { name: 'Сохранить и применить' }).click();
  const calls = await page.evaluate(() => window.__rpcCalls);
  expect(calls.find(call => call.method === 'apply').args[5]).toBe('block');
});

test('deleting a rule warns what the device loses', async ({ page }) => {
  await openZarap(page);

  await page.locator('#zarap-rules-body tr[data-rule="0"]')
    .getByRole('button', { name: 'Удалить' }).click();
  const dialog = page.locator('#modal');
  await expect(dialog).toContainText('получат прямой выход в интернет и лишатся закреплённого адреса');
  await expect(dialog).toContainText('Телевизор (00:11:22:33:44:55)');

  await page.locator('#modal').getByRole('button', { name: 'Удалить' }).click();
  await expect(page.locator('#zarap-rules-body tr')).toHaveCount(1);
  // The television is no longer guarded, so its lease is no longer editable.
  await expect(page.locator('tr[data-mac="00:11:22:33:44:55"] input[data-field="ip"]')).toHaveCount(0);
});

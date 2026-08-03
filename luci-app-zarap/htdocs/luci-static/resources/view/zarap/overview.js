'use strict';
'require dom';
'require rpc';
'require ui';
'require view';

const callStatus = rpc.declare({ object: 'zarap', method: 'status' });
const callValidate = rpc.declare({ object: 'zarap', method: 'validate', params: [ 'link', 'clients' ] });
const callApply = rpc.declare({ object: 'zarap', method: 'apply', params: [ 'link', 'enabled', 'clients' ] });
const callRestart = rpc.declare({ object: 'zarap', method: 'restart' });
const callStop = rpc.declare({ object: 'zarap', method: 'stop' });
const callLogs = rpc.declare({ object: 'zarap', method: 'logs' });
const callUpdates = rpc.declare({ object: 'zarap', method: 'updates', params: [ 'refresh' ] });
const callUpdateComponent = rpc.declare({ object: 'zarap', method: 'update_component', params: [ 'name' ] });

function notify(result, successText) {
	if (result && result.ok) {
		ui.addNotification(null, E('p', successText), 'info');
		return true;
	}
	const titles = {
		input_error: _('Ошибка входных данных'),
		compatibility_error: _('Конфигурация несовместима'),
		startup_error: _('Ошибка запуска'),
		connection_error: _('Ошибка соединения')
	};
	const title = titles[result && result.kind];
	ui.addNotification(null, E('p', {}, [ title ? E('strong', {}, title + ': ') : '',
		(result && result.error) || _('Неизвестная ошибка') ]), 'error');
	return false;
}

function statusPill(ok, yesText, noText) {
	return E('span', {
		'class': ok ? 'label success' : 'label warning',
		'style': 'display:inline-block;margin-right:.5em'
	}, ok ? yesText : noText);
}

function selectedClients() {
	const clients = [];
	document.querySelectorAll('#zarap-devices tbody tr').forEach(function(row) {
		const checkbox = row.querySelector('input[type="checkbox"]');
		if (!checkbox.checked)
			return;
		clients.push({
			mac: row.getAttribute('data-mac'),
			name: row.querySelector('input[data-field="name"]').value.trim(),
			ip: row.querySelector('input[data-field="ip"]').value.trim()
		});
	});
	return clients;
}

function deviceRow(device) {
	const unavailable = device.private_mac;
	const reason = unavailable ? _('Приватный MAC: отключите рандомизацию MAC на устройстве') : '';
	return E('tr', { 'class': 'tr', 'data-mac': device.mac }, [
		E('td', { 'class': 'td' }, [
			E('input', {
				'type': 'checkbox',
				'checked': device.selected && !unavailable ? '' : null,
				'disabled': unavailable ? '' : null,
				'title': reason
			})
		]),
		E('td', { 'class': 'td' }, [
			E('input', {
				'class': 'cbi-input-text', 'data-field': 'name',
				'value': device.name || '', 'placeholder': _('Имя устройства')
			})
		]),
		E('td', { 'class': 'td' }, device.mac),
		E('td', { 'class': 'td' }, [
			E('input', {
				'class': 'cbi-input-text', 'data-field': 'ip',
				'value': device.ip || '', 'placeholder': '192.168.1.100'
			})
		]),
		E('td', { 'class': 'td' }, [
			device.connected ? statusPill(true, _('в сети'), '') : statusPill(false, '', _('не в сети')),
			device.kill_switch ? statusPill(true, _(' kill switch'), '') : '',
			device.wireless && device.network ? E('small', {}, ' Wi-Fi: ' + device.network) : '',
			unavailable ? E('div', { 'class': 'error' }, reason) : ''
		])
	]);
}

function updateRow(name, data, owner, runtimeStatus) {
	const title = name === 'luci-app-zarap' ? 'Zarap' : 'sing-box';
	const installed = data.installed || _('не установлен');
	const action = (!data.installed || (data.checked && data.update_available))
		? E('button', {
			'class': 'btn cbi-button-action',
			'click': ui.createHandlerFn(owner, function() {
				ui.showModal(_('Подтвердите обновление'), [
					E('p', {}, _('APK обновит только компонент %s и необходимые ему зависимости.').format(title)),
					E('div', { 'class': 'right' }, [
						E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Отмена')), ' ',
						E('button', {
							'class': 'btn cbi-button-positive important',
							'click': ui.createHandlerFn(owner, async function(ev) {
								ev.currentTarget.disabled = true;
								dom.content(ev.currentTarget, _('Обновление…'));
								const result = await callUpdateComponent(name);
								ui.hideModal();
								if (notify(result, _('%s обновлён').format(title)))
									window.setTimeout(function() { window.location.reload(); }, 1200);
							})
						}, data.installed ? _('Обновить') : _('Установить'))
					])
				]);
			})
		}, data.installed ? _('Обновить') : _('Установить'))
		: E('span', {}, data.checked ? _('Установлена актуальная версия') : _('Сначала проверьте обновления'));

	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td' }, title),
		E('td', { 'class': 'td' }, [
			installed,
			name === 'sing-box' ? E('div', {}, statusPill(runtimeStatus && runtimeStatus.running,
				_('процесс работает'), _('процесс остановлен'))) : ''
		]),
		E('td', { 'class': 'td' }, data.candidate || '—'),
		E('td', { 'class': 'td' }, action)
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callStatus(), {}),
			L.resolveDefault(callUpdates(false), { components: {} }),
			L.resolveDefault(callLogs(), { logs: '' })
		]);
	},

	render: function(data) {
		const status = data[0] || {};
		const devices = status.devices || [];
		const updates = (data[1] && data[1].components) || {};
		const logs = (data[2] && data[2].logs) || '';
		devices.forEach(function(device) {
			device.kill_switch = !!(status.enabled && status.firewall && device.selected);
		});
		const configuredText = status.configured
			? _('Сохранено: %s. Оставьте поле пустым, чтобы не менять подключение.').format(status.masked_link || 'vless://********')
			: _('Вставьте VLESS Reality-ссылку. Ссылка разбирается на роутере и не возвращается в браузер.');

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'Zarap'),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Состояние')),
				E('p', { 'class': status.state && status.state.endsWith('_error') ? 'error' : '' }, status.message || _('Состояние неизвестно')),
				E('p', {}, [
					statusPill(status.running, _('sing-box работает'), _('sing-box остановлен')),
					statusPill(status.listener, _('TProxy слушает'), _('нет TProxy-порта')),
					statusPill(status.firewall, _('kill switch активен'), _('нет правил firewall')),
					statusPill(status.routing, _('маршрутизация активна'), _('нет policy routing'))
				]),
				E('div', { 'class': 'right' }, [
					E('button', {
						'class': 'btn cbi-button-action',
						'disabled': status.enabled ? null : '',
						'title': status.enabled ? '' : _('Сначала включите Zarap'),
						'click': ui.createHandlerFn(this, async function() {
							if (notify(await callRestart(), _('Zarap перезапущен')))
								window.location.reload();
						})
					}, _('Перезапустить')), ' ',
					E('button', {
						'class': 'btn cbi-button-negative',
						'disabled': status.enabled ? null : '',
						'title': status.enabled ? '' : _('Zarap уже выключен'),
						'click': ui.createHandlerFn(this, async function() {
							if (notify(await callStop(), _('Zarap остановлен; kill switch для выбранных устройств сохранён')))
								window.location.reload();
						})
					}, _('Остановить'))
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Подключение')),
				E('p', {}, configuredText),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'for': 'zarap-link' }, _('VLESS Reality-ссылка')),
					E('div', { 'class': 'cbi-value-field' }, [
						E('input', {
							'id': 'zarap-link', 'class': 'cbi-input-password', 'type': 'password',
							'autocomplete': 'off', 'style': 'width:100%', 'placeholder': 'vless://…'
						})
					])
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'for': 'zarap-enabled' }, _('Включить Zarap')),
					E('div', { 'class': 'cbi-value-field' }, [
						E('input', { 'id': 'zarap-enabled', 'type': 'checkbox', 'checked': status.enabled ? '' : null })
					])
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Устройства')),
				E('p', {}, _('Выберите устройства и укажите постоянный IPv4-адрес. Zarap создаст для них статические DHCP-аренды. При недоступности прокси внешний трафик этих устройств будет заблокирован.')),
				E('table', { 'class': 'table', 'id': 'zarap-devices' }, [
					E('thead', {}, E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Через Zarap')),
						E('th', { 'class': 'th' }, _('Имя')),
						E('th', { 'class': 'th' }, _('MAC')),
						E('th', { 'class': 'th' }, _('Статический IPv4')),
						E('th', { 'class': 'th' }, _('Состояние'))
					])),
					E('tbody', {}, devices.length ? devices.map(deviceRow) : E('tr', {}, E('td', { 'colspan': 5 }, _('Устройства пока не обнаружены'))))
				]),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.createHandlerFn(this, async function() {
							const link = document.querySelector('#zarap-link').value;
							notify(await callValidate(link, selectedClients()), _('Ссылка и список устройств корректны'));
						})
					}, _('Проверить конфигурацию')), ' ',
					E('button', {
						'class': 'btn cbi-button-save important',
						'click': ui.createHandlerFn(this, async function(ev) {
							ev.currentTarget.disabled = true;
							const result = await callApply(
								document.querySelector('#zarap-link').value,
								document.querySelector('#zarap-enabled').checked,
								selectedClients()
							);
							if (notify(result, _('Конфигурация применена'))) {
								if ((result.clients || []).some(function(client) { return client.reconnect_required; }))
									ui.addNotification(null, E('p', _('Статический IPv4 изменён. Переподключите отмеченное устройство к Wi-Fi вручную.')), 'warning');
								window.setTimeout(function() { window.location.reload(); }, 700);
							}
							else
								ev.currentTarget.disabled = false;
						})
					}, _('Сохранить и применить'))
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Компоненты и обновления')),
				E('p', {}, _('Проверка выполняется одновременно для Zarap и sing-box через настроенные APK-репозитории.')),
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Компонент')),
						E('th', { 'class': 'th' }, _('Установлено')),
						E('th', { 'class': 'th' }, _('Доступно')),
						E('th', { 'class': 'th' }, _('Действие'))
					]),
					E('tbody', { 'id': 'zarap-components-body' }, [
						updateRow('luci-app-zarap', updates['luci-app-zarap'] || {}, this, status),
						updateRow('sing-box', updates['sing-box'] || {}, this, status)
					])
				]),
				E('p', {}, E('button', {
					'class': 'btn cbi-button-action',
					'click': ui.createHandlerFn(this, async function(ev) {
						ev.currentTarget.disabled = true;
						dom.content(ev.currentTarget, E('span', {}, _('Обновление списков…')));
						const result = await callUpdates(true);
						if (notify(result, _('Списки репозиториев обновлены'))) {
							const components = result.components || {};
							dom.content(document.querySelector('#zarap-components-body'), [
								updateRow('luci-app-zarap', components['luci-app-zarap'] || {}, this, status),
								updateRow('sing-box', components['sing-box'] || {}, this, status)
							]);
						}
						dom.content(ev.currentTarget, _('Проверить обновления'));
						ev.currentTarget.disabled = false;
					})
				}, _('Проверить обновления')))
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Журнал')),
				E('pre', { 'style': 'max-height:24em;overflow:auto;white-space:pre-wrap' }, logs || _('Записей пока нет'))
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});

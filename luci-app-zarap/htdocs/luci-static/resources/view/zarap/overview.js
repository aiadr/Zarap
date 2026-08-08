'use strict';
'require dom';
'require rpc';
'require ui';
'require view';

const callStatus = rpc.declare({ object: 'zarap', method: 'status' });
const callValidate = rpc.declare({ object: 'zarap', method: 'validate', params: [ 'outbounds', 'rules', 'clients', 'final' ] });
const callApply = rpc.declare({ object: 'zarap', method: 'apply', params: [ 'enabled', 'outbounds', 'rules', 'clients', 'final' ] });
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
	// A failed ubus call does not reject: rpc.declare resolves with the bare
	// status code, which has no ok/error/kind and used to render as the
	// useless "Неизвестная ошибка".
	if (result == null || typeof result != 'object') {
		const status = typeof result == 'number'
			? '%s (%d)'.format(rpc.getStatusText(result), result)
			: _('роутер не ответил');
		ui.addNotification(null, E('p', {}, [
			E('strong', {}, _('Запрос к роутеру не выполнен') + ': '), status
		]), 'error');
		return false;
	}

	const title = titles[result && result.kind];
	const nodes = [ E('p', {}, [ title ? E('strong', {}, title + ': ') : '',
		(result && result.error) || _('Неизвестная ошибка') ]) ];
	// Backends attach the underlying tool output here; dropping it left the
	// user with a bare "unknown error" and nothing to act on.
	if (result && result.details)
		nodes.push(E('pre', {
			'style': 'max-height:12em;overflow:auto;white-space:pre-wrap;margin:.5em 0 0'
		}, result.details));
	ui.addNotification(null, nodes, 'error');
	return false;
}

// Themes float .important buttons to the far edge, so on a narrow screen an
// action pair lands on two lines at opposite sides. A flex row keeps them
// together: float does not apply to flex items.
const ACTION_ROW = 'display:flex;flex-wrap:wrap;gap:.5em;justify-content:flex-end;align-items:center';

// LuCI is usually served over plain HTTP, where navigator.clipboard does not
// exist. Fall back to a detached textarea, which still works in that context.
function copyToClipboard(text) {
	if (window.isSecureContext && navigator.clipboard)
		return navigator.clipboard.writeText(text);

	const area = E('textarea', {
		'readonly': '',
		'style': 'position:fixed;top:-1000px;left:-1000px;opacity:0'
	});
	area.value = text;
	document.body.appendChild(area);
	area.select();
	area.setSelectionRange(0, text.length);
	let copied = false;
	try {
		copied = document.execCommand('copy');
	}
	catch (e) {
		copied = false;
	}
	document.body.removeChild(area);
	return copied ? Promise.resolve() : Promise.reject(new Error('execCommand'));
}

function statusPill(ok, yesText, noText) {
	return E('span', {
		'class': ok ? 'label success' : 'label warning',
		'style': 'display:inline-block;margin-right:.5em'
	}, ok ? yesText : noText);
}

// Only devices a rule names carry a lease, and those are exactly the rows the
// apply has to send back. The rest of the table is there to be looked at.
function leasedClients() {
	const clients = [];
	document.querySelectorAll('#zarap-devices tbody tr[data-guarded="1"]').forEach(function(row) {
		clients.push({
			mac: row.getAttribute('data-mac'),
			name: row.querySelector('input[data-field="name"]').value.trim(),
			ip: row.querySelector('input[data-field="ip"]').value.trim()
		});
	});
	return clients;
}

// Connections round-trip by tag with an empty link, which tells the router to
// keep the secret it already holds. A pasted link adds one.
function submittedOutbounds(outbounds) {
	const sent = outbounds.map(function(outbound) {
		return { tag: outbound.tag, label: outbound.label || '', link: '' };
	});
	const added = document.querySelector('#zarap-link').value.trim();
	if (added)
		sent.push({ tag: '', label: '', link: added });
	return sent;
}

function targetLabel(target, outbounds) {
	if (target === 'direct')
		return _('напрямую');
	if (target === 'block')
		return _('заблокировано');
	const match = outbounds.filter(function(outbound) { return outbound.tag === target; })[0];
	return match && match.label ? '%s (%s)'.format(match.label, target) : target;
}

function deviceRow(device, outbounds) {
	const unavailable = device.private_mac;
	const reason = unavailable ? _('Приватный MAC: отключите рандомизацию MAC на устройстве') : '';
	const editable = !!device.guarded;
	return E('tr', {
		'class': 'tr', 'data-mac': device.mac, 'data-guarded': editable ? '1' : '0'
	}, [
		E('td', { 'class': 'td' }, editable ? [
			E('input', {
				'class': 'cbi-input-text', 'data-field': 'name',
				'value': device.name || '', 'placeholder': _('Имя устройства')
			})
		] : (device.name || '')),
		E('td', { 'class': 'td' }, device.mac),
		E('td', { 'class': 'td' }, editable ? [
			E('input', {
				'class': 'cbi-input-text', 'data-field': 'ip',
				'value': device.ip || '', 'placeholder': '192.168.1.100'
			})
		] : (device.ip || '')),
		E('td', { 'class': 'td' }, targetLabel(device.resolved_target, outbounds)),
		E('td', { 'class': 'td' }, [
			device.connected ? statusPill(true, _('в сети'), '') : statusPill(false, '', _('не в сети')),
			device.kill_switch ? statusPill(true, _(' kill switch'), '') : '',
			device.wireless && device.network ? E('small', {}, ' Wi-Fi: ' + device.network) : '',
			unavailable ? E('div', { 'class': 'error' }, reason) : ''
		])
	]);
}

function outboundRow(outbound) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td' }, outbound.tag),
		E('td', { 'class': 'td' }, outbound.label || '—'),
		E('td', { 'class': 'td' }, E('code', {}, outbound.masked_link || '')),
		E('td', { 'class': 'td' }, outbound.in_use
			? statusPill(true, _('используется'), '')
			: statusPill(false, '', _('не используется')))
	]);
}

function ruleRow(rule, index, outbounds) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td' }, String(index + 1)),
		E('td', { 'class': 'td' }, (rule.clients || []).join(', ')),
		E('td', { 'class': 'td' }, targetLabel(rule.target, outbounds))
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
					E('div', { 'class': 'right', 'style': ACTION_ROW }, [
						E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Отмена')),
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
		const outbounds = status.outbounds || [];
		const rules = status.rules || [];
		const final = status.final || 'direct';
		const updates = (data[1] && data[1].components) || {};
		const logs = (data[2] && data[2].logs) || '';
		devices.forEach(function(device) {
			// Holds even with Zarap switched off: only deleting the rule that
			// names a device opens its direct path to the WAN.
			device.kill_switch = !!(status.firewall && device.guarded);
		});

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
				E('p', {}, status.capture && status.capture.interface
					? _('Захват трафика: интерфейс %s').format(status.capture.interface)
					: _('LAN-интерфейс не определён')),
				E('div', { 'class': 'right', 'style': ACTION_ROW }, [
					E('button', {
						'class': 'btn cbi-button-action',
						'disabled': status.enabled ? null : '',
						'title': status.enabled ? '' : _('Сначала включите Zarap'),
						'click': ui.createHandlerFn(this, async function() {
							if (notify(await callRestart(), _('Zarap перезапущен')))
								window.location.reload();
						})
					}, _('Перезапустить')),
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
				E('h3', {}, _('Подключения')),
				E('p', {}, _('Ссылка разбирается на роутере и обратно в браузер не возвращается. Сохранённые подключения показаны в замаскированном виде.')),
				E('table', { 'class': 'table', 'id': 'zarap-outbounds' }, [
					E('thead', {}, E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Тег')),
						E('th', { 'class': 'th' }, _('Название')),
						E('th', { 'class': 'th' }, _('Ссылка')),
						E('th', { 'class': 'th' }, _('Состояние'))
					])),
					E('tbody', {}, outbounds.length
						? outbounds.map(outboundRow)
						: E('tr', {}, E('td', { 'colspan': 4 }, _('Подключений пока нет'))))
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'for': 'zarap-link' }, _('Добавить подключение')),
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
				E('h3', {}, _('Правила')),
				E('p', {}, _('Применяется первое подходящее правило. Устройство, названное правилом, остаётся под kill switch даже при выключенном Zarap: прямой доступ возвращает только удаление правила.')),
				E('table', { 'class': 'table', 'id': 'zarap-rules' }, [
					E('thead', {}, E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, '#'),
						E('th', { 'class': 'th' }, _('Устройства')),
						E('th', { 'class': 'th' }, _('Куда'))
					])),
					E('tbody', {}, rules.length
						? rules.map(function(rule, index) { return ruleRow(rule, index, outbounds); })
						: E('tr', {}, E('td', { 'colspan': 3 }, _('Правил пока нет: весь трафик идёт по умолчанию'))))
				]),
				E('p', {}, _('Остальной трафик: %s').format(targetLabel(final, outbounds))),
				E('p', { 'class': 'cbi-value-description' }, _('Редактирование правил появится в следующей версии; пока их задаёт uci в /etc/config/zarap.'))
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Устройства')),
				E('p', {}, _('Весь трафик локальной сети проходит через Zarap. Адрес можно менять только у устройств, названных правилом: Zarap держит для них статическую DHCP-аренду, на которую правило и опирается.')),
				E('table', { 'class': 'table', 'id': 'zarap-devices' }, [
					E('thead', {}, E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, _('Имя')),
						E('th', { 'class': 'th' }, _('MAC')),
						E('th', { 'class': 'th' }, _('Статический IPv4')),
						E('th', { 'class': 'th' }, _('Куда идёт')),
						E('th', { 'class': 'th' }, _('Состояние'))
					])),
					E('tbody', {}, devices.length
						? devices.map(function(device) { return deviceRow(device, outbounds); })
						: E('tr', {}, E('td', { 'colspan': 5 }, _('Устройства пока не обнаружены'))))
				]),
				E('div', { 'class': 'cbi-page-actions', 'style': ACTION_ROW }, [
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.createHandlerFn(this, async function() {
							notify(await callValidate(submittedOutbounds(outbounds), rules,
								leasedClients(), final), _('Конфигурация корректна'));
						})
					}, _('Проверить конфигурацию')),
					E('button', {
						'class': 'btn cbi-button-save important',
						'click': ui.createHandlerFn(this, async function(ev) {
							ev.currentTarget.disabled = true;
							const result = await callApply(
								document.querySelector('#zarap-enabled').checked,
								submittedOutbounds(outbounds),
								rules,
								leasedClients(),
								final
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
				E('div', { 'class': 'right', 'style': ACTION_ROW }, E('button', {
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
				E('div', { 'class': 'right', 'style': ACTION_ROW }, [
					E('button', {
						'id': 'zarap-copy-logs',
						'class': 'btn cbi-button-action',
						'disabled': logs ? null : '',
						'title': logs ? _('Секреты в журнале уже скрыты') : _('Журнал пуст'),
						// Not ui.createHandlerFn: the fallback copy must run inside the
						// click gesture, which an async wrapper would lose.
						'click': function(ev) {
							const button = ev.currentTarget;
							copyToClipboard(logs).then(function() {
								ui.addNotification(null, E('p', {}, _('Журнал скопирован в буфер обмена')), 'info');
							}, function() {
								ui.addNotification(null, E('p', {}, _('Не удалось скопировать журнал. Выделите текст и скопируйте вручную.')), 'error');
							});
							button.blur();
						}
					}, _('Скопировать журнал'))
				]),
				E('pre', { 'style': 'max-height:24em;overflow:auto;white-space:pre-wrap' }, logs || _('Записей пока нет'))
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});

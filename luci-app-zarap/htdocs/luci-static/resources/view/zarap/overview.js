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

// Everything the page is about to submit, held here rather than read back out
// of the DOM. Editing rules means rows appear, vanish and change places, and
// reading values off a table that is being rebuilt underneath does not survive
// that. Nothing here reaches the router until "Сохранить и применить".
const state = {
	enabled: false,
	outbounds: [],
	rules: [],
	final: 'direct',
	devices: [],
	// Whether the kill switch chains are loaded, reported by the router. Only
	// affects how a guarded device is labelled, never whether it is guarded.
	firewall: false
};

function loadState(status) {
	state.enabled = !!status.enabled;
	state.outbounds = (status.outbounds || []).map(function(outbound) {
		return {
			tag: outbound.tag,
			label: outbound.label || '',
			masked_link: outbound.masked_link || ''
		};
	});
	state.rules = (status.rules || []).map(function(rule) {
		return { clients: (rule.clients || []).slice(), target: rule.target };
	});
	state.final = status.final || 'direct';
	state.firewall = !!status.firewall;
	state.devices = (status.devices || []).map(function(device) {
		return Object.assign({}, device);
	});
}

// Which devices the kill switch holds, worked out from the rules on this page
// rather than taken from status. The router only knows the rules it has already
// applied, so a device just added to an unsaved rule would otherwise get no
// address field — and the apply would then fail for the address it never let
// anyone enter.
function guardedMacs() {
	const macs = {};
	state.rules.forEach(function(rule) {
		(rule.clients || []).forEach(function(mac) { macs[mac] = true; });
	});
	return macs;
}

// The first rule naming a device decides where its traffic goes; a device no
// rule names falls through to the remainder.
function resolvedTarget(mac) {
	for (let index = 0; index < state.rules.length; index++)
		if ((state.rules[index].clients || []).indexOf(mac) >= 0)
			return state.rules[index].target;
	return state.final;
}

function isUsed(tag) {
	return state.final === tag
		|| state.rules.some(function(rule) { return rule.target === tag; });
}

// Only devices a rule names carry a lease, and those are exactly the ones the
// apply has to send back. The rest of the table is there to be looked at.
function leasedClients() {
	const guarded = guardedMacs();
	return state.devices
		.filter(function(device) { return guarded[device.mac]; })
		.map(function(device) {
			return {
				mac: device.mac,
				name: (device.name || '').trim(),
				ip: (device.ip || '').trim()
			};
		});
}

// Connections round-trip by tag with an empty link, which tells the router to
// keep the secret it already holds. A pasted link adds one.
function submittedOutbounds() {
	const sent = state.outbounds.map(function(outbound) {
		return { tag: outbound.tag, label: outbound.label || '', link: '' };
	});
	const added = document.querySelector('#zarap-link').value.trim();
	if (added)
		sent.push({ tag: '', label: '', link: added });
	return sent;
}

function targetLabel(target) {
	if (target === 'direct')
		return _('напрямую');
	if (target === 'block')
		return _('заблокировано');
	const match = state.outbounds.filter(function(outbound) {
		return outbound.tag === target;
	})[0];
	return match && match.label ? '%s (%s)'.format(match.label, target) : target;
}

// Edits go straight into the state so a redraw cannot lose them.
function bindField(device, field, placeholder) {
	const input = E('input', {
		'class': 'cbi-input-text', 'data-field': field,
		'value': device[field] || '', 'placeholder': placeholder
	});
	input.addEventListener('input', function() { device[field] = input.value; });
	return input;
}

function deviceRow(device) {
	const unavailable = device.private_mac;
	const reason = unavailable ? _('Приватный MAC: отключите рандомизацию MAC на устройстве') : '';
	const guarded = !!guardedMacs()[device.mac];
	// Holds even with Zarap switched off: only deleting the rule that names a
	// device opens its direct path to the WAN.
	const killSwitch = state.firewall && guarded;
	return E('tr', {
		'class': 'tr', 'data-mac': device.mac, 'data-guarded': guarded ? '1' : '0'
	}, [
		E('td', { 'class': 'td' }, guarded
			? [ bindField(device, 'name', _('Имя устройства')) ]
			: (device.name || '')),
		E('td', { 'class': 'td' }, device.mac),
		E('td', { 'class': 'td' }, guarded
			? [ bindField(device, 'ip', '192.168.1.100') ]
			: (device.ip || '')),
		E('td', { 'class': 'td' }, targetLabel(resolvedTarget(device.mac))),
		E('td', { 'class': 'td' }, [
			device.connected ? statusPill(true, _('в сети'), '') : statusPill(false, '', _('не в сети')),
			killSwitch ? statusPill(true, _(' kill switch'), '') : '',
			device.wireless && device.network ? E('small', {}, ' Wi-Fi: ' + device.network) : '',
			unavailable ? E('div', { 'class': 'error' }, reason) : ''
		])
	]);
}

function outboundRow(outbound) {
	const used = isUsed(outbound.tag);
	return E('tr', { 'class': 'tr', 'data-tag': outbound.tag }, [
		E('td', { 'class': 'td' }, outbound.tag),
		E('td', { 'class': 'td' }, outbound.label || '—'),
		E('td', { 'class': 'td' }, E('code', {}, outbound.masked_link || '')),
		E('td', { 'class': 'td' }, used
			? statusPill(true, _('используется'), '')
			: statusPill(false, '', _('не используется')))
	]);
}

function ruleRow(rule, index) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td' }, String(index + 1)),
		E('td', { 'class': 'td' }, (rule.clients || []).join(', ')),
		E('td', { 'class': 'td' }, targetLabel(rule.target))
	]);
}

// The three sections that change while the page is open. Each renders straight
// from the state, so a redraw after an edit needs no other bookkeeping.
function renderOutbounds() {
	return state.outbounds.length
		? state.outbounds.map(outboundRow)
		: E('tr', {}, E('td', { 'colspan': 4 }, _('Подключений пока нет')));
}

function renderRules() {
	return state.rules.length
		? state.rules.map(ruleRow)
		: E('tr', {}, E('td', { 'colspan': 3 }, _('Правил пока нет: весь трафик идёт по умолчанию')));
}

function renderDevices() {
	return state.devices.length
		? state.devices.map(deviceRow)
		: E('tr', {}, E('td', { 'colspan': 5 }, _('Устройства пока не обнаружены')));
}

// Redraws everything a rule change can affect: which connection counts as used,
// which device carries a lease, and where each device's traffic ends up.
function refresh() {
	dom.content(document.querySelector('#zarap-outbounds-body'), renderOutbounds());
	dom.content(document.querySelector('#zarap-rules-body'), renderRules());
	dom.content(document.querySelector('#zarap-devices-body'), renderDevices());
	dom.content(document.querySelector('#zarap-final'),
		_('Остальной трафик: %s').format(targetLabel(state.final)));
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
		const updates = (data[1] && data[1].components) || {};
		const logs = (data[2] && data[2].logs) || '';
		loadState(status);

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
					E('tbody', { 'id': 'zarap-outbounds-body' }, renderOutbounds())
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
						E('input', { 'id': 'zarap-enabled', 'type': 'checkbox', 'checked': state.enabled ? '' : null })
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
					E('tbody', { 'id': 'zarap-rules-body' }, renderRules())
				]),
				E('p', { 'id': 'zarap-final' }, _('Остальной трафик: %s').format(targetLabel(state.final))),
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
					E('tbody', { 'id': 'zarap-devices-body' }, renderDevices())
				]),
				E('div', { 'class': 'cbi-page-actions', 'style': ACTION_ROW }, [
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.createHandlerFn(this, async function() {
							notify(await callValidate(submittedOutbounds(), state.rules,
								leasedClients(), state.final), _('Конфигурация корректна'));
						})
					}, _('Проверить конфигурацию')),
					E('button', {
						'class': 'btn cbi-button-save important',
						'click': ui.createHandlerFn(this, async function(ev) {
							ev.currentTarget.disabled = true;
							const result = await callApply(
								document.querySelector('#zarap-enabled').checked,
								submittedOutbounds(),
								state.rules,
								leasedClients(),
								state.final
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

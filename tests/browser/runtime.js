'use strict';

String.prototype.format = function(...args) {
  let index = 0;
  return String(this).replace(/%[sd]/g, () => String(args[index++]));
};

window._ = value => String(value);
window.__rpcCalls = [];
window.__reloadRequested = false;
window.__mockState = { applyError: '', validateError: '', updateError: '' };

const fixtures = {
  status: {
    ok: true,
    enabled: true,
    configured: true,
    state: 'working',
    message: 'Zarap работает',
    running: true,
    listener: true,
    firewall: true,
    routing: true,
    outbounds: [
      {
        tag: 'out_1', label: 'Нидерланды', in_use: true,
        masked_link: 'vless://********@proxy.example.test:443?security=reality&type=tcp&sni=cdn.example.test#Нидерланды'
      },
      {
        tag: 'out_2', label: 'Германия', in_use: false,
        masked_link: 'vless://********@de.example.test:443?security=reality&type=tcp&sni=cdn.example.test#Германия'
      }
    ],
    rules: [
      { clients: ['00:11:22:33:44:55'], target: 'out_1' },
      { clients: ['10:20:30:40:50:60'], target: 'block' }
    ],
    final: 'direct',
    capture: { interface: 'br-lan', active: true },
    devices: [
      {
        mac: '00:11:22:33:44:55', name: 'Телевизор', ip: '192.168.1.50',
        connected: true, wireless: true, network: 'Home', signal: -48,
        has_static_lease: true, private_mac: false,
        guarded: true, resolved_target: 'out_1'
      },
      {
        mac: '10:20:30:40:50:60', name: 'Планшет', ip: '192.168.1.61',
        connected: true, wireless: true, network: 'Home', signal: -62,
        has_static_lease: true, private_mac: false,
        guarded: true, resolved_target: 'block'
      },
      {
        mac: '02:AA:BB:CC:DD:EE', name: 'Телефон', ip: '192.168.1.72',
        connected: true, wireless: true, network: 'Home', signal: -55,
        has_static_lease: false, private_mac: true,
        guarded: false, resolved_target: 'direct'
      },
      {
        mac: 'AA:BB:CC:DD:EE:FF', name: 'Принтер', ip: '192.168.1.80',
        connected: true, wireless: false,
        has_static_lease: false, private_mac: false,
        guarded: false, resolved_target: 'direct'
      }
    ]
  },
  components: {
	'luci-app-zarap': { installed: '0.1.0-r1', checked: false, update_available: false, candidate: '' },
	'sing-box': { installed: '1.12.22-r1', checked: false, update_available: false, candidate: '' }
  },
  refreshedComponents: {
    'luci-app-zarap': {
      installed: '0.1.0-r1', update_available: true,
      checked: true,
      candidate: '0.2.0-r1'
    },
    'sing-box': {
      installed: '1.12.22-r1', update_available: true,
      checked: true,
      candidate: '1.12.23-r1'
    }
  }
};

function clone(value) {
  return structuredClone(value);
}

const handlers = {
  status: () => Object.assign(clone(fixtures.status), window.__statusOverride || {}),
  logs: () => ({ ok: true, logs: 'sing-box запущен\nUUID: [скрыто]\nReality key: [скрыто]' }),
  updates: refresh => (refresh && window.__mockState.updatesRpcStatus != null
    ? window.__mockState.updatesRpcStatus
    : refresh && window.__mockState.updatesError
    ? {
      ok: false,
      error: 'apk не смог обновить списки репозиториев',
      details: window.__mockState.updatesError,
      kind: 'operation_error',
      refresh_code: 1,
      components: clone(fixtures.components)
    }
    : {
      ok: true,
      refresh_code: 0,
      components: clone(refresh ? fixtures.refreshedComponents : fixtures.components)
    }),
  validate: () => window.__mockState.validateError
	? { ok: false, error: window.__mockState.validateError, kind: 'input_error' }
    : { ok: true, outbounds: 2, rules: 2, clients: 2, capture: 'br-lan' },
  apply: () => window.__mockState.applyError
    ? { ok: false, error: window.__mockState.applyError }
    : { ok: true, enabled: true },
  restart: () => ({ ok: true }),
  stop: () => ({ ok: true }),
  update_component: name => window.__mockState.updateError
    ? { ok: false, error: window.__mockState.updateError }
    : { ok: true, component: name }
};

window.rpc = {
  getStatusText(code) {
    return ({ 6: 'Permission denied', 7: 'Timeout' })[code] || 'Unknown error';
  },

  declare(definition) {
    return async (...args) => {
      window.__rpcCalls.push({ object: definition.object, method: definition.method, args: clone(args) });
      const handler = handlers[definition.method];
      if (!handler)
        throw new Error(`Нет RPC mock для ${definition.method}`);
      return handler(...args);
    };
  }
};

function append(parent, value) {
  if (value == null || value === false)
    return;
  if (Array.isArray(value)) {
    value.forEach(item => append(parent, item));
    return;
  }
  parent.append(value instanceof Node ? value : document.createTextNode(String(value)));
}

window.E = function(tag, attributes, children) {
  if (attributes == null || Array.isArray(attributes) || attributes instanceof Node || typeof attributes !== 'object') {
    children = attributes;
    attributes = {};
  }
  const element = document.createElement(tag);
  Object.entries(attributes).forEach(([name, value]) => {
    if (value == null || value === false)
      return;
    if (name === 'click')
      element.addEventListener('click', value);
    else if (name === 'checked' || name === 'disabled' || name === 'selected')
      // LuCI applies these as attributes, where any value marks them set. The
      // property assignment below would take '' as false.
      element[name] = true;
    else if (name === 'class')
      element.className = value;
    else if (name in element && !name.startsWith('data-'))
      element[name] = value;
    else
      element.setAttribute(name, value);
  });
  append(element, children);
  return element;
};

window.dom = {
  content(element, content) {
    element.replaceChildren();
    append(element, content);
  }
};

window.ui = {
  createHandlerFn(context, handler) {
    return event => Promise.resolve(handler.call(context, event)).catch(error => {
      window.ui.addNotification(null, E('p', {}, error.message), 'error');
    });
  },
  addNotification(_title, content, level) {
    const notice = E('div', { class: `notification ${level}`, 'data-level': level }, content);
    document.querySelector('#notifications').append(notice);
  },
  showModal(title, content) {
    const root = document.querySelector('#modal-root');
    root.replaceChildren(E('div', { id: 'modal', role: 'dialog', 'aria-modal': 'true' }, [
      E('h2', {}, title), content
    ]));
  },
  hideModal() {
    document.querySelector('#modal-root').replaceChildren();
  }
};

window.view = { extend: definition => definition };
window.L = {
  resolveDefault(promise, fallback) {
    return Promise.resolve(promise).catch(() => fallback);
  }
};

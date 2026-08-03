await import('/overview.js');

const data = await window.__zarapView.load();
document.querySelector('#app').replaceChildren(window.__zarapView.render(data));
document.body.dataset.ready = 'true';

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';

const browserDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(browserDir, '..', '..');
const viewPath = join(repositoryRoot, 'htdocs/luci-static/resources/view/zarap/overview.js');
const port = Number(process.env.PORT || 4173);

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8'
};

function extension(path) {
  const match = path.match(/(\.[a-z]+)$/i);
  return match ? match[1] : '';
}

async function transformedView() {
  const source = await readFile(viewPath, 'utf8');
  return source
    .replace('return view.extend({', 'window.__zarapView = view.extend({')
    .replaceAll('window.location.reload()', 'window.__reloadRequested = true');
}

createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
    if (pathname === '/health') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
      return;
    }
    if (pathname === '/overview.js') {
      response.writeHead(200, { 'content-type': contentTypes['.js'] });
      response.end(await transformedView());
      return;
    }

    const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
    const safePath = normalize(join(browserDir, relative));
    if (!safePath.startsWith(browserDir)) {
      response.writeHead(403);
      response.end('forbidden');
      return;
    }

    const body = await readFile(safePath);
    response.writeHead(200, { 'content-type': contentTypes[extension(safePath)] || 'application/octet-stream' });
    response.end(body);
  }
  catch (error) {
    response.writeHead(error.code === 'ENOENT' ? 404 : 500, { 'content-type': 'text/plain' });
    response.end(error.message);
  }
}).listen(port, '127.0.0.1', () => {
  console.log(`Zarap browser harness: http://127.0.0.1:${port}`);
});

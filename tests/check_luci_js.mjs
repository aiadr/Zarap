import { readFile } from 'node:fs/promises';

const source = await readFile(
  new URL('../htdocs/luci-static/resources/view/zarap/overview.js', import.meta.url),
  'utf8',
);

// LuCI view files are function bodies and intentionally use a top-level return.
// Compiling the source as a function checks its syntax in the same context.
new Function(source);

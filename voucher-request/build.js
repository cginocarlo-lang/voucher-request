// Flattens src/Index.html (Apps Script template) into public/index.html
import fs from 'node:fs';
const rd = f => fs.readFileSync(f, 'utf8');
const shim = rd('shim.html');
const html = rd('src/Index.html').replace(/<\?!= include\('([^']+)'\) \?>/g,
  (_, n) => (n === 'Js common' ? shim : '') + rd(`src/${n}.html`));
fs.mkdirSync('public', { recursive: true });
fs.writeFileSync('public/index.html', html);

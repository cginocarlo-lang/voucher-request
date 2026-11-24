// Flattens src/Index.html (Apps Script template) into public/index.html
import fs from 'node:fs';
const rd = f => fs.readFileSync(f, 'utf8');
const norm = s => s.toLowerCase().replace(/\.html?$/, '').replace(/[^a-z0-9]/g, '');
const files = fs.existsSync('src') ? fs.readdirSync('src') : [];
const byName = Object.fromEntries(files.map(f => [norm(f), f]));
const need = n => {
  const f = byName[norm(n)];
  if (!f) throw new Error(`Missing src file for "${n}". src/ currently has: ${files.join(', ') || '(empty or missing)'}`);
  return rd('src/' + f);
};
const shim = rd('shim.html');
const html = need('Index').replace(/<\?!= include\('([^']+)'\) \?>/g,
  (_, n) => (n === 'Js common' ? shim : '') + need(n));
fs.mkdirSync('public', { recursive: true });
fs.writeFileSync('public/index.html', html);

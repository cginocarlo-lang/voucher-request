import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
const TTL = 6 * 3600 * 1000;

const fail = m => { throw new Error(m); };
const run = async q => { const { data, error } = await q; if (error) fail(error.message); return data; };
const fetchAll = async make => { const out = []; for (let i = 0; ; i += 1000) { const r = await run(make().range(i, i + 999)); out.push(...r); if (r.length < 1000) return out; } };
const sha = (p, salt) => crypto.createHash('sha256').update(salt + ':' + p).digest('hex'); // same as Apps Script, so old hashes still work
const same = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const lc = s => String(s || '').trim().toLowerCase();
const num = v => Number(v) || 0;
const round2 = n => Math.round(n * 100) / 100;
const fmtDate = d => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'Asia/Manila' });
const pub = u => ({ username: u.username, name: u.name || '', office: u.office || '', role: u.role, mustChange: !!u.must_change });

const getUser = name => run(db.from('users').select('*').ilike('username', String(name || '').trim().replace(/[\\%_]/g, '\\$&')).maybeSingle());

// Session lookup also re-reads the user, so disabling a user or changing a role applies immediately
async function requireUser(token) {
  if (!token) fail('Sign in to continue.');
  const s = await run(db.from('sessions').select('*').eq('token', String(token)).maybeSingle());
  if (!s || new Date(s.exp) < new Date()) fail('Your session expired. Please sign in again.');
  const u = await getUser(s.username);
  if (!u || !u.active) fail('Your session expired. Please sign in again.');
  return pub(u);
}
const writer = async t => { const u = await requireUser(t); if (u.role === 'viewer') fail('You have read-only access.'); return u; };
const admin = async t => { const u = await requireUser(t); if (u.role !== 'admin') fail('Administrator access required.'); return u; };

// Usernames that belong to the same office as this user (blank office = just that user)
async function namesFor(username) {
  const all = await run(db.from('users').select('username,office'));
  const key = u => lc(u.office || u.username);
  const me = all.find(u => lc(u.username) === lc(username));
  const k = me ? key(me) : lc(username);
  const names = all.filter(u => key(u) === k).map(u => u.username);
  return names.length ? names : [username];
}

async function checkDup(owner, col, value, excludeId, label) {
  if (!value) return;
  let q = db.from('obr').select('id').eq(col, value).in('owner', await namesFor(owner)).limit(1);
  if (excludeId) q = q.neq('id', excludeId);
  if ((await run(q)).length) fail(label + ' ' + value + ' already exists. Use a different number.');
}

async function ownRow(id, user) {
  const r = id ? await run(db.from('obr').select('*').eq('id', id).maybeSingle()) : null;
  if (!r) fail('Record not found. Refresh the list and try again.');
  if (user.role !== 'admin' && !(await namesFor(user.username)).includes(r.owner)) fail("You cannot change another office's record.");
  return r;
}

const cleanItems = items => (items || []).map(it => ({
  rc: String(it.rc || '').trim(), particulars: String(it.particulars || '').trim(),
  fpp: String(it.fpp || '').trim(), acct: String(it.acct || '').trim(), amount: num(it.amount)
})).filter(it => it.rc || it.particulars || it.fpp || it.acct || it.amount);
const totalOf = items => round2(items.reduce((s, it) => s + num(it.amount), 0));

const toRec = r => ({
  date: fmtDate(r.created_at), obrNo: r.obr_no || '', payee: r.payee || '', office: r.office || '', address: r.address || '',
  items: r.items || [], amount: num(r.amount), id: r.id,
  dvNo: r.dv_no || '', dvDate: r.dv_date || '', idNo: r.id_no || '', dvClass: r.dv_class || '', owner: r.owner
});

const H = {
  async login(username, password) {
    username = String(username || '').trim(); password = String(password || '');
    if (!username || !password) fail('Enter your username and password.');
    let u = await getUser(username);
    if (!u && lc(username) === 'admin') { // first run only: create the admin, who must change the password
      const { count } = await db.from('users').select('*', { count: 'exact', head: true });
      if (!count) {
        const salt = crypto.randomUUID();
        u = await run(db.from('users').insert({ username: 'admin', salt, password_hash: sha('admin12345', salt), role: 'admin', office: 'PHO', name: 'Administrator', must_change: true }).select().single());
      }
    }
    if (!u || !u.active || !same(sha(password, u.salt), u.password_hash)) fail('Invalid username or password.');
    const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    await db.from('sessions').delete().lt('exp', new Date().toISOString());
    await run(db.from('sessions').insert({ token, username: u.username, exp: new Date(Date.now() + TTL).toISOString() }));
    return { token, user: pub(u) };
  },
  async logout(token) { if (token) await db.from('sessions').delete().eq('token', String(token)); return true; },
  whoAmI: token => requireUser(token),

  async changePassword(token, oldPass, newPass) {
    const me = await requireUser(token);
    if (!newPass || newPass.length < 4) fail('Password must be at least 4 characters.');
    const u = await getUser(me.username);
    if (!same(sha(oldPass || '', u.salt), u.password_hash)) fail('Current password is incorrect.');
    const salt = crypto.randomUUID();
    await run(db.from('users').update({ salt, password_hash: sha(newPass, salt), must_change: false }).eq('username', u.username));
    return { ...me, mustChange: false };
  },
  async listUsers(token) {
    await admin(token);
    return (await run(db.from('users').select('*').order('username'))).map(u => ({ username: u.username, active: u.active, role: u.role, office: u.office || '', name: u.name || '' }));
  },
  async saveUser(token, d) {
    const me = await admin(token);
    const username = String(d.username || '').trim();
    if (!username) fail('Username is required.');
    const role = ['admin', 'office', 'viewer'].includes(d.role) ? d.role : 'office';
    const f = { role, name: String(d.name || '').trim(), office: String(d.office || '').trim(), active: d.active === true || d.active === 'true' };
    const ex = await getUser(username);
    if (ex) {
      if (lc(ex.username) === lc(me.username) && (!f.active || role !== 'admin')) fail('You cannot disable or demote your own account.');
      if (d.password && d.password.length < 4) fail('Password must be at least 4 characters.');
      if (d.password) { f.salt = crypto.randomUUID(); f.password_hash = sha(d.password, f.salt); }
      await run(db.from('users').update(f).eq('username', ex.username));
    } else {
      if (!d.password || d.password.length < 4) fail('Temporary password must be at least 4 characters.');
      const salt = crypto.randomUUID();
      await run(db.from('users').insert({ username, salt, password_hash: sha(d.password, salt), must_change: true, ...f }));
    }
    return { ok: true };
  },
  async resetPassword(token, username, tmp) {
    await admin(token);
    if (!tmp || tmp.length < 4) fail('Temporary password must be at least 4 characters.');
    const u = await getUser(username);
    if (!u) fail('User not found.');
    const salt = crypto.randomUUID();
    await run(db.from('users').update({ salt, password_hash: sha(tmp, salt), must_change: true }).eq('username', u.username));
    await db.from('sessions').delete().eq('username', u.username);
    return { ok: true };
  },

  async getLookups(token) {
    await requireUser(token);
    const pick = t => run(db.from(t).select('title,code').order('code'));
    const [a, r, f] = await Promise.all([pick('account_codes'), pick('rc_codes'), pick('fpp_codes')]);
    return { acctOptions: a, rcOptions: r, fppOptions: f };
  },
  async getDefaults(token) {
    await requireUser(token);
    const out = { reqName: '', reqPos: '', budName: '', budPos: '', accName: '', treName: '', govName: '' };
    const rows = (await run(db.from('dept_head').select('name,title'))).map(r => ({ name: String(r.name || '').trim(), title: String(r.title || '').trim() })).filter(r => r.name);
    const find = w => rows.find(r => r.title.toLowerCase().includes(w));
    const bud = find('budget'), acc = find('accountant'), tre = find('treasurer'), gov = find('governor');
    const req = rows.find(r => ![bud, acc, tre, gov].includes(r));
    if (req) { out.reqName = req.name; out.reqPos = req.title; }
    if (bud) { out.budName = bud.name; out.budPos = bud.title; }
    if (acc) out.accName = acc.name;
    if (tre) out.treName = tre.name;
    if (gov) out.govName = gov.name;
    return out;
  },

  async getObrs(token) {
    const user = await requireUser(token);
    const names = user.role === 'admin' ? null : await namesFor(user.username);
    const rows = await fetchAll(() => {
      const q = db.from('obr').select('*').order('created_at', { ascending: false }).order('id');
      return names ? q.in('owner', names) : q;
    });
    return rows.map(toRec);
  },
  async saveObr(token, d) {
    const user = await writer(token);
    const obrNo = String(d.obrNo || '').trim(), items = cleanItems(d.items);
    await checkDup(user.username, 'obr_no', obrNo, null, 'ObR No.');
    const r = await run(db.from('obr').insert({ obr_no: obrNo, payee: d.payee || '', office: d.office || '', address: d.address || '', items, amount: totalOf(items), owner: user.username }).select().single());
    return { ok: true, obrNo, id: r.id, amount: num(r.amount), items, owner: user.username, date: fmtDate(r.created_at) };
  },
  async updateObr(token, d) {
    const user = await writer(token);
    const row = await ownRow(d.id, user);
    const newNo = String(d.obrNo || '').trim(), items = cleanItems(d.items);
    await checkDup(row.owner, 'obr_no', newNo, row.id, 'ObR No.');
    await run(db.from('obr').update({ obr_no: newNo, payee: d.payee || '', office: d.office || '', address: d.address || '', items, amount: totalOf(items) }).eq('id', row.id));
    return { ok: true, obrNo: newNo, id: row.id, amount: totalOf(items), items };
  },
  async saveDv(token, d) {
    const user = await writer(token);
    const row = await ownRow(d.id, user);
    const c = k => String(d[k] || '').trim();
    const dv = { dvNo: c('dvNo'), dvDate: c('dvDate'), idNo: c('idNo'), dvClass: c('dvClass') };
    await checkDup(row.owner, 'dv_no', dv.dvNo, row.id, 'DV No.');
    await run(db.from('obr').update({ dv_no: dv.dvNo, dv_date: dv.dvDate, id_no: dv.idNo, dv_class: dv.dvClass }).eq('id', row.id));
    return { ok: true, id: row.id, ...dv };
  },

  async getAccountBudgets(token) {
    await requireUser(token);
    return (await run(db.from('account_codes').select('title,code,budget').order('code'))).map(r => ({ title: r.title || '', code: r.code, budget: num(r.budget) }));
  },
  async getUsage(token) {
    const user = await requireUser(token);
    const mine = new Set(await namesFor(user.username));
    const rows = await fetchAll(() => db.from('obr').select('items,owner').order('id'));
    const out = { obr: {}, mine: {}, obrCount: 0 };
    rows.forEach(r => {
      const items = r.items || [];
      if (!items.length) return;
      out.obrCount++;
      items.forEach(it => {
        const c = String(it.acct || '').trim(), a = num(it.amount);
        out.obr[c] = (out.obr[c] || 0) + a;
        if (mine.has(r.owner)) out.mine[c] = (out.mine[c] || 0) + a;
      });
    });
    return out;
  }
};

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const { fn, args = [] } = req.body || {};
  if (!Object.hasOwn(H, fn)) return res.status(404).json({ error: 'Unknown function' });
  try { res.status(200).json({ result: await H[fn](...args) }); }
  catch (e) { res.status(200).json({ error: e.message }); }
}

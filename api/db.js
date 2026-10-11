import { neon } from '@neondatabase/serverless';

const db = neon(process.env.DATABASE_URL);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin2026';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-please-now';

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}
async function signJWT(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const data = header + '.' + body;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data + '.' + b64url(Buffer.from(sig));
}
async function verifyJWT(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const data = parts[0] + '.' + parts[1];
  try {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBuf = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) { return null; }
}

const INV_TABLES = ['products', 'customers', 'orders', 'logs', 'public_requests', 'customer_accounts'];

function getTableInfo(sqlText) {
  const s = sqlText.trim();
  let m = s.match(/^SELECT\b[\s\S]*?\bFROM\s+"?(\w+)"?/i);
  if (m) return { verb: 'SELECT', table: m[1] };
  m = s.match(/^INSERT\s+INTO\s+"?(\w+)"?/i);
  if (m) return { verb: 'INSERT INTO', table: m[1] };
  m = s.match(/^UPDATE\s+"?(\w+)"?/i);
  if (m) return { verb: 'UPDATE', table: m[1] };
  m = s.match(/^DELETE\s+FROM\s+"?(\w+)"?/i);
  if (m) return { verb: 'DELETE FROM', table: m[1] };
  return null;
}

function verifyQuery(sqlText, params, claims) {
  const info = getTableInfo(sqlText);
  if (!info) throw new Error('Cannot parse SQL');
  const { verb, table } = info;

  if (table === 'inventories') {
    if (verb === 'SELECT') {
      if (/public_token/i.test(sqlText)) return true;
      const m = sqlText.match(/\bid\s*=\s*\$(\d+)/i);
      if (!m) throw new Error('inventories query must filter by id');
      const idx = parseInt(m[1]) - 1;
      if (String(params[idx]) !== String(claims.invId)) throw new Error('inv_id mismatch');
    } else if (verb === 'UPDATE') {
      const m = sqlText.match(/\bid\s*=\s*\$(\d+)/i);
      if (!m) throw new Error('UPDATE must filter by id');
      const idx = parseInt(m[1]) - 1;
      if (String(params[idx]) !== String(claims.invId)) throw new Error('inv_id mismatch');
    } else {
      throw new Error('Operation not allowed on inventories');
    }
    return true;
  }

  if (!INV_TABLES.includes(table)) throw new Error('Table not allowed');

  if (verb.startsWith('SELECT') || verb.startsWith('UPDATE') || verb.startsWith('DELETE')) {
    const m = sqlText.match(/\binv_id\s*=\s*\$(\d+)/i);
    if (!m) throw new Error('Query must filter by inv_id');
    const idx = parseInt(m[1]) - 1;
    if (String(params[idx]) !== String(claims.invId)) throw new Error('inv_id mismatch');
  } else if (verb.startsWith('INSERT')) {
    const m = sqlText.match(/INSERT\s+INTO\s+"?\w+"?\s*\(([^)]+)\)/i);
    if (!m) throw new Error('Cannot parse INSERT');
    const cols = m[1].split(',').map(c => c.trim().replace(/"/g, '').toLowerCase());
    const invIdx = cols.indexOf('inv_id');
    if (invIdx === -1) throw new Error('INSERT must include inv_id');
    const valuesMatch = sqlText.match(/VALUES\s*\(([^)]+)\)/i);
    if (!valuesMatch) throw new Error('Cannot parse VALUES');
    const vals = valuesMatch[1].split(',').map(v => v.trim());
    const ph = vals[invIdx].match(/^\$(\d+)$/);
    if (!ph) throw new Error('inv_id must be parameterized');
    const paramIdx = parseInt(ph[1]) - 1;
    if (String(params[paramIdx]) !== String(claims.invId)) throw new Error('inv_id mismatch');
  }
  return true;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method === 'GET') return res.json({ ok: true, message: 'API works' });
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = req.body || {};
    const { action, payload, sql: sqlText, params: reqParams } = body;

    if (action === 'login') {
      const { user, invName, password } = payload || {};
      if (!user || !invName || !password) return res.status(400).json({ error: 'بيانات ناقصة' });

      if (invName === '__admin__' || invName.toLowerCase() === 'admin') {
        let realPass = ADMIN_PASSWORD;
        try {
          const rows = await db.query("SELECT password FROM inventories WHERE name='__admin__config__' LIMIT 1");
          if (rows[0] && rows[0].password) realPass = rows[0].password;
        } catch (e) {}
        if (password !== realPass) return res.status(401).json({ error: 'كلمة سر الأدمن خطأ' });
        const token = await signJWT({ role: 'admin', user, exp: Math.floor(Date.now() / 1000) + 86400 * 30 });
        return res.json({ token, role: 'admin', user });
      }

      const rows = await db.query('SELECT * FROM inventories WHERE name = $1 LIMIT 1', [invName]);
      if (!rows.length) return res.status(404).json({ error: 'لا يوجد مخزون' });
      const inv = rows[0];
      if (inv.password !== password) return res.status(401).json({ error: 'كلمة السر خطأ' });
      if (inv.status === 'suspended') return res.status(403).json({ error: 'موقوف' });
      if (inv.expires_at && new Date(inv.expires_at) < new Date()) return res.status(403).json({ error: 'انتهت المدة' });

      let mem = inv.members;
      if (typeof mem === 'string') { try { mem = JSON.parse(mem); } catch { mem = []; } }
      if (!Array.isArray(mem)) mem = [];
      if (!mem.includes(user)) {
        mem.push(user);
        await db.query('UPDATE inventories SET members = $1::jsonb WHERE id = $2', [JSON.stringify(mem), inv.id]);
      }

      const token = await signJWT({ role: 'inv', invId: inv.id, user, exp: Math.floor(Date.now() / 1000) + 86400 * 30 });
      return res.json({ token, role: 'inv', invId: inv.id, invName: inv.name, user });
    }

    if (action === 'catalog_init') {
      const { token } = payload || {};
      const rows = await db.query('SELECT * FROM inventories WHERE public_token = $1 LIMIT 1', [token]);
      if (!rows.length) return res.status(404).json({ error: 'invalid' });
      return res.json({ inv: rows[0] });
    }

    if (action === 'catalog_products') {
      const { token } = payload || {};
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 AND public_enabled = true LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      const rows = await db.query('SELECT * FROM products WHERE inv_id = $1 AND qty > 0 ORDER BY name', [invRows[0].id]);
      return res.json({ products: rows });
    }

    if (action === 'catalog_register') {
      const { token, name, phone, password } = payload || {};
      if (!name || !phone || !password || password.length < 4) return res.status(400).json({ error: 'بيانات ناقصة' });
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 AND public_enabled = true LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      try {
        const rows = await db.query('INSERT INTO customer_accounts (inv_id, name, phone, password) VALUES ($1, $2, $3, $4) RETURNING *', [invRows[0].id, name, phone, password]);
        return res.json({ account: rows[0] });
      } catch (e) {
        if (e.code === '23505') return res.status(409).json({ error: 'مسجل مسبقا' });
        throw e;
      }
    }

    if (action === 'catalog_login') {
      const { token, phone, password } = payload || {};
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 AND public_enabled = true LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      const rows = await db.query('SELECT * FROM customer_accounts WHERE inv_id = $1 AND phone = $2 LIMIT 1', [invRows[0].id, phone]);
      if (!rows.length) return res.status(404).json({ error: 'لا يوجد حساب' });
      if (rows[0].password !== password) return res.status(401).json({ error: 'كلمة السر خطأ' });
      return res.json({ account: { id: rows[0].id, name: rows[0].name, phone: rows[0].phone } });
    }

    if (action === 'catalog_my_requests') {
      const { token, accountId } = payload || {};
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      const rows = await db.query('SELECT * FROM public_requests WHERE inv_id = $1 AND customer_id = $2 ORDER BY created_at DESC LIMIT 1000', [invRows[0].id, accountId]);
      return res.json({ requests: rows });
    }

    if (action === 'catalog_submit_request') {
      const { token, accountId, items, note } = payload || {};
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 AND public_enabled = true LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      const accRows = await db.query('SELECT * FROM customer_accounts WHERE id = $1 AND inv_id = $2 LIMIT 1', [accountId, invRows[0].id]);
      if (!accRows.length) return res.status(403).json({ error: 'invalid account' });
      const acc = accRows[0];
      await db.query('INSERT INTO public_requests (inv_id, customer_id, customer_name, customer_phone, items, note, status) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)', [invRows[0].id, acc.id, acc.name, acc.phone, JSON.stringify(items), note || '', 'new']);
      return res.json({ ok: true });
    }

    if (action === 'catalog_mark_seen') {
      const { token, requestId } = payload || {};
      const invRows = await db.query('SELECT id FROM inventories WHERE public_token = $1 LIMIT 1', [token]);
      if (!invRows.length) return res.status(404).json({ error: 'invalid' });
      await db.query('UPDATE public_requests SET customer_seen = true WHERE id = $1 AND inv_id = $2', [requestId, invRows[0].id]);
      return res.json({ ok: true });
    }

    if (action === 'admin_op') {
      const auth = req.headers.authorization || '';
      const claims = await verifyJWT(auth.replace(/^Bearer\s+/i, ''));
      if (!claims || claims.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
      const { op, data } = payload || {};
      if (op === 'list') {
        const rows = await db.query("SELECT * FROM inventories WHERE name NOT IN ('__admin__config__','__admin__') ORDER BY created_at DESC");
        return res.json({ data: rows });
      }
      if (op === 'createInv') {
        const exp = new Date(Date.now() + (data.days || 30) * 86400000).toISOString();
        const rows = await db.query("INSERT INTO inventories (name, password, owner_name, status, expires_at, members, cleanup_months) VALUES ($1,$2,$3,'active',$4,'[]'::jsonb,1) RETURNING *", [data.name, data.password, data.ownerName || '', exp]);
        return res.json({ data: rows[0] });
      }
      if (op === 'toggle') {
        if (data.expiresAt) await db.query('UPDATE inventories SET status=$1, expires_at=$2 WHERE id=$3', [data.status, data.expiresAt, data.id]);
        else await db.query('UPDATE inventories SET status=$1 WHERE id=$2', [data.status, data.id]);
        return res.json({ ok: true });
      }
      if (op === 'extend') {
        await db.query('UPDATE inventories SET expires_at=$1, status=$2 WHERE id=$3', [data.expiresAt, 'active', data.id]);
        return res.json({ ok: true });
      }
      if (op === 'delete') {
        await db.query('DELETE FROM inventories WHERE id=$1', [data.id]);
        return res.json({ ok: true });
      }
      if (op === 'setAdminPass') {
        const existing = await db.query("SELECT id FROM inventories WHERE name='__admin__config__' LIMIT 1");
        if (existing.length) await db.query("UPDATE inventories SET password=$1 WHERE name='__admin__config__'", [data.password]);
        else await db.query("INSERT INTO inventories (name, password, members, status) VALUES ('__admin__config__', $1, '[]'::jsonb, 'active')", [data.password]);
        return res.json({ ok: true });
      }
      return res.status(400).json({ error: 'unknown op' });
    }

    if (sqlText && typeof sqlText === 'string') {
      const auth = req.headers.authorization || '';
      const claims = await verifyJWT(auth.replace(/^Bearer\s+/i, ''));
      if (!claims) return res.status(401).json({ error: 'unauthorized' });

      if (/DROP\s+TABLE|TRUNCATE|ALTER\s+TABLE|CREATE\s+USER|GRANT|REVOKE|CREATE\s+EXTENSION|DROP\s+DATABASE/i.test(sqlText)) {
        return res.status(403).json({ error: 'forbidden' });
      }

      if (claims.role === 'admin') {
        const info = getTableInfo(sqlText);
        if (!info || info.table !== 'inventories') return res.status(403).json({ error: 'admin can only query inventories' });
        const rows = await db.query(sqlText, reqParams || []);
        return res.json({ data: rows });
      }

      verifyQuery(sqlText, reqParams || [], claims);
      const rows = await db.query(sqlText, reqParams || []);
      return res.json({ data: rows });
    }

    return res.status(400).json({ error: 'unknown action' });
  } catch (e) {
    console.error('API error:', e);
    return res.status(500).json({ error: e.message || 'server error' });
  }
}
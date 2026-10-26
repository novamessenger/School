// Creates the five management accounts. Safe to run more than once (existing accounts are skipped).
// Run LOCALLY or in a protected CI job — never in the browser, never with the service key committed to git.
//   node --env-file=.env.local scripts/provision-accounts.mjs
import { createClient } from '@supabase/supabase-js';

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) { console.error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are missing.'); process.exit(1); }

const ACCOUNTS = [  // [username, role, display name, env var that holds the initial password]
  ['system_owner',    'owner',  'مالک سامانه',   'INIT_PW_OWNER'],
  ['school_admin',    'admin',  'مدیر مدرسه',    'INIT_PW_ADMIN'],
  ['school_deputy1',  'deputy', 'معاون اول',     'INIT_PW_DEPUTY1'],
  ['school_deputy2',  'deputy', 'معاون دوم',     'INIT_PW_DEPUTY2'],
  ['school_deputy3',  'deputy', 'معاون سوم',     'INIT_PW_DEPUTY3'],
];
const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

async function findAuthUser(email) {
  for (let page = 1; page <= 20; page++) {
    const { data, error } = await sb.auth.admin.listUsers({ page, perPage: 200 });
    if (error) throw error;
    const u = data.users.find((x) => x.email === email);
    if (u || data.users.length < 200) return u ?? null;
  }
  return null;
}

let failed = false;
for (const [username, role, name, envVar] of ACCOUNTS) {
  try {
    const { data: existing, error: e1 } = await sb.from('profiles').select('id').eq('username', username).maybeSingle();
    if (e1) throw e1;
    if (existing) { console.log(`skip   ${username} (already provisioned)`); continue; }
    const password = process.env[envVar];
    if (!password || password.length < 12) throw new Error(`${envVar} must be set (min 12 characters)`);
    const email = `${username}@staff.beheshti.school`;
    let user = await findAuthUser(email);
    if (!user) {
      const { data, error } = await sb.auth.admin.createUser({ email, password, email_confirm: true });
      if (error) throw error;
      user = data.user;
    }
    const { error: e2 } = await sb.rpc('provision_staff', { p_user: user.id, p_role: role, p_username: username, p_name: name });
    if (e2) throw e2;
    console.log(`create ${username} (${role}) — must change password at first login`);
  } catch (err) {
    failed = true;
    console.error(`FAIL   ${username}: ${err.message}`);   // never print passwords
  }
}
process.exit(failed ? 1 : 0);

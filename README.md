# سامانه مطالعه مدرسه شهید بهشتی — Database & account setup (Supabase)

**Status:** database schema, security policies, report/Excel data functions and secure account provisioning are written.
**Not yet done / not tested:** see "Limitations" at the bottom. Nothing here has been run against a live Supabase project yet.

## 1. Create the project
1. Create a Supabase project (supabase.com). Note the **Project URL**, **anon key** and **service_role key**.
2. Authentication > Sign In / Providers: keep **Email** on, turn **off** "Allow new users to sign up" (no public registration).
   Enable CAPTCHA and keep the default rate limits (brute-force protection). Set a minimum password length of 8+.
3. SQL Editor: run `supabase/migrations/001_schema.sql`, then `002_functions.sql`. Fix any error before continuing.

## 2. Create the five management accounts (secure provisioning)
```bash
cp .env.example .env.local        # fill in URL, service_role key and the five initial passwords (>= 12 chars)
npm install
npm run provision                 # idempotent: existing accounts are skipped, passwords are never printed
```
Then delete the passwords from `.env.local` (or the whole file). Accounts: `system_owner` (owner), `school_admin` (admin),
`school_deputy1..3` (deputy). Login e-mails are `<username>@staff.beheshti.school`. Passwords are stored only as Supabase Auth bcrypt hashes;
every account must change its password at first login (frontend calls `auth.updateUser({password})` and then `rpc('complete_password_change')`).
Exactly one owner can exist (unique index). To change/reset a management password later: owner uses `rpc('reset_password')` (temporary password, forced change),
or the user uses "forgot password" if you configure SMTP.

## 3. First setup in the app (frontend must call these RPCs)
1. `upsert_class` for every real class (grades 7–12 already exist). 2. `create_student` for each student (student code + temporary password, forced change at first login).
3. `set_deputy_classes` for each deputy — **a deputy with no classes sees nothing** (no silent unrestricted access).
4. `update_settings` (daily limit, entry window, edit window, non-school weekdays, goals) and `set_calendar_day` for holidays.

## 4. Roles (enforced by RLS + server functions, not by hidden buttons)
| Role | Can do |
|---|---|
| owner | everything below + roles of admin/deputy, activate/deactivate staff, reset staff passwords, audit log, `owner_health()` |
| admin | students/classes/subjects/settings/calendar, deputy class assignment, all reports, export, audited record deletion; cannot create or change an owner |
| deputy | read-only dashboards, missing-record lists and Excel data for **assigned classes only** |
| student | own records only: add (within entry window), edit/delete (within edit window), own totals |

## 5. Excel export
`rpc('report_data', {...})` returns one JSON with `students`, `classes`, `records` (+ period/expected days) computed in a single query set → build the 3 sheets
(«خلاصه دانش‌آموزان», «خلاصه کلاس‌ها», «ریز رکوردها») in the browser with SheetJS or in an Edge Function. Each export is written to the audit log.
Scheduled weekly generation is **not** configured; it needs a Supabase Edge Function + pg_cron (or an external cron) — manual export is the supported workflow.

## 6. Backup & recovery
* Supabase Dashboard > Database > Backups: daily backups on paid plans, Point-in-Time Recovery as an add-on. Free plans have **no** automatic backups — do manual dumps.
* Manual backup: `pg_dump "$DATABASE_URL" --format=custom --file=beheshti-$(date +%F).dump` (connection string from Dashboard > Database).
* Restore into a fresh project: run nothing from the migrations first, then `pg_restore --clean --if-exists --no-owner -d "$NEW_DATABASE_URL" beheshti-YYYY-MM-DD.dump`.
* Encrypt dumps, store them off-site, restrict access (they contain student names). Test a restore at least once before real use.
* Accidental deletion of a record: restore the dump to a temporary project, copy the rows back; every delete is in `audit_logs`.

## 7. Deployment
The frontend must be hosted by you (GitHub Pages / Netlify / Vercel, HTTPS). Only the **anon key** goes in frontend code; the service_role key never leaves `.env.local`.

## 8. Test checklist (all NOT YET RUN)
Owner/admin/3 deputy/student login · forced password change · wrong passwords · deputy sees only assigned classes · student cannot read another student ·
nobody can promote themselves · invalid/future dates · daily limit · duplicate click · dashboard vs Excel totals · missing-record list on holidays ·
Persian text in .xlsx · session expiry · audit entries · backup restore.

## Limitations
* SQL has **not been executed** (no PostgreSQL in the build sandbox): expect small fixes on first run.
* The existing `beheshti-study.html` is still the localStorage demo; it is **not** connected to this database yet. A new Supabase-connected frontend (all roles, dashboards, Excel) is the next step.
* `create_student`/`reset_password` write to `auth.users` directly; if a future Supabase version rejects this, create users with the Admin API (same pattern as the provisioning script).
* Failed-login history lives in Supabase Auth logs (Dashboard), not in `audit_logs`.
* Not implemented: CSV student import, scheduled weekly reports, approval workflow for records.
* This replaces the earlier `beheshti-schema.sql`: students now log in with a **student code + temporary password** (birth-date passwords are not secure enough per your new requirements).

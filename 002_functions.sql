-- =====================================================================
-- 002_functions.sql — account management, settings, records, dashboards, report data
-- Run after 001. Every function re-checks the caller's role on the server.
-- =====================================================================

-- ---------- account provisioning ----------
-- Called ONLY by scripts/provision-accounts.mjs with the service-role key (idempotent).
create function public.provision_staff(p_user uuid, p_role text, p_username text, p_name text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if coalesce(auth.jwt() ->> 'role','') <> 'service_role' then raise exception 'دسترسی غیرمجاز'; end if;
  if p_role not in ('owner','admin','deputy') then raise exception 'نقش نامعتبر است.'; end if;
  insert into public.profiles (id, role, username, full_name, must_change_password, initial_pw_hash)
  select p_user, p_role, p_username, p_name, true, u.encrypted_password from auth.users u where u.id = p_user
  on conflict (id) do nothing;
  insert into public.audit_logs (actor, action, target, details) values (null, 'provision_staff', p_user::text, jsonb_build_object('role', p_role));
end $$;

-- Call after supabase.auth.updateUser({password}) — only succeeds if the stored password hash really changed.
create function public.complete_password_change() returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.profiles p set must_change_password = false, updated_at = now()
   where p.id = auth.uid() and p.active
     and (select u.encrypted_password from auth.users u where u.id = p.id) is distinct from p.initial_pw_hash;
  if not found then raise exception 'رمز عبور هنوز تغییر نکرده است.'; end if;
  perform public.log_audit('password_changed', auth.uid()::text);
end $$;

-- ---------- students ----------
create function public.create_student(p_code text, p_name text, p_class uuid, p_temp_password text, p_identifier text default null) returns uuid
language plpgsql security definer set search_path = '' as $$
declare uid uuid := gen_random_uuid(); em text := lower(p_code) || '@students.beheshti.school'; pwh text;
begin
  perform public._require(array['owner','admin']);
  if p_temp_password is null or char_length(p_temp_password) < 8 then raise exception 'رمز موقت باید دست‌کم ۸ نویسه باشد.'; end if;
  if not exists (select 1 from public.classes where id = p_class and active) then raise exception 'کلاس نامعتبر است.'; end if;
  if exists (select 1 from public.students where lower(student_code) = lower(p_code)) then raise exception 'این شماره دانش‌آموزی قبلاً ثبت شده است.'; end if;
  pwh := extensions.crypt(p_temp_password, extensions.gen_salt('bf'));
  insert into auth.users (instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,
                          created_at,updated_at,confirmation_token,recovery_token,email_change,email_change_token_new)
  values ('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',em,pwh,now(),
          '{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');
  insert into auth.identities (id,user_id,provider_id,provider,identity_data,last_sign_in_at,created_at,updated_at)
  values (gen_random_uuid(),uid,uid::text,'email',jsonb_build_object('sub',uid::text,'email',em,'email_verified',true),now(),now(),now());
  insert into public.profiles (id,role,username,full_name,must_change_password,initial_pw_hash)
  values (uid,'student',lower(p_code),btrim(p_name),true,pwh);
  insert into public.students (user_id,student_code,school_identifier,full_name,class_id)
  values (uid,p_code,nullif(btrim(p_identifier),''),btrim(p_name),p_class);
  perform public.log_audit('create_student', uid::text, jsonb_build_object('class', p_class));
  return uid;
end $$;

create function public.update_student(p_id uuid, p_name text, p_class uuid, p_identifier text default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  if not exists (select 1 from public.classes where id = p_class and active) then raise exception 'کلاس نامعتبر است.'; end if;
  update public.students set full_name = btrim(p_name), class_id = p_class, school_identifier = nullif(btrim(p_identifier),'') where id = p_id;
  if not found then raise exception 'دانش‌آموز پیدا نشد.'; end if;
  perform public.log_audit('update_student', p_id::text, jsonb_build_object('class', p_class));
end $$;

create function public.set_user_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = '' as $$
declare tr text;
begin
  perform public._require(array['owner','admin']);
  select role into tr from public.profiles where id = p_user;
  if tr is null then raise exception 'کاربر پیدا نشد.'; end if;
  if tr = 'owner' or p_user = auth.uid() then raise exception 'این عملیات مجاز نیست.'; end if;
  if tr in ('admin','deputy') and public.role_of() <> 'owner' then raise exception 'فقط مالک می‌تواند حساب‌های مدیریتی را تغییر دهد.'; end if;
  update public.profiles set active = p_active, updated_at = now() where id = p_user;
  update public.students set active = p_active where user_id = p_user;
  update auth.users set banned_until = case when p_active then null else 'infinity'::timestamptz end where id = p_user;
  perform public.log_audit(case when p_active then 'activate_user' else 'deactivate_user' end, p_user::text);
end $$;

create function public.reset_password(p_user uuid, p_temp_password text) returns void
language plpgsql security definer set search_path = '' as $$
declare tr text; pwh text;
begin
  perform public._require(array['owner','admin']);
  select role into tr from public.profiles where id = p_user;
  if tr is null or tr = 'owner' then raise exception 'این عملیات مجاز نیست.'; end if;
  if tr in ('admin','deputy') and public.role_of() <> 'owner' then raise exception 'فقط مالک می‌تواند رمز حساب‌های مدیریتی را بازنشانی کند.'; end if;
  if p_temp_password is null or char_length(p_temp_password) < 8 then raise exception 'رمز موقت باید دست‌کم ۸ نویسه باشد.'; end if;
  pwh := extensions.crypt(p_temp_password, extensions.gen_salt('bf'));
  update auth.users set encrypted_password = pwh, updated_at = now() where id = p_user;
  update public.profiles set must_change_password = true, initial_pw_hash = pwh, updated_at = now() where id = p_user;
  perform public.log_audit('reset_password', p_user::text);
end $$;

-- ---------- roles and deputy scope ----------
create function public.owner_set_role(p_user uuid, p_role text) returns void
language plpgsql security definer set search_path = '' as $$
declare tr text;
begin
  perform public._require(array['owner']);
  select role into tr from public.profiles where id = p_user;
  if tr not in ('admin','deputy') or p_role not in ('admin','deputy') then raise exception 'تغییر این نقش مجاز نیست.'; end if;
  update public.profiles set role = p_role, updated_at = now() where id = p_user;
  if p_role = 'admin' then delete from public.deputy_classes where deputy_id = p_user; end if;
  perform public.log_audit('role_changed', p_user::text, jsonb_build_object('from', tr, 'to', p_role));
end $$;

create function public.set_deputy_classes(p_deputy uuid, p_classes uuid[]) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  if not exists (select 1 from public.profiles where id = p_deputy and role = 'deputy') then raise exception 'این کاربر معاون نیست.'; end if;
  delete from public.deputy_classes where deputy_id = p_deputy;
  insert into public.deputy_classes (deputy_id, class_id)
    select p_deputy, c.id from public.classes c where c.id = any (coalesce(p_classes, '{}'));
  perform public.log_audit('deputy_classes_changed', p_deputy::text, jsonb_build_object('count', coalesce(array_length(p_classes,1),0)));
end $$;

-- ---------- classes, subjects, settings ----------
create function public.upsert_class(p_id uuid, p_grade smallint, p_name text, p_active boolean default true) returns uuid
language plpgsql security definer set search_path = '' as $$
declare cid uuid;
begin
  perform public._require(array['owner','admin']);
  if p_id is null then insert into public.classes (grade_id, name, active) values (p_grade, btrim(p_name), p_active) returning id into cid;
  else update public.classes set grade_id = p_grade, name = btrim(p_name), active = p_active where id = p_id returning id into cid; end if;
  perform public.log_audit('upsert_class', cid::text);
  return cid;
end $$;

create function public.upsert_subject(p_id int, p_name text, p_active boolean default true, p_sort smallint default 0) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  if p_id is null then insert into public.subjects (name, active, sort) values (btrim(p_name), p_active, p_sort);
  else update public.subjects set name = btrim(p_name), active = p_active, sort = p_sort where id = p_id; end if;
  perform public.log_audit('upsert_subject', p_id::text, jsonb_build_object('name', p_name));
end $$;

create function public.update_settings(p_max int, p_entry_days smallint, p_allow_future boolean, p_edit_days smallint,
                                       p_weekdays smallint[], p_weekly int, p_monthly int) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  update public.school_settings set max_daily_minutes = p_max, entry_window_days = p_entry_days, allow_future = p_allow_future,
    edit_window_days = p_edit_days, non_school_weekdays = p_weekdays, weekly_goal_minutes = p_weekly, monthly_goal_minutes = p_monthly where id = 1;
  perform public.log_audit('update_settings', null, jsonb_build_object('max', p_max, 'entry_days', p_entry_days, 'edit_days', p_edit_days));
end $$;

create function public.set_calendar_day(p_day date, p_is_school boolean, p_note text default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  insert into public.school_calendar (day, is_school_day, note) values (p_day, p_is_school, p_note)
  on conflict (day) do update set is_school_day = excluded.is_school_day, note = excluded.note;
  perform public.log_audit('set_calendar_day', p_day::text, jsonb_build_object('school_day', p_is_school));
end $$;

create function public.clear_calendar_day(p_day date) returns void language plpgsql security definer set search_path = '' as $$
begin perform public._require(array['owner','admin']); delete from public.school_calendar where day = p_day;
      perform public.log_audit('clear_calendar_day', p_day::text); end $$;

-- ---------- study records: edits and deletes (audited by trigger) ----------
create function public.update_my_record(p_id uuid, p_subject int, p_date date, p_start time, p_minutes int, p_notes text) returns void
language plpgsql security definer set search_path = '' as $$
declare r public.study_records; s public.school_settings;
begin
  select * into r from public.study_records where id = p_id and student_id = public.my_student_id();
  if not found then raise exception 'رکورد پیدا نشد.'; end if;
  select * into s from public.school_settings where id = 1;
  if s.edit_window_days <= 0 or r.study_date < public.tehran_today() - s.edit_window_days then raise exception 'مهلت ویرایش این رکورد گذشته است.'; end if;
  update public.study_records set subject_id = p_subject, study_date = p_date, start_time = p_start,
         duration_minutes = p_minutes, notes = p_notes where id = p_id;
end $$;

create function public.delete_my_record(p_id uuid) returns void language plpgsql security definer set search_path = '' as $$
declare r public.study_records; s public.school_settings;
begin
  select * into r from public.study_records where id = p_id and student_id = public.my_student_id();
  if not found then raise exception 'رکورد پیدا نشد.'; end if;
  select * into s from public.school_settings where id = 1;
  if s.edit_window_days <= 0 or r.study_date < public.tehran_today() - s.edit_window_days then raise exception 'مهلت حذف این رکورد گذشته است.'; end if;
  delete from public.study_records where id = p_id;
end $$;

create function public.staff_delete_record(p_id uuid, p_reason text) returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin']);
  if p_reason is null or char_length(btrim(p_reason)) < 3 then raise exception 'دلیل حذف را بنویسید.'; end if;
  perform public.log_audit('staff_delete_reason', p_id::text, jsonb_build_object('reason', left(p_reason, 200)));
  delete from public.study_records where id = p_id;
  if not found then raise exception 'رکورد پیدا نشد.'; end if;
end $$;

-- ---------- per-student totals (student sees self; staff see only allowed students) ----------
create function public.student_summary(p_student uuid default null) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare sid uuid := coalesce(p_student, public.my_student_id()); t date := public.tehran_today();
        ws date := public.week_start(public.tehran_today()); m record; pm record; s record; r record;
begin
  if sid is null or not public.can_see_student(sid) then raise exception 'دسترسی غیرمجاز'; end if;
  select * into m from public._month_of(0);  select * into pm from public._month_of(1);
  select * into s from public.school_settings where id = 1;
  select coalesce(sum(x.duration_minutes) filter (where x.study_date = t),0) as today_min,
         coalesce(sum(x.duration_minutes) filter (where x.study_date between ws and ws+6),0) as week_min,
         coalesce(sum(x.duration_minutes) filter (where x.study_date between m.start_date and m.end_date),0) as month_min,
         count(distinct x.study_date) filter (where x.study_date between m.start_date and m.end_date) as active_days,
         coalesce(sum(x.duration_minutes) filter (where x.study_date between ws-7 and ws-1),0) as prev_week_min,
         coalesce(sum(x.duration_minutes) filter (where x.study_date between pm.start_date and pm.end_date),0) as prev_month_min
    into r from public.study_records x where x.student_id = sid;
  return jsonb_build_object('today_min', r.today_min, 'week_min', r.week_min, 'month_min', r.month_min, 'active_days', r.active_days,
    'prev_week_min', r.prev_week_min, 'prev_month_min', r.prev_month_min,
    'weekly_goal', s.weekly_goal_minutes, 'monthly_goal', s.monthly_goal_minutes);
end $$;

create function public.student_week(p_student uuid default null, p_offset int default 0)
returns table(day_index int, study_date date, minutes int) language plpgsql stable security definer set search_path = '' as $$
declare sid uuid := coalesce(p_student, public.my_student_id());
begin
  if sid is null or not public.can_see_student(sid) then raise exception 'دسترسی غیرمجاز'; end if;
  return query select g.i, d, coalesce((select sum(r.duration_minutes)::int from public.study_records r where r.student_id = sid and r.study_date = d), 0)
    from generate_series(0,6) g(i), lateral (select public.week_start(public.tehran_today()) - 7*greatest(p_offset,0) + g.i) x(d);
end $$;

create function public.student_month(p_student uuid default null, p_offset int default 0)
returns table(jalali_day int, study_date date, minutes int) language plpgsql stable security definer set search_path = '' as $$
declare sid uuid := coalesce(p_student, public.my_student_id());
begin
  if sid is null or not public.can_see_student(sid) then raise exception 'دسترسی غیرمجاز'; end if;
  return query with m as (select * from public._month_of(p_offset))
    select (x.d - m.start_date + 1)::int, x.d, coalesce((select sum(r.duration_minutes)::int from public.study_records r where r.student_id = sid and r.study_date = x.d), 0)
    from m, generate_series(m.start_date, m.end_date, interval '1 day') g(ts), lateral (select g.ts::date) x(d);
end $$;

-- ---------- staff: student list ----------
create function public.staff_students(p_search text default null, p_grade smallint default null, p_class uuid default null,
  p_active boolean default null, p_limit int default 30, p_offset int default 0)
returns table(id uuid, student_code text, full_name text, grade text, class_id uuid, class_name text, active boolean, created_at timestamptz, total_count bigint)
language plpgsql stable security definer set search_path = '' as $$
declare q text := replace(replace(replace(coalesce(btrim(p_search),''), '\', '\\'), '%', '\%'), '_', '\_');
begin
  perform public._require(array['owner','admin','deputy']);
  return query
  select s.id, s.student_code, s.full_name, g.name, c.id, c.name, s.active, s.created_at, count(*) over()
  from public.students s join public.classes c on c.id = s.class_id join public.grades g on g.id = c.grade_id
  where public.can_see_student(s.id) and s.active = coalesce(p_active, s.active)
    and (p_grade is null or g.id = p_grade) and (p_class is null or c.id = p_class)
    and (q = '' or s.full_name ilike '%' || q || '%' or lower(s.student_code) = lower(btrim(p_search)))
  order by g.id, c.name, s.full_name
  limit least(greatest(p_limit,1),100) offset greatest(p_offset,0);
end $$;

-- ---------- staff: who has / has not submitted (missing != "did not study") ----------
create function public.staff_submission_status(p_date date, p_from date default null, p_to date default null,
  p_grade smallint default null, p_class uuid default null)
returns table(student_id uuid, full_name text, grade text, class_name text, expected_date date, status text, period_minutes int, last_submission date)
language plpgsql stable security definer set search_path = '' as $$
begin
  perform public._require(array['owner','admin','deputy']);
  return query
  select s.id, s.full_name, g.name, c.name, p_date,
    case when exists (select 1 from public.study_records r where r.student_id = s.id and r.study_date = p_date) then 'submitted'
         when public.is_school_day(p_date) then 'missing' else 'not_expected' end,
    coalesce((select sum(r.duration_minutes)::int from public.study_records r
              where r.student_id = s.id and r.study_date between coalesce(p_from,p_date) and coalesce(p_to,p_date)), 0),
    (select max(r.study_date) from public.study_records r where r.student_id = s.id)
  from public.students s join public.classes c on c.id = s.class_id join public.grades g on g.id = c.grade_id
  where s.active and public.can_see_student(s.id) and (p_grade is null or g.id = p_grade) and (p_class is null or c.id = p_class)
  order by g.id, c.name, s.full_name;
end $$;

-- ---------- staff dashboard ----------
create function public.staff_dashboard(p_from date, p_to date, p_grade smallint default null, p_class uuid default null, p_subject int default null)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare t date := public.tehran_today(); ws date := public.week_start(public.tehran_today()); m record;
begin
  perform public._require(array['owner','admin','deputy']);
  if p_to < p_from or p_to - p_from > 92 then raise exception 'بازه زمانی نامعتبر است (حداکثر ۹۳ روز).'; end if;
  select * into m from public._month_of(0);
  return (
    with sc as (select s.id, s.full_name, c.id cid, c.name cname, g.name gname
                from public.students s join public.classes c on c.id = s.class_id join public.grades g on g.id = c.grade_id
                where s.active and public.can_see_student(s.id) and (p_grade is null or g.id = p_grade) and (p_class is null or c.id = p_class)),
    rc as (select r.student_id, r.study_date d, r.duration_minutes mins, r.subject_id
           from public.study_records r join sc on sc.id = r.student_id where p_subject is null or r.subject_id = p_subject),
    per as (select sc.id, sc.full_name, coalesce(sum(rc.mins) filter (where rc.d between p_from and p_to),0)::int tot,
                   count(rc.d) filter (where rc.d between p_from and p_to) n
            from sc left join rc on rc.student_id = sc.id group by sc.id, sc.full_name),
    sub as (select count(distinct r2.student_id) n from public.study_records r2 join sc on sc.id = r2.student_id where r2.study_date = t)
    select jsonb_build_object(
      'students', (select count(*) from sc),
      'today_min', (select coalesce(sum(mins),0) from rc where d = t),
      'week_min',  (select coalesce(sum(mins),0) from rc where d between ws and ws+6),
      'month_min', (select coalesce(sum(mins),0) from rc where d between m.start_date and m.end_date),
      'today_is_school_day', public.is_school_day(t),
      'submitted_today', (select n from sub),
      'missing_today', case when public.is_school_day(t) then (select count(*) from sc) - (select n from sub) else 0 end,
      'avg_per_student_min', (select coalesce(round(avg(tot)),0) from per),
      'by_class', (select coalesce(jsonb_agg(to_jsonb(x) order by x.grade, x.class),'[]') from
                   (select sc.cid class_id, sc.gname grade, sc.cname class, count(distinct sc.id) students,
                           coalesce(sum(rc.mins) filter (where rc.d between p_from and p_to),0)::int minutes
                    from sc left join rc on rc.student_id = sc.id group by sc.cid, sc.gname, sc.cname) x),
      'by_subject', (select coalesce(jsonb_agg(to_jsonb(y) order by y.minutes desc),'[]') from
                     (select sb.name subject, sum(rc.mins)::int minutes from rc join public.subjects sb on sb.id = rc.subject_id
                      where rc.d between p_from and p_to group by sb.name) y),
      'top', (select coalesce(jsonb_agg(to_jsonb(a)),'[]') from (select id student_id, full_name name, tot minutes from per where n > 0 order by tot desc limit 5) a),
      'lowest', (select coalesce(jsonb_agg(to_jsonb(b)),'[]') from (select id student_id, full_name name, tot minutes from per where n > 0 order by tot asc limit 5) b),
      'trend', (select coalesce(jsonb_agg(to_jsonb(z) order by z.d),'[]') from
                (select g.ts::date as d, coalesce((select sum(rc.mins) from rc where rc.d = g.ts::date),0)::int as minutes
                 from generate_series(p_from, p_to, interval '1 day') g(ts)) z)
    ));
end $$;

-- ---------- Excel data: ONE query set so sheet totals always agree with the dashboard ----------
create function public.report_data(p_from date, p_to date, p_grade smallint default null, p_class uuid default null,
                                   p_student uuid default null, p_subject int default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare res jsonb; exp_days int;
begin
  perform public._require(array['owner','admin','deputy']);
  if p_to < p_from or p_to - p_from > 92 then raise exception 'بازه گزارش نامعتبر است (حداکثر ۹۳ روز).'; end if;
  select count(*) into exp_days from generate_series(p_from, p_to, interval '1 day') g(ts) where public.is_school_day(g.ts::date);
  res := (
    with sc as (select s.id, s.student_code code, s.full_name, c.id cid, c.name cname, g.name gname
                from public.students s join public.classes c on c.id = s.class_id join public.grades g on g.id = c.grade_id
                where s.active and public.can_see_student(s.id) and (p_grade is null or g.id = p_grade)
                  and (p_class is null or c.id = p_class) and (p_student is null or s.id = p_student)),
    rc as (select r.id rid, r.student_id, r.study_date d, sb.name subject, r.start_time st, r.duration_minutes mins, r.created_at ca, r.updated_at ua
           from public.study_records r join sc on sc.id = r.student_id join public.subjects sb on sb.id = r.subject_id
           where r.study_date between p_from and p_to and (p_subject is null or r.subject_id = p_subject)),
    bys as (select student_id, subject, sum(mins)::int mins from rc group by student_id, subject),
    stu as (select sc.id, sc.code, sc.full_name, sc.cid, sc.cname, sc.gname, coalesce(sum(rc.mins),0)::int tot, count(rc.rid) n,
                   count(distinct rc.d) days, count(distinct rc.d) filter (where public.is_school_day(rc.d)) sdays
            from sc left join rc on rc.student_id = sc.id group by sc.id, sc.code, sc.full_name, sc.cid, sc.cname, sc.gname)
    select jsonb_build_object(
      'period', jsonb_build_object('from', p_from, 'to', p_to, 'from_jalali', public.jalali_text(p_from), 'to_jalali', public.jalali_text(p_to), 'expected_days', exp_days),
      'students', coalesce((select jsonb_agg(jsonb_build_object('student_code', stu.code, 'name', stu.full_name, 'grade', stu.gname, 'class', stu.cname,
          'total_min', stu.tot, 'by_subject', coalesce((select jsonb_object_agg(b.subject, b.mins) from bys b where b.student_id = stu.id), '{}'::jsonb),
          'records', stu.n, 'days', stu.days, 'avg_daily_min', case when stu.days > 0 then round(stu.tot::numeric / stu.days) else 0 end,
          'missing_expected_days', greatest(exp_days - stu.sdays, 0)) order by stu.gname, stu.cname, stu.full_name) from stu), '[]'::jsonb),
      'classes', coalesce((select jsonb_agg(jsonb_build_object('grade', k.gname, 'class', k.cname, 'students', k.ns, 'submitted', k.sb, 'missing', k.ns - k.sb,
          'total_min', k.tot, 'avg_per_student_min', case when k.ns > 0 then round(k.tot::numeric / k.ns) else 0 end,
          'by_subject', coalesce((select jsonb_object_agg(x.subject, x.mins) from
                (select b.subject, sum(b.mins)::int mins from bys b join sc on sc.id = b.student_id where sc.cid = k.cid group by b.subject) x), '{}'::jsonb))
          order by k.gname, k.cname)
        from (select cid, gname, cname, count(*) ns, count(*) filter (where n > 0) sb, coalesce(sum(tot),0)::int tot from stu group by cid, gname, cname) k), '[]'::jsonb),
      'records', coalesce((select jsonb_agg(jsonb_build_object('record_id', rc.rid, 'student_code', sc.code, 'name', sc.full_name, 'grade', sc.gname, 'class', sc.cname,
          'date', rc.d, 'jalali_date', public.jalali_text(rc.d), 'subject', rc.subject, 'start_time', rc.st, 'minutes', rc.mins,
          'created_at', rc.ca, 'updated_at', case when rc.ua > rc.ca + interval '1 second' then rc.ua end) order by rc.d, sc.full_name)
        from rc join sc on sc.id = rc.student_id), '[]'::jsonb)
    ));
  perform public.log_audit('export_report', null, jsonb_build_object('from', p_from, 'to', p_to, 'grade', p_grade, 'class', p_class, 'student', p_student));
  return res;
end $$;

-- ---------- owner: system health ----------
create function public.owner_health() returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  perform public._require(array['owner']);
  return jsonb_build_object('ok', true, 'db_time', now(),
    'students', (select count(*) from public.students where active),
    'staff', (select count(*) from public.profiles where role <> 'student' and active),
    'records', (select count(*) from public.study_records),
    'last_audit', (select max(created_at) from public.audit_logs));
end $$;

-- ---------- permissions: everything private unless listed ----------
alter default privileges in schema public revoke execute on functions from public, anon;
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.role_of(), public.my_student_id(), public.can_see_student(uuid), public.tehran_today(),
  public.to_jalali(date), public.jalali_text(date), public.complete_password_change(),
  public.create_student(text,text,uuid,text,text), public.update_student(uuid,text,uuid,text), public.set_user_active(uuid,boolean),
  public.reset_password(uuid,text), public.owner_set_role(uuid,text), public.set_deputy_classes(uuid,uuid[]),
  public.upsert_class(uuid,smallint,text,boolean), public.upsert_subject(int,text,boolean,smallint),
  public.update_settings(int,smallint,boolean,smallint,smallint[],int,int), public.set_calendar_day(date,boolean,text), public.clear_calendar_day(date),
  public.update_my_record(uuid,int,date,time,int,text), public.delete_my_record(uuid), public.staff_delete_record(uuid,text),
  public.student_summary(uuid), public.student_week(uuid,int), public.student_month(uuid,int),
  public.staff_students(text,smallint,uuid,boolean,int,int), public.staff_submission_status(date,date,date,smallint,uuid),
  public.staff_dashboard(date,date,smallint,uuid,int), public.report_data(date,date,smallint,uuid,uuid,int), public.owner_health()
to authenticated;
grant execute on function public.provision_staff(uuid,text,text,text) to service_role;

-- =====================================================================
-- 001_schema.sql — tables, helpers, validation triggers, RLS
-- Shahid Beheshti School study tracker (Supabase / PostgreSQL)
-- Run first. Contains NO passwords or secrets.
-- =====================================================================
create extension if not exists pgcrypto with schema extensions;

-- ---------- reference data ----------
create table public.grades (id smallint primary key, name text not null unique);
insert into public.grades values (7,'هفتم'),(8,'هشتم'),(9,'نهم'),(10,'دهم'),(11,'یازدهم'),(12,'دوازدهم');

create table public.classes (
  id uuid primary key default gen_random_uuid(),
  grade_id smallint not null references public.grades(id),
  name text not null check (char_length(name) between 1 and 20),
  active boolean not null default true,
  unique (grade_id, name)
);

create table public.subjects (
  id serial primary key, name text not null unique check (char_length(name) between 1 and 40),
  active boolean not null default true, sort smallint not null default 0
);
insert into public.subjects (name, sort) values
 ('فارسی',1),('عربی',2),('زبان انگلیسی',3),('ریاضی',4),('قرآن',5),('علوم',6),
 ('کار و فناوری',7),('تفکر و سبک زندگی',8),('مطالعات اجتماعی',9),('هنر',10),('سایر',99);

-- ---------- identity ----------
create table public.profiles (          -- one row per login (staff and students); NO passwords here
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','deputy','student')),
  username text not null unique check (username ~ '^[a-z0-9_]{3,40}$'),
  full_name text not null default '',
  must_change_password boolean not null default true,
  active boolean not null default true,
  initial_pw_hash text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index one_owner on public.profiles ((role)) where role = 'owner';

create table public.students (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete restrict,
  student_code text not null unique check (student_code ~ '^[0-9A-Za-z]{3,20}$'),
  school_identifier text unique,
  full_name text not null check (char_length(btrim(full_name)) between 3 and 60),
  class_id uuid not null references public.classes(id),
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create index students_class_idx on public.students (class_id);

create table public.deputy_classes (
  deputy_id uuid not null references public.profiles(id) on delete cascade,
  class_id  uuid not null references public.classes(id) on delete cascade,
  primary key (deputy_id, class_id)
);

-- ---------- settings ----------
create table public.school_settings (
  id int primary key default 1 check (id = 1),
  max_daily_minutes    int      not null default 720  check (max_daily_minutes between 60 and 1440),
  entry_window_days    smallint not null default 7    check (entry_window_days between 0 and 60),
  allow_future         boolean  not null default false,
  edit_window_days     smallint not null default 1    check (edit_window_days between 0 and 30),
  non_school_weekdays  smallint[] not null default '{5}',   -- 0=Sunday .. 6=Saturday ; default Friday
  weekly_goal_minutes  int not null default 1200 check (weekly_goal_minutes > 0),
  monthly_goal_minutes int not null default 4800 check (monthly_goal_minutes > 0)
);
insert into public.school_settings (id) values (1);

create table public.school_calendar (   -- holidays / extra school days overriding the weekday rule
  day date primary key, is_school_day boolean not null, note text check (char_length(note) <= 100)
);

-- ---------- study records ----------
create table public.study_records (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  subject_id int  not null references public.subjects(id),
  study_date date not null,
  start_time time,
  duration_minutes int not null check (duration_minutes between 1 and 1440),
  notes text check (notes is null or char_length(notes) <= 200),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid, updated_by uuid
);
create index study_student_date_idx on public.study_records (student_id, study_date);
create index study_date_idx on public.study_records (study_date);

create table public.audit_logs (
  id bigserial primary key, actor uuid, action text not null, target text,
  details jsonb, created_at timestamptz not null default now()
);
create index audit_created_idx on public.audit_logs (created_at desc);

-- ---------- helpers ----------
create function public.tehran_today() returns date language sql stable as
$$ select (now() at time zone 'Asia/Tehran')::date $$;

create function public.role_of() returns text language sql stable security definer set search_path = '' as
$$ select p.role from public.profiles p where p.id = auth.uid() and p.active $$;

create function public._require(r text[]) returns void language plpgsql stable security definer set search_path = '' as
$$ begin if not (coalesce(public.role_of(),'-') = any(r)) then raise exception 'دسترسی غیرمجاز'; end if; end $$;

create function public.my_student_id() returns uuid language sql stable security definer set search_path = '' as
$$ select s.id from public.students s where s.user_id = auth.uid() and s.active and public.role_of() = 'student' $$;

-- Owner/Admin: everyone. Deputy: only students of classes assigned to them (none assigned = no access). Student: self.
create function public.can_see_student(sid uuid) returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.students s where s.id = sid and (
    public.role_of() in ('owner','admin')
    or (public.role_of() = 'student' and s.user_id = auth.uid())
    or (public.role_of() = 'deputy' and exists (select 1 from public.deputy_classes d
                                                where d.deputy_id = auth.uid() and d.class_id = s.class_id))))
$$;

create function public.is_school_day(d date) returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select c.is_school_day from public.school_calendar c where c.day = d),
    not (extract(dow from d)::int = any (coalesce((select z.non_school_weekdays from public.school_settings z where z.id = 1), '{5}'::smallint[]))))
$$;

create function public.log_audit(p_action text, p_target text default null, p_details jsonb default null) returns void
language sql security definer set search_path = '' as
$$ insert into public.audit_logs (actor, action, target, details) values (auth.uid(), p_action, p_target, p_details) $$;

-- Jalali calendar
create function public.to_jalali(g date, out jy int, out jm int, out jd int) language plpgsql immutable as $$
declare gy int := extract(year from g)::int; gm int := extract(month from g)::int; gd int := extract(day from g)::int;
        gdm int[] := array[0,31,59,90,120,151,181,212,243,273,304,334]; gy2 int; days int;
begin
  gy2 := case when gm > 2 then gy + 1 else gy end;
  days := 355666 + (365*gy) + ((gy2+3)/4) - ((gy2+99)/100) + ((gy2+399)/400) + gd + gdm[gm];
  jy := -1595 + (33*(days/12053)); days := days % 12053;
  jy := jy + 4*(days/1461);        days := days % 1461;
  if days > 365 then jy := jy + ((days-1)/365); days := (days-1) % 365; end if;
  if days < 186 then jm := 1 + days/31; jd := 1 + days%31; else jm := 7 + (days-186)/30; jd := 1 + (days-186)%30; end if;
end $$;

create function public.jalali_text(d date) returns text language sql immutable as
$$ select format('%s/%s/%s', jy, lpad(jm::text,2,'0'), lpad(jd::text,2,'0')) from public.to_jalali(d) $$;

create function public.jalali_month_range(g date, out start_date date, out end_date date) language plpgsql immutable as $$
declare j record; len int;
begin
  select * into j from public.to_jalali(g);
  start_date := g - (j.jd - 1);
  len := case when j.jm <= 6 then 31 when j.jm <= 11 then 30
              when (select x.jm from public.to_jalali(start_date + 29) x) = 12 then 30 else 29 end;
  end_date := start_date + (len - 1);
end $$;

create function public._month_of(p_offset int, out start_date date, out end_date date) language plpgsql stable as $$
declare d date := public.tehran_today(); i int;
begin
  for i in 1..greatest(p_offset,0) loop d := (select a.start_date from public.jalali_month_range(d) a) - 1; end loop;
  select a.start_date, a.end_date into start_date, end_date from public.jalali_month_range(d) a;
end $$;

create function public.week_start(g date) returns date language sql immutable as   -- Saturday-based week
$$ select g - ((extract(dow from g)::int + 1) % 7) $$;

-- ---------- study-record validation (server side) ----------
create function public.trg_study_record() returns trigger language plpgsql security definer set search_path = '' as $$
declare s public.school_settings; today date := public.tehran_today(); v_sum int;
begin
  perform pg_advisory_xact_lock(hashtext(new.student_id::text));
  select * into s from public.school_settings where id = 1;
  if tg_op = 'INSERT' then new.created_by := auth.uid(); end if;
  new.updated_by := auth.uid(); new.updated_at := now();
  if not exists (select 1 from public.subjects where id = new.subject_id and active) then
    raise exception 'درس انتخاب‌شده معتبر نیست.'; end if;
  if new.study_date > today and not s.allow_future then raise exception 'ثبت مطالعه برای تاریخ آینده مجاز نیست.'; end if;
  if new.study_date < today - s.entry_window_days then raise exception 'مهلت ثبت مطالعه برای این تاریخ گذشته است.'; end if;
  select coalesce(sum(duration_minutes),0) into v_sum from public.study_records
   where student_id = new.student_id and study_date = new.study_date and id is distinct from new.id;
  if v_sum + new.duration_minutes > s.max_daily_minutes then
    raise exception 'مجموع مطالعه یک روز نمی‌تواند از سقف مجاز بیشتر شود.'; end if;
  if tg_op = 'INSERT' and exists (select 1 from public.study_records where student_id = new.student_id
      and study_date = new.study_date and subject_id = new.subject_id and duration_minutes = new.duration_minutes
      and created_at > now() - interval '10 seconds') then
    raise exception 'این رکورد هم‌اکنون ثبت شده است.'; end if;
  return new;
end $$;
create trigger study_record_check before insert or update on public.study_records
  for each row execute function public.trg_study_record();

create function public.trg_audit_record() returns trigger language plpgsql security definer set search_path = '' as $$
declare r public.study_records := case when tg_op = 'DELETE' then old else new end;
begin
  insert into public.audit_logs (actor, action, target, details)
  values (auth.uid(), 'record_' || lower(tg_op), r.id::text,
          jsonb_build_object('student', r.student_id, 'date', r.study_date, 'minutes', r.duration_minutes));
  return null;
end $$;
create trigger study_record_audit after insert or update or delete on public.study_records
  for each row execute function public.trg_audit_record();

-- ---------- Row Level Security ----------
alter table public.grades          enable row level security;
alter table public.classes         enable row level security;
alter table public.subjects        enable row level security;
alter table public.profiles        enable row level security;
alter table public.students        enable row level security;
alter table public.deputy_classes  enable row level security;
alter table public.school_settings enable row level security;
alter table public.school_calendar enable row level security;
alter table public.study_records   enable row level security;
alter table public.audit_logs      enable row level security;

create policy ref_grades   on public.grades          for select to authenticated using (true);
create policy ref_classes  on public.classes         for select to authenticated using (true);
create policy ref_subjects on public.subjects        for select to authenticated using (true);
create policy ref_settings on public.school_settings for select to authenticated using (true);
create policy ref_calendar on public.school_calendar for select to authenticated using (true);
create policy prof_read    on public.profiles        for select to authenticated
  using (id = auth.uid() or public.role_of() in ('owner','admin'));
create policy stud_read    on public.students        for select to authenticated using (public.can_see_student(id));
create policy dep_read     on public.deputy_classes  for select to authenticated
  using (deputy_id = auth.uid() or public.role_of() in ('owner','admin'));
create policy rec_read     on public.study_records   for select to authenticated using (public.can_see_student(student_id));
create policy rec_insert   on public.study_records   for insert to authenticated with check (student_id = public.my_student_id());
create policy audit_read   on public.audit_logs      for select to authenticated using (public.role_of() in ('owner','admin'));
-- No UPDATE/DELETE policies anywhere: every change goes through the audited functions in 002.

revoke all on all tables in schema public from anon, authenticated;
grant select on public.grades, public.classes, public.subjects, public.school_settings, public.school_calendar,
                public.students, public.deputy_classes, public.study_records, public.audit_logs to authenticated;
grant select (id, role, username, full_name, must_change_password, active, created_at) on public.profiles to authenticated;
grant insert (student_id, subject_id, study_date, start_time, duration_minutes, notes) on public.study_records to authenticated;

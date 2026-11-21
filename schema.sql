-- ════════════════════════════════════════════════════════════════════
--  سامانه یکپارچه انتخابات مدارس — اسکریپت کامل پایگاه داده (Supabase / Postgres)
--  یک‌بار در SQL Editor اجرا کنید. اجرای دوباره بی‌خطر است (idempotent).
--  نقش‌ها: ادمین ارشد (super) → مدیر کل (manager) → مدیر مدرسه (school) → رأی‌دهنده
--  همهٔ جدول‌ها RLS دارند و هیچ policy ندارند؛ دسترسی فقط از راه توابع mc_* است.
-- ════════════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

-- ═══ جدول‌ها ═══
create table if not exists public.mc_superadmin (
  id int primary key default 1 check (id = 1),
  username text not null,
  pass_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.mc_system (
  id int primary key default 1 check (id = 1),
  site_enabled boolean not null default true,
  message text,
  updated_at timestamptz not null default now()
);
insert into public.mc_system(id) select 1 where not exists (select 1 from public.mc_system);

create table if not exists public.mc_secret (
  id int primary key default 1 check (id = 1),
  pepper text not null
);
insert into public.mc_secret(id, pepper)
select 1, encode(extensions.gen_random_bytes(32), 'hex')
where not exists (select 1 from public.mc_secret);

create table if not exists public.mc_managers (
  id uuid primary key default gen_random_uuid(),
  username text not null,
  pass_hash text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create unique index if not exists mc_managers_username_uq on public.mc_managers (lower(username));

create table if not exists public.mc_schools (
  id uuid primary key default gen_random_uuid(),
  manager_id uuid not null references public.mc_managers(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 120),
  username text not null,
  pass_hash text not null,
  slug text not null unique default encode(extensions.gen_random_bytes(6), 'hex'),
  title text not null default 'انتخابات شورای دانش‌آموزی',
  picks int not null default 5 check (picks between 1 and 50),
  open boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create unique index if not exists mc_schools_username_uq on public.mc_schools (lower(username));
create index if not exists mc_schools_manager_idx on public.mc_schools(manager_id);

create table if not exists public.mc_candidates (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references public.mc_schools(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 80),
  created_at timestamptz not null default now()
);
create unique index if not exists mc_candidates_school_name_uq on public.mc_candidates (school_id, lower(name));

create table if not exists public.mc_voters (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references public.mc_schools(id) on delete cascade,
  nid_hash text not null,               -- HMAC کد ملی؛ کد ملی خام ذخیره نمی‌شود
  fname text not null,
  lname text not null,
  tracking_code text not null unique,
  created_at timestamptz not null default now(),
  constraint mc_voters_school_nid_uq unique (school_id, nid_hash)
);

create table if not exists public.mc_votes (
  voter_id uuid not null references public.mc_voters(id) on delete cascade,
  candidate_id uuid not null references public.mc_candidates(id) on delete restrict,
  school_id uuid not null references public.mc_schools(id) on delete cascade,
  primary key (voter_id, candidate_id)
);
create index if not exists mc_votes_candidate_idx on public.mc_votes(candidate_id);
create index if not exists mc_votes_school_idx on public.mc_votes(school_id);

create table if not exists public.mc_sessions (
  token text primary key,
  role text not null check (role in ('super','manager','school')),
  school_id uuid references public.mc_schools(id) on delete cascade,
  manager_id uuid references public.mc_managers(id) on delete cascade,
  expires_at timestamp with time zone not null
);
create index if not exists mc_sessions_exp_idx on public.mc_sessions(expires_at);

create table if not exists public.mc_login_attempts (
  id bigserial primary key,
  k text not null,
  at timestamptz not null default now()
);
create index if not exists mc_login_attempts_k_idx on public.mc_login_attempts(k, at);

alter table public.mc_superadmin enable row level security;
alter table public.mc_system enable row level security;
alter table public.mc_secret enable row level security;
alter table public.mc_managers enable row level security;
alter table public.mc_schools enable row level security;
alter table public.mc_candidates enable row level security;
alter table public.mc_voters enable row level security;
alter table public.mc_votes enable row level security;
alter table public.mc_sessions enable row level security;
alter table public.mc_login_attempts enable row level security;
revoke all on public.mc_superadmin, public.mc_system, public.mc_secret, public.mc_managers, public.mc_schools,
  public.mc_candidates, public.mc_voters, public.mc_votes, public.mc_sessions, public.mc_login_attempts from anon, authenticated;
revoke all on sequence public.mc_login_attempts_id_seq from anon, authenticated;

-- ═══ توابع داخلی (برای anon بسته‌اند) ═══
create or replace function public.mc_assert_site_enabled()
returns void language plpgsql security definer set search_path = public, extensions as $$
declare s public.mc_system;
begin
  select * into s from public.mc_system where id = 1;
  if not s.site_enabled then
    raise exception '%', coalesce(nullif(trim(s.message), ''), 'دسترسی به سامانه توسط ادمین ارشد موقتاً قطع شده است.');
  end if;
end $$;

-- برای super: نشست را می‌سنجد. برای manager: شناسهٔ مدیر. برای school: شناسهٔ مدرسه.
create or replace function public.mc_check_session(p_token text, p_role text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare s public.mc_sessions;
begin
  select * into s from public.mc_sessions where token = p_token and role = p_role and expires_at > now();
  if not found then raise exception 'نشست نامعتبر یا منقضی شده است. دوباره وارد شوید.'; end if;
  if p_role <> 'super' then perform public.mc_assert_site_enabled(); end if;
  if p_role = 'manager' then
    if not exists (select 1 from public.mc_managers where id = s.manager_id and active) then
      delete from public.mc_sessions where token = p_token;
      raise exception 'دسترسی شما توسط ادمین ارشد قطع شده است.';
    end if;
    return s.manager_id;
  end if;
  if p_role = 'school' then
    if not exists (select 1 from public.mc_schools where id = s.school_id and active) then
      delete from public.mc_sessions where token = p_token;
      raise exception 'دسترسی مدرسه شما توسط ادمین ارشد قطع شده است.';
    end if;
  end if;
  return s.school_id;
end $$;

create or replace function public.mc_throttle(p_key text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from public.mc_login_attempts where at < now() - interval '1 day';
  if (select count(*) from public.mc_login_attempts where k = p_key and at > now() - interval '10 minutes') >= 5 then
    raise exception 'تعداد تلاش ناموفق زیاد است. ده دقیقه بعد دوباره تلاش کنید.';
  end if;
end $$;

create or replace function public.mc_valid_national_id(n text)
returns boolean language plpgsql immutable as $$
declare s int := 0; i int; c int; r int;
begin
  if n !~ '^[0-9]{10}$' or n ~ '^(.)\1{9}$' then return false; end if;
  for i in 1..9 loop s := s + substr(n, i, 1)::int * (11 - i); end loop;
  r := s % 11; c := substr(n, 10, 1)::int;
  return (r < 2 and c = r) or (r >= 2 and c = 11 - r);
end $$;

create or replace function public.mc_school_payload(p_school uuid)
returns jsonb language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'school', jsonb_build_object('id', s.id, 'name', s.name, 'slug', s.slug),
    'title', s.title, 'picks', s.picks, 'open', s.open,
    'total_voters', (select count(*) from public.mc_voters v where v.school_id = s.id),
    'total_votes',  (select count(*) from public.mc_votes x where x.school_id = s.id),
    'winners_count', least(s.picks, (select count(*) from public.mc_candidates c where c.school_id = s.id)),
    'candidates', coalesce((
      select jsonb_agg(jsonb_build_object('id', c.id, 'name', c.name, 'vote_count', c.n) order by c.n desc, c.name)
      from (select c.id, c.name, (select count(*) from public.mc_votes x where x.candidate_id = c.id) n
            from public.mc_candidates c where c.school_id = s.id) c
    ), '[]'::jsonb))
  from public.mc_schools s where s.id = p_school
$$;

-- ═══ وضعیت و ورود ═══
create or replace function public.mc_manager_status()
returns jsonb language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'super_setup_required', not exists (select 1 from public.mc_superadmin),
    'setup_required', false,
    'site_enabled', (select site_enabled from public.mc_system where id = 1))
$$;

create or replace function public.mc_super_setup(username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if exists (select 1 from public.mc_superadmin) then raise exception 'حساب ادمین ارشد قبلاً ساخته شده است.'; end if;
  if username is null or username !~ '^[a-zA-Z0-9_.-]{4,40}$' then raise exception 'نام کاربری نامعتبر است.'; end if;
  if password is null or char_length(password) < 12 then raise exception 'رمز عبور حداقل ۱۲ نویسه باشد.'; end if;
  insert into public.mc_superadmin(id, username, pass_hash) values (1, username, extensions.crypt(password, extensions.gen_salt('bf', 10)));
  return jsonb_build_object('ok', true);
exception when unique_violation then raise exception 'حساب ادمین ارشد قبلاً ساخته شده است.';
end $$;

create or replace function public.mc_super_login(username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare m public.mc_superadmin; t text; k text := 'a:' || lower(coalesce(username,''));
begin
  perform public.mc_throttle(k);
  select * into m from public.mc_superadmin where lower(mc_superadmin.username) = lower(coalesce(mc_super_login.username,''));
  if not found or m.pass_hash <> extensions.crypt(coalesce(password,''), m.pass_hash) then
    insert into public.mc_login_attempts(k) values (k);
    raise exception 'نام کاربری یا رمز عبور نادرست است.';
  end if;
  delete from public.mc_sessions where expires_at < now();
  t := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.mc_sessions(token, role, expires_at) values (t, 'super', now() + interval '8 hours');
  return jsonb_build_object('token', t);
end $$;

create or replace function public.mc_manager_login(username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare m public.mc_managers; t text; k text := 'm:' || lower(coalesce(username,''));
begin
  perform public.mc_assert_site_enabled();
  perform public.mc_throttle(k);
  select * into m from public.mc_managers where lower(mc_managers.username) = lower(coalesce(mc_manager_login.username,''));
  if not found or m.pass_hash <> extensions.crypt(coalesce(password,''), m.pass_hash) then
    insert into public.mc_login_attempts(k) values (k);
    raise exception 'نام کاربری یا رمز عبور نادرست است.';
  end if;
  if not m.active then raise exception 'دسترسی شما توسط ادمین ارشد قطع شده است.'; end if;
  delete from public.mc_sessions where expires_at < now();
  t := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.mc_sessions(token, role, manager_id, expires_at) values (t, 'manager', m.id, now() + interval '12 hours');
  return jsonb_build_object('token', t);
end $$;

create or replace function public.mc_school_login(username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare s public.mc_schools; t text; k text := 's:' || lower(coalesce(username,''));
begin
  perform public.mc_assert_site_enabled();
  perform public.mc_throttle(k);
  select * into s from public.mc_schools where lower(mc_schools.username) = lower(coalesce(mc_school_login.username,''));
  if not found or s.pass_hash <> extensions.crypt(coalesce(password,''), s.pass_hash) then
    insert into public.mc_login_attempts(k) values (k);
    raise exception 'نام کاربری یا رمز عبور نادرست است.';
  end if;
  if not s.active then raise exception 'حساب این مدرسه غیرفعال است.'; end if;
  delete from public.mc_sessions where expires_at < now();
  t := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.mc_sessions(token, role, school_id, expires_at) values (t, 'school', s.id, now() + interval '12 hours');
  return jsonb_build_object('token', t);
end $$;

-- ═══ ادمین ارشد ═══
create or replace function public.mc_super_state(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  return jsonb_build_object(
    'site_enabled', (select site_enabled from public.mc_system where id = 1),
    'message', (select message from public.mc_system where id = 1),
    'updated_at', (select updated_at from public.mc_system where id = 1),
    'school_count', (select count(*) from public.mc_schools),
    'manager_count', (select count(*) from public.mc_managers),
    'active_sessions', (select count(*) from public.mc_sessions where role in ('manager','school') and expires_at > now()),
    'total_voters', (select count(*) from public.mc_voters),
    'managers', coalesce((
      select jsonb_agg(jsonb_build_object('id', m.id, 'username', m.username, 'active', m.active, 'created_at', m.created_at,
        'school_count', (select count(*) from public.mc_schools s where s.manager_id = m.id)) order by m.created_at)
      from public.mc_managers m), '[]'::jsonb),
    'schools', coalesce((
      select jsonb_agg(jsonb_build_object('id', s.id, 'name', s.name, 'username', s.username, 'active', s.active, 'open', s.open,
        'manager_username', m.username,
        'vote_count', (select count(*) from public.mc_votes x where x.school_id = s.id)) order by s.created_at desc)
      from public.mc_schools s join public.mc_managers m on m.id = s.manager_id), '[]'::jsonb));
end $$;

-- کلید قطع/وصل سراسری؛ هنگام قطع، نشست‌های مدیران و مدارس بلافاصله پاک می‌شود
create or replace function public.mc_super_set_site(token text, enabled boolean, message text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if enabled is null then raise exception 'وضعیت نامعتبر است.'; end if;
  if message is not null and char_length(message) > 300 then raise exception 'پیام حداکثر ۳۰۰ نویسه باشد.'; end if;
  update public.mc_system set site_enabled = enabled,
    message = case when enabled then null else nullif(trim(mc_super_set_site.message), '') end, updated_at = now() where id = 1;
  if not enabled then delete from public.mc_sessions where role in ('manager','school'); end if;
  return jsonb_build_object('site_enabled', enabled);
end $$;

create or replace function public.mc_super_create_manager(token text, username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid;
begin
  perform public.mc_check_session(token, 'super');
  if username is null or username !~ '^[a-zA-Z0-9_.-]{4,40}$' then raise exception 'نام کاربری فقط حروف انگلیسی، عدد و . _ - (حداقل ۴ نویسه) باشد.'; end if;
  if password is null or char_length(password) < 12 then raise exception 'رمز عبور حداقل ۱۲ نویسه باشد.'; end if;
  insert into public.mc_managers(username, pass_hash) values (username, extensions.crypt(password, extensions.gen_salt('bf', 10))) returning id into mid;
  return jsonb_build_object('id', mid);
exception when unique_violation then raise exception 'این نام کاربری قبلاً استفاده شده است.';
end $$;

create or replace function public.mc_super_set_manager_active(token text, manager_id uuid, active boolean)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if active is null then raise exception 'وضعیت نامعتبر است.'; end if;
  update public.mc_managers m set active = mc_super_set_manager_active.active where m.id = mc_super_set_manager_active.manager_id;
  if not found then raise exception 'مدیر پیدا نشد.'; end if;
  if not active then delete from public.mc_sessions s where s.manager_id = mc_super_set_manager_active.manager_id; end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.mc_super_reset_manager_password(token text, manager_id uuid, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if password is null or char_length(password) < 12 then raise exception 'رمز عبور حداقل ۱۲ نویسه باشد.'; end if;
  update public.mc_managers m set pass_hash = extensions.crypt(password, extensions.gen_salt('bf', 10)) where m.id = mc_super_reset_manager_password.manager_id;
  if not found then raise exception 'مدیر پیدا نشد.'; end if;
  delete from public.mc_sessions s where s.manager_id = mc_super_reset_manager_password.manager_id;
  return jsonb_build_object('ok', true);
end $$;

-- کلید دسترسی هر مدرسه؛ هنگام قطع، نشست مدیر مدرسه پاک و لینک رأی‌دهندگان بسته می‌شود
create or replace function public.mc_super_set_school_active(token text, school_id uuid, active boolean)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if active is null then raise exception 'وضعیت نامعتبر است.'; end if;
  update public.mc_schools s set active = mc_super_set_school_active.active where s.id = mc_super_set_school_active.school_id;
  if not found then raise exception 'مدرسه پیدا نشد.'; end if;
  if not active then delete from public.mc_sessions x where x.school_id = mc_super_set_school_active.school_id; end if;
  return jsonb_build_object('ok', true);
end $$;

-- ═══ مدیر کل (فقط مدارس خودش) ═══
create or replace function public.mc_manager_schools(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager');
begin
  return jsonb_build_object('schools', coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', s.id, 'name', s.name, 'username', s.username, 'slug', s.slug, 'active', s.active, 'open', s.open,
      'candidate_count', (select count(*) from public.mc_candidates c where c.school_id = s.id),
      'vote_count', (select count(*) from public.mc_votes x where x.school_id = s.id)
    ) order by s.created_at desc) from public.mc_schools s where s.manager_id = mid), '[]'::jsonb));
end $$;

create or replace function public.mc_manager_dashboard(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager');
begin
  return jsonb_build_object(
    'school_count', (select count(*) from public.mc_schools where manager_id = mid),
    'active_schools', (select count(*) from public.mc_schools where manager_id = mid and active),
    'total_voters', (select count(*) from public.mc_voters v join public.mc_schools s on s.id = v.school_id where s.manager_id = mid),
    'total_votes', (select count(*) from public.mc_votes x join public.mc_schools s on s.id = x.school_id where s.manager_id = mid),
    'schools', coalesce((
      select jsonb_agg(jsonb_build_object('id', q.id, 'name', q.name, 'vote_count', q.n) order by q.n desc, q.name)
      from (select s.id, s.name, (select count(*) from public.mc_votes x where x.school_id = s.id) n
            from public.mc_schools s where s.manager_id = mid) q
    ), '[]'::jsonb));
end $$;

create or replace function public.mc_manager_create_school(token text, name text, username text, password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager'); sid uuid;
begin
  if name is null or char_length(trim(name)) < 2 then raise exception 'نام مدرسه نامعتبر است.'; end if;
  if username is null or username !~ '^[a-zA-Z0-9_.-]{3,40}$' then raise exception 'نام کاربری فقط حروف انگلیسی، عدد و . _ - باشد.'; end if;
  if password is null or char_length(password) < 12 then raise exception 'رمز عبور حداقل ۱۲ نویسه باشد.'; end if;
  insert into public.mc_schools(name, username, pass_hash, manager_id)
  values (trim(name), username, extensions.crypt(password, extensions.gen_salt('bf', 10)), mid) returning id into sid;
  return jsonb_build_object('id', sid);
exception when unique_violation then raise exception 'این نام کاربری قبلاً استفاده شده است.';
end $$;

create or replace function public.mc_manager_school_detail(token text, school_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager'); r jsonb;
begin
  if not exists (select 1 from public.mc_schools s where s.id = mc_manager_school_detail.school_id and s.manager_id = mid) then
    raise exception 'مدرسه پیدا نشد.';
  end if;
  r := public.mc_school_payload(school_id);
  return r;
end $$;

create or replace function public.mc_manager_results(token text, school_id uuid default null, "limit" int default 10)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager');
        lim int := greatest(1, least(coalesce("limit", 10), 500));
        sid uuid := mc_manager_results.school_id;
begin
  if sid is not null and not exists (select 1 from public.mc_schools s where s.id = sid and s.manager_id = mid) then
    raise exception 'مدرسه پیدا نشد.';
  end if;
  return jsonb_build_object(
    'total_voters', (select count(*) from public.mc_voters v join public.mc_schools s on s.id = v.school_id where s.manager_id = mid and (sid is null or v.school_id = sid)),
    'total_votes',  (select count(*) from public.mc_votes x join public.mc_schools s on s.id = x.school_id where s.manager_id = mid and (sid is null or x.school_id = sid)),
    'rows', coalesce((
      select jsonb_agg(jsonb_build_object('rank', q.rk, 'candidate_name', q.cname, 'school_name', q.sname, 'vote_count', q.n) order by q.rk)
      from (
        select row_number() over (order by a.n desc, a.cname) rk, a.cname, a.sname, a.n
        from (
          select c.name cname, s.name sname, (select count(*) from public.mc_votes x where x.candidate_id = c.id) n
          from public.mc_candidates c join public.mc_schools s on s.id = c.school_id
          where s.manager_id = mid and (sid is null or c.school_id = sid)
        ) a
        order by a.n desc, a.cname limit lim
      ) q), '[]'::jsonb));
end $$;

-- ═══ مدیر مدرسه ═══
create or replace function public.mc_school_detail(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  return public.mc_school_payload(public.mc_check_session(token, 'school'));
end $$;

create or replace function public.mc_school_add_candidates(token text, names text[])
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := public.mc_check_session(token, 'school'); n text; added int := 0;
begin
  if names is null or array_length(names, 1) is null then raise exception 'حداقل یک نام وارد کنید.'; end if;
  if array_length(names, 1) > 200 then raise exception 'در هر بار حداکثر ۲۰۰ کاندیدا مجاز است.'; end if;
  foreach n in array names loop
    n := trim(regexp_replace(coalesce(n,''), '\s+', ' ', 'g'));
    if char_length(n) < 2 or char_length(n) > 80 then raise exception 'نام هر کاندیدا باید بین ۲ تا ۸۰ نویسه باشد.'; end if;
    insert into public.mc_candidates(school_id, name) values (sid, n) on conflict do nothing;
    if found then added := added + 1; end if;
  end loop;
  return jsonb_build_object('added', added);
end $$;

create or replace function public.mc_school_delete_candidate(token text, candidate_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := public.mc_check_session(token, 'school');
begin
  if exists (select 1 from public.mc_votes x where x.candidate_id = mc_school_delete_candidate.candidate_id) then
    raise exception 'این کاندیدا رأی دارد و قابل حذف نیست.';
  end if;
  delete from public.mc_candidates c where c.id = mc_school_delete_candidate.candidate_id and c.school_id = sid;
  if not found then raise exception 'کاندیدا پیدا نشد.'; end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.mc_school_settings(token text, title text default null, picks int default null, "open" boolean default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := public.mc_check_session(token, 'school');
begin
  if title is not null and (char_length(trim(title)) < 3 or char_length(title) > 120) then raise exception 'عنوان انتخابات نامعتبر است.'; end if;
  if picks is not null and (picks < 1 or picks > 50) then raise exception 'تعداد انتخاب باید بین ۱ تا ۵۰ باشد.'; end if;
  update public.mc_schools s set
    title = coalesce(trim(mc_school_settings.title), s.title),
    picks = coalesce(mc_school_settings.picks, s.picks),
    open  = coalesce(mc_school_settings."open", s.open)
  where s.id = sid;
  return jsonb_build_object('ok', true);
end $$;

-- ═══ رأی‌دهندگان (عمومی) ═══
create or replace function public.mc_public_election(school_slug text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare s public.mc_schools;
begin
  perform public.mc_assert_site_enabled();
  select * into s from public.mc_schools where slug = school_slug;
  if not found or not s.active then raise exception 'این انتخابات پیدا نشد.'; end if;
  return jsonb_build_object(
    'school_name', s.name, 'title', s.title, 'picks', s.picks, 'open', s.open,
    'candidates', case when s.open then coalesce((
      select jsonb_agg(jsonb_build_object('id', c.id, 'name', c.name) order by c.name)
      from public.mc_candidates c where c.school_id = s.id), '[]'::jsonb) else '[]'::jsonb end);
end $$;

create or replace function public.mc_cast_vote(school_slug text, fname text, lname text, national_id text, candidate_ids uuid[])
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare s public.mc_schools; pepper text; h text; vid uuid; code text; ids uuid[];
begin
  perform public.mc_assert_site_enabled();
  select * into s from public.mc_schools where slug = school_slug for share;
  if not found or not s.active then raise exception 'این انتخابات پیدا نشد.'; end if;
  if not s.open then raise exception 'رأی‌گیری بسته است.'; end if;
  fname := trim(coalesce(fname,'')); lname := trim(coalesce(lname,''));
  if char_length(fname) not between 1 and 60 or char_length(lname) not between 1 and 60 then raise exception 'نام و نام خانوادگی را درست وارد کنید.'; end if;
  national_id := regexp_replace(coalesce(national_id,''), '\D', '', 'g');
  if not public.mc_valid_national_id(national_id) then raise exception 'کد ملی معتبر نیست.'; end if;
  select array(select distinct x from unnest(coalesce(candidate_ids, '{}')) x) into ids;
  if coalesce(array_length(ids,1),0) < 1 then raise exception 'حداقل یک کاندیدا را انتخاب کنید.'; end if;
  if array_length(ids,1) > s.picks then raise exception 'تعداد انتخاب‌ها بیش از حد مجاز است.'; end if;
  if (select count(*) from public.mc_candidates c where c.school_id = s.id and c.id = any(ids)) <> array_length(ids,1) then
    raise exception 'کاندیدای انتخاب‌شده معتبر نیست.';
  end if;
  select m.pepper into pepper from public.mc_secret m where m.id = 1;
  h := encode(extensions.hmac(national_id || ':' || s.id::text, pepper, 'sha256'), 'hex');
  code := 'V-' || upper(encode(extensions.gen_random_bytes(5), 'hex'));
  begin
    insert into public.mc_voters(school_id, nid_hash, fname, lname, tracking_code)
    values (s.id, h, fname, lname, code) returning id into vid;
  exception when unique_violation then
    raise exception 'با این کد ملی قبلاً در این انتخابات رأی ثبت شده است.';
  end;
  insert into public.mc_votes(voter_id, candidate_id, school_id) select vid, x, s.id from unnest(ids) x;
  return jsonb_build_object('tracking_code', code);
end $$;


-- ═══ عملیات حذف و پاک‌سازی مدیریتی ═══
create or replace function public.mc_super_delete_manager(token text, manager_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare school_ids uuid[];
begin
  perform public.mc_check_session(token, 'super');
  if not exists (select 1 from public.mc_managers where id = mc_super_delete_manager.manager_id) then
    raise exception 'مدیر کل پیدا نشد.';
  end if;
  select array_agg(id) into school_ids from public.mc_schools where manager_id = mc_super_delete_manager.manager_id;
  if school_ids is not null then
    delete from public.mc_votes where school_id = any(school_ids);
    delete from public.mc_voters where school_id = any(school_ids);
    delete from public.mc_candidates where school_id = any(school_ids);
    delete from public.mc_schools where id = any(school_ids);
  end if;
  delete from public.mc_managers where id = mc_super_delete_manager.manager_id;
  return jsonb_build_object('ok', true, 'deleted_schools', coalesce(cardinality(school_ids), 0));
end $$;

create or replace function public.mc_super_delete_school(token text, school_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if not exists (select 1 from public.mc_schools where id = mc_super_delete_school.school_id) then
    raise exception 'مدرسه پیدا نشد.';
  end if;
  delete from public.mc_votes where school_id = mc_super_delete_school.school_id;
  delete from public.mc_voters where school_id = mc_super_delete_school.school_id;
  delete from public.mc_candidates where school_id = mc_super_delete_school.school_id;
  delete from public.mc_schools where id = mc_super_delete_school.school_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.mc_super_clear_all_results(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare vc bigint; xc bigint;
begin
  perform public.mc_check_session(token, 'super');
  select count(*) into vc from public.mc_voters;
  select count(*) into xc from public.mc_votes;
  delete from public.mc_voters;
  return jsonb_build_object('ok', true, 'deleted_voters', vc, 'deleted_votes', xc);
end $$;

create or replace function public.mc_manager_delete_school(token text, school_id uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager');
begin
  if not exists (select 1 from public.mc_schools where id = mc_manager_delete_school.school_id and manager_id = mid) then
    raise exception 'مدرسه پیدا نشد یا متعلق به شما نیست.';
  end if;
  delete from public.mc_votes where school_id = mc_manager_delete_school.school_id;
  delete from public.mc_voters where school_id = mc_manager_delete_school.school_id;
  delete from public.mc_candidates where school_id = mc_manager_delete_school.school_id;
  delete from public.mc_schools where id = mc_manager_delete_school.school_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.mc_manager_clear_results(token text, school_id uuid default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid := public.mc_check_session(token, 'manager'); vc bigint; xc bigint;
begin
  if school_id is not null and not exists (
    select 1 from public.mc_schools where id = mc_manager_clear_results.school_id and manager_id = mid
  ) then raise exception 'مدرسه پیدا نشد یا متعلق به شما نیست.'; end if;
  select count(*) into vc from public.mc_voters v join public.mc_schools s on s.id=v.school_id
    where s.manager_id=mid and (mc_manager_clear_results.school_id is null or s.id=mc_manager_clear_results.school_id);
  select count(*) into xc from public.mc_votes x join public.mc_schools s on s.id=x.school_id
    where s.manager_id=mid and (mc_manager_clear_results.school_id is null or s.id=mc_manager_clear_results.school_id);
  delete from public.mc_voters v using public.mc_schools s
    where v.school_id=s.id and s.manager_id=mid
      and (mc_manager_clear_results.school_id is null or s.id=mc_manager_clear_results.school_id);
  return jsonb_build_object('ok', true, 'deleted_voters', vc, 'deleted_votes', xc);
end $$;

create or replace function public.mc_school_clear_results(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare sid uuid := public.mc_check_session(token, 'school'); vc bigint; xc bigint;
begin
  select count(*) into vc from public.mc_voters where school_id=sid;
  select count(*) into xc from public.mc_votes where school_id=sid;
  delete from public.mc_voters where school_id=sid;
  return jsonb_build_object('ok', true, 'deleted_voters', vc, 'deleted_votes', xc);
end $$;

-- نام کاربری فعلی ادمین ارشد
create or replace function public.mc_super_me(token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  return jsonb_build_object('username', (select username from public.mc_superadmin where id = 1));
end $$;

-- تغییر نام کاربری ادمین ارشد (با تأیید رمز فعلی)
create or replace function public.mc_super_change_username(token text, current_password text, new_username text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare m public.mc_superadmin; k text;
begin
  perform public.mc_check_session(token, 'super');
  select * into m from public.mc_superadmin where id = 1;
  k := 'a:' || lower(m.username);
  perform public.mc_throttle(k);
  if m.pass_hash <> extensions.crypt(coalesce(current_password,''), m.pass_hash) then
    insert into public.mc_login_attempts(k) values (k);
    raise exception 'رمز عبور فعلی نادرست است.';
  end if;
  if new_username is null or new_username !~ '^[a-zA-Z0-9_.-]{4,40}$' then
    raise exception 'نام کاربری فقط حروف انگلیسی، عدد و . _ - (حداقل ۴ نویسه) باشد.';
  end if;
  update public.mc_superadmin set username = new_username where id = 1;
  return jsonb_build_object('ok', true, 'username', new_username);
end $$;

-- تغییر رمز عبور ادمین ارشد (با تأیید رمز فعلی)؛ نشست‌های دیگر ادمین ارشد بسته می‌شود
create or replace function public.mc_super_change_password(token text, current_password text, new_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare m public.mc_superadmin; k text;
begin
  perform public.mc_check_session(token, 'super');
  select * into m from public.mc_superadmin where id = 1;
  k := 'a:' || lower(m.username);
  perform public.mc_throttle(k);
  if m.pass_hash <> extensions.crypt(coalesce(current_password,''), m.pass_hash) then
    insert into public.mc_login_attempts(k) values (k);
    raise exception 'رمز عبور فعلی نادرست است.';
  end if;
  if new_password is null or char_length(new_password) < 12 then
    raise exception 'رمز عبور جدید حداقل ۱۲ نویسه باشد.';
  end if;
  if new_password = current_password then
    raise exception 'رمز جدید باید با رمز فعلی متفاوت باشد.';
  end if;
  update public.mc_superadmin set pass_hash = extensions.crypt(new_password, extensions.gen_salt('bf', 10)) where id = 1;
  delete from public.mc_sessions s where s.role = 'super' and s.token <> mc_super_change_password.token;
  return jsonb_build_object('ok', true);
end $$;

-- تغییر نام کاربری یک مدیر کل توسط ادمین ارشد
create or replace function public.mc_super_change_manager_username(token text, manager_id uuid, new_username text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public.mc_check_session(token, 'super');
  if new_username is null or new_username !~ '^[a-zA-Z0-9_.-]{4,40}$' then
    raise exception 'نام کاربری فقط حروف انگلیسی، عدد و . _ - (حداقل ۴ نویسه) باشد.';
  end if;
  update public.mc_managers m set username = new_username where m.id = mc_super_change_manager_username.manager_id;
  if not found then raise exception 'مدیر پیدا نشد.'; end if;
  return jsonb_build_object('ok', true);
exception when unique_violation then raise exception 'این نام کاربری قبلاً استفاده شده است.';
end $$;

-- ═══ دسترسی‌ها: فقط توابع API برای anon؛ توابع داخلی بسته ═══
revoke all on function public.mc_assert_site_enabled(), public.mc_check_session(text,text), public.mc_throttle(text),
  public.mc_valid_national_id(text), public.mc_school_payload(uuid) from public, anon, authenticated;

do $$ declare f text; begin
  foreach f in array array[
    'mc_manager_status()','mc_super_setup(text,text)','mc_super_login(text,text)','mc_manager_login(text,text)','mc_school_login(text,text)',
    'mc_super_state(text)','mc_super_set_site(text,boolean,text)','mc_super_create_manager(text,text,text)',
    'mc_super_set_manager_active(text,uuid,boolean)','mc_super_reset_manager_password(text,uuid,text)','mc_super_set_school_active(text,uuid,boolean)',
    'mc_super_delete_manager(text,uuid)','mc_super_delete_school(text,uuid)','mc_super_clear_all_results(text)',
    'mc_super_me(text)','mc_super_change_username(text,text,text)','mc_super_change_password(text,text,text)','mc_super_change_manager_username(text,uuid,text)',
    'mc_manager_delete_school(text,uuid)','mc_manager_clear_results(text,uuid)','mc_school_clear_results(text)',
    'mc_manager_schools(text)','mc_manager_dashboard(text)','mc_manager_create_school(text,text,text,text)',
    'mc_manager_school_detail(text,uuid)','mc_manager_results(text,uuid,int)','mc_school_detail(text)',
    'mc_school_add_candidates(text,text[])','mc_school_delete_candidate(text,uuid)','mc_school_settings(text,text,int,boolean)',
    'mc_public_election(text)','mc_cast_vote(text,text,text,text,uuid[])'
  ] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

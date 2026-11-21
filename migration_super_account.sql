-- ════════════════════════════════════════════════════════════════════
--  افزونه: تغییر نام کاربری و رمز عبور ادمین ارشد + تغییر نام کاربری مدیر کل
--  برای نسخه‌ای که از قبل نصب شده است، یک‌بار در SQL Editor اجرا کنید (اجرای دوباره بی‌خطر است).
-- ════════════════════════════════════════════════════════════════════

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

do $$ declare f text; begin
  foreach f in array array[
    'mc_super_me(text)',
    'mc_super_change_username(text,text,text)',
    'mc_super_change_password(text,text,text)',
    'mc_super_change_manager_username(text,uuid,text)'
  ] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

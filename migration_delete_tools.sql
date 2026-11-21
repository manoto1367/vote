
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


-- Restrict direct invocation to the API roles used by the application.
revoke all on function public.mc_super_delete_manager(text,uuid) from public;
revoke all on function public.mc_super_delete_school(text,uuid) from public;
revoke all on function public.mc_super_clear_all_results(text) from public;
revoke all on function public.mc_manager_delete_school(text,uuid) from public;
revoke all on function public.mc_manager_clear_results(text,uuid) from public;
revoke all on function public.mc_school_clear_results(text) from public;

grant execute on function public.mc_super_delete_manager(text,uuid) to anon, authenticated;
grant execute on function public.mc_super_delete_school(text,uuid) to anon, authenticated;
grant execute on function public.mc_super_clear_all_results(text) to anon, authenticated;
grant execute on function public.mc_manager_delete_school(text,uuid) to anon, authenticated;
grant execute on function public.mc_manager_clear_results(text,uuid) to anon, authenticated;
grant execute on function public.mc_school_clear_results(text) to anon, authenticated;


-- حذف کاندیدا همراه با آرای ثبت‌شده خودش؛ آرای سایر کاندیداها دست‌نخورده می‌ماند.
create or replace function public.mc_school_delete_candidate(token text, candidate_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $function$
declare
  sid uuid := public.mc_check_session(token, 'school');
  deleted_votes bigint;
begin
  if not exists (
    select 1 from public.mc_candidates c
    where c.id = mc_school_delete_candidate.candidate_id
      and c.school_id = sid
  ) then
    raise exception 'کاندیدا پیدا نشد یا متعلق به این مدرسه نیست.';
  end if;

  delete from public.mc_votes v
  where v.candidate_id = mc_school_delete_candidate.candidate_id
    and v.school_id = sid;
  get diagnostics deleted_votes = row_count;

  delete from public.mc_candidates c
  where c.id = mc_school_delete_candidate.candidate_id
    and c.school_id = sid;

  return jsonb_build_object('ok', true, 'deleted_votes', deleted_votes);
end
$function$;
revoke all on function public.mc_school_delete_candidate(text, uuid) from public;
grant execute on function public.mc_school_delete_candidate(text, uuid) to anon, authenticated;

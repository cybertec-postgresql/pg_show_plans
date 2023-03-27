create extension pg_show_plans;

show pg_show_plans.is_enabled;
show pg_show_plans.max_plan_length;

create function nest()
  returns table (level bigint, plan text)
  language plpgsql
as $$
  begin
    return query
      select pg_show_plans.level, pg_show_plans.plan from pg_show_plans
        where pg_show_plans.level >= 0;
  end;
$$;

-- text output
show pg_show_plans.plan_format;
select level, plan from pg_show_plans;
select * from nest();

set pg_show_plans.plan_format = 'json'; -- fails

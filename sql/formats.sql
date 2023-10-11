-- explain output on PG12/13 is missing "Async Capable"
select setting::int < 140000 as pg12_13 from pg_settings where name = 'server_version_num';

-- json output
set pg_show_plans.plan_format = 'json';
show pg_show_plans.plan_format;
select * from nest();

-- yaml output
set pg_show_plans.plan_format = 'yaml';
show pg_show_plans.plan_format;
select * from nest();

-- xml output
set pg_show_plans.plan_format = 'xml';
show pg_show_plans.plan_format;
select * from nest();

-- check plan format after reconnect
\c
show pg_show_plans.plan_format;

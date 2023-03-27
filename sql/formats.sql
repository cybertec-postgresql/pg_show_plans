-- explain output on PG12/13 is missing "Async Capable"
select setting::int < 140000 as pg12_13 from pg_settings where name = 'server_version_num';

-- json output
select pgsp_format_json();
show pg_show_plans.plan_format;
select * from nest();

-- yaml output
select pgsp_format_yaml();
show pg_show_plans.plan_format;
select * from nest();

-- xml output
select pgsp_format_xml();
show pg_show_plans.plan_format;
select * from nest();

-- check plan format after reconnect
\c
show pg_show_plans.plan_format;

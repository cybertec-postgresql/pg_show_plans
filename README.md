# pg_show_plans

PostgreSQL extension that shows query plans of all the currently running SQL
statements.

Plan output format can either be plain TEXT (default), or JSON.

### NOTE

This extension creates a hash table within shared memory. The hash table is not
resizable, thus, no new plans can be added once it has been filled up.

# INSTALL

There are several ways of doing it...

## Using `pg_confg` (recommended):

```
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
USE_PGXS=true # `pg_config` binary must be in your $PATH (install Postgres).
make
make install
```

## Within PostgreSQL source tree:

```
export PG_VER='15.1' # Export the required PostgreSQL version.
curl -O "https://download.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2"
tar xvfj "postgresql-${PG_VER}.tar.bz2"
cd postgresql-${PG_VER}
./configure

cd contrib
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
make
make install
```

# USAGE

Add `pg_show_plans` to `shared_preload_libraries` within `postgresql.conf`:

```
shared_preload_libraries = 'pg_show_plans' # Like that.
```

Start the server, and invoke `CREATE EXTENSION pg_show_plans;`:

```
postgresql=# CREATE EXTENSION pg_show_plans; # Like that.
CREATE EXTENSION
postgresql=#
```

To get the query plans along with relevant information:

```
testdb=# SELECT * FROM pg_show_plans;
  pid  | level | userid | dbid  |                                 plan
-------+-------+--------+-------+-----------------------------------------------------------------------
 11473 |     0 |     10 | 16384 | Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=56)
 11504 |     0 |     10 | 16384 | Function Scan on print_item  (cost=0.25..10.25 rows=1000 width=524)
 11504 |     1 |     10 | 16384 | Result  (cost=0.00..0.01 rows=1 width=4)
(3 rows)
```

To get the plans and see the corresponding query expression:

```
testdb=# \x
Expanded display is on.
testdb=# SELECT p.pid, p.level, p.plan, a.query
         FROM pg_show_plans p
         LEFT JOIN pg_stat_activity a
         ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;
-[ RECORD 1 ]-----------------------------------------------------------------------------------------
pid   | 11473
level | 0
plan  | Sort  (cost=72.08..74.58 rows=1000 width=80)                                                  +
      |   Sort Key: pg_show_plans.pid, pg_show_plans.level                                            +
      |   ->  Hash Left Join  (cost=2.25..22.25 rows=1000 width=80)                                   +
      |         Hash Cond: (pg_show_plans.pid = s.pid)                                                +
      |         Join Filter: (pg_show_plans.level = 0)                                                +
      |         ->  Function Scan on pg_show_plans  (cost=0.00..10.00 rows=1000 width=48)             +
      |         ->  Hash  (cost=1.00..1.00 rows=100 width=44)                                         +
      |               ->  Function Scan on pg_stat_get_activity s  (cost=0.00..1.00 rows=100 width=44)
query | SELECT p.pid, p.level, p.plan, a.query FROM pg_show_plans p                                   +
      |    LEFT JOIN pg_stat_activity a                                                               +
      |    ON p.pid = a.pid AND p.level = 0 ORDER BY p.pid, p.level;
-[ RECORD 2 ]-----------------------------------------------------------------------------------------
pid   | 11517
level | 0
plan  | Function Scan on print_item  (cost=0.25..10.25 rows=1000 width=524)
query | SELECT * FROM print_item(1,20);
-[ RECORD 3 ]-----------------------------------------------------------------------------------------
pid   | 11517
level | 1
plan  | Result  (cost=0.00..0.01 rows=1 width=4)
query |

```

# pg_show_plans VIEW
 - *pid*: the pid of the process which the query is running.
 - *level*: the level of the query which runs the query. Top level is `0`. For
   example, if you execute a simple select query, the level of this query's
   plan is 0. If you execute a function that invokes a select query, level 0 is
   the plan of the function and level 1 is the plan of the select query invoked
   by the function.
 - *userid*: the userid of the user which runs the query.
 - *dbid*: the database id of the database which the query is running.
 - *plan*: the query plan of the running query.

# FUNCTIONs
 - *pg_show_plans_disable()* disables the feature. Only superuser can execute
   it.
 - *pg_show_plans_enable()* enables the feature. Only superuser can execute it.
 - *pgsp_format_json()* changes the output format to `json`. Note that the
   format of the plans that are stored in the memory before executing this
   function cannot be changed.
 - *pgsp_format_text()* changes the output format to `text`. Note that the
   format of the plans that are stored in the memory before executing this
   function cannot be changed.

# CONFIGURATION
 - *pg_show_plans.plan_format* : It controls the output format of query plans.
   It can be selected either `text` or `json`. Default is `text`.
 - *pg_show_plans.max_plan_length* : It sets the maximum length of query plans.
   Default is `16384` [byte]. Note that this parameter must be set to an
   integer. Note that pg_show plans allocates approximately (max_plan_length *
   max_connecions) bytes on the shared memory to store plans, Therefore, if the
   value of max_plan_length is too large, PostgreSQL may not start due to an
   out of memory error.
 - *pg_show_plans.enable* : It controls whether this feature is enabled or not
   in each user. Default is 'true'.

# CHANGELOG

 - 22 Mar, 2022: Version 1.0 Released.
 - 22 Mar, 2022: Improved memory utilization efficiency and obsoleted a
   parameter:pg_show_plans.enable_txid.
 - 30 Aug, 2021: Added a parameter:pg_show_plans.enable_txid.
 - 4 Feb, 2021: Added a parameter:pg_show_plans.enable.
 - 19 Oct, 2020: Confirmed this can be run on PostgreSQL 13.0.
 - 10 Apr, 2020: Version 1.0 RC3 Released. Supported Streaming Replication.
   This extension can be run on the standby server since this version.
 - 26 Mar, 2020: Version 1.0 RC2 Released. Added pgsp_format_json() and
   pgsp_format_text(); deleted the parameter `show_level`.
 - 21 Dec, 2019: Version 1.0 RC Released. Supported versions from 9.1 to 9.4.
 - 16 Aug, 2019: Version 0.8 Released. Supported the parameter:max_plan_length.
 - 12 Aug, 2019: Version 0.3 Released. Supported garbage collection.
 - 9 Aug, 2019: Version 0.2 Released. Supported nested queries.
 - 8 Aug, 2019: Version 0.1 Released.

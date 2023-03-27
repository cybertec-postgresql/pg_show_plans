# pg_show_plans

PostgreSQL extension that shows query plans of all the currently running SQL
statements.

Plan output format can be plain TEXT (default), JSON, YAML, or XML.

PostgreSQL versions 12 and later are supported.

### NOTE

This extension creates a hash table within shared memory. The hash table is not
resizable, thus, no new plans can be added once it has been filled up.

# INSTALL

There are several ways of doing it...

## Using `pg_config` (recommended):

```
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
make # `pg_config` binary must be in your $PATH (install Postgres).
sudo make install
```

## Within PostgreSQL source tree:

```
PG_VER='15.1' # Set the required PostgreSQL version.
curl -O "https://download.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2"
tar xvfj "postgresql-${PG_VER}.tar.bz2"
cd postgresql-${PG_VER}
./configure

cd contrib
git clone https://github.com/cybertec-postgresql/pg_show_plans.git
cd pg_show_plans
make
sudo make install
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
 - *pgsp_format_text()* changes the output format to `text`. Note that the
   format of the plans that are stored in the memory before executing this
   function cannot be changed.
 - *pgsp_format_json()* changes the output format to `json`.
 - *pgsp_format_yaml()* changes the output format to `yaml`.
 - *pgsp_format_xml()* changes the output format to `xml`.

# CONFIGURATION
 - *pg_show_plans.plan_format* : It controls the output format of query plans.
   It can be selected `text`, `json`, `yaml`, `xml`. Default is `text`.
 - *pg_show_plans.max_plan_length* : It sets the maximum length of query plans.
   Default is `16384` [byte]. Note that this parameter must be set to an
   integer. Note that pg_show plans allocates approximately (max_plan_length *
   max_connecions) bytes on the shared memory to store plans, Therefore, if the
   value of max_plan_length is too large, PostgreSQL may not start due to an
   out of memory error.
 - *pg_show_plans.is_enabled* : It controls whether the extension starts
   enabled. Default is `true`
